// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Runtime telemetry sampling and bounded historical retention.
//!
//! Kagi keeps the collection path deliberately local and cheap: Linux block statistics,
//! queue state, network counters, and process-independent host statistics are sampled on
//! each node and retained in memory for a configurable interval. Cluster views aggregate
//! those node-local histories through the existing authenticated internal API rather than
//! introducing a second monitoring database.
//!
//! Counter deltas are calculated here, close to the kernel data, so the web/API layer sees
//! explicit rates and latencies rather than having to reinterpret raw /proc or /sys values.

use crate::cluster::ClusterConfig;
use crate::storage;
use crate::webui::SystemStats;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Local operations-telemetry sampling and in-memory history policy.
pub struct TelemetryConfig {
    /// Enable periodic telemetry collection. Default: true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Sampling interval in milliseconds. Default: 1,000; clamped to 250..=60,000.
    #[serde(default = "default_sample_interval_ms")]
    pub sample_interval_ms: u64,
    /// Number of samples retained in memory. Default: 3,600; clamped to 60..=86,400.
    #[serde(default = "default_retention_samples")]
    pub retention_samples: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            sample_interval_ms: default_sample_interval_ms(),
            retention_samples: default_retention_samples(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_sample_interval_ms() -> u64 {
    1_000
}

fn default_retention_samples() -> usize {
    3_600
}

#[derive(Debug, Clone, Default)]
struct RawDiskCounters {
    reads: u64,
    sectors_read: u64,
    read_ms: u64,
    writes: u64,
    sectors_written: u64,
    write_ms: u64,
    inflight: u64,
    io_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct RawNetworkCounters {
    rx_bytes: u64,
    rx_packets: u64,
    rx_errors: u64,
    rx_drops: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errors: u64,
    tx_drops: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskTelemetry {
    pub disk: String,
    pub device_path: Option<String>,
    pub scheduler: Option<String>,
    pub available_schedulers: Vec<String>,
    pub write_cache: Option<String>,
    pub read_ahead_kb: Option<u64>,
    pub nr_requests: Option<u64>,
    pub queue_depth: u64,
    pub read_iops: f64,
    pub write_iops: f64,
    pub read_bytes_per_second: f64,
    pub write_bytes_per_second: f64,
    pub average_read_latency_ms: f64,
    pub average_write_latency_ms: f64,
    pub busy_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkTelemetry {
    pub interface: String,
    pub rx_bytes_per_second: f64,
    pub tx_bytes_per_second: f64,
    pub rx_packets_per_second: f64,
    pub tx_packets_per_second: f64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeTelemetry {
    pub unix_ms: u128,
    pub node: String,
    pub site: Option<String>,
    pub rack: Option<String>,
    pub system: SystemStats,
    pub disks: Vec<DiskTelemetry>,
    pub networks: Vec<NetworkTelemetry>,
    pub total_read_iops: f64,
    pub total_write_iops: f64,
    pub total_read_bytes_per_second: f64,
    pub total_write_bytes_per_second: f64,
}

#[derive(Default)]
struct State {
    previous_unix_ms: Option<u128>,
    previous_disks: BTreeMap<String, RawDiskCounters>,
    previous_networks: BTreeMap<String, RawNetworkCounters>,
    history: VecDeque<NodeTelemetry>,
}

#[derive(Clone)]
pub struct TelemetryStore {
    config: TelemetryConfig,
    state: Arc<Mutex<State>>,
}

impl TelemetryStore {
    pub fn new(config: TelemetryConfig) -> Self {
        let mut config = config;
        config.sample_interval_ms = config.sample_interval_ms.clamp(250, 60_000);
        config.retention_samples = config.retention_samples.clamp(60, 86_400);
        Self {
            config,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    pub fn current(&self) -> Option<NodeTelemetry> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .history
            .back()
            .cloned()
    }

    pub fn history(&self, after_unix_ms: u128) -> Vec<NodeTelemetry> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .history
            .iter()
            .filter(|sample| sample.unix_ms >= after_unix_ms)
            .cloned()
            .collect()
    }

    pub fn sample(&self, cluster: &ClusterConfig, local_host: &str) -> NodeTelemetry {
        let now = now_ms();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed_seconds = state
            .previous_unix_ms
            .map(|previous| (now.saturating_sub(previous) as f64 / 1_000.0).max(0.001))
            .unwrap_or(self.config.sample_interval_ms as f64 / 1_000.0);

        let host = cluster.hosts.iter().find(|host| host.id == local_host);
        let mut disks = Vec::new();
        if let Some(host) = host {
            for disk in &host.disks {
                let raw = disk
                    .device_path
                    .as_deref()
                    .and_then(read_disk_counters)
                    .unwrap_or_default();
                let previous = state
                    .previous_disks
                    .get(&disk.id)
                    .cloned()
                    .unwrap_or_default();
                let queue = disk
                    .device_path
                    .as_deref()
                    .map(storage::queue_settings)
                    .and_then(Result::ok)
                    .unwrap_or_default();

                let reads = raw.reads.saturating_sub(previous.reads);
                let writes = raw.writes.saturating_sub(previous.writes);
                let read_ms = raw.read_ms.saturating_sub(previous.read_ms);
                let write_ms = raw.write_ms.saturating_sub(previous.write_ms);
                let io_ms = raw.io_ms.saturating_sub(previous.io_ms);
                let sectors_read = raw.sectors_read.saturating_sub(previous.sectors_read);
                let sectors_written = raw.sectors_written.saturating_sub(previous.sectors_written);

                disks.push(DiskTelemetry {
                    disk: disk.id.clone(),
                    device_path: disk.device_path.clone(),
                    scheduler: queue.scheduler,
                    available_schedulers: queue.available_schedulers,
                    write_cache: queue.write_cache,
                    read_ahead_kb: queue.read_ahead_kb,
                    nr_requests: queue.nr_requests,
                    queue_depth: raw.inflight,
                    read_iops: reads as f64 / elapsed_seconds,
                    write_iops: writes as f64 / elapsed_seconds,
                    read_bytes_per_second: sectors_read as f64 * 512.0 / elapsed_seconds,
                    write_bytes_per_second: sectors_written as f64 * 512.0 / elapsed_seconds,
                    average_read_latency_ms: if reads == 0 {
                        0.0
                    } else {
                        read_ms as f64 / reads as f64
                    },
                    average_write_latency_ms: if writes == 0 {
                        0.0
                    } else {
                        write_ms as f64 / writes as f64
                    },
                    busy_percent: (io_ms as f64 / (elapsed_seconds * 1_000.0) * 100.0)
                        .clamp(0.0, 100.0),
                });
                state.previous_disks.insert(disk.id.clone(), raw);
            }
        }

        let mut networks = Vec::new();
        for (interface, raw) in read_network_counters() {
            let previous = state
                .previous_networks
                .get(&interface)
                .cloned()
                .unwrap_or_default();
            networks.push(NetworkTelemetry {
                interface: interface.clone(),
                rx_bytes_per_second: raw.rx_bytes.saturating_sub(previous.rx_bytes) as f64
                    / elapsed_seconds,
                tx_bytes_per_second: raw.tx_bytes.saturating_sub(previous.tx_bytes) as f64
                    / elapsed_seconds,
                rx_packets_per_second: raw.rx_packets.saturating_sub(previous.rx_packets) as f64
                    / elapsed_seconds,
                tx_packets_per_second: raw.tx_packets.saturating_sub(previous.tx_packets) as f64
                    / elapsed_seconds,
                rx_errors: raw.rx_errors,
                tx_errors: raw.tx_errors,
                rx_drops: raw.rx_drops,
                tx_drops: raw.tx_drops,
            });
            state.previous_networks.insert(interface, raw);
        }

        let sample = NodeTelemetry {
            unix_ms: now,
            node: local_host.to_string(),
            site: host.and_then(|host| host.site.clone()),
            rack: host.and_then(|host| host.rack.clone()),
            system: crate::webui::system_stats(),
            total_read_iops: disks.iter().map(|disk| disk.read_iops).sum(),
            total_write_iops: disks.iter().map(|disk| disk.write_iops).sum(),
            total_read_bytes_per_second: disks.iter().map(|disk| disk.read_bytes_per_second).sum(),
            total_write_bytes_per_second: disks
                .iter()
                .map(|disk| disk.write_bytes_per_second)
                .sum(),
            disks,
            networks,
        };

        state.previous_unix_ms = Some(now);
        state.history.push_back(sample.clone());
        while state.history.len() > self.config.retention_samples {
            state.history.pop_front();
        }
        sample
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn block_name(device: &str) -> Option<String> {
    let path = fs::canonicalize(device).unwrap_or_else(|_| Path::new(device).to_path_buf());
    path.file_name()?.to_str().map(str::to_string)
}

fn read_disk_counters(device: &str) -> Option<RawDiskCounters> {
    let name = block_name(device)?;
    let stat = fs::read_to_string(format!("/sys/class/block/{name}/stat")).ok()?;
    let values = stat
        .split_whitespace()
        .filter_map(|value| value.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if values.len() < 10 {
        return None;
    }
    Some(RawDiskCounters {
        reads: values[0],
        sectors_read: values[2],
        read_ms: values[3],
        writes: values[4],
        sectors_written: values[6],
        write_ms: values[7],
        inflight: values[8],
        io_ms: values[9],
    })
}

fn read_network_counters() -> BTreeMap<String, RawNetworkCounters> {
    let mut counters = BTreeMap::new();
    let Ok(input) = fs::read_to_string("/proc/net/dev") else {
        return counters;
    };
    for line in input.lines().skip(2) {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let fields = values
            .split_whitespace()
            .filter_map(|value| value.parse::<u64>().ok())
            .collect::<Vec<_>>();
        if fields.len() < 16 {
            continue;
        }
        counters.insert(
            name.trim().to_string(),
            RawNetworkCounters {
                rx_bytes: fields[0],
                rx_packets: fields[1],
                rx_errors: fields[2],
                rx_drops: fields[3],
                tx_bytes: fields[8],
                tx_packets: fields[9],
                tx_errors: fields[10],
                tx_drops: fields[11],
            },
        );
    }
    counters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_configuration_is_bounded() {
        let store = TelemetryStore::new(TelemetryConfig {
            enabled: true,
            sample_interval_ms: 1,
            retention_samples: 2,
        });
        assert_eq!(store.config().sample_interval_ms, 250);
        assert_eq!(store.config().retention_samples, 60);
    }

    #[test]
    fn block_name_accepts_normal_device_paths() {
        assert_eq!(block_name("/dev/nvme0n1").as_deref(), Some("nvme0n1"));
    }
}
