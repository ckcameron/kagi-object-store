// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi physical-storage discovery and admission rules.
//!
//! Storage devices are classified by media/backend type and checked against configured
//! identity information before use. Unknown or mismatched volumes are kept out of placement
//! until an administrator explicitly admits them, which prevents accidental reuse of a
//! mounted filesystem or a disk moved from another node.

// Physical-device discovery and health normalization for NVMe, SATA, SAS and Fibre Channel storage.
//! Physical backend discovery and health for NVMe and rotational block devices.
//! Rotational backends support direct-attached SATA/SAS and Fibre Channel SCSI LUNs.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
/// Supported StorageKind states or operations.
pub enum StorageKind {
    #[default]
    Auto,
    Nvme,
    SataHdd,
    SasHdd,
    FibreChannelHdd,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Linux block queue controls surfaced by Kagi's operations API.
pub struct QueueSettings {
    pub scheduler: Option<String>,
    #[serde(default)]
    pub available_schedulers: Vec<String>,
    pub write_cache: Option<String>,
    pub read_ahead_kb: Option<u64>,
    pub nr_requests: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
/// Requested queue/cache changes. Fields left unset are not modified.
pub struct QueueTuning {
    pub scheduler: Option<String>,
    pub write_cache_enabled: Option<bool>,
    pub read_cache_enabled: Option<bool>,
    pub read_ahead_kb: Option<u64>,
}

fn block_name(device: &str) -> Result<String> {
    let canonical = fs::canonicalize(device).unwrap_or_else(|_| PathBuf::from(device));
    canonical
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .context("device path has no usable block-device name")
}

fn queue_path(device: &str) -> Result<PathBuf> {
    Ok(PathBuf::from("/sys/class/block")
        .join(block_name(device)?)
        .join("queue"))
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_scheduler(value: &str) -> (Option<String>, Vec<String>) {
    let mut selected = None;
    let mut available = Vec::new();
    for item in value.split_whitespace() {
        let active = item.starts_with('[') && item.ends_with(']');
        let name = item.trim_matches(['[', ']']).to_string();
        if name.is_empty() {
            continue;
        }
        if active {
            selected = Some(name.clone());
        }
        available.push(name);
    }
    (selected, available)
}

/// Read Linux block-layer scheduling and cache controls for a configured device.
pub fn queue_settings(device: &str) -> Result<QueueSettings> {
    let queue = queue_path(device)?;
    let scheduler_raw = read_trimmed(&queue.join("scheduler")).unwrap_or_default();
    let (scheduler, available_schedulers) = parse_scheduler(&scheduler_raw);
    Ok(QueueSettings {
        scheduler,
        available_schedulers,
        write_cache: read_trimmed(&queue.join("write_cache")),
        read_ahead_kb: read_trimmed(&queue.join("read_ahead_kb"))
            .and_then(|value| value.parse().ok()),
        nr_requests: read_trimmed(&queue.join("nr_requests"))
            .and_then(|value| value.parse().ok()),
    })
}

/// Apply an administrator-requested block queue policy through sysfs.
///
/// Kagi deliberately does not shell out to hdparm or vendor tools here.  The kernel
/// queue interface is auditable, applies immediately, and lets the device/driver reject
/// unsupported settings.  A failed write is returned to the administrator instead of
/// pretending that a cache or scheduler change took effect.
pub fn apply_queue_tuning(device: &str, tuning: &QueueTuning) -> Result<QueueSettings> {
    let queue = queue_path(device)?;
    let current = queue_settings(device)?;

    if let Some(scheduler) = tuning.scheduler.as_deref() {
        if !current
            .available_schedulers
            .iter()
            .any(|candidate| candidate == scheduler)
        {
            bail!(
                "scheduler {scheduler} is not available for {device}; available={:?}",
                current.available_schedulers
            );
        }
        fs::write(queue.join("scheduler"), scheduler)
            .with_context(|| format!("set scheduler for {device}"))?;
    }

    if let Some(enabled) = tuning.write_cache_enabled {
        let value = if enabled { "write back" } else { "write through" };
        fs::write(queue.join("write_cache"), value)
            .with_context(|| format!("set write-cache policy for {device}"))?;
    }

    if let Some(read_ahead_kb) = tuning.read_ahead_kb {
        if read_ahead_kb > 1_048_576 {
            bail!("read_ahead_kb must not exceed 1048576");
        }
        fs::write(queue.join("read_ahead_kb"), read_ahead_kb.to_string())
            .with_context(|| format!("set read-ahead for {device}"))?;
    } else if let Some(enabled) = tuning.read_cache_enabled {
        let value = if enabled {
            current.read_ahead_kb.filter(|value| *value > 0).unwrap_or(128)
        } else {
            0
        };
        fs::write(queue.join("read_ahead_kb"), value.to_string())
            .with_context(|| format!("set read-cache/read-ahead policy for {device}"))?;
    }

    queue_settings(device)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Kagi state or configuration used by the DeviceHealth path.
pub struct DeviceHealth {
    pub ok: bool,
    pub kind: StorageKind,
    pub transport: Option<String>,
    pub rotational: Option<bool>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub size_bytes: Option<u64>,
    pub smart_passed: Option<bool>,
    pub media_errors: u64,
    pub critical_warning: u64,
    pub reallocated_sectors: u64,
    pub pending_sectors: u64,
    pub uncorrectable_sectors: u64,
    pub temperature_c: Option<i64>,
    pub reason: Option<String>,
}
/// Implements the text step and keeps its validation and state transitions visible at the call site.
fn text(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
/// Implements the u64v step and keeps its validation and state transitions visible at the call site.
fn u64v(v: Option<&serde_json::Value>) -> Option<u64> {
    v.and_then(|x| x.as_u64()).or_else(|| {
        v.and_then(|x| x.as_i64())
            .and_then(|x| u64::try_from(x).ok())
    })
}
/// Implements the attr raw step and keeps its validation and state transitions visible at the call site.
fn attr_raw(table: &serde_json::Value, name: &str) -> u64 {
    table
        .get("ata_smart_attributes")
        .and_then(|x| x.get("table"))
        .and_then(|x| x.as_array())
        .and_then(|attributes| {
            attributes.iter().find(|entry| {
                entry
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|candidate| candidate.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            })
        })
        .and_then(|entry| entry.get("raw"))
        .and_then(|raw| raw.get("value"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
}
/// Implements the smartctl step and keeps its validation and state transitions visible at the call site.
fn smartctl(device: &str) -> Option<serde_json::Value> {
    // smartctl auto-detects NVMe, ATA/SATA, SAS/SCSI and most FC-attached SCSI devices.
    let out = Command::new("smartctl")
        .args(["-a", "-j", device])
        .output()
        .ok()?;
    // smartctl uses exit bits for SMART findings, so parse useful JSON even on non-zero status.
    serde_json::from_slice(&out.stdout).ok()
}
/// Implements the lsblk step and keeps its validation and state transitions visible at the call site.
fn lsblk(device: &str) -> Option<serde_json::Value> {
    let out = Command::new("lsblk")
        .args([
            "-J",
            "-b",
            "-d",
            "-o",
            "PATH,TRAN,ROTA,SERIAL,WWN,SIZE,MODEL,VENDOR",
            device,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}
/// Implements the norm transport step and keeps its validation and state transitions visible at the call site.
fn norm_transport(s: Option<String>) -> Option<String> {
    s.map(|x| match x.to_ascii_lowercase().as_str() {
        "ata" => "sata".into(),
        "fibre_channel" => "fc".into(),
        x => x.into(),
    })
}
/// Implements the inferred kind step and keeps its validation and state transitions visible at the call site.
fn inferred_kind(transport: Option<&str>, rotational: Option<bool>, device: &str) -> StorageKind {
    if device.contains("nvme") {
        return StorageKind::Nvme;
    }
    match (transport, rotational) {
        (Some("sata"), Some(true)) => StorageKind::SataHdd,
        (Some("sas"), Some(true)) => StorageKind::SasHdd,
        (Some("fc"), Some(true)) => StorageKind::FibreChannelHdd,
        _ => StorageKind::Auto,
    }
}
/// Implements the compatible step and keeps its validation and state transitions visible at the call site.
fn compatible(expected: &StorageKind, actual: &StorageKind, rotational: Option<bool>) -> bool {
    match expected {
        StorageKind::Auto => true,
        StorageKind::Directory => false,
        StorageKind::Nvme => *actual == StorageKind::Nvme,
        StorageKind::SataHdd => *actual == StorageKind::SataHdd && rotational == Some(true),
        StorageKind::SasHdd => *actual == StorageKind::SasHdd && rotational == Some(true),
        StorageKind::FibreChannelHdd => {
            *actual == StorageKind::FibreChannelHdd && rotational == Some(true)
        }
    }
}
/// Implements the probe step and keeps its validation and state transitions visible at the call site.
pub fn probe(
    device: Option<&str>,
    expected_kind: &StorageKind,
    expected_serial: Option<&str>,
    expected_wwn: Option<&str>,
) -> DeviceHealth {
    let Some(device) = device else {
        return DeviceHealth {
            ok: *expected_kind == StorageKind::Auto || *expected_kind == StorageKind::Directory,
            kind: StorageKind::Directory,
            ..Default::default()
        };
    };
    if !Path::new(device).exists() {
        return DeviceHealth {
            ok: false,
            kind: expected_kind.clone(),
            reason: Some(format!("block device {device} does not exist")),
            ..Default::default()
        };
    }
    let l = lsblk(device);
    let row = l
        .as_ref()
        .and_then(|x| x.get("blockdevices"))
        .and_then(|x| x.as_array())
        .and_then(|x| x.first());
    let transport = norm_transport(text(row.and_then(|x| x.get("tran"))));
    let rotational = row
        .and_then(|x| x.get("rota"))
        .and_then(|x| x.as_bool())
        .or_else(|| {
            row.and_then(|x| x.get("rota"))
                .and_then(|x| x.as_u64())
                .map(|x| x != 0)
        });
    let mut serial = text(row.and_then(|x| x.get("serial")));
    let mut wwn = text(row.and_then(|x| x.get("wwn")));
    let model = text(row.and_then(|x| x.get("model")));
    let vendor = text(row.and_then(|x| x.get("vendor")));
    let size_bytes = u64v(row.and_then(|x| x.get("size")));
    let actual = inferred_kind(transport.as_deref(), rotational, device);
    let s = smartctl(device);
    if serial.is_none() {
        serial = text(s.as_ref().and_then(|x| x.get("serial_number")))
    }
    if wwn.is_none() {
        wwn = text(
            s.as_ref()
                .and_then(|x| x.get("wwn"))
                .and_then(|x| x.get("naa")),
        )
        .map(|x| format!("0x{x}"))
    }
    let smart_passed = s
        .as_ref()
        .and_then(|x| x.get("smart_status"))
        .and_then(|x| x.get("passed"))
        .and_then(|x| x.as_bool());
    let media_errors = s
        .as_ref()
        .and_then(|x| x.get("nvme_smart_health_information_log"))
        .and_then(|x| x.get("media_errors"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let critical_warning = s
        .as_ref()
        .and_then(|x| x.get("nvme_smart_health_information_log"))
        .and_then(|x| x.get("critical_warning"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let reallocated_sectors = s
        .as_ref()
        .map(|x| attr_raw(x, "Reallocated_Sector_Ct"))
        .unwrap_or(0);
    let pending_sectors = s
        .as_ref()
        .map(|x| attr_raw(x, "Current_Pending_Sector"))
        .unwrap_or(0);
    let uncorrectable_sectors = s
        .as_ref()
        .map(|x| attr_raw(x, "Offline_Uncorrectable"))
        .unwrap_or(0);
    let temperature_c = s
        .as_ref()
        .and_then(|x| x.get("temperature"))
        .and_then(|x| x.get("current"))
        .and_then(|x| x.as_i64());
    let mut reasons = Vec::new();
    if !compatible(expected_kind, &actual, rotational) {
        reasons.push(format!(
            "expected {:?}, detected {:?} transport={:?} rotational={:?}",
            expected_kind, actual, transport, rotational
        ));
    }
    if let Some(e) = expected_serial {
        if serial.as_deref() != Some(e) {
            reasons.push(format!("serial mismatch expected={e} actual={:?}", serial));
        }
    }
    if let Some(e) = expected_wwn {
        if wwn
            .as_deref()
            .map(|x| x.trim_start_matches("0x").to_ascii_lowercase())
            != Some(e.trim_start_matches("0x").to_ascii_lowercase())
        {
            reasons.push(format!("WWN mismatch expected={e} actual={:?}", wwn));
        }
    }
    if smart_passed == Some(false) {
        reasons.push("SMART overall-health failed".into())
    }
    if media_errors > 0 {
        reasons.push(format!("NVMe media_errors={media_errors}"))
    }
    if critical_warning > 0 {
        reasons.push(format!("NVMe critical_warning={critical_warning}"))
    }
    // Reallocated sectors are diagnostic and not alone fatal; pending/uncorrectable sectors are unsafe for new writes.
    if pending_sectors > 0 {
        reasons.push(format!("pending sectors={pending_sectors}"))
    }
    if uncorrectable_sectors > 0 {
        reasons.push(format!("uncorrectable sectors={uncorrectable_sectors}"))
    }
    DeviceHealth {
        ok: reasons.is_empty(),
        kind: actual,
        transport,
        rotational,
        serial,
        wwn,
        model,
        vendor,
        size_bytes,
        smart_passed,
        media_errors,
        critical_warning,
        reallocated_sectors,
        pending_sectors,
        uncorrectable_sectors,
        temperature_c,
        reason: if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ata_rotational_is_sata_hdd() {
        assert_eq!(
            inferred_kind(Some("sata"), Some(true), "/dev/sda"),
            StorageKind::SataHdd
        );
    }
    #[test]
    fn sas_rotational_is_sas_hdd() {
        assert_eq!(
            inferred_kind(Some("sas"), Some(true), "/dev/sdb"),
            StorageKind::SasHdd
        );
    }
    #[test]
    fn fc_rotational_is_fc_hdd() {
        assert_eq!(
            inferred_kind(Some("fc"), Some(true), "/dev/sdc"),
            StorageKind::FibreChannelHdd
        );
    }
    #[test]
    fn nvme_is_detected_by_device_name() {
        assert_eq!(
            inferred_kind(None, Some(false), "/dev/nvme0n1"),
            StorageKind::Nvme
        );
    }
    #[test]
    fn scheduler_parser_tracks_selected_and_available() {
        let (selected, available) = parse_scheduler("none [mq-deadline] kyber bfq");
        assert_eq!(selected.as_deref(), Some("mq-deadline"));
        assert_eq!(available, vec!["none", "mq-deadline", "kyber", "bfq"]);
    }

    #[test]
    fn rotational_requirement_is_enforced() {
        assert!(!compatible(
            &StorageKind::SataHdd,
            &StorageKind::SataHdd,
            Some(false)
        ));
    }
}
