// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi background maintenance scheduler.
//!
//! Scrub, repair, rebalance, garbage collection, and snapshot archival share one scheduler
//! so background work can be rate-limited and kept behind foreground I/O. The configuration
//! here defines the resource budgets and maintenance windows consumed by the node daemon.

use anyhow::{bail, Result};
use chrono::{Datelike, Timelike, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Notify, Semaphore};
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceWindow {
    /// Lowercase weekday names. Empty means every day.
    #[serde(default)]
    pub days: Vec<String>,
    /// Inclusive local start time in HH:MM form.
    pub start: String,
    /// Local end time in HH:MM form.
    pub end: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPolicy {
    /// Enable this maintenance operation. Default: true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Allowed execution windows. Default: empty, meaning unrestricted by time.
    #[serde(default)]
    pub windows: Vec<MaintenanceWindow>,
}
impl Default for OperationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            windows: vec![],
        }
    }
}

fn yes() -> bool {
    true
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceQuotas {
    /// Maintenance network budget in megabits/second. Default: 100.
    #[serde(default = "net_default")]
    pub network_mbps: f64,
    /// Maintenance CPU budget as a percentage. Default: 20.
    #[serde(default = "cpu_default")]
    pub cpu_percent: f64,
    /// Maintenance memory budget in MiB. Default: 512.
    #[serde(default = "mem_default")]
    pub memory_mib: u64,
    /// Maximum simultaneous maintenance operations. Default: 2.
    #[serde(default = "conc_default")]
    pub max_concurrency: usize,
}

fn net_default() -> f64 {
    100.0
}

fn cpu_default() -> f64 {
    20.0
}

fn mem_default() -> u64 {
    512
}

fn conc_default() -> usize {
    2
}
impl Default for ResourceQuotas {
    fn default() -> Self {
        Self {
            network_mbps: net_default(),
            cpu_percent: cpu_default(),
            memory_mib: mem_default(),
            max_concurrency: conc_default(),
        }
    }
}

/// Background maintenance schedules and resource ceilings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceConfig {
    /// Master maintenance switch. Default: true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// IANA timezone used to interpret maintenance windows. Default: UTC.
    #[serde(default = "tz_default")]
    pub timezone: String,
    /// Resource ceilings shared by maintenance operations.
    #[serde(default)]
    pub quotas: ResourceQuotas,
    #[serde(default)]
    pub scrub: OperationPolicy,
    #[serde(default)]
    pub proactive_repair: OperationPolicy,
    #[serde(default)]
    pub garbage_collection: OperationPolicy,
    #[serde(default)]
    pub snapshot_archive: OperationPolicy,
    #[serde(default)]
    pub rebalance: OperationPolicy,
    /// Scrub scheduler evaluation interval in milliseconds. Default: 300,000.
    #[serde(default = "scrub_interval")]
    pub scrub_interval_ms: u64,
}

fn tz_default() -> String {
    "UTC".into()
}

fn scrub_interval() -> u64 {
    300_000
}
impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timezone: tz_default(),
            quotas: ResourceQuotas::default(),
            scrub: OperationPolicy::default(),
            proactive_repair: OperationPolicy::default(),
            garbage_collection: OperationPolicy::default(),
            snapshot_archive: OperationPolicy::default(),
            rebalance: OperationPolicy::default(),
            scrub_interval_ms: scrub_interval(),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct MaintenanceStatus {
    pub foreground_active: usize,
    pub maintenance_active: usize,
    pub timezone: String,
    pub quotas: ResourceQuotas,
    pub operations: BTreeMap<String, bool>,
}

/// Background workers yield between bounded units and share concurrency, memory,
/// and network limits. Foreground requests enter without taking a maintenance permit.
#[derive(Clone)]
pub struct MaintenanceManager {
    cfg: Arc<MaintenanceConfig>,
    foreground: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    concurrency: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    network: Arc<Mutex<TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    last: Instant,
}

pub struct ForegroundGuard {
    mgr: MaintenanceManager,
}

/// Owns the concurrency and memory permits for one unit of maintenance work.
pub struct MaintenancePermit {
    mgr: MaintenanceManager,
    _conc: tokio::sync::OwnedSemaphorePermit,
    _mem: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for ForegroundGuard {
    fn drop(&mut self) {
        self.mgr.foreground.fetch_sub(1, Ordering::SeqCst);
        self.mgr.notify.notify_waiters();
    }
}
impl Drop for MaintenancePermit {
    fn drop(&mut self) {
        self.mgr.active.fetch_sub(1, Ordering::SeqCst);
        self.mgr.notify.notify_waiters();
    }
}
impl MaintenanceManager {
    pub fn new(cfg: MaintenanceConfig) -> Self {
        let mem_units = (cfg.quotas.memory_mib.max(1).min(u32::MAX as u64)) as usize;
        let conc = cfg.quotas.max_concurrency.max(1);
        Self {
            cfg: Arc::new(cfg),
            foreground: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
            concurrency: Arc::new(Semaphore::new(conc)),
            memory: Arc::new(Semaphore::new(mem_units)),
            network: Arc::new(Mutex::new(TokenBucket {
                tokens: 0.0,
                last: Instant::now(),
            })),
        }
    }

    /// Keep the guard alive for the foreground request. Dropping it wakes waiting
    /// maintenance workers.
    pub fn foreground(&self) -> ForegroundGuard {
        self.foreground.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_waiters();
        ForegroundGuard { mgr: self.clone() }
    }
    pub fn policy(&self, name: &str) -> &OperationPolicy {
        match name {
            "scrub" => &self.cfg.scrub,
            "proactive_repair" => &self.cfg.proactive_repair,
            "garbage_collection" => &self.cfg.garbage_collection,
            "snapshot_archive" => &self.cfg.snapshot_archive,
            "rebalance" => &self.cfg.rebalance,
            _ => &self.cfg.scrub,
        }
    }
    pub fn allowed_now(&self, name: &str) -> bool {
        self.cfg.enabled
            && self.policy(name).enabled
            && window_open(&self.cfg.timezone, &self.policy(name).windows)
    }

    /// Admit one unit under the operation's schedule and resource budgets. Recheck
    /// foreground work after waiting for the concurrency permit.
    pub async fn acquire(
        &self,
        name: &str,
        estimated_memory_bytes: u64,
    ) -> Result<MaintenancePermit> {
        loop {
            if !self.allowed_now(name) {
                bail!("maintenance operation {name} is outside its configured window")
            };
            while self.foreground.load(Ordering::SeqCst) > 0 {
                self.notify.notified().await;
            }
            let conc = self.concurrency.clone().acquire_owned().await?;
            if self.foreground.load(Ordering::SeqCst) > 0 {
                drop(conc);
                continue;
            }
            let mib = ((estimated_memory_bytes.saturating_add(1_048_575)) / 1_048_576)
                .max(1)
                .min(self.cfg.quotas.memory_mib.max(1))
                .min(u32::MAX as u64);
            let mem = self.memory.clone().acquire_many_owned(mib as u32).await?;
            self.active.fetch_add(1, Ordering::SeqCst);
            return Ok(MaintenancePermit {
                mgr: self.clone(),
                _conc: conc,
                _mem: mem,
            });
        }
    }

    /// Throttle background traffic with the shared token bucket. A single charge
    /// can fit even when it exceeds a second of the configured rate.
    pub async fn charge_network(&self, bytes: u64) {
        let rate = self.cfg.quotas.network_mbps * 1_000_000.0 / 8.0;
        if rate <= 0.0 {
            return;
        }
        loop {
            let wait = {
                let mut b = self.network.lock().await;
                let now = Instant::now();
                let cap = rate.max(bytes as f64).max(64.0 * 1024.0);
                b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * rate).min(cap);
                b.last = now;
                if b.tokens >= bytes as f64 {
                    b.tokens -= bytes as f64;
                    0.0
                } else {
                    let need = bytes as f64 - b.tokens;
                    b.tokens = 0.0;
                    need / rate
                }
            };
            if wait <= 0.0 {
                return;
            }
            tokio::time::sleep(Duration::from_secs_f64(wait.min(1.0))).await;
            if self.foreground.load(Ordering::SeqCst) > 0 {
                while self.foreground.load(Ordering::SeqCst) > 0 {
                    self.notify.notified().await;
                }
            }
        }
    }
    pub async fn cpu_yield(&self, worked: Duration) {
        let p = self.cfg.quotas.cpu_percent.clamp(1.0, 100.0);
        if p < 100.0 {
            tokio::time::sleep(worked.mul_f64((100.0 - p) / p)).await;
        }
    }
    pub fn status(&self) -> MaintenanceStatus {
        let mut ops = BTreeMap::new();
        for n in [
            "scrub",
            "proactive_repair",
            "garbage_collection",
            "snapshot_archive",
            "rebalance",
        ] {
            ops.insert(n.into(), self.allowed_now(n));
        }
        MaintenanceStatus {
            foreground_active: self.foreground.load(Ordering::SeqCst),
            maintenance_active: self.active.load(Ordering::SeqCst),
            timezone: self.cfg.timezone.clone(),
            quotas: self.cfg.quotas.clone(),
            operations: ops,
        }
    }
    pub fn scrub_interval_ms(&self) -> u64 {
        self.cfg.scrub_interval_ms
    }
}

fn hm(s: &str) -> Option<u32> {
    let (mut i, mut it) = (0u32, s.split(':'));
    i += it.next()?.parse::<u32>().ok()? * 60;
    i += it.next()?.parse::<u32>().ok()?;
    Some(i)
}

fn window_open(tz: &str, ws: &[MaintenanceWindow]) -> bool {
    if ws.is_empty() {
        return true;
    }
    let tz: Tz = match tz.parse() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let n = Utc::now().with_timezone(&tz);
    let minute = n.hour() * 60 + n.minute();
    let day = format!("{:?}", n.weekday()).to_lowercase();
    ws.iter().any(|w| {
        if !w.days.is_empty()
            && !w
                .days
                .iter()
                .any(|d| day.starts_with(&d.to_lowercase()[..d.len().min(3)]))
        {
            return false;
        }
        let (Some(a), Some(z)) = (hm(&w.start), hm(&w.end)) else {
            return false;
        };
        if a <= z {
            minute >= a && minute < z
        } else {
            minute >= a || minute < z
        }
    })
}
