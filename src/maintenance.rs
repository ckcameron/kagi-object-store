// Copyright (c) 2026 CK Cameron. All Rights Reserved. Proprietary and Confidential.
//! Kagi background maintenance scheduler.
//!
//! Scrub, repair, rebalance, garbage collection, and snapshot archival share one scheduler
//! so background work can be rate-limited and kept behind foreground I/O. The configuration
//! here defines the resource budgets and maintenance windows consumed by the node daemon.

// Background-maintenance scheduler, time windows, quotas, and foreground/system priority arbitration.
//! Background maintenance scheduling, quotas and foreground preemption.
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
/// Kagi state or configuration used by the MaintenanceWindow path.
pub struct MaintenanceWindow {
    #[serde(default)]
    pub days: Vec<String>,
    pub start: String,
    pub end: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the OperationPolicy path.
pub struct OperationPolicy {
    #[serde(default = "yes")]
    pub enabled: bool,
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
/// Implements the yes step and keeps its validation and state transitions visible at the call site.
fn yes() -> bool {
    true
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the ResourceQuotas path.
pub struct ResourceQuotas {
    #[serde(default = "net_default")]
    pub network_mbps: f64,
    #[serde(default = "cpu_default")]
    pub cpu_percent: f64,
    #[serde(default = "mem_default")]
    pub memory_mib: u64,
    #[serde(default = "conc_default")]
    pub max_concurrency: usize,
}
/// Implements the net default step and keeps its validation and state transitions visible at the call site.
fn net_default() -> f64 {
    100.0
}
/// Implements the cpu default step and keeps its validation and state transitions visible at the call site.
fn cpu_default() -> f64 {
    20.0
}
/// Implements the mem default step and keeps its validation and state transitions visible at the call site.
fn mem_default() -> u64 {
    512
}
/// Implements the conc default step and keeps its validation and state transitions visible at the call site.
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
#[derive(Debug, Clone, Deserialize, Serialize)]
// ---- User-configurable schedules and resource ceilings -------------------------
pub struct MaintenanceConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "tz_default")]
    pub timezone: String,
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
    #[serde(default = "scrub_interval")]
    pub scrub_interval_ms: u64,
}
/// Implements the tz default step and keeps its validation and state transitions visible at the call site.
fn tz_default() -> String {
    "UTC".into()
}
/// Implements the scrub interval step and keeps its validation and state transitions visible at the call site.
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
#[derive(Clone)] // ---- Priority-aware admission and cooperative throttling -----------------------
                 // Foreground/system work is never made to wait for a new maintenance unit;
                 // background work yields between bounded units and obeys CPU/network/memory caps.
pub struct MaintenanceManager {
    cfg: Arc<MaintenanceConfig>,
    foreground: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    concurrency: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    network: Arc<Mutex<TokenBucket>>,
}
/// Kagi state or configuration used by the TokenBucket path.
struct TokenBucket {
    tokens: f64,
    last: Instant,
}
/// Kagi state or configuration used by the ForegroundGuard path.
pub struct ForegroundGuard {
    mgr: MaintenanceManager,
}
/// Kagi state or configuration used by the MaintenancePermit path.
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
/// Implements the hm step and keeps its validation and state transitions visible at the call site.
fn hm(s: &str) -> Option<u32> {
    let (mut i, mut it) = (0u32, s.split(':'));
    i += it.next()?.parse::<u32>().ok()? * 60;
    i += it.next()?.parse::<u32>().ok()?;
    Some(i)
}
/// Implements the window open step and keeps its validation and state transitions visible at the call site.
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
