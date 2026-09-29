// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi health tracking and recovery planning.
//!
//! Health is represented hierarchically across site, rack, host, and disk failure domains.
//! The recovery controller detects stale/flapping resources, quarantines unstable members,
//! scores object risk, and determines which repairs should run first without placing new
//! fragments back onto a resource that has not satisfied its re-entry policy.

// Health-state machine, failure-domain correlation, quarantine, survivability, and repair control.
//! Autonomous health, failure-domain, repair, rebalance, and flap quarantine controller.
use crate::cluster::{ObjectManifest, PeerHost};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
/// Supported ResourceState states or operations.
pub enum ResourceState {
    #[default]
    Healthy,
    Suspect,
    Down,
    Out,
    Probing,
    Recovering,
    Quarantined,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the ResourceHealth path.
pub struct ResourceHealth {
    pub state: ResourceState,
    pub last_seen_ms: u128,
    pub since_ms: u128,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub reason: String,
    /// Beginning of the current uninterrupted healthy/probing interval.
    #[serde(default)]
    pub stable_since_ms: u128,
    /// Recent availability transitions used for flap detection.
    #[serde(default)]
    pub transitions_ms: VecDeque<u128>,
    /// Set automatically after excessive flapping. Excluded from placement until
    /// minimum stable uptime elapses or an operator explicitly clears it.
    #[serde(default)]
    pub flap_quarantined: bool,
    #[serde(default)]
    pub flap_events: u64,
}
impl ResourceHealth {
    fn new(t: u128, state: ResourceState, reason: &str) -> Self {
        Self {
            state,
            last_seen_ms: t,
            since_ms: t,
            failures: 0,
            reason: reason.into(),
            stable_since_ms: if matches!(
                state,
                ResourceState::Healthy | ResourceState::Probing | ResourceState::Recovering
            ) {
                t
            } else {
                0
            },
            transitions_ms: VecDeque::new(),
            flap_quarantined: false,
            flap_events: 0,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the Heartbeat path.
pub struct Heartbeat {
    pub host: String,
    #[serde(default)]
    pub boot_id: String,
    #[serde(default)]
    pub disks: BTreeMap<String, bool>,
    #[serde(default)]
    pub disk_serials: BTreeMap<String, String>,
    #[serde(default)]
    pub disk_media_errors: BTreeMap<String, u64>,
    #[serde(default)]
    pub disk_critical_warning: BTreeMap<String, u64>,
    #[serde(default)]
    pub free_bytes: BTreeMap<String, u64>,
    #[serde(default)]
    pub io_pressure: f64,
    pub unix_ms: u128,
}
#[derive(Debug, Clone, Deserialize)]
// ---- Recovery/survivability policy ---------------------------------------------
pub struct RecoveryConfig {
    /// Health-probe cadence in milliseconds. Default: 2,000.
#[serde(default = "d_hb")]
    pub heartbeat_ms: u64,
    /// Age without health confirmation before SUSPECT, in milliseconds. Default: 6,000.
#[serde(default = "d_suspect")]
    pub suspect_after_ms: u64,
    /// Age before DOWN, in milliseconds. Default: 15,000.
#[serde(default = "d_down")]
    pub down_after_ms: u64,
    /// Age before OUT/placement exclusion, in milliseconds. Default: 120,000.
#[serde(default = "d_out")]
    pub out_after_ms: u64,
    /// Repair-controller cadence in milliseconds. Default: 10,000.
#[serde(default = "d_repair")]
    pub repair_interval_ms: u64,
    /// Maximum simultaneous repairs. Default: 4.
#[serde(default = "d_parallel")]
    pub max_parallel_repairs: usize,
    /// Consecutive healthy probes required for return. Default: 3.
#[serde(default = "d_return")]
    pub return_probe_successes: u32,
    /// Sliding interval in which state changes count toward flapping.
    #[serde(default = "d_flap_window")]
    pub flap_window_ms: u64,
    /// Number of up/down transitions in flap_window_ms that quarantines a resource.
    #[serde(default = "d_flap_transitions")]
    pub flap_transition_threshold: u32,
    /// Continuous healthy time required before an automatically quarantined resource
    /// can re-enter placement. Manual clearance bypasses this timer.
    #[serde(default = "d_min_uptime")]
    pub minimum_reinclude_uptime_ms: u64,
}
impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            heartbeat_ms: d_hb(),
            suspect_after_ms: d_suspect(),
            down_after_ms: d_down(),
            out_after_ms: d_out(),
            repair_interval_ms: d_repair(),
            max_parallel_repairs: d_parallel(),
            return_probe_successes: d_return(),
            flap_window_ms: d_flap_window(),
            flap_transition_threshold: d_flap_transitions(),
            minimum_reinclude_uptime_ms: d_min_uptime(),
        }
    }
}
/// Implements the d hb step and keeps its validation and state transitions visible at the call site.
fn d_hb() -> u64 {
    2_000
}
/// Implements the d suspect step and keeps its validation and state transitions visible at the call site.
fn d_suspect() -> u64 {
    6_000
}
/// Implements the d down step and keeps its validation and state transitions visible at the call site.
fn d_down() -> u64 {
    15_000
}
/// Implements the d out step and keeps its validation and state transitions visible at the call site.
fn d_out() -> u64 {
    120_000
}
/// Implements the d repair step and keeps its validation and state transitions visible at the call site.
fn d_repair() -> u64 {
    10_000
}
/// Implements the d parallel step and keeps its validation and state transitions visible at the call site.
fn d_parallel() -> usize {
    4
}
/// Implements the d return step and keeps its validation and state transitions visible at the call site.
fn d_return() -> u32 {
    3
}
/// Implements the d flap window step and keeps its validation and state transitions visible at the call site.
fn d_flap_window() -> u64 {
    300_000
}
/// Implements the d flap transitions step and keeps its validation and state transitions visible at the call site.
fn d_flap_transitions() -> u32 {
    4
}
/// Implements the d min uptime step and keeps its validation and state transitions visible at the call site.
fn d_min_uptime() -> u64 {
    600_000
}
#[derive(Clone, Default)]
pub struct HealthMap {
    pub resources: Arc<RwLock<BTreeMap<String, ResourceHealth>>>,
}
/// Implements the now step and keeps its validation and state transitions visible at the call site.
fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
/// Implements the host key step and keeps its validation and state transitions visible at the call site.
pub fn host_key(h: &str) -> String {
    format!("host:{h}")
}
/// Implements the disk key step and keeps its validation and state transitions visible at the call site.
pub fn disk_key(h: &str, d: &str) -> String {
    format!("disk:{h}/{d}")
}
/// Implements the rack key step and keeps its validation and state transitions visible at the call site.
pub fn rack_key(r: &str) -> String {
    format!("rack:{r}")
}
/// Implements the site key step and keeps its validation and state transitions visible at the call site.
pub fn site_key(s: &str) -> String {
    format!("site:{s}")
}
/// Implements the available step and keeps its validation and state transitions visible at the call site.
fn available(s: ResourceState) -> bool {
    matches!(s, ResourceState::Healthy | ResourceState::Recovering)
}
/// Implements the record transition step and keeps its validation and state transitions visible at the call site.
fn record_transition(
    e: &mut ResourceHealth,
    new: ResourceState,
    t: u128,
    cfg: &RecoveryConfig,
    reason: String,
) {
    if e.flap_quarantined && !available(new) {
        e.stable_since_ms = 0;
        e.state = ResourceState::Quarantined;
        e.reason = format!("flap quarantine; {reason}");
        return;
    }
    if e.state == new {
        return;
    }
    let was = available(e.state);
    let is = available(new);
    if was != is {
        e.transitions_ms.push_back(t);
        while e
            .transitions_ms
            .front()
            .map(|x| t.saturating_sub(*x) > cfg.flap_window_ms as u128)
            .unwrap_or(false)
        {
            e.transitions_ms.pop_front();
        }
    }
    e.state = new;
    e.since_ms = t;
    e.reason = reason;
    if is {
        e.stable_since_ms = t
    } else {
        e.stable_since_ms = 0
    }
    if e.transitions_ms.len() >= cfg.flap_transition_threshold as usize
        && cfg.flap_transition_threshold > 0
    {
        e.flap_quarantined = true;
        e.flap_events += 1;
        e.state = ResourceState::Quarantined;
        e.since_ms = t;
        e.reason = format!(
            "flapping: {} availability transitions within {}ms",
            e.transitions_ms.len(),
            cfg.flap_window_ms
        );
        if is {
            e.stable_since_ms = t
        }
    }
}
/// Implements the maybe release step and keeps its validation and state transitions visible at the call site.
fn maybe_release(e: &mut ResourceHealth, t: u128, cfg: &RecoveryConfig) {
    if !e.flap_quarantined {
        return;
    }
    if e.stable_since_ms > 0
        && t.saturating_sub(e.stable_since_ms) >= cfg.minimum_reinclude_uptime_ms as u128
    {
        e.flap_quarantined = false;
        e.transitions_ms.clear();
        e.state = ResourceState::Recovering;
        e.since_ms = t;
        e.reason = format!(
            "flap quarantine expired after {}ms stable uptime",
            cfg.minimum_reinclude_uptime_ms
        );
    }
}
impl HealthMap {
    pub async fn state(&self, key: &str) -> ResourceState {
        self.resources
            .read()
            .await
            .get(key)
            .map(|x| x.state)
            .unwrap_or(ResourceState::Healthy)
    }
    pub async fn usable(&self, h: &PeerHost, d: &str) -> bool {
        if !available(self.state(&host_key(&h.id)).await) {
            return false;
        }
        if !available(self.state(&disk_key(&h.id, d)).await) {
            return false;
        }
        if let Some(r) = &h.rack {
            if !available(self.state(&rack_key(r)).await) {
                return false;
            }
        }
        if let Some(s) = &h.site {
            if !available(self.state(&site_key(s)).await) {
                return false;
            }
        }
        true
    }
    pub async fn apply_heartbeat(&self, hb: &Heartbeat, cfg: &RecoveryConfig) {
        let mut m = self.resources.write().await;
        let t = now();
        let hk = host_key(&hb.host);
        let e = m
            .entry(hk)
            .or_insert_with(|| ResourceHealth::new(t, ResourceState::Healthy, "first heartbeat"));
        e.last_seen_ms = t;
        e.failures = 0;
        if e.flap_quarantined {
            if e.stable_since_ms == 0 {
                e.stable_since_ms = t
            }
            maybe_release(e, t, cfg)
        } else if matches!(
            e.state,
            ResourceState::Down
                | ResourceState::Out
                | ResourceState::Suspect
                | ResourceState::Probing
        ) {
            record_transition(
                e,
                ResourceState::Recovering,
                t,
                cfg,
                "heartbeat restored".into(),
            )
        } else if e.state == ResourceState::Recovering
            && t.saturating_sub(e.stable_since_ms)
                >= cfg
                    .heartbeat_ms
                    .saturating_mul(cfg.return_probe_successes as u64) as u128
        {
            record_transition(
                e,
                ResourceState::Healthy,
                t,
                cfg,
                "return probes satisfied".into(),
            )
        }
        for (d, ok) in &hb.disks {
            let k = disk_key(&hb.host, d);
            let e = m.entry(k).or_insert_with(|| {
                ResourceHealth::new(
                    t,
                    if *ok {
                        ResourceState::Healthy
                    } else {
                        ResourceState::Down
                    },
                    "first disk probe",
                )
            });
            if *ok {
                e.last_seen_ms = t;
                e.failures = 0;
                if e.flap_quarantined {
                    if e.stable_since_ms == 0 {
                        e.stable_since_ms = t
                    }
                    maybe_release(e, t, cfg)
                } else if !available(e.state) {
                    record_transition(
                        e,
                        ResourceState::Recovering,
                        t,
                        cfg,
                        "device probe restored".into(),
                    )
                } else if e.state == ResourceState::Recovering
                    && t.saturating_sub(e.stable_since_ms)
                        >= cfg
                            .heartbeat_ms
                            .saturating_mul(cfg.return_probe_successes as u64)
                            as u128
                {
                    record_transition(
                        e,
                        ResourceState::Healthy,
                        t,
                        cfg,
                        "device return probes satisfied".into(),
                    )
                }
            } else {
                e.failures = e.failures.saturating_add(1);
                record_transition(
                    e,
                    ResourceState::Down,
                    t,
                    cfg,
                    "device health probe failed".into(),
                )
            }
        }
    }
    pub async fn age(&self, hosts: &[PeerHost], cfg: &RecoveryConfig) {
        let t = now();
        let mut m = self.resources.write().await;
        for h in hosts {
            let k = host_key(&h.id);
            let e = m
                .entry(k)
                .or_insert_with(|| ResourceHealth::new(t, ResourceState::Healthy, "bootstrap"));
            let age = t.saturating_sub(e.last_seen_ms) as u64;
            if e.flap_quarantined {
                if age < cfg.suspect_after_ms {
                    if e.stable_since_ms == 0 {
                        e.stable_since_ms = t
                    }
                    maybe_release(e, t, cfg)
                } else {
                    e.stable_since_ms = 0
                }
                continue;
            }
            let ns = if age >= cfg.out_after_ms {
                Some(ResourceState::Out)
            } else if age >= cfg.down_after_ms {
                Some(ResourceState::Down)
            } else if age >= cfg.suspect_after_ms {
                Some(ResourceState::Suspect)
            } else {
                None
            };
            if let Some(ns) = ns {
                record_transition(e, ns, t, cfg, format!("heartbeat age {age}ms"))
            }
        }
        let mut domains: Vec<(String, Vec<String>)> = Vec::new();
        let mut racks: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut sites: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for h in hosts {
            if let Some(r) = &h.rack {
                racks.entry(r.clone()).or_default().push(h.id.clone())
            }
            if let Some(s) = &h.site {
                sites.entry(s.clone()).or_default().push(h.id.clone())
            }
        }
        for (r, hs) in racks {
            domains.push((rack_key(&r), hs))
        }
        for (s, hs) in sites {
            domains.push((site_key(&s), hs))
        }
        for (k, hs) in domains {
            let bad = hs
                .iter()
                .filter(|h| {
                    !available(
                        m.get(&host_key(h))
                            .map(|x| x.state)
                            .unwrap_or(ResourceState::Healthy),
                    )
                })
                .count();
            let all_bad = hs.len() > 1 && bad == hs.len();
            let e = m.entry(k).or_insert_with(|| {
                ResourceHealth::new(t, ResourceState::Healthy, "domain healthy")
            });
            if all_bad {
                e.failures = bad as u32;
                record_transition(
                    e,
                    ResourceState::Down,
                    t,
                    cfg,
                    "all member hosts unavailable".into(),
                )
            } else {
                e.last_seen_ms = t;
                e.failures = 0;
                if e.flap_quarantined {
                    if e.stable_since_ms == 0 {
                        e.stable_since_ms = t
                    }
                    maybe_release(e, t, cfg)
                } else if !available(e.state) {
                    record_transition(
                        e,
                        ResourceState::Recovering,
                        t,
                        cfg,
                        "domain members restored".into(),
                    )
                } else if e.state == ResourceState::Recovering
                    && t.saturating_sub(e.stable_since_ms)
                        >= cfg
                            .heartbeat_ms
                            .saturating_mul(cfg.return_probe_successes as u64)
                            as u128
                {
                    record_transition(
                        e,
                        ResourceState::Healthy,
                        t,
                        cfg,
                        "domain return probes satisfied".into(),
                    )
                }
            }
        }
    }
    /// Operator override for an automatically quarantined site/rack/host/disk. This
    /// clears flap history and permits the resource to re-enter through Recovering.
    pub async fn clear_flap(&self, key: &str) -> bool {
        let t = now();
        let mut m = self.resources.write().await;
        if let Some(e) = m.get_mut(key) {
            e.flap_quarantined = false;
            e.transitions_ms.clear();
            e.stable_since_ms = t;
            e.state = ResourceState::Recovering;
            e.since_ms = t;
            e.reason = "flap quarantine manually cleared".into();
            true
        } else {
            false
        }
    }
    pub async fn snapshot(&self) -> BTreeMap<String, ResourceHealth> {
        self.resources.read().await.clone()
    }
}
/// Implements the object risk step and keeps its validation and state transitions visible at the call site.
pub async fn object_risk(m: &ObjectManifest, health: &HealthMap, hosts: &[PeerHost]) -> usize {
    let mut good = BTreeSet::new();
    for c in &m.chunks {
        for r in &c.replicas {
            if let Some(h) = hosts.iter().find(|h| h.id == r.host) {
                if health.usable(h, &r.disk).await {
                    good.insert(c.chunk);
                    break;
                }
            }
        }
    }
    let required = if m.data_shards > 0 {
        m.data_shards as usize
    } else {
        1
    };
    good.len().saturating_sub(required)
}
