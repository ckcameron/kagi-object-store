// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi topology planner, Monte Carlo durability simulator, and deployment-plan generator.
//!
//! This binary turns a physical topology and failure model into a deterministic 60-bit
//! keyspace layout. It evaluates replication and erasure-code candidates, validates the
//! configured failure envelope, estimates rare loss events, and writes equal host
//! key ranges and deployable placement policies. The interactive wizard and progress renderer live here because they are
//! part of the planning workflow rather than the runtime data path.

mod checkpoint;
mod durability;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use blake3::Hasher;
use clap::{Parser, ValueEnum};
use kagi_object_store::placement::{
    mask_position, DiskPermutations, DomainDisk, FailureBudget, HostRange, PlacementPlan,
    ProtectionLayout, KEYSPACE_BITS, TWO_SITE_ACKNOWLEDGMENT,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use statrs::distribution::{Beta, ContinuousCDF};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Full search or a bounded quick simulation preset.
enum RunMode {
    Full,
    Quick30,
    Quick60,
}
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Execution backend for evaluating sampled protection layouts.
enum McBackend {
    Auto,
    Cpu,
    Cuda,
    Hip,
    Opencl,
}

// CLI and serializable simulation input
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(name = "kagi-config", version)]
struct Args {
    /// Directory for periodic atomic simulation checkpoints (contains a secret admission key).
    #[arg(long, conflicts_with = "resume")]
    checkpoint: Option<PathBuf>,
    /// Resume using the saved topology and options; no original input file is needed.
    #[arg(long, conflicts_with_all=["config","wizard","trials","candidates","seed","rare_trials","finalists","validation_keys","time_trials","horizon_years","ais_rounds","elite_fraction","run_mode","mc_backend","output","join_key_output","mount_root","checkpoint_batch_trials","checkpoint_seconds","max_storage_overhead","example_object_size_bytes","chunk_replicas","object_replicas"])]
    resume: Option<PathBuf>,
    /// Save completed batches at this interval, checked at batch boundaries.
    #[arg(long, default_value_t = 60)]
    checkpoint_seconds: u64,
    /// Trials per saved batch; fixes reduction order and maximum unsaved work granularity.
    #[arg(long, default_value_t = 1024)]
    checkpoint_batch_trials: u64,

    /// Existing YAML configuration. Required unless --wizard is used.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Interactively build a topology/configuration before running the optimizer.
    #[arg(long)]
    wizard: bool,
    /// Save the wizard-generated input configuration for repeatable future runs.
    #[arg(long, default_value = "kagi.wizard.yaml")]
    wizard_config_output: PathBuf,
    /// Override the mount root used for automatically generated disk mount paths.
    #[arg(long)]
    mount_root: Option<PathBuf>,
    #[arg(short, long, default_value = "kagi.generated.yaml")]
    output: PathBuf,
    #[arg(long, default_value_t = 100_000)]
    trials: u64,
    #[arg(long, default_value_t = 256)]
    candidates: u64,
    #[arg(long, default_value_t = 0xC0FFEE)]
    seed: u64,
    /// Biased rare-event trials per finalist.
    #[arg(long, default_value_t = 100_000)]
    rare_trials: u64,
    /// Number of best ordinary-MC candidates to evaluate with importance sampling.
    #[arg(long, default_value_t = 8)]
    finalists: usize,
    // Accepted for compatibility with older command lines. Validation now covers all host ranges.
    #[arg(long, default_value_t = 128, hide = true)]
    validation_keys: usize,
    /// Continuous-time failure/repair trajectories per finalist.
    #[arg(long, default_value_t = 20_000)]
    time_trials: u64,
    /// Simulated years per continuous-time trajectory.
    #[arg(long, default_value_t = 10.0)]
    horizon_years: f64,
    /// Adaptive importance-sampling rounds.
    #[arg(long, default_value_t = 4)]
    ais_rounds: usize,
    /// Elite loss-near-miss fraction used to adapt the rare-event bias.
    #[arg(long, default_value_t = 0.10)]
    elite_fraction: f64,
    /// File receiving the one-time cluster admission key. Protect this as a secret.
    #[arg(long, default_value = "kagi.join.key")]
    join_key_output: PathBuf,
    /// Disable the interactive terminal progress display.
    #[arg(long)]
    no_progress: bool,
    /// Refresh interval for the interactive progress display.
    #[arg(long, default_value_t = 150)]
    progress_interval_ms: u64,
    /// Simulation confidence/runtime preset. quick30/quick60 trade confidence for much shorter runs.
    #[arg(long,value_enum,default_value_t=RunMode::Full)]
    run_mode: RunMode,
    /// Monte Carlo execution backend. CUDA accelerates bulk EC readability scoring when built with --features cuda.
    #[arg(long,value_enum,default_value_t=McBackend::Auto)]
    mc_backend: McBackend,
    /// Cap the nominal stored/logical payload ratio for every selected policy.
    #[arg(long)]
    max_storage_overhead: Option<f64>,
    /// Object size for the encoded-payload estimate. Repeat for multiple sizes.
    #[arg(long)]
    #[serde(default)]
    example_object_size_bytes: Vec<u64>,
    /// Number of copies of every planned chunk.
    #[arg(long)]
    chunk_replicas: Option<usize>,
    /// Plan this many full object copies instead of searching erasure geometries.
    #[arg(long, conflicts_with = "chunk_replicas")]
    object_replicas: Option<usize>,
}

fn apply_run_mode(args: &mut Args) {
    match args.run_mode {
        RunMode::Full => {}
        RunMode::Quick30 => {
            args.candidates = 32;
            args.trials = 12_000;
            args.rare_trials = 20_000;
            args.finalists = 4;
            args.validation_keys = 32;
            args.time_trials = 4_000;
            args.horizon_years = 5.0;
            args.ais_rounds = 2;
        }
        RunMode::Quick60 => {
            args.candidates = 64;
            args.trials = 25_000;
            args.rare_trials = 40_000;
            args.finalists = 6;
            args.validation_keys = 64;
            args.time_trials = 8_000;
            args.horizon_years = 7.5;
            args.ais_rounds = 3;
        }
    }
}

fn run_mode_label(mode: RunMode) -> (&'static str, &'static str) {
    match mode {
        RunMode::Full => ("full", "full confidence target"),
        RunMode::Quick30 => (
            "quick30",
            "reduced confidence; approximately 30-minute class on reference multi-core/GPU systems",
        ),
        RunMode::Quick60 => (
            "quick60",
            "reduced confidence; approximately 60-minute class on reference multi-core/GPU systems",
        ),
    }
}

fn backend_label(b: McBackend) -> &'static str {
    match resolved_backend(b) {
        McBackend::Cpu => "cpu-rayon",
        McBackend::Cuda => "cuda+cpu",
        McBackend::Hip => "hip+cpu",
        McBackend::Opencl => "opencl+cpu",
        McBackend::Auto => "auto",
    }
}

// Interactive optimizer progress
//
// Worker threads only update atomics. A single renderer thread owns stderr,
// which prevents Rayon workers from interleaving terminal output. Progress is
// automatically disabled when stderr is not a terminal so YAML output remains
// clean when the program is redirected or used from automation.
const PROGRESS_LINES: usize = 6;
static PROGRESS: OnceLock<Arc<ProgressState>> = OnceLock::new();
struct ProgressState {
    enabled: bool,
    started: Instant,
    running: AtomicBool,
    rendered: AtomicBool,
    phase_index: AtomicU64,
    phase_total: AtomicU64,
    current: AtomicU64,
    current_total: AtomicU64,
    simulations: AtomicU64,
    phase: Mutex<String>,
    operation: Mutex<String>,
    best_keyspace: Mutex<(f64, String)>,
    best_schema: Mutex<(f64, String)>,
}
impl ProgressState {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            started: Instant::now(),
            running: AtomicBool::new(true),
            rendered: AtomicBool::new(false),
            phase_index: AtomicU64::new(0),
            phase_total: AtomicU64::new(1),
            current: AtomicU64::new(0),
            current_total: AtomicU64::new(0),
            simulations: AtomicU64::new(0),
            phase: Mutex::new("initializing".into()),
            operation: Mutex::new("validating configuration".into()),
            best_keyspace: Mutex::new((f64::INFINITY, "not evaluated yet".into())),
            best_schema: Mutex::new((f64::INFINITY, "not evaluated yet".into())),
        }
    }
    fn render(&self) {
        if !self.enabled {
            return;
        }
        let phase_index = self.phase_index.load(Ordering::Relaxed);
        let phase_total = self.phase_total.load(Ordering::Relaxed).max(1);
        let current = self.current.load(Ordering::Relaxed);
        let current_total = self.current_total.load(Ordering::Relaxed);
        let phase = self.phase.lock().unwrap().clone();
        let operation = self.operation.lock().unwrap().clone();
        let simulations = self.simulations.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed();
        let rate = simulations as f64 / elapsed.as_secs_f64().max(1e-9);
        let local_fraction = if current_total == 0 {
            0.0
        } else {
            current.min(current_total) as f64 / current_total as f64
        };
        let overall_fraction =
            (((phase_index.saturating_sub(1)) as f64) + local_fraction) / phase_total as f64;
        let best_keyspace = self.best_keyspace.lock().unwrap().1.clone();
        let best_schema = self.best_schema.lock().unwrap().1.clone();
        let current_text = if current_total == 0 {
            format!("{} | {}", progress_bar(0, 0, 28), operation)
        } else {
            format!(
                "{} {}/{} | {}",
                progress_bar(current, current_total, 28),
                current.min(current_total),
                current_total,
                operation
            )
        };
        let lines = [
            "Kagi Monte Carlo optimizer".to_string(),
            format!(
                "Overall {} phase {}/{} | {}",
                progress_bar_fraction(overall_fraction, 28),
                phase_index,
                phase_total,
                phase
            ),
            format!("Current {}", current_text),
            format!(
                "Simulations {:>12} | {:>10.1}/s | elapsed {}",
                simulations,
                rate,
                format_elapsed(elapsed)
            ),
            format!("Best keyspace {}", best_keyspace),
            format!("Best EC       {}", best_schema),
        ];
        let mut err = io::stderr().lock();
        if self.rendered.swap(true, Ordering::Relaxed) {
            let _ = write!(err, "\x1b[{}A", PROGRESS_LINES);
        }
        for line in lines {
            let _ = writeln!(err, "\x1b[2K\r{}", line);
        }
        let _ = err.flush();
    }
}

struct ProgressGuard {
    state: Arc<ProgressState>,
    renderer: Option<thread::JoinHandle<()>>,
}
impl ProgressGuard {
    fn start(enabled: bool, interval_ms: u64) -> Self {
        let state = Arc::new(ProgressState::new(enabled));
        let _ = PROGRESS.set(state.clone());
        let renderer = if enabled {
            let state = state.clone();
            Some(thread::spawn(move || {
                let interval = Duration::from_millis(interval_ms.clamp(50, 2_000));
                while state.running.load(Ordering::Acquire) {
                    state.render();
                    thread::sleep(interval);
                }
                state.render();
            }))
        } else {
            None
        };
        Self { state, renderer }
    }
}
impl Drop for ProgressGuard {
    fn drop(&mut self) {
        self.state.running.store(false, Ordering::Release);
        if let Some(handle) = self.renderer.take() {
            let _ = handle.join();
        }
        if self.state.enabled {
            eprintln!();
        }
    }
}

fn progress_bar(done: u64, total: u64, width: usize) -> String {
    if total == 0 {
        return format!("[{}]   --.-%", "-".repeat(width));
    }
    progress_bar_fraction(done.min(total) as f64 / total as f64, width)
}

fn progress_bar_fraction(fraction: f64, width: usize) -> String {
    let f = fraction.clamp(0.0, 1.0);
    let filled = (f * width as f64).round() as usize;
    format!(
        "[{}{}] {:6.2}%",
        "#".repeat(filled),
        "-".repeat(width.saturating_sub(filled)),
        f * 100.0
    )
}

fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn progress_phase(index: u64, total: u64, phase: impl Into<String>) {
    checkpoint::flush().expect("checkpoint flush failed at phase boundary");
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        p.phase_index.store(index, Ordering::Relaxed);
        p.phase_total.store(total.max(1), Ordering::Relaxed);
        p.current.store(0, Ordering::Relaxed);
        p.current_total.store(0, Ordering::Relaxed);
        *p.phase.lock().unwrap() = phase.into();
    }
}

fn progress_operation(operation: impl Into<String>, total: u64) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        p.current.store(0, Ordering::Relaxed);
        p.current_total.store(total, Ordering::Relaxed);
        *p.operation.lock().unwrap() = operation.into();
    }
}

fn progress_operation_label(operation: impl Into<String>) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        *p.operation.lock().unwrap() = operation.into();
    }
}

fn progress_tick(n: u64) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        p.current.fetch_add(n, Ordering::Relaxed);
        p.simulations.fetch_add(n, Ordering::Relaxed);
    }
}

fn progress_step(n: u64) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        p.current.fetch_add(n, Ordering::Relaxed);
    }
}

struct SimulationTick;
impl Drop for SimulationTick {
    fn drop(&mut self) {
        progress_tick(1);
    }
}

fn progress_best_keyspace(loss: f64, summary: impl Into<String>) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        let mut best = p.best_keyspace.lock().unwrap();
        if loss < best.0 {
            *best = (loss, summary.into());
        }
    }
}

fn progress_best_schema(loss: f64, summary: impl Into<String>) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        let mut best = p.best_schema.lock().unwrap();
        if loss < best.0 {
            *best = (loss, summary.into());
        }
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    #[serde(default = "default_slot_bits")]
    slot_bits: u8,
    topology: Topology,
    policies: BTreeMap<String, Policy>,
    failure_model: FailureModel,
    #[serde(default)]
    repair_model: RepairModel,
    #[serde(default)]
    optimization: Optimization,
    #[serde(default = "default_example_object_sizes")]
    example_object_sizes_bytes: Vec<u64>,
}

fn default_slot_bits() -> u8 {
    16
}

fn default_example_object_sizes() -> Vec<u64> {
    vec![4_096, 1_048_576, 1_073_741_824]
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Topology {
    /// Root directory below which physical disks are mounted.
    #[serde(default = "default_mount_root")]
    mount_root: String,
    #[serde(default)]
    network_domains: Vec<NetworkDomain>,
    #[serde(default)]
    disk_classes: Vec<DiskClass>,
    #[serde(default)]
    hosts: Vec<HostTopology>,
    disks: Vec<Disk>,
    #[serde(skip)]
    placement_disks: Vec<DomainDisk>,
}

fn default_mount_root() -> String {
    "/var/lib/kagi/disks".into()
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct NetworkDomain {
    id: String,
    cidr: String,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    rack: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct DiskClass {
    name: String,
    #[serde(default)]
    media: String,
    #[serde(default)]
    annual_failure_probability: Option<f64>,
    #[serde(default)]
    default_capacity_bytes: Option<u64>,
    #[serde(default = "one")]
    default_weight: f64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct HostTopology {
    name: String,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    rack: Option<String>,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    addresses: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Disk {
    /// Stable logical disk identifier used by placement.
    id: String,
    /// Mountpoint where Kagi stores data for this disk.
    path: String,
    /// Optional underlying block-device path such as /dev/disk/by-id/....
    #[serde(default)]
    device_path: Option<String>,
    capacity_bytes: u64,
    #[serde(default)]
    class: String,
    #[serde(default)]
    ordinal: usize,
    #[serde(default)]
    mount_name: String,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    rack: Option<String>,
    host: String,
    #[serde(default = "one")]
    weight: f64,
}

fn one() -> f64 {
    1.0
}

// Data-protection policy model
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Policy {
    protection: Protection,
    #[serde(default)]
    locality: Locality,
    #[serde(default)]
    tolerate: Tolerance,
    #[serde(default)]
    optimize: Option<ProtectionSearch>,
    #[serde(default = "one_usize")]
    chunk_replicas: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
/// Replication and erasure geometries evaluated by the planner.
enum Protection {
    Replication {
        copies: usize,
    },
    /// Conventional MDS Reed-Solomon geometry: k data + m parity chunks.
    ReedSolomon {
        k: usize,
        m: usize,
    },
    /// Local reconstruction code: k data chunks split across local groups plus global parity.
    Lrc {
        k: usize,
        local_groups: usize,
        local_parity: usize,
        global_parity: usize,
    },
    /// Minimum-storage regenerating-code model. d is the repair fan-in.
    Msr {
        k: usize,
        m: usize,
        d: usize,
    },
    /// CLAY-code model. For durability, CLAY is MDS-like; d primarily affects repair behavior.
    Clay {
        k: usize,
        m: usize,
        d: usize,
    },
}
impl Protection {
    fn fragments(&self) -> usize {
        match self {
            Self::Replication { copies } => *copies,
            Self::ReedSolomon { k, m } | Self::Msr { k, m, .. } | Self::Clay { k, m, .. } => {
                k.saturating_add(*m)
            }
            Self::Lrc {
                k,
                local_groups,
                local_parity,
                global_parity,
            } => k
                .saturating_add(local_groups.saturating_mul(*local_parity))
                .saturating_add(*global_parity),
        }
    }
    fn data_fragments(&self) -> usize {
        match self {
            Self::Replication { .. } => 1,
            Self::ReedSolomon { k, .. }
            | Self::Lrc { k, .. }
            | Self::Msr { k, .. }
            | Self::Clay { k, .. } => *k,
        }
    }
    fn parity_fragments(&self) -> usize {
        self.fragments().saturating_sub(self.data_fragments())
    }
    fn schema_name(&self) -> &'static str {
        match self {
            Self::Replication { .. } => "replication",
            Self::ReedSolomon { .. } => "reed_solomon",
            Self::Lrc { .. } => "lrc",
            Self::Msr { .. } => "msr",
            Self::Clay { .. } => "clay",
        }
    }
    fn layout(&self) -> ProtectionLayout {
        match self {
            Self::Replication { copies } => ProtectionLayout::Replication { copies: *copies },
            Self::ReedSolomon { k, m } => ProtectionLayout::ReedSolomon { k: *k, m: *m },
            Self::Lrc { k, .. } => ProtectionLayout::Lrc {
                k: *k,
                m: self.parity_fragments(),
            },
            Self::Msr { k, m, d } => ProtectionLayout::Msr {
                k: *k,
                m: *m,
                d: *d,
            },
            Self::Clay { k, m, d } => ProtectionLayout::Clay {
                k: *k,
                m: *m,
                d: *d,
            },
        }
    }
    fn readable(&self, alive: &[bool]) -> bool {
        self.layout().readable(alive)
    }
}

impl Policy {
    fn auto_geometry(&self) -> bool {
        self.optimize
            .as_ref()
            .is_some_and(|search| search.auto_geometry)
    }

    fn plan(
        &self,
        topology: &Topology,
        salt: u64,
        acknowledged_unsafe_two_site: bool,
    ) -> PlacementPlan {
        PlacementPlan {
            salt,
            disks: topology.placement_disks.clone(),
            protection: self.protection.layout(),
            chunk_replicas: self.chunk_replicas,
            max_fragments_per_host: self.locality.max_fragments_per_host,
            max_fragments_per_disk: self.locality.max_fragments_per_disk,
            tolerate: FailureBudget {
                sites: self.tolerate.sites,
                racks: self.tolerate.racks,
                hosts: self.tolerate.hosts,
                disks: self.tolerate.disks,
                networks: self.tolerate.networks,
            },
            acknowledged_unsafe_two_site: acknowledged_unsafe_two_site && self.tolerate.sites == 0,
        }
    }

    fn overhead(&self) -> f64 {
        self.protection
            .layout()
            .nominal_overhead(self.chunk_replicas)
    }

    fn within_overhead_limit(&self) -> bool {
        self.optimize
            .as_ref()
            .and_then(|search| search.max_storage_overhead)
            .is_none_or(|limit| self.overhead() <= limit)
    }
}

fn protection_summary(p: &Protection) -> String {
    match p {
        Protection::Replication { copies } => format!("replication x{copies}"),
        Protection::ReedSolomon { k, m } => format!("reed_solomon k={k} m={m}"),
        Protection::Lrc {
            k,
            local_groups,
            local_parity,
            global_parity,
        } => format!("lrc k={k} groups={local_groups} lp={local_parity} gp={global_parity}"),
        Protection::Msr { k, m, d } => format!("msr k={k} m={m} d={d}"),
        Protection::Clay { k, m, d } => format!("clay k={k} m={m} d={d}"),
    }
}

fn policy_schema_summary(cfg: &Config) -> String {
    cfg.policies
        .iter()
        .map(|(name, p)| format!("{name}={}", protection_summary(&p.protection)))
        .collect::<Vec<_>>()
        .join(", ")
}
/// Optional user bounds for protection-geometry search.  Even when this block is absent,
/// the report compares the supported EC families using topology-derived search bounds.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct ProtectionSearch {
    /// When true, replace the policy's selected protection with the lowest-risk feasible EC geometry.
    #[serde(default)]
    auto_geometry: bool,
    /// Upper bound for total data+parity chunks considered by automatic search (default 32).
    #[serde(default)]
    max_total_fragments: Option<usize>,
    #[serde(default)]
    min_data_fragments: Option<usize>,
    #[serde(default)]
    max_data_fragments: Option<usize>,
    #[serde(default)]
    replication_copies: Vec<usize>,
    /// Maximum encoded payload bytes divided by logical payload bytes.
    #[serde(default)]
    max_storage_overhead: Option<f64>,
    #[serde(default)]
    rs_k: Vec<usize>,
    #[serde(default)]
    rs_m: Vec<usize>,
    #[serde(default)]
    lrc_k: Vec<usize>,
    #[serde(default)]
    lrc_local_groups: Vec<usize>,
    #[serde(default)]
    lrc_local_parity: Vec<usize>,
    #[serde(default)]
    lrc_global_parity: Vec<usize>,
    #[serde(default)]
    msr_k: Vec<usize>,
    #[serde(default)]
    msr_m: Vec<usize>,
    #[serde(default)]
    msr_d: Vec<usize>,
    #[serde(default)]
    clay_k: Vec<usize>,
    #[serde(default)]
    clay_m: Vec<usize>,
    #[serde(default)]
    clay_d: Vec<usize>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Optimization {
    #[serde(default = "default_loss_weight")]
    loss_weight: f64,
    #[serde(default = "default_overhead_weight")]
    overhead_weight: f64,
    #[serde(default = "default_imbalance_weight")]
    imbalance_weight: f64,
}
impl Default for Optimization {
    fn default() -> Self {
        Self {
            loss_weight: default_loss_weight(),
            overhead_weight: default_overhead_weight(),
            imbalance_weight: default_imbalance_weight(),
        }
    }
}
fn default_loss_weight() -> f64 {
    1e6
}

fn default_overhead_weight() -> f64 {
    1.0
}

fn default_imbalance_weight() -> f64 {
    100.0
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct RepairModel {
    #[serde(default)]
    disk_mttr_hours: f64,
    #[serde(default)]
    host_mttr_hours: f64,
    #[serde(default)]
    rack_mttr_hours: f64,
    #[serde(default)]
    site_mttr_hours: f64,
    #[serde(default)]
    network_mttr_hours: f64,
    #[serde(default)]
    repair_bandwidth_bytes_per_sec: f64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Locality {
    #[serde(default)]
    site: Mode,
    #[serde(default)]
    rack: Mode,
    #[serde(default = "one_usize")]
    max_fragments_per_host: usize,
    #[serde(default = "one_usize")]
    max_fragments_per_disk: usize,
}
impl Default for Locality {
    fn default() -> Self {
        Self {
            site: Mode::Ignore,
            rack: Mode::Ignore,
            max_fragments_per_host: 1,
            max_fragments_per_disk: 1,
        }
    }
}
fn one_usize() -> usize {
    1
}
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
/// Policy for distributing fragments across a failure domain.
enum Mode {
    Spread,
    Localize,
    Prefer,
    #[default]
    Ignore,
}
const TOPOLOGY_DEFAULT: usize = usize::MAX;

fn topology_default() -> usize {
    TOPOLOGY_DEFAULT
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Tolerance {
    #[serde(default = "topology_default")]
    disks: usize,
    #[serde(default = "topology_default")]
    hosts: usize,
    #[serde(default = "topology_default")]
    racks: usize,
    #[serde(default = "topology_default")]
    sites: usize,
    #[serde(default = "topology_default")]
    networks: usize,
}
impl Default for Tolerance {
    fn default() -> Self {
        Self {
            disks: TOPOLOGY_DEFAULT,
            hosts: TOPOLOGY_DEFAULT,
            racks: TOPOLOGY_DEFAULT,
            sites: TOPOLOGY_DEFAULT,
            networks: TOPOLOGY_DEFAULT,
        }
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct FailureModel {
    disk_annual_probability: f64,
    host_annual_probability: f64,
    rack_annual_probability: f64,
    site_annual_probability: f64,
    #[serde(default)]
    network_annual_probability: f64,
    #[serde(default)]
    correlated_events: Vec<CorrelatedEvent>,
    #[serde(default = "default_bias")]
    importance_bias: f64,
}

fn default_bias() -> f64 {
    8.0
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct CorrelatedEvent {
    probability: f64,
    domain: Domain,
    count_min: usize,
    count_max: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Resource scopes that can fail together in one modeled event.
enum Domain {
    Disk,
    Host,
    Rack,
    Site,
    Network,
}

// Generated deployment/simulation output
#[derive(Debug, Serialize)]
struct Output {
    format_version: u32,
    infrastructure: InfrastructureOutput,
    keyspace: AddressSpacePlan,
    optimizer: OptimizerResult,
    policies: BTreeMap<String, PolicyOutput>,
    join_admission: JoinAdmission,
}
#[derive(Debug, Serialize)]
struct InfrastructureOutput {
    mount_root: String,
    network_domains: Vec<NetworkDomain>,
    disk_classes: Vec<DiskClass>,
    hosts: Vec<HostTopology>,
}
#[derive(Debug, Serialize)]
struct JoinAdmission {
    algorithm: String,
    key_hash_hex: String,
}
#[derive(Debug, Serialize)]
struct AddressSpacePlan {
    bits: u8,
    min: String,
    max: String,
    mapping: String,
    salt: u64,
    host_ranges: Vec<HostRange>,
    disks: Vec<DiskShare>,
}
#[derive(Debug, Serialize)]
struct DiskShare {
    id: String,
    host: String,
    class: String,
    ordinal: usize,
    mount_name: String,
    path: String,
    device_path: Option<String>,
    weight: f64,
}
#[derive(Debug, Serialize)]
struct OptimizerResult {
    run_mode: String,
    confidence: String,
    mc_backend: String,
    trials_per_candidate: u64,
    candidates: u64,
    ordinary_mc: Estimate,
    importance_sampling: Estimate,
    adaptive_importance_sampling: AdaptiveEstimate,
    time_domain: TimeDomainEstimate,
    objective_score: f64,
    rarest_observed_data_loss_scenario: Option<Scenario>,
}
#[derive(Debug, Clone, Serialize)]
struct Estimate {
    durability: durability::Durability,
    estimated_unreadable_probability: f64,
    estimated_readability: f64,
    ci95_low: f64,
    ci95_high: f64,
    losses: u64,
    trials: u64,
}
#[derive(Debug, Clone, Serialize)]
struct AdaptiveEstimate {
    durability: durability::Durability,
    estimated_unreadable_probability: f64,
    ci95_low: f64,
    ci95_high: f64,
    effective_sample_size: f64,
    final_bias: f64,
    rounds: usize,
    trials_per_round: u64,
}
#[derive(Debug, Clone, Serialize)]
struct TimeDomainEstimate {
    durability_within_horizon: durability::Durability,
    simulated_trajectory_years: f64,
    trajectories: u64,
    data_loss_trajectories: u64,
    estimated_annual_data_loss_rate: f64,
    probability_of_loss_within_horizon: f64,
    ci95_low: f64,
    ci95_high: f64,
}
#[derive(Default, Clone)]
struct WeightedStats {
    n: u64,
    sum: f64,
    sumsq: f64,
    weight_sum: f64,
    weight_sq_sum: f64,
    losses: u64,
}
impl WeightedStats {
    fn push(&mut self, x: f64, w: f64, loss: bool) {
        self.n += 1;
        self.sum += x * w;
        self.sumsq += x * x * w * w;
        self.weight_sum += w;
        self.weight_sq_sum += w * w;
        if loss {
            self.losses += 1;
        }
    }
    fn mean(&self) -> f64 {
        self.sum / self.n.max(1) as f64
    }
    fn ess(&self) -> f64 {
        if self.weight_sq_sum == 0.0 {
            return 0.0;
        }
        self.weight_sum * self.weight_sum / self.weight_sq_sum
    }
    fn ci95(&self) -> (f64, f64) {
        let n = self.n.max(1) as f64;
        let m = self.mean();
        let var = (self.sumsq / n - m * m).max(0.0);
        let se = (var / n).sqrt();
        ((m - 1.96 * se).max(0.0), (m + 1.96 * se).min(1.0))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Scenario {
    policy: String,
    failed_disks: Vec<String>,
    estimated_probability: f64,
}
#[derive(Debug, Serialize)]
struct PolicyOutput {
    selected_protection: Protection,
    fragments: usize,
    storage_overhead: f64,
    estimated_object_storage: Vec<ObjectStorageEstimate>,
    tolerance_validated: bool,
    estimated_repair_window_hours: f64,
    /// Best simulated chunk geometry for every supported erasure-coding family.
    erasure_scheme_optimization: BTreeMap<String, SchemeOptimization>,
    deployment: PlacementPlan,
}
#[derive(Debug, Clone, Serialize)]
struct SchemeOptimization {
    schema: String,
    feasible: bool,
    reason: Option<String>,
    selected_protection: Option<Protection>,
    data_fragments: usize,
    parity_fragments: usize,
    total_fragments: usize,
    simulated_unreadable_probability: f64,
    simulation_trials: u64,
    sampled_loss_events: u64,
    loss_probability_resolved: bool,
    disk_failures_to_unreadable: Option<usize>,
    objective_score: f64,
    storage_overhead: f64,
    estimated_object_storage: Vec<ObjectStorageEstimate>,
    tolerance_validated: bool,
    estimated_repair_window_hours: f64,
}
#[derive(Debug, Clone, Serialize)]
struct ObjectStorageEstimate {
    logical_bytes: u64,
    encoded_payload_bytes: u64,
    extra_payload_bytes: u64,
}
#[derive(Clone, Copy)]
struct SchemeSearchRun {
    salt: u64,
    seed: u64,
    trials: u64,
    backend: McBackend,
}

// Wizard, topology normalization, and validation
/// Normalize an arbitrary topology label into a safe, deterministic mount-name component.
fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}
/// Generate the mount name required by the deployment plan: host-diskclass-ordinal.
fn generated_mount_name(host: &str, class: &str, ordinal: usize) -> String {
    format!(
        "{}-{}-{ordinal:02}",
        slug(host),
        slug(if class.is_empty() { "default" } else { class })
    )
}
/// Return the network-domain IDs that can carry traffic for a disk's host.
fn disk_networks(cfg: &Config, d: &Disk) -> Vec<String> {
    if !d.networks.is_empty() {
        return d.networks.clone();
    }
    cfg.topology
        .hosts
        .iter()
        .find(|h| h.name == d.host)
        .map(|h| h.networks.clone())
        .unwrap_or_default()
}
/// A multi-homed disk/host is unreachable only when every configured network path is failed.
/// A multi-homed disk loses connectivity only when every configured network is down.
fn network_unreachable(cfg: &Config, d: &Disk, failed: &BTreeSet<String>) -> bool {
    let n = disk_networks(cfg, d);
    !n.is_empty() && n.iter().all(|x| failed.contains(x))
}
/// Resolve disk AFR from its class, falling back to the global failure-model AFR.
fn disk_failure_probability(cfg: &Config, d: &Disk) -> f64 {
    cfg.topology
        .disk_classes
        .iter()
        .find(|c| c.name == d.class)
        .and_then(|c| c.annual_failure_probability)
        .unwrap_or(cfg.failure_model.disk_annual_probability)
}
/// Make old configuration files deployable by inferring host records, class ordinals and mount paths.
/// Fill in derived hosts and mount locations before validation. Explicit device paths
/// are preserved unless the caller supplies a mount-root override.
fn normalize_topology(cfg: &mut Config, mount_override: Option<&Path>) {
    if let Some(root) = mount_override {
        cfg.topology.mount_root = root.to_string_lossy().into_owned();
    }
    if cfg.topology.mount_root.trim().is_empty() {
        cfg.topology.mount_root = default_mount_root();
    }
    if cfg.topology.hosts.is_empty() {
        let mut hosts = BTreeMap::<String, HostTopology>::new();
        for d in &cfg.topology.disks {
            hosts.entry(d.host.clone()).or_insert_with(|| HostTopology {
                name: d.host.clone(),
                site: d.site.clone(),
                rack: d.rack.clone(),
                networks: d.networks.clone(),
                addresses: Vec::new(),
            });
        }
        cfg.topology.hosts = hosts.into_values().collect();
    }
    let hosts: BTreeMap<_, _> = cfg
        .topology
        .hosts
        .iter()
        .map(|h| (h.name.as_str(), h))
        .collect();
    let mut ordinal = BTreeMap::<(String, String), usize>::new();
    for d in &mut cfg.topology.disks {
        if let Some(host) = hosts.get(d.host.as_str()) {
            if d.site.is_none() {
                d.site = host.site.clone();
            }
            if d.rack.is_none() {
                d.rack = host.rack.clone();
            }
        }
        if d.class.trim().is_empty() {
            d.class = "default".into();
        }
        let k = (d.host.clone(), d.class.clone());
        let n = ordinal.entry(k).or_insert(0);
        *n += 1;
        if d.ordinal == 0 {
            d.ordinal = *n;
        }
        if d.mount_name.trim().is_empty() {
            d.mount_name = generated_mount_name(&d.host, &d.class, d.ordinal);
        }
        if d.path.trim().is_empty() || mount_override.is_some() {
            d.path = Path::new(&cfg.topology.mount_root)
                .join(&d.mount_name)
                .to_string_lossy()
                .into_owned();
        }
    }
    cfg.topology.placement_disks = cfg
        .topology
        .disks
        .iter()
        .map(|d| DomainDisk {
            id: d.id.clone(),
            host: d.host.clone(),
            rack: d.rack.clone(),
            site: d.site.clone(),
            networks: disk_networks(cfg, d),
        })
        .collect();
    let minimum = topology_minimum_tolerance(&cfg.topology);
    for p in cfg.policies.values_mut() {
        for (value, default) in [
            (&mut p.tolerate.disks, minimum.disks),
            (&mut p.tolerate.hosts, minimum.hosts),
            (&mut p.tolerate.racks, minimum.racks),
            (&mut p.tolerate.sites, minimum.sites),
            (&mut p.tolerate.networks, minimum.networks),
        ] {
            if *value == TOPOLOGY_DEFAULT {
                *value = default;
            }
        }
    }
}

fn prompt_line(label: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(d) => print!("{label} [{d}]: "),
        None => print!("{label}: "),
    }
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim();
    Ok(if s.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        s.to_string()
    })
}

fn prompt_usize(label: &str, default: usize) -> Result<usize> {
    loop {
        let s = prompt_line(label, Some(&default.to_string()))?;
        match s.parse() {
            Ok(v) => return Ok(v),
            Err(_) => eprintln!("Enter a non-negative integer."),
        }
    }
}

fn prompt_usize_min(label: &str, default: usize, min: usize) -> Result<usize> {
    loop {
        let v = prompt_usize(label, default.max(min))?;
        if v >= min {
            return Ok(v);
        }
        eprintln!("Value must be at least {min}.")
    }
}

fn prompt_f64(label: &str, default: f64) -> Result<f64> {
    loop {
        let s = prompt_line(label, Some(&default.to_string()))?;
        match s.parse() {
            Ok(v) => return Ok(v),
            Err(_) => eprintln!("Enter a number."),
        }
    }
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    loop {
        let d = if default { "Y/n" } else { "y/N" };
        let s = prompt_line(&format!("{label} ({d})"), Some(""))?.to_ascii_lowercase();
        if s.is_empty() {
            return Ok(default);
        }
        match s.as_str() {
            "y" | "yes" | "true" => return Ok(true),
            "n" | "no" | "false" => return Ok(false),
            _ => eprintln!("Enter y or n."),
        }
    }
}
/// Very small IPv4 CIDR allocator used only by the wizard. It avoids adding a runtime dependency.
fn nth_ipv4(cidr: &str, n: u32) -> Option<String> {
    use std::net::Ipv4Addr;
    let (ip, pfx) = cidr.split_once('/')?;
    let ip: u32 = ip.parse::<Ipv4Addr>().ok()?.into();
    let pfx: u32 = pfx.parse().ok()?;
    if pfx > 32 {
        return None;
    }
    let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
    let net = ip & mask;
    let host_bits = 32 - pfx;
    let max = if host_bits == 32 {
        u32::MAX
    } else {
        (1u64 << host_bits) as u32 - 1
    };
    let off = n.saturating_add(1);
    if off >= max {
        return None;
    }
    Some(Ipv4Addr::from(net.saturating_add(off)).to_string())
}
/// Quick mode allocates sequential /24s from 10.0.0.0/8: 10.0.0.0/24,
/// 10.0.1.0/24, ... 10.1.0.0/24 and so on.
fn quick_ipv4_cidr(index: usize) -> Result<String> {
    if index >= 65_536 {
        bail!("quick mode exhausted the 10.0.0.0/8 /24 pool")
    }
    Ok(format!("10.{}.{}.0/24", index / 256, index % 256))
}
/// Require one loss by default whenever there is more than one domain member.
fn minimum_tolerance_for_count(n: usize) -> usize {
    usize::from(n >= 2)
}
fn topology_domain_counts(t: &Topology) -> Tolerance {
    let hosts = t.hosts.len();
    let racks = t
        .disks
        .iter()
        .filter_map(|d| d.site.as_ref().zip(d.rack.as_ref()))
        .collect::<BTreeSet<_>>()
        .len();
    let sites = t
        .disks
        .iter()
        .filter_map(|h| h.site.as_ref())
        .collect::<BTreeSet<_>>()
        .len();
    let networks = if t.placement_disks.is_empty() {
        t.hosts
            .iter()
            .flat_map(|h| h.networks.iter())
            .collect::<BTreeSet<_>>()
            .len()
    } else {
        t.placement_disks
            .iter()
            .flat_map(|d| d.networks.iter())
            .collect::<BTreeSet<_>>()
            .len()
    };
    Tolerance {
        disks: t.disks.len(),
        hosts,
        racks,
        sites,
        networks,
    }
}

fn topology_minimum_tolerance(t: &Topology) -> Tolerance {
    let counts = topology_domain_counts(t);
    Tolerance {
        disks: minimum_tolerance_for_count(counts.disks),
        hosts: minimum_tolerance_for_count(counts.hosts),
        racks: minimum_tolerance_for_count(counts.racks),
        sites: minimum_tolerance_for_count(counts.sites),
        networks: minimum_tolerance_for_count(counts.networks),
    }
}

fn requires_site_acknowledgment(cfg: &Config) -> bool {
    topology_domain_counts(&cfg.topology).sites == 2
        && cfg.policies.values().any(|p| p.tolerate.sites == 0)
}

fn acknowledge_site_risk(cfg: &Config) -> Result<bool> {
    if !requires_site_acknowledgment(cfg) {
        return Ok(false);
    }
    eprintln!("\x1b[1;97;41m DANGER: LOSING ONE SITE CAN MAKE OBJECTS UNAVAILABLE \x1b[0m");
    eprintln!("Type exactly: {TWO_SITE_ACKNOWLEDGMENT}");
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != TWO_SITE_ACKNOWLEDGMENT {
        bail!("the required two-site outage acknowledgment was not entered");
    }
    Ok(true)
}

fn default_auto_search() -> ProtectionSearch {
    ProtectionSearch {
        auto_geometry: true,
        max_total_fragments: Some(32),
        min_data_fragments: Some(2),
        ..Default::default()
    }
}

fn default_failure_model() -> FailureModel {
    FailureModel {
        disk_annual_probability: 0.01,
        host_annual_probability: 0.002,
        rack_annual_probability: 0.0005,
        site_annual_probability: 0.0001,
        network_annual_probability: 0.001,
        correlated_events: Vec::new(),
        importance_bias: 8.0,
    }
}

fn default_repair_model() -> RepairModel {
    RepairModel {
        disk_mttr_hours: 24.0,
        host_mttr_hours: 4.0,
        rack_mttr_hours: 4.0,
        site_mttr_hours: 24.0,
        network_mttr_hours: 1.0,
        repair_bandwidth_bytes_per_sec: 1_000_000_000.0,
    }
}

fn wizard_policy(name: &str, minimum: &Tolerance) -> Result<Policy> {
    println!("\nPolicy {name}");
    let auto = prompt_bool(
        "Have Monte Carlo choose the lowest-risk chunk geometry across all EC schemas",
        true,
    )?;
    let protection = if auto {
        // This seed geometry is replaced after simulation; it only gives the initial salt search
        // a valid six-fragment placement for the minimum supported cluster.
        Protection::Clay { k: 4, m: 2, d: 5 }
    } else {
        let kind = prompt_line(
            "Protection type (replication/reed_solomon/lrc/msr/clay)",
            Some("clay"),
        )?
        .to_ascii_lowercase();
        match kind.as_str() {
            "replication" => Protection::Replication {
                copies: prompt_usize_min("Replication copies", 3, 1)?,
            },
            "lrc" => Protection::Lrc {
                k: prompt_usize_min("LRC data fragments k", 4, 2)?,
                local_groups: prompt_usize_min("LRC local groups", 2, 1)?,
                local_parity: prompt_usize_min("Local parity per group", 1, 1)?,
                global_parity: prompt_usize_min("Global parity", 1, 1)?,
            },
            "msr" => Protection::Msr {
                k: prompt_usize_min("MSR data fragments k", 4, 2)?,
                m: prompt_usize_min("MSR parity fragments m (product-matrix needs m>=k-1)", 3, 1)?,
                d: prompt_usize_min("MSR repair fan-in d (must equal 2k-2)", 6, 2)?,
            },
            "clay" => Protection::Clay {
                k: prompt_usize_min("CLAY data fragments k", 4, 2)?,
                m: prompt_usize_min("CLAY parity fragments m", 2, 1)?,
                d: prompt_usize_min("CLAY repair fan-in d", 5, 2)?,
            },
            _ => Protection::ReedSolomon {
                k: prompt_usize_min("Reed-Solomon data fragments k", 4, 2)?,
                m: prompt_usize_min("Reed-Solomon parity fragments m", 2, 1)?,
            },
        }
    };
    let locality = Locality {
        site: Mode::Spread,
        rack: Mode::Spread,
        max_fragments_per_host: prompt_usize_min("Maximum fragments per host", 1, 1)?,
        max_fragments_per_disk: prompt_usize_min("Maximum fragments per disk", 1, 1)?,
    };
    let tolerate = Tolerance {
        disks: prompt_usize(
            "Required simultaneous disk failures tolerated",
            minimum.disks,
        )?,
        hosts: prompt_usize(
            "Required simultaneous host failures tolerated",
            minimum.hosts,
        )?,
        racks: prompt_usize(
            "Required simultaneous rack failures tolerated",
            minimum.racks,
        )?,
        sites: prompt_usize(
            "Required simultaneous site failures tolerated",
            minimum.sites,
        )?,
        networks: prompt_usize(
            "Required simultaneous network-domain failures tolerated",
            minimum.networks,
        )?,
    };
    Ok(Policy {
        protection,
        locality,
        tolerate,
        chunk_replicas: 1,
        optimize: if auto {
            Some(default_auto_search())
        } else {
            None
        },
    })
}
/// Maximum fragments this policy can place while respecting per-host and per-disk limits.
fn max_placeable_fragments(cfg: &Config, p: &Policy) -> usize {
    let disk_cap = cfg
        .topology
        .disks
        .len()
        .saturating_mul(p.locality.max_fragments_per_disk);
    let mut per_host = BTreeMap::<&str, usize>::new();
    for d in &cfg.topology.disks {
        *per_host.entry(d.host.as_str()).or_default() += 1;
    }
    let host_cap = per_host.into_values().fold(0usize, |capacity, disks| {
        capacity.saturating_add(
            disks
                .saturating_mul(p.locality.max_fragments_per_disk)
                .min(p.locality.max_fragments_per_host),
        )
    });
    disk_cap.min(host_cap) / p.chunk_replicas.max(1)
}

fn validate_protection_geometry(p: &Protection) -> Result<()> {
    if !matches!(p, Protection::Replication { .. }) && p.fragments() > 255 {
        bail!("erasure geometry exceeds 255 fragments");
    }
    match p {
        Protection::Replication { copies } => {
            if *copies < 1 {
                bail!("replication copies must be at least 1")
            }
        }
        Protection::ReedSolomon { k, m } => {
            if *k < 2 || *m < 1 {
                bail!("reed_solomon requires k>=2 and m>=1")
            }
        }
        Protection::Lrc {
            k,
            local_groups,
            local_parity,
            global_parity,
        } => {
            if *k < 2
                || *local_groups < 1
                || *local_groups > *k
                || *local_parity != 1
                || *global_parity != 1
            {
                bail!("Kagi LRC requires k>=2, 1..=k local groups, one local parity per group, and one global parity")
            }
        }
        Protection::Msr { k, m, d } => {
            let want = k.saturating_mul(2).saturating_sub(2);
            if *k < 2 || *m < k.saturating_sub(1) || *d != want || *d >= p.fragments() {
                bail!("msr runtime uses product-matrix MSR and requires k>=2, m>=k-1, d=2k-2, and d<k+m")
            }
        }
        Protection::Clay { k, m, d } => {
            if *k < 2 || *m < 2 || *d <= *k || *d >= p.fragments() {
                bail!("clay requires k>=2, m>=2, and k+1<=d<k+m")
            }
        }
    }
    p.layout().validate()
}
/// Validate topology/model invariants before expensive simulation begins.
fn validate_config(cfg: &Config) -> Result<()> {
    if cfg.topology.disks.is_empty() {
        bail!("no disks configured")
    }
    if cfg.policies.is_empty() {
        bail!("no protection policies configured")
    }
    if cfg.topology.hosts.len() < 6 {
        bail!(
            "Kagi requires at least 6 servers; configured {}",
            cfg.topology.hosts.len()
        )
    }
    for (name, p) in [
        ("disk", cfg.failure_model.disk_annual_probability),
        ("host", cfg.failure_model.host_annual_probability),
        ("rack", cfg.failure_model.rack_annual_probability),
        ("site", cfg.failure_model.site_annual_probability),
        ("network", cfg.failure_model.network_annual_probability),
    ] {
        if !(0.0..=1.0).contains(&p) {
            bail!("{name} annual failure probability must be in 0..=1")
        }
    }
    let max_other_probability = cfg
        .failure_model
        .host_annual_probability
        .max(cfg.failure_model.rack_annual_probability)
        .max(cfg.failure_model.site_annual_probability)
        .max(cfg.failure_model.network_annual_probability);
    if cfg.failure_model.disk_annual_probability < max_other_probability {
        bail!("the fallback disk annual failure probability must be at least the host, rack, site, and network probabilities");
    }
    for class in &cfg.topology.disk_classes {
        if let Some(rate) = class.annual_failure_probability {
            if !(max_other_probability..=1.0).contains(&rate) {
                bail!("disk class {} annual failure probability must be between {max_other_probability} and 1", class.name);
            }
        }
    }
    for event in &cfg.failure_model.correlated_events {
        if !(0.0..=1.0).contains(&event.probability) || event.count_max < event.count_min {
            bail!(
                "correlated failure events require probability in 0..=1 and count_max >= count_min"
            );
        }
    }
    let mut host_ids = BTreeSet::new();
    for h in &cfg.topology.hosts {
        if !host_ids.insert(h.name.as_str()) {
            bail!("duplicate host name {}", h.name)
        }
        if h.site.as_deref().is_none_or(|site| site.trim().is_empty())
            || h.rack.as_deref().is_none_or(|rack| rack.trim().is_empty())
        {
            bail!("host {} requires a site and rack", h.name);
        }
    }
    let network_ids: BTreeSet<_> = cfg
        .topology
        .network_domains
        .iter()
        .map(|n| n.id.as_str())
        .collect();
    let mut disk_ids = BTreeSet::new();
    let mut mount_paths = BTreeSet::new();
    let mut per_host = BTreeMap::<&str, usize>::new();
    for d in &cfg.topology.disks {
        if !disk_ids.insert(d.id.as_str()) {
            bail!("duplicate disk id {}", d.id)
        }
        if d.capacity_bytes == 0 || d.weight <= 0.0 {
            bail!("disk {} must have positive capacity and weight", d.id)
        }
        if !host_ids.contains(d.host.as_str()) {
            bail!("disk {} references unknown host {}", d.id, d.host)
        }
        let host = cfg
            .topology
            .hosts
            .iter()
            .find(|h| h.name == d.host)
            .unwrap();
        if d.site != host.site || d.rack != host.rack {
            bail!(
                "disk {} must use the site and rack of its host {}",
                d.id,
                host.name
            );
        }
        *per_host.entry(d.host.as_str()).or_default() += 1;
        if !mount_paths.insert(d.path.as_str()) {
            bail!("duplicate disk mount path {}", d.path)
        }
        for n in disk_networks(cfg, d) {
            if !network_ids.contains(n.as_str()) {
                bail!("disk/host {} references unknown network {}", d.host, n)
            }
        }
    }
    for h in &cfg.topology.hosts {
        let n = *per_host.get(h.name.as_str()).unwrap_or(&0);
        if n < 6 {
            bail!(
                "host {} has {} disks; Kagi requires at least 6 disks per host",
                h.name,
                n
            )
        }
    }
    let counts = topology_domain_counts(&cfg.topology);
    if counts.racks < 2 {
        bail!("Kagi requires at least two racks to tolerate a rack outage");
    }
    for (name, p) in &cfg.policies {
        validate_protection_geometry(&p.protection).with_context(|| format!("policy {name}"))?;
        for (domain, actual, count) in [
            ("disk", p.tolerate.disks, counts.disks),
            ("host", p.tolerate.hosts, counts.hosts),
            ("rack", p.tolerate.racks, counts.racks),
            ("site", p.tolerate.sites, counts.sites),
            ("network", p.tolerate.networks, counts.networks),
        ] {
            let required = if domain == "site" && count == 2 && actual == 0 {
                0
            } else {
                minimum_tolerance_for_count(count)
            };
            let maximum = count - count.div_ceil(4);
            if actual < required {
                bail!("policy {name} requests tolerance {actual} for {domain} failures; topology requires at least {required}")
            }
            if actual > maximum {
                bail!("policy {name} requests tolerance {actual} for {domain} failures; at most {maximum} of {count} {domain} domains may be requested (75%)");
            }
        }
        if p.locality.max_fragments_per_host == 0
            || p.locality.max_fragments_per_disk == 0
            || p.chunk_replicas == 0
        {
            bail!("policy {name} fragment locality limits and chunk_replicas must be positive")
        }
        if let Some(limit) = p
            .optimize
            .as_ref()
            .and_then(|search| search.max_storage_overhead)
        {
            if !limit.is_finite() || limit < 1.0 {
                bail!("policy {name} max_storage_overhead must be a finite ratio of at least 1.0");
            }
            if !p.auto_geometry() && !p.within_overhead_limit() {
                bail!("policy {name} requires {:.4}x nominal storage, above max_storage_overhead {limit:.4}x", p.overhead());
            }
        }
        if !p.auto_geometry()
            && p.protection
                .fragments()
                .checked_mul(p.chunk_replicas)
                .is_none_or(|n| n > u32::MAX as usize)
        {
            bail!("policy {name} requires more placements than the fragment format can represent");
        }
        if p.protection.fragments() > max_placeable_fragments(cfg, p)
            && !p
                .optimize
                .as_ref()
                .map(|x| x.auto_geometry)
                .unwrap_or(false)
        {
            bail!(
                "policy {name} requires {} fragments but locality/topology can place at most {}",
                p.protection.fragments(),
                max_placeable_fragments(cfg, p)
            );
        }
    }
    Ok(())
}
/// Build the intentionally opinionated quick topology.  The four topology counts are
/// the only required inputs; every other value uses documented defaults.
fn run_quick_wizard(args: &Args) -> Result<Config> {
    println!("\nQuick-default mode: generated names, sequential 10.0.0.0/8 /24 networks, 8 TB NVMe disks, and default failure/repair rates.\n");
    let sites = prompt_usize_min("Number of sites", 6, 1)?;
    let minimum_racks = if sites == 1 { 2 } else { 1 };
    let default_racks = match sites {
        1 => 4,
        2 => 3,
        3..=5 => 2,
        _ => 1,
    };
    let racks_per_site = prompt_usize_min("Racks per site", default_racks, minimum_racks)?;
    let default_hosts = 6usize.div_ceil(sites.saturating_mul(racks_per_site));
    let hosts_per_rack = loop {
        let h = prompt_usize_min("Hosts per rack", default_hosts, 1)?;
        let total = sites.saturating_mul(racks_per_site).saturating_mul(h);
        if total >= 6 {
            break h;
        }
        eprintln!(
            "That topology has {total} servers; Kagi requires at least 6. Increase hosts per rack."
        );
    };
    let disks_per_host = prompt_usize_min("NVMe disks per host", 6, 6)?;
    let mount_root = args
        .mount_root
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(default_mount_root);
    let mut network_domains = Vec::new();
    let mut hosts = Vec::new();
    let mut disks = Vec::new();
    let mut subnet = 0usize;
    for si in 0..sites {
        let site = format!("site-{:02}", si + 1);
        for ri in 0..racks_per_site {
            let rack = format!("{}-rack-{:02}", site, ri + 1);
            let network_count = hosts_per_rack.div_ceil(254) * 2;
            let mut rack_networks = Vec::new();
            for ni in 0..network_count {
                let cidr = quick_ipv4_cidr(subnet)?;
                subnet += 1;
                let id = format!("{}-net-{:02}", rack, ni + 1);
                rack_networks.push((id.clone(), cidr.clone()));
                network_domains.push(NetworkDomain {
                    id,
                    cidr,
                    site: Some(site.clone()),
                    rack: Some(rack.clone()),
                });
            }
            for hi in 0..hosts_per_rack {
                let host = format!("{}-host-{:02}", rack, hi + 1);
                let net_idx = (hi / 254) * 2;
                let host_idx = (hi % 254) as u32;
                let mut networks = Vec::with_capacity(2);
                let mut addresses = Vec::with_capacity(2);
                for (id, cidr) in &rack_networks[net_idx..net_idx + 2] {
                    networks.push(id.clone());
                    addresses.push(nth_ipv4(cidr, host_idx).context("quick-mode IPv4 allocation")?);
                }
                hosts.push(HostTopology {
                    name: host.clone(),
                    site: Some(site.clone()),
                    rack: Some(rack.clone()),
                    networks: networks.clone(),
                    addresses,
                });
                for di in 1..=disks_per_host {
                    let mount_name = generated_mount_name(&host, "nvme", di);
                    let path = Path::new(&mount_root)
                        .join(&mount_name)
                        .to_string_lossy()
                        .into_owned();
                    disks.push(Disk {
                        id: mount_name.clone(),
                        path,
                        device_path: None,
                        capacity_bytes: 8_000_000_000_000,
                        class: "nvme".into(),
                        ordinal: di,
                        mount_name,
                        networks: networks.clone(),
                        site: Some(site.clone()),
                        rack: Some(rack.clone()),
                        host: host.clone(),
                        weight: 1.0,
                    });
                }
            }
        }
    }
    let topology = Topology {
        mount_root,
        network_domains,
        disk_classes: vec![DiskClass {
            name: "nvme".into(),
            media: "nvme".into(),
            annual_failure_probability: Some(0.01),
            default_capacity_bytes: Some(8_000_000_000_000),
            default_weight: 1.0,
        }],
        hosts,
        disks,
        placement_disks: Vec::new(),
    };
    let policy = Policy {
        protection: Protection::Clay { k: 4, m: 2, d: 5 },
        locality: Locality {
            site: Mode::Spread,
            rack: Mode::Spread,
            max_fragments_per_host: 1,
            max_fragments_per_disk: 1,
        },
        tolerate: Tolerance::default(),
        optimize: Some(default_auto_search()),
        chunk_replicas: 1,
    };
    Ok(Config {
        slot_bits: 16,
        topology,
        policies: BTreeMap::from([("default".into(), policy)]),
        failure_model: default_failure_model(),
        repair_model: default_repair_model(),
        optimization: Optimization::default(),
        example_object_sizes_bytes: default_example_object_sizes(),
    })
}
/// Full wizard for operators who need explicit failure rates, disk classes, addressing,
/// multi-homing, device identities, repair bandwidth, and policy constraints.
fn run_full_wizard(args: &Args) -> Result<Config> {
    let slot_bits = prompt_usize("64-bit keyspace slot bits (2^N slots)", 16)? as u8;
    let mount_root = if let Some(root) = &args.mount_root {
        root.to_string_lossy().into_owned()
    } else {
        prompt_line("Disk mount root", Some("/var/lib/kagi/disks"))?
    };
    let class_count = prompt_usize_min("Number of disk classes", 1, 1)?;
    let mut disk_classes = Vec::new();
    for i in 0..class_count {
        println!("\nDisk class {}", i + 1);
        let name = prompt_line("Class name", Some(if i == 0 { "nvme" } else { "class" }))?;
        let media = prompt_line(
            "Media/transport (nvme/sata_hdd/sas_hdd/fibre_channel_hdd)",
            Some("nvme"),
        )?;
        let tb = prompt_f64("Default capacity TB", 8.0)?;
        let afr = prompt_f64("Annual failure probability (0..1)", 0.01)?;
        let weight = prompt_f64("Placement weight", 1.0)?;
        disk_classes.push(DiskClass {
            name,
            media,
            annual_failure_probability: Some(afr),
            default_capacity_bytes: Some((tb * 1_000_000_000_000.0) as u64),
            default_weight: weight,
        });
    }
    let site_count = prompt_usize_min("Number of sites", 1, 1)?;
    let mut network_domains = Vec::new();
    let mut hosts = Vec::new();
    let mut disks = Vec::new();
    for si in 0..site_count {
        let site = prompt_line(
            &format!("Site {} name", si + 1),
            Some(&format!("site-{}", si + 1)),
        )?;
        let sn = prompt_usize(&format!("Network/IP ranges available at {site}"), 1)?;
        let mut site_nets = Vec::new();
        for ni in 0..sn {
            let id = prompt_line("  Network name", Some(&format!("{}-net-{}", site, ni + 1)))?;
            let cidr = prompt_line(
                "  IPv4 CIDR",
                Some(&format!("10.{}.{}.0/24", si + 1, ni + 1)),
            )?;
            network_domains.push(NetworkDomain {
                id: id.clone(),
                cidr,
                site: Some(site.clone()),
                rack: None,
            });
            site_nets.push(id);
        }
        let rack_count = prompt_usize_min(&format!("Number of racks in {site}"), 1, 1)?;
        for ri in 0..rack_count {
            let rack = prompt_line("Rack name", Some(&format!("{}-rack-{}", site, ri + 1)))?;
            let rn = prompt_usize("Rack-specific network/IP ranges", 0)?;
            let mut rack_nets = Vec::new();
            for ni in 0..rn {
                let id = prompt_line(
                    "  Rack network name",
                    Some(&format!("{}-net-{}", rack, ni + 1)),
                )?;
                let cidr = prompt_line(
                    "  IPv4 CIDR",
                    Some(&format!("172.{}.{}.0/24", si + 16, ri * 8 + ni + 1)),
                )?;
                network_domains.push(NetworkDomain {
                    id: id.clone(),
                    cidr,
                    site: Some(site.clone()),
                    rack: Some(rack.clone()),
                });
                rack_nets.push(id);
            }
            let hc = prompt_usize_min(&format!("Number of servers in {rack}"), 1, 1)?;
            let hp = prompt_line("Server naming prefix", Some(&format!("{}-host", rack)))?;
            for hi in 0..hc {
                let host = prompt_line(
                    &format!("Server {} name", hi + 1),
                    Some(&format!("{}-{:02}", hp, hi + 1)),
                )?;
                let multi = prompt_bool("Multiple IP/network paths on this server", false)?;
                let nic_count = if multi {
                    prompt_usize_min("Number of network paths", 2, 2)?
                } else {
                    1
                };
                let candidates: Vec<String> =
                    rack_nets.iter().chain(site_nets.iter()).cloned().collect();
                if candidates.is_empty() {
                    bail!("host {host} has no site or rack network available")
                }
                let mut hnets = Vec::new();
                let mut addresses = Vec::new();
                for ni in 0..nic_count {
                    let def = candidates.get(ni % candidates.len()).cloned().unwrap();
                    let net = prompt_line(&format!("  Interface {} network", ni + 1), Some(&def))?;
                    hnets.push(net.clone());
                    if let Some(nd) = network_domains.iter().find(|x| x.id == net) {
                        let auto = nth_ipv4(&nd.cidr, (hi + ni * 64) as u32)
                            .unwrap_or_else(|| "auto".into());
                        addresses.push(prompt_line("  IP address", Some(&auto))?);
                    }
                }
                hosts.push(HostTopology {
                    name: host.clone(),
                    site: Some(site.clone()),
                    rack: Some(rack.clone()),
                    networks: hnets.clone(),
                    addresses,
                });
                loop {
                    let mut counts = Vec::new();
                    let mut total = 0usize;
                    for class in &disk_classes {
                        let dc = prompt_usize(
                            &format!("Number of {} disks on {}", class.name, host),
                            if class.name == disk_classes[0].name {
                                6
                            } else {
                                0
                            },
                        )?;
                        total += dc;
                        counts.push(dc);
                    }
                    if total < 6 {
                        eprintln!("Host {host} has {total} disks; at least 6 are required. Re-enter disk counts.");
                        continue;
                    }
                    for (class, dc) in disk_classes.iter().zip(counts) {
                        for di in 1..=dc {
                            let mount_name = generated_mount_name(&host, &class.name, di);
                            let path = Path::new(&mount_root)
                                .join(&mount_name)
                                .to_string_lossy()
                                .into_owned();
                            let dev = prompt_line(
                                &format!("  Device path for {} (blank allowed)", mount_name),
                                Some(""),
                            )?;
                            let cap = class.default_capacity_bytes.unwrap_or(8_000_000_000_000);
                            disks.push(Disk {
                                id: mount_name.clone(),
                                path,
                                device_path: if dev.is_empty() { None } else { Some(dev) },
                                capacity_bytes: cap,
                                class: class.name.clone(),
                                ordinal: di,
                                mount_name,
                                networks: hnets.clone(),
                                site: Some(site.clone()),
                                rack: Some(rack.clone()),
                                host: host.clone(),
                                weight: class.default_weight,
                            });
                        }
                    }
                    break;
                }
            }
        }
    }
    if hosts.len() < 6 {
        bail!(
            "wizard produced {} servers; Kagi requires at least 6",
            hosts.len()
        )
    }
    let topology = Topology {
        mount_root,
        network_domains,
        disk_classes,
        hosts,
        disks,
        placement_disks: Vec::new(),
    };
    let minimum = topology_minimum_tolerance(&topology);
    let pc = prompt_usize_min("Number of data-protection policies", 1, 1)?;
    let mut policies = BTreeMap::new();
    for i in 0..pc {
        let name = prompt_line(
            &format!("Policy {} name", i + 1),
            Some(if i == 0 { "default" } else { "policy" }),
        )?;
        policies.insert(name.clone(), wizard_policy(&name, &minimum)?);
    }
    println!("\nFailure and repair model");
    let disk_annual_probability = prompt_f64("Fallback disk annual failure probability", 0.01)?;
    let host_annual_probability = prompt_f64("Host annual failure probability", 0.002)?;
    let rack_annual_probability = prompt_f64("Rack annual failure probability", 0.0005)?;
    let site_annual_probability = prompt_f64("Site annual failure probability", 0.0001)?;
    let network_annual_probability =
        prompt_f64("Network-domain annual failure probability", 0.001)?;
    let importance_bias = prompt_f64("Importance-sampling bias", 8.0)?;
    let ce_count = prompt_usize("Number of correlated failure-event definitions", 0)?;
    let mut correlated_events = Vec::new();
    for i in 0..ce_count {
        println!("Correlated event {}", i + 1);
        let d = prompt_line("  Domain (disk/host/rack/site/network)", Some("rack"))?
            .to_ascii_lowercase();
        let domain = match d.as_str() {
            "disk" => Domain::Disk,
            "host" => Domain::Host,
            "site" => Domain::Site,
            "network" => Domain::Network,
            _ => Domain::Rack,
        };
        correlated_events.push(CorrelatedEvent {
            probability: prompt_f64("  Annual/event probability", 0.0001)?,
            domain,
            count_min: prompt_usize_min("  Minimum domains affected", 1, 1)?,
            count_max: prompt_usize_min("  Maximum domains affected", 1, 1)?,
        });
    }
    let failure_model = FailureModel {
        disk_annual_probability,
        host_annual_probability,
        rack_annual_probability,
        site_annual_probability,
        network_annual_probability,
        correlated_events,
        importance_bias,
    };
    let repair_model = RepairModel {
        disk_mttr_hours: prompt_f64("Disk MTTR hours", 24.0)?,
        host_mttr_hours: prompt_f64("Host MTTR hours", 4.0)?,
        rack_mttr_hours: prompt_f64("Rack MTTR hours", 4.0)?,
        site_mttr_hours: prompt_f64("Site MTTR hours", 24.0)?,
        network_mttr_hours: prompt_f64("Network MTTR hours", 1.0)?,
        repair_bandwidth_bytes_per_sec: prompt_f64("Repair bandwidth bytes/sec", 1_000_000_000.0)?,
    };
    println!("\nOptimization objective weights");
    let optimization = Optimization {
        loss_weight: prompt_f64("Data-loss weight", default_loss_weight())?,
        overhead_weight: prompt_f64("Storage-overhead weight", default_overhead_weight())?,
        imbalance_weight: prompt_f64("Slot-imbalance weight", default_imbalance_weight())?,
    };
    Ok(Config {
        slot_bits,
        topology,
        policies,
        failure_model,
        repair_model,
        optimization,
        example_object_sizes_bytes: default_example_object_sizes(),
    })
}
/// Interactive entry point.  Quick mode is deliberately the first question so an
/// operator can create a useful six-node-or-larger plan without knowing every tunable.
fn run_wizard(args: &mut Args) -> Result<Config> {
    println!("Kagi topology and Monte Carlo configuration wizard\n");
    let default_mode = match args.run_mode {
        RunMode::Full => "full",
        RunMode::Quick30 => "quick30",
        RunMode::Quick60 => "quick60",
    };
    let mode = prompt_line("Simulation mode (full/quick30/quick60)", Some(default_mode))?
        .to_ascii_lowercase();
    args.run_mode = match mode.as_str() {
        "quick30" => RunMode::Quick30,
        "quick60" => RunMode::Quick60,
        _ => RunMode::Full,
    };
    apply_run_mode(args);
    if prompt_bool(
        "Use quick topology defaults (sites/racks/hosts/disks only)",
        true,
    )? {
        run_quick_wizard(args)
    } else {
        run_full_wizard(args)
    }
}

// Deterministic placement
fn hash64(parts: &[&[u8]]) -> u64 {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap())
}
type ShardPlacement = Vec<Vec<usize>>;

struct PlacementCache {
    by_owner: Vec<Option<ShardPlacement>>,
    permutations: DiskPermutations,
}

impl PlacementCache {
    fn new(cfg: &Config, policy: &Policy, salt: u64) -> Self {
        let plan = policy.plan(&cfg.topology, salt, false);
        let ranges = plan.host_ranges();
        Self {
            by_owner: ranges
                .iter()
                .map(|r| plan.locations(r.start_key).ok())
                .collect(),
            permutations: plan.permutations(),
        }
    }

    fn lookup(&self, position: u64) -> Option<TrialPlacement<'_>> {
        let position = mask_position(position);
        let owner = self.permutations.owner_index(position)?;
        Some(TrialPlacement {
            base: self.by_owner.get(owner)?.as_ref()?,
            permutations: &self.permutations,
            position,
            owner,
        })
    }
}

struct TrialPlacement<'a> {
    base: &'a ShardPlacement,
    permutations: &'a DiskPermutations,
    position: u64,
    owner: usize,
}

impl TrialPlacement<'_> {
    fn shards(&self) -> impl Iterator<Item = impl Iterator<Item = usize> + '_> + '_ {
        self.base.iter().map(|copies| {
            copies.iter().map(|&disk| {
                self.permutations
                    .disk_index_for_owner(self.position, self.owner, disk)
            })
        })
    }
}

// For one physical copy of each MDS shard, sort disks by the number of
// shards they hold and remove the most populated disks first. Replication
// becomes unreadable when every disk holding at least one whole copy is lost.
fn disk_loss_margin(protection: &Protection, cache: &PlacementCache) -> Option<usize> {
    if matches!(protection, Protection::Lrc { .. }) {
        return None;
    }
    let shards_to_lose = protection.fragments() - protection.data_fragments() + 1;
    cache
        .by_owner
        .iter()
        .map(|layout| {
            let mut counts = BTreeMap::<usize, usize>::new();
            for copies in layout.as_ref()? {
                let [disk] = copies.as_slice() else {
                    return None;
                };
                *counts.entry(*disk).or_default() += 1;
            }
            let mut counts: Vec<_> = counts.into_values().collect();
            counts.sort_unstable_by(|a, b| b.cmp(a));
            let mut lost = 0;
            counts
                .iter()
                .position(|count| {
                    lost += count;
                    lost >= shards_to_lose
                })
                .map(|index| index + 1)
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .min()
}

fn surviving_shards(placement: &TrialPlacement<'_>, failed: &[bool]) -> Vec<bool> {
    placement
        .shards()
        .map(|mut copies| copies.any(|disk| !failed[disk]))
        .collect()
}

// Snapshot Monte Carlo and rare-event sampling
/// Weight a biased Bernoulli draw by its likelihood under the configured failure model.
fn bernoulli_lr(x: bool, p: f64, q: f64) -> f64 {
    let p = p.clamp(1e-15, 1.0 - 1e-15);
    let q = q.clamp(1e-15, 1.0 - 1e-15);
    if x {
        p / q
    } else {
        (1.0 - p) / (1.0 - q)
    }
}
fn geometry_bias(cfg: &Config) -> f64 {
    cfg.failure_model.importance_bias.max(16.0)
}

fn biased(p: f64, bias: f64) -> f64 {
    (p * bias).min(0.35).max(p)
}
fn rack_id(disk: &Disk) -> Option<String> {
    let (site, rack) = disk.site.as_ref().zip(disk.rack.as_ref())?;
    Some(format!("{}:{site}{rack}", site.len()))
}

fn fail_domains<R: Rng>(
    rng: &mut R,
    cfg: &Config,
    importance: bool,
    bias_override: Option<f64>,
) -> (Vec<bool>, f64) {
    let ds = &cfg.topology.disks;
    let b = bias_override.unwrap_or(cfg.failure_model.importance_bias);
    let mut failed = vec![false; ds.len()];
    let mut fh = BTreeSet::new();
    let mut fr = BTreeSet::new();
    let mut fs = BTreeSet::new();
    let mut fnw = BTreeSet::new();
    let mut lr = 1.0;
    for s in ds
        .iter()
        .filter_map(|d| d.site.clone())
        .collect::<BTreeSet<_>>()
    {
        let p = cfg.failure_model.site_annual_probability;
        let q = if importance { biased(p, b) } else { p };
        let x = rng.gen_bool(q.clamp(0.0, 1.0));
        if importance {
            lr *= bernoulli_lr(x, p, q);
        }
        if x {
            fs.insert(s);
        }
    }
    for r in ds.iter().filter_map(rack_id).collect::<BTreeSet<_>>() {
        let p = cfg.failure_model.rack_annual_probability;
        let q = if importance { biased(p, b) } else { p };
        let x = rng.gen_bool(q.clamp(0.0, 1.0));
        if importance {
            lr *= bernoulli_lr(x, p, q);
        }
        if x {
            fr.insert(r);
        }
    }
    for h in ds.iter().map(|d| d.host.clone()).collect::<BTreeSet<_>>() {
        let p = cfg.failure_model.host_annual_probability;
        let q = if importance { biased(p, b) } else { p };
        let x = rng.gen_bool(q.clamp(0.0, 1.0));
        if importance {
            lr *= bernoulli_lr(x, p, q);
        }
        if x {
            fh.insert(h);
        }
    }
    for n in cfg
        .topology
        .network_domains
        .iter()
        .map(|n| n.id.clone())
        .collect::<BTreeSet<_>>()
    {
        let p = cfg.failure_model.network_annual_probability;
        let q = if importance { biased(p, b) } else { p };
        let x = rng.gen_bool(q.clamp(0.0, 1.0));
        if importance {
            lr *= bernoulli_lr(x, p, q);
        }
        if x {
            fnw.insert(n);
        }
    }
    for ev in &cfg.failure_model.correlated_events {
        let p = ev.probability;
        let q = if importance { biased(p, b) } else { p };
        let x = rng.gen_bool(q.clamp(0.0, 1.0));
        if importance {
            lr *= bernoulli_lr(x, p, q);
        }
        if x {
            let count = if ev.count_max > ev.count_min {
                rng.gen_range(ev.count_min..=ev.count_max)
            } else {
                ev.count_min
            };
            match ev.domain {
                Domain::Disk => {
                    for _ in 0..count {
                        failed[rng.gen_range(0..ds.len())] = true
                    }
                }
                Domain::Host => {
                    let v: Vec<_> = ds.iter().map(|d| d.host.clone()).collect();
                    for _ in 0..count {
                        fh.insert(v[rng.gen_range(0..v.len())].clone());
                    }
                }
                Domain::Rack => {
                    let v: Vec<_> = ds.iter().filter_map(rack_id).collect();
                    if !v.is_empty() {
                        for _ in 0..count {
                            fr.insert(v[rng.gen_range(0..v.len())].clone());
                        }
                    }
                }
                Domain::Site => {
                    let v: Vec<_> = ds.iter().filter_map(|d| d.site.clone()).collect();
                    if !v.is_empty() {
                        for _ in 0..count {
                            fs.insert(v[rng.gen_range(0..v.len())].clone());
                        }
                    }
                }
                Domain::Network => {
                    let v: Vec<_> = cfg
                        .topology
                        .network_domains
                        .iter()
                        .map(|x| x.id.clone())
                        .collect();
                    if !v.is_empty() {
                        for _ in 0..count {
                            fnw.insert(v[rng.gen_range(0..v.len())].clone());
                        }
                    }
                }
            }
        }
    }
    for (i, d) in ds.iter().enumerate() {
        let p = disk_failure_probability(cfg, d);
        let q = if importance { biased(p, b) } else { p };
        let x = rng.gen_bool(q.clamp(0.0, 1.0));
        if importance {
            lr *= bernoulli_lr(x, p, q);
        }
        if x || fh.contains(&d.host)
            || rack_id(d).is_some_and(|id| fr.contains(&id))
            || d.site.as_ref().map(|x| fs.contains(x)).unwrap_or(false)
            || network_unreachable(cfg, d, &fnw)
        {
            failed[i] = true;
        }
    }
    (failed, lr)
}
#[derive(Default, Clone, Serialize, Deserialize)]
struct Eval {
    trials: u64,
    losses: u64,
    weighted_loss: f64,
    weight_sum: f64,
    rare: Option<Scenario>,
}

fn evaluate(cfg: &Config, salt: u64, trials: u64, seed: u64, importance: bool) -> Eval {
    let placements: Vec<_> = cfg
        .policies
        .values()
        .map(|p| PlacementCache::new(cfg, p, salt))
        .collect();
    checkpoint::reduce(
        &("evaluate", cfg, salt, trials, seed, importance),
        trials,
        |t| {
            let _simulation_tick = SimulationTick;
            let mut rng = ChaCha20Rng::seed_from_u64(
                seed ^ salt.rotate_left(17) ^ t.wrapping_mul(0x9E3779B97F4A7C15),
            );
            let (failed, w) = fail_domains(&mut rng, cfg, importance, None);
            let key = rng.gen::<u64>();
            let mut e = Eval {
                trials: 1,
                weight_sum: w,
                ..Default::default()
            };
            for ((name, p), cache) in cfg.policies.iter().zip(&placements) {
                let Some(pl) = cache.lookup(key) else {
                    e.losses += 1;
                    e.weighted_loss += w;
                    break;
                };
                let alive = surviving_shards(&pl, &failed);
                if !p.protection.readable(&alive) {
                    e.losses += 1;
                    e.weighted_loss += w;
                    let fd = pl
                        .shards()
                        .flatten()
                        .filter(|i| failed[*i])
                        .map(|i| cfg.topology.disks[i].id.clone())
                        .collect();
                    e.rare = Some(Scenario {
                        policy: name.clone(),
                        failed_disks: fd,
                        estimated_probability: w / trials as f64,
                    });
                    break;
                }
            }
            e
        },
        Eval::default,
        |mut a, b| {
            a.trials += b.trials;
            a.losses += b.losses;
            a.weighted_loss += b.weighted_loss;
            a.weight_sum += b.weight_sum;
            if b.rare.is_some() {
                a.rare = b.rare;
            }
            a
        },
    )
}
#[cfg(feature = "cuda")]
extern "C" {
    fn kagi_mc_readability_cuda(
        alive: *const u8,
        lost: *mut u8,
        trials: u64,
        fragments: u32,
        mode: u32,
        k: u32,
        local_groups: u32,
        local_parity: u32,
        global_parity: u32,
    ) -> i32;
}
#[cfg(feature = "hip")]
extern "C" {
    fn kagi_mc_readability_hip(
        alive: *const u8,
        lost: *mut u8,
        trials: u64,
        fragments: u32,
        mode: u32,
        k: u32,
        local_groups: u32,
        local_parity: u32,
        global_parity: u32,
    ) -> i32;
}
#[cfg(feature = "opencl")]
extern "C" {
    fn kagi_mc_readability_opencl(
        alive: *const u8,
        lost: *mut u8,
        trials: u64,
        fragments: u32,
        mode: u32,
        k: u32,
        local_groups: u32,
        local_parity: u32,
        global_parity: u32,
    ) -> i32;
}

fn resolved_backend(requested: McBackend) -> McBackend {
    #[cfg(feature = "cuda")]
    if matches!(requested, McBackend::Auto | McBackend::Cuda) {
        extern "C" {
            fn keyspace_cuda_available() -> i32;
        }
        if unsafe { keyspace_cuda_available() != 0 } {
            return McBackend::Cuda;
        }
    }
    #[cfg(feature = "hip")]
    if matches!(requested, McBackend::Auto | McBackend::Hip) {
        extern "C" {
            fn kagi_hip_available() -> i32;
        }
        if unsafe { kagi_hip_available() != 0 } {
            return McBackend::Hip;
        }
    }
    #[cfg(feature = "opencl")]
    if matches!(requested, McBackend::Auto | McBackend::Opencl) {
        extern "C" {
            fn kagi_opencl_available() -> i32;
        }
        if unsafe { kagi_opencl_available() != 0 } {
            return McBackend::Opencl;
        }
    }
    let _ = requested;
    McBackend::Cpu
}

fn validate_requested_backend(requested: McBackend) -> Result<()> {
    match requested {
        McBackend::Auto | McBackend::Cpu => Ok(()),
        explicit if resolved_backend(explicit) == explicit => Ok(()),
        explicit => bail!(
            "requested Monte Carlo backend {explicit:?} is not compiled or has no available device"
        ),
    }
}

#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
fn gpu_policy_batch(
    cfg: &Config,
    p: &Policy,
    start: u64,
    end: u64,
    seed: u64,
    backend: McBackend,
    cache: &PlacementCache,
) -> Eval {
    let trials = end - start;
    let fragments = p.protection.fragments();
    if fragments == 0 || trials == 0 {
        return Eval::default();
    }
    let rows: Vec<(Vec<u8>, f64)> = (start..end)
        .into_par_iter()
        .map(|t| {
            let _simulation_tick = SimulationTick;
            let mut rng = ChaCha20Rng::seed_from_u64(seed ^ t.wrapping_mul(0x9E3779B97F4A7C15));
            let (failed, weight) = fail_domains(&mut rng, cfg, true, Some(geometry_bias(cfg)));
            let key = rng.gen::<u64>();
            let row = cache.lookup(key).map_or_else(
                || vec![0; fragments],
                |pl| {
                    surviving_shards(&pl, &failed)
                        .into_iter()
                        .map(u8::from)
                        .collect()
                },
            );
            (row, weight)
        })
        .collect();
    let mut alive = Vec::with_capacity(trials as usize * fragments);
    let mut weights = Vec::with_capacity(trials as usize);
    for (row, weight) in rows {
        alive.extend_from_slice(&row);
        weights.push(weight);
    }
    let (mode, k, lg, lp, gp) = match p.protection {
        Protection::Replication { .. } => (0, 1, 0, 0, 0),
        Protection::ReedSolomon { k, .. }
        | Protection::Msr { k, .. }
        | Protection::Clay { k, .. } => (1, k, 0, 0, 0),
        Protection::Lrc {
            k,
            local_groups,
            local_parity,
            global_parity,
        } => (2, k, local_groups, local_parity, global_parity),
    };
    let mut lost = vec![0u8; trials as usize];
    let rc = match backend {
        #[cfg(feature = "cuda")]
        McBackend::Cuda => unsafe {
            kagi_mc_readability_cuda(
                alive.as_ptr(),
                lost.as_mut_ptr(),
                trials,
                fragments as u32,
                mode,
                k as u32,
                lg as u32,
                lp as u32,
                gp as u32,
            )
        },
        #[cfg(feature = "hip")]
        McBackend::Hip => unsafe {
            kagi_mc_readability_hip(
                alive.as_ptr(),
                lost.as_mut_ptr(),
                trials,
                fragments as u32,
                mode,
                k as u32,
                lg as u32,
                lp as u32,
                gp as u32,
            )
        },
        #[cfg(feature = "opencl")]
        McBackend::Opencl => unsafe {
            kagi_mc_readability_opencl(
                alive.as_ptr(),
                lost.as_mut_ptr(),
                trials,
                fragments as u32,
                mode,
                k as u32,
                lg as u32,
                lp as u32,
                gp as u32,
            )
        },
        _ => -1,
    };
    if rc != 0 {
        eprintln!("Kagi Monte Carlo {backend:?} batch fell back to CPU (code {rc})");
        for (row, loss) in alive.chunks_exact(fragments).zip(&mut lost) {
            *loss = u8::from(
                !p.protection
                    .readable(&row.iter().map(|x| *x != 0).collect::<Vec<_>>()),
            );
        }
    }
    let losses = lost.iter().filter(|x| **x != 0).count() as u64;
    Eval {
        trials,
        losses,
        weighted_loss: lost
            .iter()
            .zip(&weights)
            .filter(|(loss, _)| **loss != 0)
            .map(|(_, w)| w)
            .sum(),
        weight_sum: weights.iter().sum(),
        rare: None,
    }
}
/// Evaluate one policy in isolation. Geometry optimization must not be contaminated
/// by another policy in the same config failing first during the same trial. CUDA mode
/// batches topology-generated survival vectors and evaluates EC readability on the GPU.
fn evaluate_policy(
    cfg: &Config,
    policy_name: &str,
    p: &Policy,
    run: SchemeSearchRun,
    cache: &PlacementCache,
) -> Eval {
    let SchemeSearchRun {
        salt,
        seed,
        trials,
        backend: _backend,
    } = run;
    #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
    if !matches!(p.protection, Protection::Lrc { .. })
        && matches!(
            resolved_backend(_backend),
            McBackend::Cuda | McBackend::Hip | McBackend::Opencl
        )
    {
        return checkpoint::batches(
            &(
                "gpu-policy-tail-v1",
                cfg,
                policy_name,
                p,
                salt,
                trials,
                seed,
            ),
            trials,
            |start, end| {
                gpu_policy_batch(cfg, p, start, end, seed, resolved_backend(_backend), cache)
            },
            Eval::default,
            |mut a, b| {
                a.trials += b.trials;
                a.losses += b.losses;
                a.weighted_loss += b.weighted_loss;
                a.weight_sum += b.weight_sum;
                a
            },
        );
    }
    checkpoint::reduce(
        &("policy-tail-v1", cfg, policy_name, p, salt, trials, seed),
        trials,
        |t| {
            let _simulation_tick = SimulationTick;
            let mut rng = ChaCha20Rng::seed_from_u64(seed ^ t.wrapping_mul(0x9E3779B97F4A7C15));
            let (failed, w) = fail_domains(&mut rng, cfg, true, Some(geometry_bias(cfg)));
            let key = rng.gen::<u64>();
            let mut e = Eval {
                trials: 1,
                weight_sum: w,
                ..Default::default()
            };
            let Some(pl) = cache.lookup(key) else {
                e.losses = 1;
                e.weighted_loss = w;
                return e;
            };
            let alive = surviving_shards(&pl, &failed);
            if !p.protection.readable(&alive) {
                e.losses = 1;
                e.weighted_loss = w;
                let fd = pl
                    .shards()
                    .flatten()
                    .filter(|i| failed[*i])
                    .map(|i| cfg.topology.disks[i].id.clone())
                    .collect();
                e.rare = Some(Scenario {
                    policy: policy_name.into(),
                    failed_disks: fd,
                    estimated_probability: w / trials.max(1) as f64,
                });
            }
            e
        },
        Eval::default,
        |mut a, b| {
            a.trials += b.trials;
            a.losses += b.losses;
            a.weighted_loss += b.weighted_loss;
            a.weight_sum += b.weight_sum;
            if b.rare.is_some() {
                a.rare = b.rare;
            }
            a
        },
    )
}

fn ci(losses: u64, trials: u64) -> (f64, f64) {
    if trials == 0 {
        return (0.0, 1.0);
    }
    // Jeffreys interval.
    let a = losses as f64 + 0.5;
    let b = (trials - losses) as f64 + 0.5;
    let beta = Beta::new(a, b).unwrap();
    (beta.inverse_cdf(0.025), beta.inverse_cdf(0.975))
}

fn estimate(e: &Eval, importance: bool) -> Estimate {
    let p = if importance {
        e.weighted_loss / e.trials.max(1) as f64
    } else {
        e.losses as f64 / e.trials.max(1) as f64
    };
    let (lo, hi) = ci(e.losses, e.trials);
    Estimate {
        durability: durability::describe(p),
        estimated_unreadable_probability: p,
        estimated_readability: 1.0 - p,
        ci95_low: lo,
        ci95_high: hi,
        losses: e.losses,
        trials: e.trials,
    }
}
fn loss_for_failure(
    cfg: &Config,
    placements: &[PlacementCache],
    key: u64,
    failed: &[bool],
) -> bool {
    for (p, cache) in cfg.policies.values().zip(placements) {
        let Some(pl) = cache.lookup(key) else {
            return true;
        };
        let alive = surviving_shards(&pl, failed);
        if !p.protection.readable(&alive) {
            return true;
        }
    }
    false
}

/// Use each round to adjust the bias toward rare failures, then report the weighted
/// estimate from the final round.
fn adaptive_importance_sampling(
    cfg: &Config,
    salt: u64,
    trials: u64,
    seed: u64,
    rounds: usize,
    elite_fraction: f64,
) -> AdaptiveEstimate {
    let placements: Vec<_> = cfg
        .policies
        .values()
        .map(|p| PlacementCache::new(cfg, p, salt))
        .collect();
    let mut bias = cfg.failure_model.importance_bias.max(1.0);
    let mut final_stats = WeightedStats::default();
    for round in 0..rounds.max(1) {
        let samples: Vec<(f64, f64, f64)> = checkpoint::reduce(
            &("adaptive", cfg, salt, trials, seed, round, bias),
            trials,
            |t| {
                let _simulation_tick = SimulationTick;
                let mut rng = ChaCha20Rng::seed_from_u64(
                    seed ^ salt.rotate_left(23)
                        ^ (round as u64).rotate_left(9)
                        ^ t.wrapping_mul(0xD1B54A32D192ED03),
                );
                let (failed, w) = fail_domains(&mut rng, cfg, true, Some(bias));
                let key = rng.gen::<u64>();
                let loss = loss_for_failure(cfg, &placements, key, &failed);
                let failed_fraction =
                    failed.iter().filter(|x| **x).count() as f64 / failed.len().max(1) as f64;
                vec![(if loss { 1.0 } else { 0.0 }, w, failed_fraction)]
            },
            Vec::new,
            |mut a, b| {
                a.extend(b);
                a
            },
        );
        let mut stats = WeightedStats::default();
        let mut severities = Vec::with_capacity(samples.len());
        for (loss, w, sev) in samples {
            stats.push(loss, w, loss > 0.0);
            severities.push((sev, loss > 0.0));
        }
        final_stats = stats;
        // Cross-entropy-style adaptation: move the proposal toward the elite tail.
        // Losses are always elite; otherwise use highest failed-device fractions.
        severities.sort_by(|a, b| b.0.total_cmp(&a.0));
        let elite_n =
            ((severities.len() as f64 * elite_fraction.clamp(0.01, 0.5)).ceil() as usize).max(1);
        let loss_rate =
            severities.iter().filter(|x| x.1).count() as f64 / severities.len().max(1) as f64;
        let elite_sev = severities[..elite_n].iter().map(|x| x.0).sum::<f64>() / elite_n as f64;
        if loss_rate < 0.02 {
            bias = (bias * (1.25 + 4.0 * elite_sev)).min(5000.0);
        } else if loss_rate > 0.25 {
            bias = (bias * 0.75).max(1.0);
        }
    }
    let (lo, hi) = final_stats.ci95();
    AdaptiveEstimate {
        durability: durability::describe(final_stats.mean()),
        estimated_unreadable_probability: final_stats.mean(),
        ci95_low: lo,
        ci95_high: hi,
        effective_sample_size: final_stats.ess(),
        final_bias: bias,
        rounds: rounds.max(1),
        trials_per_round: trials,
    }
}

// Continuous-time failure and repair simulation
fn exp_wait<R: Rng>(rng: &mut R, rate_per_year: f64) -> f64 {
    if rate_per_year <= 0.0 {
        return f64::INFINITY;
    }
    -((1.0 - rng.gen::<f64>()).max(1e-15)).ln() / rate_per_year
}

fn mttr_years(cfg: &Config, domain: &str) -> f64 {
    let h = match domain {
        "disk" => cfg.repair_model.disk_mttr_hours,
        "host" => cfg.repair_model.host_mttr_hours,
        "rack" => cfg.repair_model.rack_mttr_hours,
        "network" => cfg.repair_model.network_mttr_hours,
        _ => cfg.repair_model.site_mttr_hours,
    };
    h.max(1e-9) / (24.0 * 365.25)
}
#[derive(Clone)]
struct RepairEvent {
    at: f64,
    domain: String,
    id: String,
}

fn time_domain_simulation(
    cfg: &Config,
    salt: u64,
    trials: u64,
    horizon: f64,
    seed: u64,
) -> TimeDomainEstimate {
    let placements: Vec<_> = cfg
        .policies
        .values()
        .map(|p| PlacementCache::new(cfg, p, salt))
        .collect();
    let losses: (u64, u64) = checkpoint::reduce(
        &("time", cfg, salt, trials, horizon, seed),
        trials,
        |t| {
            let _simulation_tick = SimulationTick;
            let mut rng =
                ChaCha20Rng::seed_from_u64(seed ^ salt ^ t.wrapping_mul(0x94D049BB133111EB));
            let key = rng.gen::<u64>();
            let disks = &cfg.topology.disks;
            let hosts: Vec<String> = disks
                .iter()
                .map(|d| d.host.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let racks: Vec<String> = disks
                .iter()
                .filter_map(rack_id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let sites: Vec<String> = disks
                .iter()
                .filter_map(|d| d.site.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let networks: Vec<String> = cfg
                .topology
                .network_domains
                .iter()
                .map(|n| n.id.clone())
                .collect();
            let mut failed_disks = BTreeSet::new();
            let mut failed_hosts = BTreeSet::new();
            let mut failed_racks = BTreeSet::new();
            let mut failed_sites = BTreeSet::new();
            let mut failed_networks = BTreeSet::new();
            let mut repairs: Vec<RepairEvent> = Vec::new();
            let mut now = 0.0;
            while now < horizon {
                let disk_rates: Vec<f64> = disks
                    .iter()
                    .map(|d| -((1.0 - disk_failure_probability(cfg, d)).max(1e-15)).ln())
                    .collect();
                let rate_disk: f64 = disk_rates.iter().sum();
                let rate_host = -((1.0 - cfg.failure_model.host_annual_probability).max(1e-15))
                    .ln()
                    * hosts.len() as f64;
                let rate_rack = -((1.0 - cfg.failure_model.rack_annual_probability).max(1e-15))
                    .ln()
                    * racks.len() as f64;
                let rate_site = -((1.0 - cfg.failure_model.site_annual_probability).max(1e-15))
                    .ln()
                    * sites.len() as f64;
                let rate_network =
                    -((1.0 - cfg.failure_model.network_annual_probability).max(1e-15)).ln()
                        * networks.len() as f64;
                let total = rate_disk + rate_host + rate_rack + rate_site + rate_network;
                let next_fail = now + exp_wait(&mut rng, total);
                let next_repair = repairs.iter().map(|x| x.at).fold(f64::INFINITY, f64::min);
                if next_repair <= next_fail && next_repair <= horizon {
                    now = next_repair;
                    let mut keep = Vec::new();
                    for e in repairs.drain(..) {
                        if (e.at - now).abs() < 1e-12 {
                            match e.domain.as_str() {
                                "disk" => {
                                    failed_disks.remove(&e.id);
                                }
                                "host" => {
                                    failed_hosts.remove(&e.id);
                                }
                                "rack" => {
                                    failed_racks.remove(&e.id);
                                }
                                "network" => {
                                    failed_networks.remove(&e.id);
                                }
                                _ => {
                                    failed_sites.remove(&e.id);
                                }
                            }
                        } else {
                            keep.push(e);
                        }
                    }
                    repairs = keep;
                    continue;
                }
                if next_fail > horizon || total <= 0.0 {
                    break;
                }
                now = next_fail;
                let mut x = rng.gen::<f64>() * total;
                let (domain, id) = if x < rate_disk {
                    let mut y = rng.gen::<f64>() * rate_disk;
                    let mut idx = 0usize;
                    for (i, w) in disk_rates.iter().enumerate() {
                        if y < *w {
                            idx = i;
                            break;
                        }
                        y -= *w;
                    }
                    ("disk", disks[idx].id.clone())
                } else {
                    x -= rate_disk;
                    if x < rate_host {
                        ("host", hosts[rng.gen_range(0..hosts.len())].clone())
                    } else {
                        x -= rate_host;
                        if x < rate_rack && !racks.is_empty() {
                            ("rack", racks[rng.gen_range(0..racks.len())].clone())
                        } else {
                            x -= rate_rack;
                            if x < rate_site && !sites.is_empty() {
                                ("site", sites[rng.gen_range(0..sites.len())].clone())
                            } else if !networks.is_empty() {
                                (
                                    "network",
                                    networks[rng.gen_range(0..networks.len())].clone(),
                                )
                            } else {
                                continue;
                            }
                        }
                    }
                };
                match domain {
                    "disk" => {
                        failed_disks.insert(id.clone());
                    }
                    "host" => {
                        failed_hosts.insert(id.clone());
                    }
                    "rack" => {
                        failed_racks.insert(id.clone());
                    }
                    "network" => {
                        failed_networks.insert(id.clone());
                    }
                    _ => {
                        failed_sites.insert(id.clone());
                    }
                }
                repairs.push(RepairEvent {
                    at: now + mttr_years(cfg, domain),
                    domain: domain.into(),
                    id,
                });
                let failed: Vec<bool> = disks
                    .iter()
                    .map(|d| {
                        failed_disks.contains(&d.id)
                            || failed_hosts.contains(&d.host)
                            || rack_id(d).is_some_and(|id| failed_racks.contains(&id))
                            || d.site
                                .as_ref()
                                .map(|s| failed_sites.contains(s))
                                .unwrap_or(false)
                            || network_unreachable(cfg, d, &failed_networks)
                    })
                    .collect();
                if loss_for_failure(cfg, &placements, key, &failed) {
                    return (1u64, 1u64);
                }
            }
            (0u64, 1u64)
        },
        || (0, 0),
        |(a, b), (c, d)| (a + c, b + d),
    );
    let p = losses.0 as f64 / losses.1.max(1) as f64;
    let (lo, hi) = ci(losses.0, losses.1);
    let annual_rate = if p >= 1.0 {
        f64::INFINITY
    } else {
        -(1.0 - p).ln() / horizon.max(1e-12)
    };
    TimeDomainEstimate {
        simulated_trajectory_years: horizon * losses.1 as f64,
        trajectories: losses.1,
        data_loss_trajectories: losses.0,
        estimated_annual_data_loss_rate: annual_rate,
        durability_within_horizon: durability::describe(p),
        probability_of_loss_within_horizon: p,
        ci95_low: lo,
        ci95_high: hi,
    }
}
// ---- Deterministic tolerance validation and policy optimization -------------
fn validate_policy(cfg: &Config, policy: &Policy, salt: u64) -> Result<()> {
    policy
        .plan(&cfg.topology, salt, requires_site_acknowledgment(cfg))
        .validate_tolerance()
}

/// Return bounded automatic-search limits derived from both operator constraints and
/// what the topology can physically place.  The default 32-chunk ceiling keeps the
/// geometry search tractable; it can be raised with optimize.max_total_fragments.
fn geometry_bounds(cfg: &Config, p: &Policy) -> (usize, usize, usize, usize) {
    let search = p.optimize.as_ref();
    let feasible = max_placeable_fragments(cfg, p);
    let max_total = search
        .and_then(|s| s.max_total_fragments)
        .unwrap_or(32)
        .min(feasible)
        .min(255);
    let min_k = search
        .and_then(|s| s.min_data_fragments)
        .unwrap_or(2)
        .max(2);
    let max_k = search
        .and_then(|s| s.max_data_fragments)
        .unwrap_or(max_total.saturating_sub(1))
        .min(max_total.saturating_sub(1));
    // A single-copy shard needs parity for every lost physical domain it
    // occupies. Multi-homed paths and extra shard copies can absorb losses
    // without consuming parity, so their exact effect is checked by placement.
    let min_parity = if p.chunk_replicas == 1 {
        p.tolerate
            .disks
            .max(p.tolerate.hosts)
            .max(p.tolerate.racks)
            .max(p.tolerate.sites)
            .max(1)
    } else {
        1
    };
    (min_k, max_k, max_total, min_parity)
}

fn push_unique(out: &mut Vec<Protection>, seen: &mut BTreeSet<String>, p: Protection) {
    let k = format!("{:?}", p);
    if seen.insert(k) {
        out.push(p)
    }
}
/// Generate candidate chunk geometries for one EC family.  The search is exhaustive
/// within the configured k/m bounds for MDS-like codes and bounded by local-group
/// divisors for LRC.  Deterministic tolerance validation later rejects geometries that
/// look good probabilistically but cannot survive the requested failure-domain losses.
fn scheme_candidates(cfg: &Config, p: &Policy, schema: &str) -> Vec<Protection> {
    let (min_k, max_k, max_total, min_parity) = geometry_bounds(cfg, p);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    if p.protection.schema_name() == schema {
        push_unique(&mut out, &mut seen, p.protection.clone())
    }
    match schema {
        "replication" => {
            if let Some(search) = &p.optimize {
                for &copies in &search.replication_copies {
                    push_unique(&mut out, &mut seen, Protection::Replication { copies });
                }
            }
        }
        "reed_solomon" => {
            for k in min_k..=max_k {
                for m in min_parity..=max_total.saturating_sub(k) {
                    if k.saturating_add(m) <= max_total {
                        push_unique(&mut out, &mut seen, Protection::ReedSolomon { k, m })
                    }
                }
            }
            if let Some(s) = &p.optimize {
                for &k in &s.rs_k {
                    for &m in &s.rs_m {
                        if k >= 2 && m >= 1 && k.saturating_add(m) <= max_total {
                            push_unique(&mut out, &mut seen, Protection::ReedSolomon { k, m })
                        }
                    }
                }
            }
        }
        "lrc" => {
            for k in min_k..=max_k {
                for groups in 1..=k.min(max_total.saturating_sub(k + 1)) {
                    if groups + 1 >= min_parity {
                        push_unique(
                            &mut out,
                            &mut seen,
                            Protection::Lrc {
                                k,
                                local_groups: groups,
                                local_parity: 1,
                                global_parity: 1,
                            },
                        );
                    }
                }
            }
            if let Some(search) = &p.optimize {
                for &k in search.lrc_k.iter().filter(|&&k| k <= max_total) {
                    for &groups in search
                        .lrc_local_groups
                        .iter()
                        .filter(|&&groups| groups <= max_total)
                    {
                        if search.lrc_local_parity.contains(&1)
                            && search.lrc_global_parity.contains(&1)
                        {
                            push_unique(
                                &mut out,
                                &mut seen,
                                Protection::Lrc {
                                    k,
                                    local_groups: groups,
                                    local_parity: 1,
                                    global_parity: 1,
                                },
                            );
                        }
                    }
                }
            }
        }
        "msr" => {
            for k in min_k..=max_k {
                let d = 2 * k - 2;
                for m in min_parity.max(k.saturating_sub(1))..=max_total.saturating_sub(k) {
                    let n = k.saturating_add(m);
                    if n <= max_total && n > d {
                        push_unique(&mut out, &mut seen, Protection::Msr { k, m, d })
                    }
                }
            }
            if let Some(s) = &p.optimize {
                for &k in &s.msr_k {
                    for &m in &s.msr_m {
                        for &d in &s.msr_d {
                            if k >= 2
                                && m >= k.saturating_sub(1)
                                && d == k.saturating_mul(2).saturating_sub(2)
                                && d < k.saturating_add(m)
                                && k.saturating_add(m) <= max_total
                            {
                                push_unique(&mut out, &mut seen, Protection::Msr { k, m, d })
                            }
                        }
                    }
                }
            }
        }
        "clay" => {
            for k in min_k..=max_k {
                for m in min_parity..=max_total.saturating_sub(k) {
                    let n = k.saturating_add(m);
                    if n <= max_total && n > k {
                        push_unique(&mut out, &mut seen, Protection::Clay { k, m, d: n - 1 })
                    }
                }
            }
            if let Some(s) = &p.optimize {
                for &k in &s.clay_k {
                    for &m in &s.clay_m {
                        for &d in &s.clay_d {
                            if k >= 2
                                && m >= 1
                                && d >= k
                                && d < k.saturating_add(m)
                                && k.saturating_add(m) <= max_total
                            {
                                push_unique(&mut out, &mut seen, Protection::Clay { k, m, d })
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    out.retain(|protection| {
        if validate_protection_geometry(protection).is_err()
            || protection.fragments() > max_total
            || protection
                .fragments()
                .checked_mul(p.chunk_replicas)
                .is_none_or(|n| n > u32::MAX as usize)
        {
            return false;
        }
        let mut candidate = p.clone();
        candidate.protection = protection.clone();
        candidate.within_overhead_limit()
    });
    out
}

fn estimate_object_storage(cfg: &Config, p: &Policy) -> Result<Vec<ObjectStorageEstimate>> {
    cfg.example_object_sizes_bytes
        .iter()
        .map(|&logical_bytes| {
            let encoded_payload_bytes = p
                .protection
                .layout()
                .payload_bytes(logical_bytes, p.chunk_replicas)?;
            Ok(ObjectStorageEstimate {
                logical_bytes,
                encoded_payload_bytes,
                extra_payload_bytes: encoded_payload_bytes.saturating_sub(logical_bytes),
            })
        })
        .collect()
}
fn optimize_scheme(
    cfg: &Config,
    name: &str,
    base: &Policy,
    schema: &str,
    run: SchemeSearchRun,
) -> Result<SchemeOptimization> {
    let SchemeSearchRun {
        salt,
        seed,
        trials,
        backend,
    } = run;
    let candidates = scheme_candidates(cfg, base, schema);
    let geometry_trials = (trials / 200).clamp(250, 2_000);
    progress_operation(
        format!(
            "geometry MC policy={name} schema={schema} candidates={}",
            candidates.len()
        ),
        geometry_trials.saturating_mul(candidates.len() as u64),
    );
    let mut best = None::<(f64, f64, Policy, Option<String>, Option<usize>, u64)>;
    let mut first_invalid = None;
    for protection in candidates {
        let mut candidate = base.clone();
        candidate.protection = protection;
        progress_operation_label(format!(
            "mixed tolerance validation policy={name} {}",
            protection_summary(&candidate.protection),
        ));
        if let Err(error) = validate_policy(cfg, &candidate, salt) {
            if first_invalid.is_none() {
                first_invalid = Some((0.0, 1.0, candidate, Some(format!("{error:#}")), None, 0));
            }
            progress_step(geometry_trials);
            continue;
        }
        let cache = PlacementCache::new(cfg, &candidate, salt);
        let estimate = evaluate_policy(
            cfg,
            name,
            &candidate,
            SchemeSearchRun {
                salt,
                seed,
                trials: geometry_trials,
                backend,
            },
            &cache,
        );
        let loss = estimate.weighted_loss / estimate.trials.max(1) as f64;
        let margin = disk_loss_margin(&candidate.protection, &cache);
        let score = cfg.optimization.loss_weight * loss
            + cfg.optimization.overhead_weight * candidate.overhead();
        progress_best_schema(
            loss,
            format!(
                "loss={loss:.3e} policy={name} {} objective={score:.6e}",
                protection_summary(&candidate.protection)
            ),
        );
        let improved =
            best.as_ref()
                .is_none_or(|(best_score, best_loss, best_policy, _, best_margin, _)| {
                    loss.total_cmp(best_loss)
                        .then_with(|| match (best_margin, margin) {
                            (Some(best), Some(current)) => best.cmp(&current),
                            _ => std::cmp::Ordering::Equal,
                        })
                        .then_with(|| score.total_cmp(best_score))
                        .then_with(|| {
                            candidate
                                .protection
                                .fragments()
                                .cmp(&best_policy.protection.fragments())
                        })
                        .is_lt()
                });
        if improved {
            best = Some((score, loss, candidate, None, margin, estimate.losses));
        }
    }
    let best = best.or(first_invalid);
    let Some((score, loss, candidate, error, margin, sampled_loss_events)) = best else {
        return Ok(SchemeOptimization {
            schema: schema.into(),
            feasible: false,
            reason: Some(
                "no deployable geometry meets the placement limits and max_storage_overhead".into(),
            ),
            selected_protection: None,
            data_fragments: 0,
            parity_fragments: 0,
            total_fragments: 0,
            simulated_unreadable_probability: 1.0,
            simulation_trials: 0,
            sampled_loss_events: 0,
            loss_probability_resolved: false,
            disk_failures_to_unreadable: None,
            objective_score: 0.0,
            storage_overhead: 0.0,
            estimated_object_storage: Vec::new(),
            tolerance_validated: false,
            estimated_repair_window_hours: 0.0,
        });
    };
    let feasible = error.is_none();
    let protection = &candidate.protection;
    Ok(SchemeOptimization {
        schema: schema.into(),
        feasible,
        reason: error,
        selected_protection: Some(protection.clone()),
        data_fragments: protection.data_fragments(),
        parity_fragments: protection.parity_fragments(),
        total_fragments: protection.fragments(),
        simulated_unreadable_probability: loss,
        simulation_trials: if feasible { geometry_trials } else { 0 },
        sampled_loss_events,
        loss_probability_resolved: sampled_loss_events > 0,
        disk_failures_to_unreadable: margin,
        objective_score: score,
        storage_overhead: candidate.overhead(),
        estimated_object_storage: estimate_object_storage(cfg, &candidate)?,
        tolerance_validated: feasible,
        estimated_repair_window_hours: repair_window(cfg, &candidate),
    })
}

fn schema_preference(schema: &str) -> u8 {
    match schema {
        "clay" => 0,
        "msr" => 1,
        "lrc" => 2,
        "reed_solomon" => 3,
        _ => 4,
    }
}
fn optimize_protections(
    cfg: &mut Config,
    salt: u64,
    seed: u64,
    trials: u64,
    backend: McBackend,
) -> Result<BTreeMap<String, BTreeMap<String, SchemeOptimization>>> {
    let names: Vec<_> = cfg.policies.keys().cloned().collect();
    let mut reports = BTreeMap::new();
    for name in names {
        let base = cfg.policies[&name].clone();
        let mut per = BTreeMap::new();
        if !base.auto_geometry() {
            validate_policy(cfg, &base, salt).with_context(|| {
                format!("policy {name} cannot meet the configured mixed failure tolerance")
            })?;
        } else {
            let mut schemes = vec!["reed_solomon", "lrc", "msr", "clay"];
            if base
                .optimize
                .as_ref()
                .is_some_and(|search| !search.replication_copies.is_empty())
            {
                schemes.push("replication");
            }
            for schema in schemes {
                let report = optimize_scheme(
                    cfg,
                    &name,
                    &base,
                    schema,
                    SchemeSearchRun {
                        salt,
                        seed,
                        trials,
                        backend,
                    },
                )?;
                per.insert(schema.into(), report);
            }
            let best = per.values().filter(|r| r.feasible).min_by(|a, b| {
                a.simulated_unreadable_probability
                    .total_cmp(&b.simulated_unreadable_probability)
                    .then_with(|| {
                        match (a.disk_failures_to_unreadable, b.disk_failures_to_unreadable) {
                            (Some(a), Some(b)) => b.cmp(&a),
                            _ => std::cmp::Ordering::Equal,
                        }
                    })
                    .then_with(|| a.objective_score.total_cmp(&b.objective_score))
                    .then_with(|| a.total_fragments.cmp(&b.total_fragments))
                    .then_with(|| schema_preference(&a.schema).cmp(&schema_preference(&b.schema)))
            });
            let Some(best) = best else {
                let reasons = per
                    .iter()
                    .filter_map(|(schema, r)| {
                        r.reason
                            .as_ref()
                            .map(|reason| format!("{schema}: {reason}"))
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                bail!("policy {name} has no feasible protection for the configured mixed failure tolerance and storage overhead: {reasons}");
            };
            cfg.policies.get_mut(&name).unwrap().protection = best
                .selected_protection
                .clone()
                .expect("feasible geometry selected");
        }
        reports.insert(name, per);
    }
    Ok(reports)
}

fn repair_window(cfg: &Config, p: &Policy) -> f64 {
    let base = cfg
        .repair_model
        .disk_mttr_hours
        .max(cfg.repair_model.host_mttr_hours)
        .max(cfg.repair_model.rack_mttr_hours)
        .max(cfg.repair_model.site_mttr_hours);
    if cfg.repair_model.repair_bandwidth_bytes_per_sec <= 0.0 {
        return base;
    }
    // Approximate one-fragment rebuild using average disk capacity as a conservative upper workload unit.
    let avg = cfg
        .topology
        .disks
        .iter()
        .map(|d| d.capacity_bytes as f64)
        .sum::<f64>()
        / cfg.topology.disks.len() as f64;
    let traffic = match p.protection {
        Protection::Replication { .. } => avg,
        Protection::ReedSolomon { k, .. } => avg * k as f64,
        Protection::Lrc { k, .. } => avg * (k as f64 / 2.0).max(1.0),
        Protection::Msr { k, d, .. } | Protection::Clay { k, d, .. } => {
            avg * (d as f64 / (d - k + 1) as f64)
        }
    };
    base + traffic / cfg.repair_model.repair_bandwidth_bytes_per_sec / 3600.0
}
/// Select the placement salt with the current policy geometries.  Geometry search and
/// placement-salt search are alternated in main so chunk count is optimized against the
/// actual failure-case placement rather than against a fixed arbitrary salt.
fn select_best_salt(cfg: &Config, args: &Args) -> Result<u64> {
    progress_operation(
        format!("ordinary placement search across {} salts", args.candidates),
        args.candidates.saturating_mul(args.trials),
    );
    let mut prelim: Vec<(u64, Eval)> = (0..args.candidates)
        .into_par_iter()
        .filter_map(|c| {
            let salt = hash64(&[&args.seed.to_le_bytes(), &c.to_le_bytes()]);
            if cfg
                .policies
                .values()
                .any(|policy| validate_policy(cfg, policy, salt).is_err())
            {
                progress_tick(args.trials);
                return None;
            }
            let eval = evaluate(cfg, salt, args.trials, args.seed, false);
            let loss = eval.losses as f64 / eval.trials.max(1) as f64;
            progress_best_keyspace(
                loss,
                format!(
                    "loss={loss:.3e} salt=0x{salt:016x} {}",
                    policy_schema_summary(cfg)
                ),
            );
            Some((salt, eval))
        })
        .collect();
    prelim.sort_by(|a, b| {
        (a.1.losses as f64 / a.1.trials.max(1) as f64)
            .total_cmp(&(b.1.losses as f64 / b.1.trials.max(1) as f64))
    });
    if let Some((salt, e)) = prelim.first() {
        let loss = e.losses as f64 / e.trials.max(1) as f64;
        progress_best_keyspace(
            loss,
            format!(
                "loss={loss:.3e} salt=0x{salt:016x} {}",
                policy_schema_summary(cfg)
            ),
        );
    }
    let finals = &prelim[..args.finalists.min(prelim.len())];
    progress_operation(
        format!("rare-event finalist search across {} salts", finals.len()),
        (finals.len() as u64).saturating_mul(args.rare_trials),
    );
    let mut best = None::<(f64, u64)>;
    for (salt, _) in finals {
        let rare = evaluate(cfg, *salt, args.rare_trials, args.seed ^ 0xA5A5A5A5, true);
        let p = rare.weighted_loss / rare.trials.max(1) as f64;
        let overhead = cfg.policies.values().map(Policy::overhead).sum::<f64>();
        let obj = cfg.optimization.loss_weight * p + cfg.optimization.overhead_weight * overhead;
        progress_best_keyspace(
            p,
            format!(
                "loss={p:.3e} objective={obj:.6e} salt=0x{salt:016x} {}",
                policy_schema_summary(cfg)
            ),
        );
        if best.map(|x| obj < x.0).unwrap_or(true) {
            best = Some((obj, *salt));
        }
    }
    if let Some((_, salt)) = best {
        return Ok(salt);
    }
    bail!("no placement salt met every mixed failure budget")
}
const CHECKPOINT_PLANNER_FORMAT: u32 = 3;

#[derive(Serialize, Deserialize)]
struct SavedRun {
    version: String,
    #[serde(default)]
    planner_format: u32,
    args: Args,
    config: Config,
    admission_key: String,
}

// Program orchestration
fn main() -> Result<()> {
    let cli = Args::parse();
    let mut args = cli.clone();
    let mut store = if let Some(path) = cli.resume.as_ref().or(cli.checkpoint.as_ref()) {
        Some(checkpoint::Store::open(
            path.clone(),
            cli.resume.is_some(),
            Duration::from_secs(cli.checkpoint_seconds),
            cli.checkpoint_batch_trials,
        )?)
    } else {
        None
    };
    let (mut cfg, admission_key) = if cli.resume.is_some() {
        let saved: SavedRun = store.as_ref().unwrap().manifest()?;
        if saved.planner_format != CHECKPOINT_PLANNER_FORMAT {
            bail!(
                "checkpoint uses incompatible planner format {}; start a new configuration run",
                saved.planner_format
            );
        }
        if saved.version != env!("CARGO_PKG_VERSION") {
            bail!("checkpoint requires Kagi {}", saved.version);
        }
        args = saved.args;
        args.no_progress |= cli.no_progress;
        store.as_mut().unwrap().batch = args.checkpoint_batch_trials;
        store.as_mut().unwrap().interval = Duration::from_secs(args.checkpoint_seconds);
        eprintln!("Resuming saved Kagi configuration and trial batches");
        (saved.config, saved.admission_key)
    } else {
        if !args.wizard {
            apply_run_mode(&mut args);
        }
        let mut config = if args.wizard {
            run_wizard(&mut args)?
        } else {
            let path = args
                .config
                .as_ref()
                .context("--config is required unless --wizard or --resume is used")?;
            serde_saphyr::from_str(&fs::read_to_string(path).context("read config")?)
                .context("parse YAML")?
        };
        if !args.example_object_size_bytes.is_empty() {
            config.example_object_sizes_bytes = args.example_object_size_bytes.clone();
        }
        for policy in config.policies.values_mut() {
            if let Some(copies) = args.object_replicas {
                policy.protection = Protection::Replication { copies };
                policy.chunk_replicas = 1;
                if let Some(search) = &mut policy.optimize {
                    search.auto_geometry = false;
                }
            }
            if let Some(copies) = args.chunk_replicas {
                policy.chunk_replicas = copies;
            }
            if let Some(limit) = args.max_storage_overhead {
                policy
                    .optimize
                    .get_or_insert_with(ProtectionSearch::default)
                    .max_storage_overhead = Some(limit);
            }
        }
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        (
            config,
            base64::engine::general_purpose::STANDARD.encode(key),
        )
    };
    if args.trials == 0
        || args.rare_trials == 0
        || args.time_trials == 0
        || args.candidates == 0
        || args.finalists == 0
        || args.horizon_years <= 0.0
        || !args.horizon_years.is_finite()
    {
        bail!("trial/candidate/finalist counts and horizon_years must be positive");
    }
    normalize_topology(&mut cfg, args.mount_root.as_deref());
    validate_config(&cfg)?;
    let acknowledged_unsafe_two_site = acknowledge_site_risk(&cfg)?;
    if cli.resume.is_none() && args.wizard {
        checkpoint::atomic_write(
            &args.wizard_config_output,
            serde_saphyr::to_string(&cfg)?.as_bytes(),
        )?;
    }
    validate_requested_backend(args.mc_backend)?;
    if cli.resume.is_none() {
        let cwd = std::env::current_dir().context("resolve output directory")?;
        for path in [
            &mut args.output,
            &mut args.join_key_output,
            &mut args.wizard_config_output,
        ] {
            if path.is_relative() {
                *path = cwd.join(&*path);
            }
        }
    }
    if let Some(store) = store {
        if cli.resume.is_none() {
            store.save_manifest(&SavedRun {
                version: env!("CARGO_PKG_VERSION").into(),
                planner_format: CHECKPOINT_PLANNER_FORMAT,
                args: args.clone(),
                config: cfg.clone(),
                admission_key: admission_key.clone(),
            })?;
        }
        checkpoint::install(Arc::new(store))?;
    }
    let progress = ProgressGuard::start(
        !args.no_progress && io::stderr().is_terminal(),
        args.progress_interval_ms,
    );
    const PHASES: u64 = 8;
    progress_phase(1, PHASES, "initial mixed tolerance and geometry search");
    let preferred_salt = hash64(&[&args.seed.to_le_bytes(), &0u64.to_le_bytes()]);
    let mut salt_candidates = std::iter::once(preferred_salt)
        .chain(
            (0..args.candidates)
                .map(|i| hash64(&[&args.seed.to_le_bytes(), &i.to_le_bytes()]))
                .filter(|salt| *salt != preferred_salt),
        )
        .peekable();
    let (first_salt, first_reports) = loop {
        let salt = salt_candidates
            .next()
            .context("no placement salt candidates")?;
        let mut candidate = cfg.clone();
        match optimize_protections(
            &mut candidate,
            salt,
            args.seed,
            args.trials,
            args.mc_backend,
        ) {
            Ok(reports) => {
                cfg = candidate;
                break (salt, reports);
            }
            Err(error) if salt_candidates.peek().is_none() => return Err(error),
            Err(_) => progress_operation_label(format!(
                "placement salt {salt:#x} has no feasible geometry"
            )),
        }
    };
    progress_phase(2, PHASES, "placement search across verified salts");
    let salt = select_best_salt(&cfg, &args).unwrap_or(first_salt);
    progress_phase(3, PHASES, "erasure geometry search at selected salt");
    let scheme_reports = if salt == first_salt {
        first_reports
    } else {
        optimize_protections(&mut cfg, salt, args.seed, args.trials, args.mc_backend)?
    };
    progress_phase(4, PHASES, "final ordinary Monte Carlo");
    progress_operation("final ordinary Monte Carlo", args.trials);
    let mc = evaluate(&cfg, salt, args.trials, args.seed, false);
    progress_phase(5, PHASES, "final rare-event Monte Carlo");
    progress_operation("final importance-sampled Monte Carlo", args.rare_trials);
    let rare = evaluate(&cfg, salt, args.rare_trials, args.seed ^ 0xA5A5A5A5, true);
    progress_phase(
        6,
        PHASES,
        "deployment-plan and deterministic tolerance validation",
    );
    let objective = cfg.optimization.loss_weight * (rare.weighted_loss / rare.trials.max(1) as f64)
        + cfg.optimization.overhead_weight
            * cfg.policies.values().map(Policy::overhead).sum::<f64>();
    let disks = cfg
        .topology
        .disks
        .iter()
        .map(|d| DiskShare {
            id: d.id.clone(),
            host: d.host.clone(),
            class: d.class.clone(),
            ordinal: d.ordinal,
            mount_name: d.mount_name.clone(),
            path: d.path.clone(),
            device_path: d.device_path.clone(),
            weight: d.weight,
        })
        .collect();
    let mut host_ranges = Vec::new();
    let mut po = BTreeMap::new();
    for (name, p) in &cfg.policies {
        progress_operation(
            format!(
                "final mixed tolerance validation policy={name} {}",
                protection_summary(&p.protection)
            ),
            0,
        );
        let deployment = p.plan(&cfg.topology, salt, acknowledged_unsafe_two_site);
        deployment
            .validate_tolerance()
            .with_context(|| format!("cannot emit deployment for policy {name}"))?;
        if host_ranges.is_empty() {
            host_ranges = deployment.host_ranges();
        }
        po.insert(
            name.clone(),
            PolicyOutput {
                selected_protection: p.protection.clone(),
                fragments: p.protection.fragments(),
                storage_overhead: p.overhead(),
                estimated_object_storage: estimate_object_storage(&cfg, p)?,
                tolerance_validated: true,
                estimated_repair_window_hours: repair_window(&cfg, p),
                erasure_scheme_optimization: scheme_reports.get(name).cloned().unwrap_or_default(),
                deployment,
            },
        );
    }
    progress_phase(7, PHASES, "adaptive importance sampling");
    progress_operation(
        format!(
            "adaptive importance sampling {} rounds",
            args.ais_rounds.max(1)
        ),
        args.rare_trials
            .saturating_mul(args.ais_rounds.max(1) as u64),
    );
    let ais = adaptive_importance_sampling(
        &cfg,
        salt,
        args.rare_trials,
        args.seed ^ 0xC3C3C3C3,
        args.ais_rounds,
        args.elite_fraction,
    );
    progress_phase(8, PHASES, "continuous-time failure and repair simulation");
    progress_operation(
        format!(
            "time-domain trajectories over {:.2} years",
            args.horizon_years
        ),
        args.time_trials,
    );
    let td = time_domain_simulation(
        &cfg,
        salt,
        args.time_trials,
        args.horizon_years,
        args.seed ^ 0x5A5A5A5A,
    );
    let out = Output {
        format_version: 7,
        infrastructure: InfrastructureOutput {
            mount_root: cfg.topology.mount_root.clone(),
            network_domains: cfg.topology.network_domains.clone(),
            disk_classes: cfg.topology.disk_classes.clone(),
            hosts: cfg.topology.hosts.clone(),
        },
        keyspace: AddressSpacePlan {
            bits: KEYSPACE_BITS,
            min: "0x0000000000000000".into(),
            max: format!("0x{:016x}", mask_position(u64::MAX)),
            mapping: "equal_host_ranges".into(),
            salt,
            host_ranges,
            disks,
        },
        optimizer: {
            let (mode, confidence) = run_mode_label(args.run_mode);
            OptimizerResult {
                run_mode: mode.into(),
                confidence: confidence.into(),
                mc_backend: backend_label(args.mc_backend).into(),
                trials_per_candidate: args.trials,
                candidates: args.candidates,
                ordinary_mc: estimate(&mc, false),
                importance_sampling: estimate(&rare, true),
                adaptive_importance_sampling: ais,
                time_domain: td,
                objective_score: objective,
                rarest_observed_data_loss_scenario: rare.rare,
            }
        },
        policies: po,
        join_admission: {
            let key = base64::engine::general_purpose::STANDARD.decode(&admission_key)?;
            checkpoint::atomic_write(
                &args.join_key_output,
                format!("{admission_key}\n").as_bytes(),
            )?;
            JoinAdmission {
                algorithm: "BLAKE3(join-key-v1)".into(),
                key_hash_hex: blake3::hash(&key).to_hex().to_string(),
            }
        },
    };
    let yaml = serde_saphyr::to_string(&out)?;
    checkpoint::flush()?;
    checkpoint::atomic_write(&args.output, yaml.as_bytes())?;
    drop(progress);
    println!("{yaml}");
    Ok(())
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    /// Six hosts with six disks each is the smallest supported production topology.
    fn base_cfg() -> Config {
        let networks = vec![
            NetworkDomain {
                id: "n1".into(),
                cidr: "10.0.0.0/24".into(),
                site: Some("s1".into()),
                rack: Some("r1".into()),
            },
            NetworkDomain {
                id: "n2".into(),
                cidr: "10.0.1.0/24".into(),
                site: Some("s1".into()),
                rack: Some("r1".into()),
            },
            NetworkDomain {
                id: "n3".into(),
                cidr: "10.0.2.0/24".into(),
                site: Some("s1".into()),
                rack: Some("r1".into()),
            },
        ];
        let mut hosts = Vec::new();
        let mut disks = Vec::new();
        for hi in 1..=6 {
            let host = format!("h{hi}");
            let rack = if hi <= 3 { "r1" } else { "r2" };
            hosts.push(HostTopology {
                name: host.clone(),
                site: Some("s1".into()),
                rack: Some(rack.into()),
                networks: vec!["n1".into(), "n2".into(), "n3".into()],
                addresses: vec![
                    format!("10.0.0.{hi}"),
                    format!("10.0.1.{hi}"),
                    format!("10.0.2.{hi}"),
                ],
            });
            for di in 1..=6 {
                disks.push(Disk {
                    id: format!("{host}-sas-{di:02}"),
                    path: "".into(),
                    device_path: None,
                    capacity_bytes: 8_000_000_000_000,
                    class: "sas".into(),
                    ordinal: 0,
                    mount_name: "".into(),
                    networks: vec![],
                    site: Some("s1".into()),
                    rack: Some(rack.into()),
                    host: host.clone(),
                    weight: 1.0,
                });
            }
        }
        Config {
            slot_bits: 8,
            topology: Topology {
                mount_root: "/mnt/keyspace".into(),
                network_domains: networks,
                disk_classes: vec![DiskClass {
                    name: "sas".into(),
                    media: "sas_hdd".into(),
                    annual_failure_probability: Some(0.02),
                    default_capacity_bytes: Some(8_000_000_000_000),
                    default_weight: 1.0,
                }],
                hosts,
                disks,
                placement_disks: Vec::new(),
            },
            policies: BTreeMap::from([(
                "p".into(),
                Policy {
                    protection: Protection::ReedSolomon { k: 4, m: 2 },
                    locality: Locality {
                        site: Mode::Spread,
                        rack: Mode::Spread,
                        max_fragments_per_host: 1,
                        max_fragments_per_disk: 1,
                    },
                    tolerate: Tolerance {
                        disks: 1,
                        hosts: 1,
                        racks: 1,
                        sites: 0,
                        networks: 1,
                    },
                    optimize: Some(default_auto_search()),
                    chunk_replicas: 1,
                },
            )]),
            failure_model: FailureModel {
                disk_annual_probability: 0.01,
                host_annual_probability: 0.0,
                rack_annual_probability: 0.0,
                site_annual_probability: 0.0,
                network_annual_probability: 0.0,
                correlated_events: vec![],
                importance_bias: 8.0,
            },
            repair_model: default_repair_model(),
            optimization: Optimization::default(),
            example_object_sizes_bytes: default_example_object_sizes(),
        }
    }
    #[test]
    fn mount_name_is_deterministic() {
        assert_eq!(
            generated_mount_name("Host A", "SAS HDD", 3),
            "host-a-sas-hdd-03"
        )
    }
    #[test]
    fn cidr_allocator_returns_host_address() {
        assert_eq!(nth_ipv4("10.4.0.0/24", 0).as_deref(), Some("10.4.0.1"))
    }
    #[test]
    fn quick_cidrs_advance_serially() {
        assert_eq!(quick_ipv4_cidr(0).unwrap(), "10.0.0.0/24");
        assert_eq!(quick_ipv4_cidr(1).unwrap(), "10.0.1.0/24");
        assert_eq!(quick_ipv4_cidr(256).unwrap(), "10.1.0.0/24")
    }
    #[test]
    fn minimum_tolerance_targets_one_when_possible() {
        assert_eq!(minimum_tolerance_for_count(1), 0);
        assert_eq!(minimum_tolerance_for_count(2), 1);
        assert_eq!(minimum_tolerance_for_count(3), 1);
        assert_eq!(minimum_tolerance_for_count(99), 1)
    }
    #[test]
    fn multihoming_requires_all_paths_failed() {
        let c = base_cfg();
        let d = &c.topology.disks[0];
        assert!(!network_unreachable(
            &c,
            d,
            &BTreeSet::from(["n1".into(), "n2".into()])
        ));
        assert!(network_unreachable(
            &c,
            d,
            &BTreeSet::from(["n1".into(), "n2".into(), "n3".into()])
        ))
    }
    #[test]
    fn class_afr_overrides_global() {
        let c = base_cfg();
        assert!((disk_failure_probability(&c, &c.topology.disks[0]) - 0.02).abs() < 1e-12)
    }
    #[test]
    fn normalization_assigns_ordinals_and_mounts() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        assert_eq!(c.topology.disks[0].ordinal, 1);
        assert_eq!(c.topology.disks[1].ordinal, 2);
        assert!(c.topology.disks[0].path.ends_with("h1-sas-01"))
    }
    #[test]
    fn equal_host_ranges_cover_keyspace() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let ranges = c.policies["p"].plan(&c.topology, 42, false).host_ranges();
        assert_eq!(ranges.len(), 6);
        assert_eq!(ranges.first().unwrap().start_key, 0);
        assert_eq!(ranges.last().unwrap().end_key, (1 << 60) - 1);
        for pair in ranges.windows(2) {
            assert_eq!(pair[0].end_key + 1, pair[1].start_key);
            let width = |range: &HostRange| range.end_key - range.start_key + 1;
            assert!(width(&pair[0]).abs_diff(width(&pair[1])) <= 1);
        }
    }
    #[test]
    fn validation_rejects_duplicate_disk_ids() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        c.topology.disks[1].id = c.topology.disks[0].id.clone();
        assert!(validate_config(&c).is_err())
    }
    #[test]
    fn validation_rejects_fewer_than_six_hosts() {
        let mut c = base_cfg();
        c.topology.hosts.retain(|h| h.name != "h6");
        c.topology.disks.retain(|d| d.host != "h6");
        normalize_topology(&mut c, None);
        assert!(validate_config(&c).is_err())
    }
    #[test]
    fn validation_rejects_fewer_than_six_disks_per_host() {
        let mut c = base_cfg();
        let mut removed = false;
        c.topology.disks.retain(|d| {
            if !removed && d.host == "h1" {
                removed = true;
                false
            } else {
                true
            }
        });
        normalize_topology(&mut c, None);
        assert!(validate_config(&c).is_err())
    }
    #[test]
    fn validation_enforces_minimum_failure_tolerance() {
        let mut c = base_cfg();
        c.policies.get_mut("p").unwrap().tolerate.hosts = 0;
        normalize_topology(&mut c, None);
        assert!(validate_config(&c).is_err())
    }
    #[test]
    fn yaml_config_round_trip_preserves_topology() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let y = serde_saphyr::to_string(&c).unwrap();
        let d: Config = serde_saphyr::from_str(&y).unwrap();
        assert_eq!(d.topology.disks.len(), 36);
        assert_eq!(d.topology.network_domains.len(), 3);
    }
    #[test]
    fn planner_uses_shared_placement_and_counts_only_distinct_surviving_shards() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let p = &c.policies["p"];
        let plan = p.plan(&c.topology, 7, false);
        let cache = PlacementCache::new(&c, p, 7);
        let range = &plan.host_ranges()[1];
        for key in [range.start_key, range.start_key + 1, range.end_key] {
            let placement = cache.lookup(key).unwrap();
            assert_eq!(
                placement
                    .shards()
                    .map(Iterator::collect::<Vec<_>>)
                    .collect::<Vec<_>>(),
                plan.locations(key).unwrap()
            );
        }
        let base = vec![vec![0, 1], vec![2, 3]];
        let placement = TrialPlacement {
            base: &base,
            permutations: &cache.permutations,
            position: range.start_key,
            owner: 1,
        };
        assert_eq!(
            surviving_shards(&placement, &[true, false, true, true]),
            vec![true, false]
        );
    }
    #[test]
    fn mount_root_override_changes_generated_paths() {
        let mut c = base_cfg();
        normalize_topology(&mut c, Some(Path::new("/srv/keyspace")));
        assert!(c
            .topology
            .disks
            .iter()
            .all(|d| d.path.starts_with("/srv/keyspace/")));
    }
    #[test]
    fn validation_rejects_unknown_network() {
        let mut c = base_cfg();
        c.topology.hosts[0].networks.push("does-not-exist".into());
        normalize_topology(&mut c, None);
        assert!(validate_config(&c).is_err());
    }
    #[test]
    fn mds_schemas_survive_two_fragment_losses() {
        let alive = [false, false, true, true, true, true];
        assert!(Protection::ReedSolomon { k: 4, m: 2 }.readable(&alive));
        assert!(Protection::Msr { k: 4, m: 2, d: 5 }.readable(&alive));
        assert!(Protection::Clay { k: 4, m: 2, d: 5 }.readable(&alive));
    }
    #[test]
    fn automatic_geometry_is_bounded_by_host_locality() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let p = &c.policies["p"];
        let (_, _, max_total, _) = geometry_bounds(&c, p);
        assert_eq!(max_total, 6);
        for schema in ["reed_solomon", "lrc", "msr", "clay"] {
            assert!(scheme_candidates(&c, p, schema)
                .iter()
                .all(|x| x.fragments() <= 6));
        }
    }
    #[test]
    fn a_recoverable_disk_outage_does_not_prove_mixed_tolerance() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let mut p = c.policies["p"].clone();
        assert!(p
            .protection
            .readable(&[false, true, true, true, true, true]));
        assert!(validate_policy(&c, &p, 123).is_err());
        p.protection = Protection::Replication { copies: 6 };
        assert!(validate_policy(&c, &p, 123).is_ok());
    }

    #[test]
    fn overhead_cap_filters_geometry_and_estimate_includes_copies_and_padding() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let mut p = c.policies["p"].clone();
        p.chunk_replicas = 2;
        p.locality.max_fragments_per_host = 2;
        p.optimize.as_mut().unwrap().max_storage_overhead = Some(3.0);
        c.example_object_sizes_bytes = vec![5];
        assert_eq!(p.overhead(), 3.0);
        assert_eq!(
            estimate_object_storage(&c, &p).unwrap()[0].encoded_payload_bytes,
            24
        );
        let candidates = scheme_candidates(&c, &p, "reed_solomon");
        assert!(candidates.contains(&p.protection));
        assert!(candidates
            .iter()
            .all(|geometry| geometry.layout().nominal_overhead(2) <= 3.0));
        p.optimize.as_mut().unwrap().max_storage_overhead = Some(2.0);
        assert!(scheme_candidates(&c, &p, "reed_solomon").is_empty());
    }

    #[test]
    fn two_site_zero_tolerance_requires_explicit_acknowledgment() {
        let mut c = base_cfg();
        for host in &mut c.topology.hosts[3..] {
            host.site = Some("s2".into());
        }
        for disk in &mut c.topology.disks[18..] {
            disk.site = Some("s2".into());
        }
        normalize_topology(&mut c, None);
        assert!(validate_config(&c).is_ok());
        assert!(requires_site_acknowledgment(&c));
        let mut p = c.policies["p"].clone();
        p.protection = Protection::Replication { copies: 6 };
        assert!(p.plan(&c.topology, 7, false).validate_tolerance().is_err());
        assert!(p.plan(&c.topology, 7, true).validate_tolerance().is_ok());
    }
    #[test]
    fn invalid_msr_repair_fanin_is_rejected() {
        assert!(validate_protection_geometry(&Protection::Msr { k: 4, m: 3, d: 5 }).is_err());
    }
    #[test]
    fn progress_bar_reports_fraction_and_bounds() {
        let half = progress_bar(50, 100, 10);
        assert!(half.contains("50.00%"));
        assert_eq!(half.matches('#').count(), 5);
        let over = progress_bar(150, 100, 10);
        assert!(over.contains("100.00%"));
        assert_eq!(over.matches('#').count(), 10);
    }
    #[test]
    fn quick_modes_reduce_simulation_work() {
        let mut a = Args {
            checkpoint: None,
            resume: None,
            checkpoint_seconds: 60,
            checkpoint_batch_trials: 1024,
            config: None,
            wizard: true,
            wizard_config_output: "x".into(),
            mount_root: None,
            output: "o".into(),
            trials: 100_000,
            candidates: 256,
            seed: 1,
            rare_trials: 100_000,
            finalists: 8,
            validation_keys: 128,
            time_trials: 20_000,
            horizon_years: 10.0,
            ais_rounds: 4,
            elite_fraction: 0.1,
            join_key_output: "j".into(),
            no_progress: true,
            progress_interval_ms: 150,
            run_mode: RunMode::Quick30,
            mc_backend: McBackend::Cpu,
            max_storage_overhead: None,
            example_object_size_bytes: Vec::new(),
            chunk_replicas: None,
            object_replicas: None,
        };
        apply_run_mode(&mut a);
        assert_eq!(a.candidates, 32);
        assert!(a.trials < 100_000);
        assert!(a.time_trials < 20_000);
    }
    #[test]
    fn protection_summary_exposes_erasure_geometry() {
        let rs = protection_summary(&Protection::ReedSolomon { k: 6, m: 3 });
        assert!(rs.contains("reed_solomon"));
        assert!(rs.contains("k=6"));
        assert!(rs.contains("m=3"));
        let clay = protection_summary(&Protection::Clay { k: 8, m: 4, d: 11 });
        assert!(clay.contains("clay"));
        assert!(clay.contains("d=11"));
    }

    #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
    #[test]
    fn planner_gpu_readability_matches_reference() {
        let requested = match std::env::var("KAGI_REQUIRE_GPU_BACKEND").ok().as_deref() {
            Some("cuda") => McBackend::Cuda,
            Some("hip") => McBackend::Hip,
            Some("opencl") => McBackend::Opencl,
            Some(other) => panic!("unknown KAGI_REQUIRE_GPU_BACKEND={other}"),
            None => McBackend::Auto,
        };
        let backend = resolved_backend(requested);
        if backend == McBackend::Cpu {
            assert!(
                std::env::var_os("KAGI_REQUIRE_GPU_TESTS").is_none(),
                "planner GPU execution required but requested backend is unavailable"
            );
            eprintln!("planner GPU execution skipped: no available device");
            return;
        }

        let cases = [(
            Protection::ReedSolomon { k: 4, m: 2 },
            vec![
                vec![true, true, true, true, false, false],
                vec![true, true, true, false, false, false],
                vec![false, true, true, true, true, false],
                vec![false, false, true, true, true, true],
            ],
        )];

        for (protection, rows) in cases {
            let fragments = protection.fragments();
            let trials = rows.len() as u64;
            let alive = rows
                .iter()
                .flat_map(|row| row.iter().map(|value| u8::from(*value)))
                .collect::<Vec<_>>();
            let mut lost = vec![0u8; rows.len()];
            let (mode, k, groups, local_parity, global_parity) = match protection {
                Protection::Replication { .. } => (0, 1, 0, 0, 0),
                Protection::ReedSolomon { k, .. }
                | Protection::Msr { k, .. }
                | Protection::Clay { k, .. } => (1, k, 0, 0, 0),
                Protection::Lrc {
                    k,
                    local_groups,
                    local_parity,
                    global_parity,
                } => (2, k, local_groups, local_parity, global_parity),
            };
            let rc = match backend {
                #[cfg(feature = "cuda")]
                McBackend::Cuda => unsafe {
                    kagi_mc_readability_cuda(
                        alive.as_ptr(),
                        lost.as_mut_ptr(),
                        trials,
                        fragments as u32,
                        mode,
                        k as u32,
                        groups as u32,
                        local_parity as u32,
                        global_parity as u32,
                    )
                },
                #[cfg(feature = "hip")]
                McBackend::Hip => unsafe {
                    kagi_mc_readability_hip(
                        alive.as_ptr(),
                        lost.as_mut_ptr(),
                        trials,
                        fragments as u32,
                        mode,
                        k as u32,
                        groups as u32,
                        local_parity as u32,
                        global_parity as u32,
                    )
                },
                #[cfg(feature = "opencl")]
                McBackend::Opencl => unsafe {
                    kagi_mc_readability_opencl(
                        alive.as_ptr(),
                        lost.as_mut_ptr(),
                        trials,
                        fragments as u32,
                        mode,
                        k as u32,
                        groups as u32,
                        local_parity as u32,
                        global_parity as u32,
                    )
                },
                _ => unreachable!("resolved GPU backend must be compiled"),
            };
            assert_eq!(rc, 0, "planner {backend:?} kernel failed with code {rc}");
            let expected = rows
                .iter()
                .map(|row| u8::from(!protection.readable(row)))
                .collect::<Vec<_>>();
            assert_eq!(lost, expected, "planner {backend:?} result mismatch");
        }
    }
}
