// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi topology planner, Monte Carlo durability simulator, and deployment-plan generator.
//!
//! This binary turns a physical topology and failure model into a deterministic 64-bit
//! keyspace layout. It evaluates replication and erasure-code candidates, validates the
//! configured failure envelope, estimates rare loss events, and writes the selected disk
//! slot ranges. The interactive wizard and progress renderer live here because they are
//! part of the planning workflow rather than the runtime data path.

mod checkpoint;
mod durability;

// Link the core's native accelerator libraries for this binary's Monte Carlo FFI.
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
use kagi_object_store as _;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use blake3::Hasher;
use clap::{Parser, ValueEnum};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use statrs::distribution::{Beta, ContinuousCDF};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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
/// Supported RunMode states or operations.
enum RunMode {
    Full,
    Quick30,
    Quick60,
}
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Supported McBackend states or operations.
enum McBackend {
    Auto,
    Cpu,
    Cuda,
    Hip,
    Opencl,
}
// ---- CLI and serializable simulation input ---------------------------------
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(name = "kagi-config", version)]
struct Args {
    /// Directory for periodic atomic simulation checkpoints (contains a secret admission key).
    #[arg(long, conflicts_with = "resume")]
    checkpoint: Option<PathBuf>,
    /// Resume using the saved topology and options; no original input file is needed.
    #[arg(long, conflicts_with_all=["config","wizard","trials","candidates","seed","rare_trials","finalists","validation_keys","time_trials","horizon_years","ais_rounds","elite_fraction","run_mode","mc_backend","output","join_key_output","mount_root","checkpoint_batch_trials","checkpoint_seconds"])]
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
    /// Number of deterministic keyspace samples used for exhaustive tolerance validation.
    #[arg(long, default_value_t = 128)]
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
}
/// Implements the apply run mode step and keeps its validation and state transitions visible at the call site.
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
/// Implements the run mode label step and keeps its validation and state transitions visible at the call site.
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
/// Implements the backend label step and keeps its validation and state transitions visible at the call site.
fn backend_label(b: McBackend) -> &'static str {
    match resolved_backend(b) {
        McBackend::Cpu => "cpu-rayon",
        McBackend::Cuda => "cuda+cpu",
        McBackend::Hip => "hip+cpu",
        McBackend::Opencl => "opencl+cpu",
        McBackend::Auto => "auto",
    }
}
// ---- Interactive optimizer progress ----------------------------------------
//
// Worker threads only update atomics. A single renderer thread owns stderr,
// which prevents Rayon workers from interleaving terminal output. Progress is
// automatically disabled when stderr is not a terminal so YAML output remains
// clean when the program is redirected or used from automation.
const PROGRESS_LINES: usize = 6;
static PROGRESS: OnceLock<Arc<ProgressState>> = OnceLock::new();
/// Kagi state or configuration used by the ProgressState path.
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
/// Kagi state or configuration used by the ProgressGuard path.
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
/// Implements the progress bar step and keeps its validation and state transitions visible at the call site.
fn progress_bar(done: u64, total: u64, width: usize) -> String {
    if total == 0 {
        return format!("[{}]   --.-%", "-".repeat(width));
    }
    progress_bar_fraction(done.min(total) as f64 / total as f64, width)
}
/// Implements the progress bar fraction step and keeps its validation and state transitions visible at the call site.
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
/// Implements the format elapsed step and keeps its validation and state transitions visible at the call site.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}
/// Implements the progress phase step and keeps its validation and state transitions visible at the call site.
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
/// Implements the progress operation step and keeps its validation and state transitions visible at the call site.
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
/// Implements the progress operation label step and keeps its validation and state transitions visible at the call site.
fn progress_operation_label(operation: impl Into<String>) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        *p.operation.lock().unwrap() = operation.into();
    }
}
/// Implements the progress tick step and keeps its validation and state transitions visible at the call site.
fn progress_tick(n: u64) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        p.current.fetch_add(n, Ordering::Relaxed);
        p.simulations.fetch_add(n, Ordering::Relaxed);
    }
}
/// Implements the progress step step and keeps its validation and state transitions visible at the call site.
fn progress_step(n: u64) {
    if let Some(p) = PROGRESS.get() {
        if !p.enabled {
            return;
        }
        p.current.fetch_add(n, Ordering::Relaxed);
    }
}
/// Kagi state or configuration used by the SimulationTick path.
struct SimulationTick;
impl Drop for SimulationTick {
    fn drop(&mut self) {
        progress_tick(1);
    }
}
/// Implements the progress best keyspace step and keeps its validation and state transitions visible at the call site.
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
/// Implements the progress best schema step and keeps its validation and state transitions visible at the call site.
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
/// Kagi state or configuration used by the Config path.
struct Config {
    slot_bits: u8,
    topology: Topology,
    policies: BTreeMap<String, Policy>,
    failure_model: FailureModel,
    #[serde(default)]
    repair_model: RepairModel,
    #[serde(default)]
    optimization: Optimization,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the Topology path.
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
}
/// Implements the default mount root step and keeps its validation and state transitions visible at the call site.
fn default_mount_root() -> String {
    "/var/lib/kagi/disks".into()
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the NetworkDomain path.
struct NetworkDomain {
    id: String,
    cidr: String,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    rack: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the DiskClass path.
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
/// Kagi state or configuration used by the HostTopology path.
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
/// Kagi state or configuration used by the Disk path.
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
/// Implements the one step and keeps its validation and state transitions visible at the call site.
fn one() -> f64 {
    1.0
}
// ---- Data-protection policy model ------------------------------------------
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Policy {
    protection: Protection,
    #[serde(default)]
    locality: Locality,
    tolerate: Tolerance,
    #[serde(default)]
    optimize: Option<ProtectionSearch>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
/// Supported Protection states or operations.
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
                *k + *m
            }
            Self::Lrc {
                k,
                local_groups,
                local_parity,
                global_parity,
            } => *k + *local_groups * *local_parity + *global_parity,
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
    fn overhead(&self) -> f64 {
        match self {
            Self::Replication { copies } => *copies as f64,
            Self::ReedSolomon { k, .. }
            | Self::Lrc { k, .. }
            | Self::Msr { k, .. }
            | Self::Clay { k, .. } => self.fragments() as f64 / *k as f64,
        }
    }
    fn readable(&self, alive: &[bool]) -> bool {
        match self {
            Self::Replication { .. } => alive.iter().any(|x| *x),
            Self::ReedSolomon { k, .. } | Self::Msr { k, .. } | Self::Clay { k, .. } => {
                alive.iter().filter(|x| **x).count() >= *k
            }
            Self::Lrc {
                k,
                local_groups,
                local_parity,
                global_parity,
            } => {
                if *local_groups == 0 || !(*k).is_multiple_of(*local_groups) {
                    return false;
                }
                let per = *k / *local_groups;
                let mut deficit = 0usize;
                let mut idx = 0usize;
                for _ in 0..*local_groups {
                    let len = per + *local_parity;
                    let survivors = alive[idx..idx + len].iter().filter(|x| **x).count();
                    deficit += per.saturating_sub(survivors);
                    idx += len;
                }
                let gp = alive[idx..idx + *global_parity]
                    .iter()
                    .filter(|x| **x)
                    .count();
                deficit <= gp
            }
        }
    }
}
/// Implements the protection summary step and keeps its validation and state transitions visible at the call site.
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
/// Implements the policy schema summary step and keeps its validation and state transitions visible at the call site.
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
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// Kagi state or configuration used by the Optimization path.
struct Optimization {
    #[serde(default = "default_loss_weight")]
    loss_weight: f64,
    #[serde(default = "default_overhead_weight")]
    overhead_weight: f64,
    #[serde(default = "default_imbalance_weight")]
    imbalance_weight: f64,
}
/// Implements the default loss weight step and keeps its validation and state transitions visible at the call site.
fn default_loss_weight() -> f64 {
    1e6
}
/// Implements the default overhead weight step and keeps its validation and state transitions visible at the call site.
fn default_overhead_weight() -> f64 {
    1.0
}
/// Implements the default imbalance weight step and keeps its validation and state transitions visible at the call site.
fn default_imbalance_weight() -> f64 {
    100.0
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// Kagi state or configuration used by the RepairModel path.
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
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// Kagi state or configuration used by the Locality path.
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
/// Implements the one usize step and keeps its validation and state transitions visible at the call site.
fn one_usize() -> usize {
    1
}
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
/// Supported Mode states or operations.
enum Mode {
    Spread,
    Localize,
    Prefer,
    #[default]
    Ignore,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the Tolerance path.
struct Tolerance {
    #[serde(default)]
    disks: usize,
    #[serde(default)]
    hosts: usize,
    #[serde(default)]
    racks: usize,
    #[serde(default)]
    sites: usize,
    #[serde(default)]
    networks: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the FailureModel path.
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
/// Implements the default bias step and keeps its validation and state transitions visible at the call site.
fn default_bias() -> f64 {
    8.0
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the CorrelatedEvent path.
struct CorrelatedEvent {
    probability: f64,
    domain: Domain,
    count_min: usize,
    count_max: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Supported Domain states or operations.
enum Domain {
    Disk,
    Host,
    Rack,
    Site,
    Network,
}
// ---- Generated deployment/simulation output --------------------------------
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
/// Kagi state or configuration used by the InfrastructureOutput path.
struct InfrastructureOutput {
    mount_root: String,
    network_domains: Vec<NetworkDomain>,
    disk_classes: Vec<DiskClass>,
    hosts: Vec<HostTopology>,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the JoinAdmission path.
struct JoinAdmission {
    algorithm: String,
    key_hash_hex: String,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the AddressSpacePlan path.
struct AddressSpacePlan {
    bits: u8,
    min: String,
    max: String,
    slot_bits: u8,
    slots: u64,
    mapping: String,
    salt: u64,
    slot_assignment: Vec<SlotRange>,
    disks: Vec<DiskShare>,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the SlotRange path.
struct SlotRange {
    start_slot: u64,
    end_slot: u64,
    start_key: String,
    end_key: String,
    disk: String,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the DiskShare path.
struct DiskShare {
    id: String,
    host: String,
    class: String,
    ordinal: usize,
    mount_name: String,
    path: String,
    device_path: Option<String>,
    weight: f64,
    expected_fraction: f64,
    expected_slots: u64,
    actual_slots: u64,
    slot_ranges: Vec<DiskSlotRange>,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the DiskSlotRange path.
struct DiskSlotRange {
    start_slot: u64,
    end_slot: u64,
    start_key: String,
    end_key: String,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the OptimizerResult path.
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
    slot_imbalance: f64,
    rarest_observed_data_loss_scenario: Option<Scenario>,
}
#[derive(Debug, Clone, Serialize)]
/// Kagi state or configuration used by the Estimate path.
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
/// Kagi state or configuration used by the AdaptiveEstimate path.
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
/// Kagi state or configuration used by the TimeDomainEstimate path.
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
/// Kagi state or configuration used by the WeightedStats path.
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
/// Kagi state or configuration used by the Scenario path.
struct Scenario {
    policy: String,
    failed_disks: Vec<String>,
    estimated_probability: f64,
}
#[derive(Debug, Serialize)]
/// Kagi state or configuration used by the PolicyOutput path.
struct PolicyOutput {
    selected_protection: Protection,
    fragments: usize,
    storage_overhead: f64,
    tolerance_validated: bool,
    minimum_counterexample: Option<Counterexample>,
    estimated_repair_window_hours: f64,
    /// Best simulated chunk geometry for every supported erasure-coding family.
    erasure_scheme_optimization: BTreeMap<String, SchemeOptimization>,
}
#[derive(Debug, Clone, Serialize)]
/// Kagi state or configuration used by the SchemeOptimization path.
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
    objective_score: f64,
    storage_overhead: f64,
    tolerance_validated: bool,
    minimum_counterexample: Option<Counterexample>,
    estimated_repair_window_hours: f64,
}
#[derive(Debug, Clone, Serialize)]
/// Kagi state or configuration used by the Counterexample path.
struct Counterexample {
    key: String,
    domain: String,
    failed: Vec<String>,
}
#[derive(Debug, Clone)]
/// Kagi state or configuration used by the SchemeCandidateMetrics path.
struct SchemeCandidateMetrics {
    loss: f64,
    trials: u64,
    score: f64,
    feasible: bool,
    counterexample: Option<Counterexample>,
}
#[derive(Debug, Clone, Copy)]
/// Kagi state or configuration used by the SchemeSearchRun path.
struct SchemeSearchRun {
    salt: u64,
    seed: u64,
    trials: u64,
    validation_keys: usize,
    backend: McBackend,
}
// ---- Wizard, topology normalization, and validation -------------------------
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
    let mut ordinal = BTreeMap::<(String, String), usize>::new();
    for d in &mut cfg.topology.disks {
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
}
/// Implements the prompt line step and keeps its validation and state transitions visible at the call site.
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
/// Implements the prompt usize step and keeps its validation and state transitions visible at the call site.
fn prompt_usize(label: &str, default: usize) -> Result<usize> {
    loop {
        let s = prompt_line(label, Some(&default.to_string()))?;
        match s.parse() {
            Ok(v) => return Ok(v),
            Err(_) => eprintln!("Enter a non-negative integer."),
        }
    }
}
/// Implements the prompt usize min step and keeps its validation and state transitions visible at the call site.
fn prompt_usize_min(label: &str, default: usize, min: usize) -> Result<usize> {
    loop {
        let v = prompt_usize(label, default.max(min))?;
        if v >= min {
            return Ok(v);
        }
        eprintln!("Value must be at least {min}.")
    }
}
/// Implements the prompt f64 step and keeps its validation and state transitions visible at the call site.
fn prompt_f64(label: &str, default: f64) -> Result<f64> {
    loop {
        let s = prompt_line(label, Some(&default.to_string()))?;
        match s.parse() {
            Ok(v) => return Ok(v),
            Err(_) => eprintln!("Enter a number."),
        }
    }
}
/// Implements the prompt bool step and keeps its validation and state transitions visible at the call site.
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
/// A failure category should tolerate two simultaneous losses whenever at least three
/// independent members exist.  With two members the achievable minimum is one; with
/// one member it is zero because losing that sole domain necessarily removes all data.
fn minimum_tolerance_for_count(n: usize) -> usize {
    if n >= 3 {
        2
    } else {
        n.saturating_sub(1)
    }
}
/// Implements the topology minimum tolerance step and keeps its validation and state transitions visible at the call site.
fn topology_minimum_tolerance(t: &Topology) -> Tolerance {
    let hosts = t.hosts.len();
    let racks = t
        .hosts
        .iter()
        .filter_map(|h| h.rack.as_ref())
        .collect::<BTreeSet<_>>()
        .len();
    let sites = t
        .hosts
        .iter()
        .filter_map(|h| h.site.as_ref())
        .collect::<BTreeSet<_>>()
        .len();
    let networks = t.network_domains.len();
    Tolerance {
        disks: minimum_tolerance_for_count(t.disks.len()),
        hosts: minimum_tolerance_for_count(hosts),
        racks: minimum_tolerance_for_count(racks),
        sites: minimum_tolerance_for_count(sites),
        networks: minimum_tolerance_for_count(networks),
    }
}
/// Implements the default auto search step and keeps its validation and state transitions visible at the call site.
fn default_auto_search() -> ProtectionSearch {
    ProtectionSearch {
        auto_geometry: true,
        max_total_fragments: Some(32),
        min_data_fragments: Some(2),
        ..Default::default()
    }
}
/// Implements the default failure model step and keeps its validation and state transitions visible at the call site.
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
/// Implements the default repair model step and keeps its validation and state transitions visible at the call site.
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
/// Implements the wizard policy step and keeps its validation and state transitions visible at the call site.
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
                global_parity: prompt_usize_min("Global parity", 2, 1)?,
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
    let host_cap = per_host
        .into_values()
        .map(|dcount| {
            dcount
                .saturating_mul(p.locality.max_fragments_per_disk)
                .min(p.locality.max_fragments_per_host)
        })
        .sum::<usize>();
    disk_cap.min(host_cap)
}
/// Implements the validate protection geometry step and keeps its validation and state transitions visible at the call site.
fn validate_protection_geometry(p: &Protection) -> Result<()> {
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
                || *local_parity < 1
                || *global_parity < 1
                || !(*k).is_multiple_of(*local_groups)
            {
                bail!("lrc requires k>=2, positive parity, and local_groups dividing k")
            }
        }
        Protection::Msr { k, m, d } => {
            let want = 2 * k - 2;
            if *k < 2 || *m < k.saturating_sub(1) || *d != want || *d >= *k + *m {
                bail!("msr runtime uses product-matrix MSR and requires k>=2, m>=k-1, d=2k-2, and d<k+m")
            }
        }
        Protection::Clay { k, m, d } => {
            if *k < 2 || *m < 2 || *d < *k + 1 || *d >= *k + *m {
                bail!("clay requires k>=2, m>=2, and k+1<=d<k+m")
            }
        }
    }
    Ok(())
}
/// Validate topology/model invariants before expensive simulation begins.
fn validate_config(cfg: &Config) -> Result<()> {
    if !(8..=24).contains(&cfg.slot_bits) {
        bail!("slot_bits must be 8..=24; explicit slot output above 2^24 is intentionally refused")
    }
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
    let mut host_ids = BTreeSet::new();
    for h in &cfg.topology.hosts {
        if !host_ids.insert(h.name.as_str()) {
            bail!("duplicate host name {}", h.name)
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
    let minimum = topology_minimum_tolerance(&cfg.topology);
    for (name, p) in &cfg.policies {
        validate_protection_geometry(&p.protection).with_context(|| format!("policy {name}"))?;
        for (domain, actual, required) in [
            ("disk", p.tolerate.disks, minimum.disks),
            ("host", p.tolerate.hosts, minimum.hosts),
            ("rack", p.tolerate.racks, minimum.racks),
            ("site", p.tolerate.sites, minimum.sites),
            ("network", p.tolerate.networks, minimum.networks),
        ] {
            if actual < required {
                bail!("policy {name} requests tolerance {actual} for {domain} failures; topology requires at least {required}")
            }
        }
        if p.locality.max_fragments_per_host == 0 || p.locality.max_fragments_per_disk == 0 {
            bail!("policy {name} fragment locality limits must be positive")
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
    let sites = prompt_usize_min("Number of sites", 1, 1)?;
    let racks_per_site = prompt_usize_min("Racks per site", 1, 1)?;
    let hosts_per_rack = loop {
        let h = prompt_usize_min("Hosts per rack", 6, 1)?;
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
            let network_count = hosts_per_rack.div_ceil(254);
            let mut rack_networks = Vec::new();
            for ni in 0..network_count {
                let cidr = quick_ipv4_cidr(subnet)?;
                subnet += 1;
                let id = format!("{}-net-{:02}", rack, ni + 1);
                network_domains.push(NetworkDomain {
                    id: id.clone(),
                    cidr,
                    site: Some(site.clone()),
                    rack: Some(rack.clone()),
                });
                rack_networks.push(id);
            }
            for hi in 0..hosts_per_rack {
                let host = format!("{}-host-{:02}", rack, hi + 1);
                let net_idx = hi / 254;
                let host_idx = (hi % 254) as u32;
                let net_id = rack_networks[net_idx].clone();
                let cidr = &network_domains
                    .iter()
                    .find(|n| n.id == net_id)
                    .expect("quick network exists")
                    .cidr;
                let address = nth_ipv4(cidr, host_idx).context("quick-mode IPv4 allocation")?;
                hosts.push(HostTopology {
                    name: host.clone(),
                    site: Some(site.clone()),
                    rack: Some(rack.clone()),
                    networks: vec![net_id.clone()],
                    addresses: vec![address],
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
                        networks: vec![net_id.clone()],
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
    };
    let tolerate = topology_minimum_tolerance(&topology);
    let policy = Policy {
        protection: Protection::Clay { k: 4, m: 2, d: 5 },
        locality: Locality {
            site: Mode::Spread,
            rack: Mode::Spread,
            max_fragments_per_host: 1,
            max_fragments_per_disk: 1,
        },
        tolerate,
        optimize: Some(default_auto_search()),
    };
    Ok(Config {
        slot_bits: 16,
        topology,
        policies: BTreeMap::from([("default".into(), policy)]),
        failure_model: default_failure_model(),
        repair_model: default_repair_model(),
        optimization: Optimization::default(),
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
// ---- Deterministic placement ------------------------------------------------
fn hash64(parts: &[&[u8]]) -> u64 {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap())
}
/// Implements the u01 step and keeps its validation and state transitions visible at the call site.
fn u01(x: u64) -> f64 {
    ((x as f64) + 1.0) / ((u64::MAX as f64) + 2.0)
}
/// Implements the score step and keeps its validation and state transitions visible at the call site.
fn score(key: u64, frag: usize, salt: u64, d: &Disk) -> f64 {
    let h = hash64(&[
        &key.to_le_bytes(),
        &(frag as u64).to_le_bytes(),
        &salt.to_le_bytes(),
        d.id.as_bytes(),
    ]);
    u01(h).powf(1.0 / (d.weight * d.capacity_bytes as f64))
}
/// Implements the place step and keeps its validation and state transitions visible at the call site.
fn place(key: u64, p: &Policy, disks: &[Disk], salt: u64) -> Option<Vec<usize>> {
    let n = p.protection.fragments();
    let mut out = Vec::with_capacity(n);
    let mut hc: HashMap<&str, usize> = HashMap::new();
    let mut dc: HashMap<usize, usize> = HashMap::new();
    let mut sites = BTreeSet::new();
    let mut racks = BTreeSet::new();
    for f in 0..n {
        let mut c: Vec<_> = disks
            .iter()
            .enumerate()
            .map(|(i, d)| (i, score(key, f, salt, d)))
            .collect();
        c.sort_by(|a, b| b.1.total_cmp(&a.1));
        let chosen = c
            .into_iter()
            .find(|(i, _)| {
                let d = &disks[*i];
                if *dc.get(i).unwrap_or(&0) >= p.locality.max_fragments_per_disk {
                    return false;
                }
                if *hc.get(d.host.as_str()).unwrap_or(&0) >= p.locality.max_fragments_per_host {
                    return false;
                }
                if p.locality.site == Mode::Spread {
                    let all = disks
                        .iter()
                        .filter_map(|x| x.site.as_ref())
                        .collect::<BTreeSet<_>>()
                        .len();
                    if sites.len() < all
                        && d.site.as_ref().map(|s| sites.contains(s)).unwrap_or(false)
                    {
                        return false;
                    }
                }
                if p.locality.rack == Mode::Spread {
                    let all = disks
                        .iter()
                        .filter_map(|x| x.rack.as_ref())
                        .collect::<BTreeSet<_>>()
                        .len();
                    if racks.len() < all
                        && d.rack.as_ref().map(|r| racks.contains(r)).unwrap_or(false)
                    {
                        return false;
                    }
                }
                true
            })?
            .0;
        let d = &disks[chosen];
        *dc.entry(chosen).or_default() += 1;
        *hc.entry(d.host.as_str()).or_default() += 1;
        if let Some(s) = &d.site {
            sites.insert(s.clone());
        }
        if let Some(r) = &d.rack {
            racks.insert(r.clone());
        }
        out.push(chosen);
    }
    Some(out)
}
// ---- Snapshot Monte Carlo and rare-event sampling ---------------------------
fn bernoulli_lr(x: bool, p: f64, q: f64) -> f64 {
    let p = p.clamp(1e-15, 1.0 - 1e-15);
    let q = q.clamp(1e-15, 1.0 - 1e-15);
    if x {
        p / q
    } else {
        (1.0 - p) / (1.0 - q)
    }
}
/// Implements the biased step and keeps its validation and state transitions visible at the call site.
fn biased(p: f64, bias: f64) -> f64 {
    (p * bias).min(0.35).max(p)
}
/// Implements the fail domains step and keeps its validation and state transitions visible at the call site.
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
    for r in ds
        .iter()
        .filter_map(|d| d.rack.clone())
        .collect::<BTreeSet<_>>()
    {
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
                    let v: Vec<_> = ds.iter().filter_map(|d| d.rack.clone()).collect();
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
            || d.rack.as_ref().map(|x| fr.contains(x)).unwrap_or(false)
            || d.site.as_ref().map(|x| fs.contains(x)).unwrap_or(false)
            || network_unreachable(cfg, d, &fnw)
        {
            failed[i] = true;
        }
    }
    (failed, lr)
}
#[derive(Default, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the Eval path.
struct Eval {
    trials: u64,
    losses: u64,
    weighted_loss: f64,
    weight_sum: f64,
    rare: Option<Scenario>,
}
/// Implements the evaluate step and keeps its validation and state transitions visible at the call site.
fn evaluate(cfg: &Config, salt: u64, trials: u64, seed: u64, importance: bool) -> Eval {
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
            for (name, p) in &cfg.policies {
                let Some(pl) = place(key, p, &cfg.topology.disks, salt) else {
                    e.losses += 1;
                    e.weighted_loss += w;
                    break;
                };
                let alive: Vec<_> = pl.iter().map(|i| !failed[*i]).collect();
                if !p.protection.readable(&alive) {
                    e.losses += 1;
                    e.weighted_loss += w;
                    let fd = pl
                        .iter()
                        .filter(|i| failed[**i])
                        .map(|i| cfg.topology.disks[*i].id.clone())
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
/// Implements the resolved backend step and keeps its validation and state transitions visible at the call site.
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
/// Implements the cuda policy eval step and keeps its validation and state transitions visible at the call site.
fn gpu_policy_batch(
    cfg: &Config,
    p: &Policy,
    salt: u64,
    start: u64,
    end: u64,
    seed: u64,
    backend: McBackend,
) -> Eval {
    let trials = end - start;
    let fragments = p.protection.fragments();
    if fragments == 0 || trials == 0 {
        return Eval::default();
    }
    let rows: Vec<Vec<u8>> = (start..end)
        .into_par_iter()
        .map(|t| {
            let _simulation_tick = SimulationTick;
            let mut rng = ChaCha20Rng::seed_from_u64(
                seed ^ salt.rotate_left(17) ^ t.wrapping_mul(0x9E3779B97F4A7C15),
            );
            let (failed, _) = fail_domains(&mut rng, cfg, false, None);
            let key = rng.gen::<u64>();
            let Some(pl) = place(key, p, &cfg.topology.disks, salt) else {
                return vec![0; fragments];
            };
            pl.iter().map(|i| if failed[*i] { 0 } else { 1 }).collect()
        })
        .collect();
    let mut alive = Vec::with_capacity(trials as usize * fragments);
    for r in rows {
        alive.extend_from_slice(&r)
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
        weighted_loss: losses as f64,
        weight_sum: trials as f64,
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
    salt: u64,
    trials: u64,
    seed: u64,
    _backend: McBackend,
) -> Eval {
    #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
    if matches!(
        resolved_backend(_backend),
        McBackend::Cuda | McBackend::Hip | McBackend::Opencl
    ) {
        return checkpoint::batches(
            &("gpu-policy", cfg, policy_name, p, salt, trials, seed),
            trials,
            |start, end| {
                gpu_policy_batch(cfg, p, salt, start, end, seed, resolved_backend(_backend))
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
        &("policy", cfg, policy_name, p, salt, trials, seed),
        trials,
        |t| {
            let _simulation_tick = SimulationTick;
            let mut rng = ChaCha20Rng::seed_from_u64(
                seed ^ salt.rotate_left(17) ^ t.wrapping_mul(0x9E3779B97F4A7C15),
            );
            let (failed, w) = fail_domains(&mut rng, cfg, false, None);
            let key = rng.gen::<u64>();
            let mut e = Eval {
                trials: 1,
                weight_sum: w,
                ..Default::default()
            };
            let Some(pl) = place(key, p, &cfg.topology.disks, salt) else {
                e.losses = 1;
                e.weighted_loss = w;
                return e;
            };
            let alive: Vec<_> = pl.iter().map(|i| !failed[*i]).collect();
            if !p.protection.readable(&alive) {
                e.losses = 1;
                e.weighted_loss = w;
                let fd = pl
                    .iter()
                    .filter(|i| failed[**i])
                    .map(|i| cfg.topology.disks[*i].id.clone())
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
/// Implements the ci step and keeps its validation and state transitions visible at the call site.
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
/// Implements the estimate step and keeps its validation and state transitions visible at the call site.
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
/// Implements the loss for failure step and keeps its validation and state transitions visible at the call site.
fn loss_for_failure(cfg: &Config, salt: u64, key: u64, failed: &[bool]) -> bool {
    for p in cfg.policies.values() {
        let Some(pl) = place(key, p, &cfg.topology.disks, salt) else {
            return true;
        };
        let alive: Vec<bool> = pl.iter().map(|i| !failed[*i]).collect();
        if !p.protection.readable(&alive) {
            return true;
        }
    }
    false
}
/// Implements the adaptive importance sampling step and keeps its validation and state transitions visible at the call site.
fn adaptive_importance_sampling(
    cfg: &Config,
    salt: u64,
    trials: u64,
    seed: u64,
    rounds: usize,
    elite_fraction: f64,
) -> AdaptiveEstimate {
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
                let loss = loss_for_failure(cfg, salt, key, &failed);
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
// ---- Continuous-time failure and repair simulation --------------------------
fn exp_wait<R: Rng>(rng: &mut R, rate_per_year: f64) -> f64 {
    if rate_per_year <= 0.0 {
        return f64::INFINITY;
    }
    -((1.0 - rng.gen::<f64>()).max(1e-15)).ln() / rate_per_year
}
/// Implements the mttr years step and keeps its validation and state transitions visible at the call site.
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
/// Kagi state or configuration used by the RepairEvent path.
struct RepairEvent {
    at: f64,
    domain: String,
    id: String,
}
/// Implements the time domain simulation step and keeps its validation and state transitions visible at the call site.
fn time_domain_simulation(
    cfg: &Config,
    salt: u64,
    trials: u64,
    horizon: f64,
    seed: u64,
) -> TimeDomainEstimate {
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
                .filter_map(|d| d.rack.clone())
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
                            || d.rack
                                .as_ref()
                                .map(|r| failed_racks.contains(r))
                                .unwrap_or(false)
                            || d.site
                                .as_ref()
                                .map(|s| failed_sites.contains(s))
                                .unwrap_or(false)
                            || network_unreachable(cfg, d, &failed_networks)
                    })
                    .collect();
                if loss_for_failure(cfg, salt, key, &failed) {
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
fn combinations<T: Clone>(v: &[T], k: usize, limit: usize) -> Vec<Vec<T>> {
    fn rec<T: Clone>(
        v: &[T],
        k: usize,
        start: usize,
        cur: &mut Vec<T>,
        out: &mut Vec<Vec<T>>,
        limit: usize,
    ) {
        if out.len() >= limit {
            return;
        }
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..v.len() {
            cur.push(v[i].clone());
            rec(v, k, i + 1, cur, out, limit);
            cur.pop();
            if out.len() >= limit {
                return;
            }
        }
    }
    let mut out = vec![];
    rec(v, k, 0, &mut vec![], &mut out, limit);
    out
}
/// Implements the validate policy step and keeps its validation and state transitions visible at the call site.
fn validate_policy(
    cfg: &Config,
    p: &Policy,
    salt: u64,
    keys: usize,
) -> (bool, Option<Counterexample>) {
    let domains = [
        ("disk", p.tolerate.disks),
        ("host", p.tolerate.hosts),
        ("rack", p.tolerate.racks),
        ("site", p.tolerate.sites),
        ("network", p.tolerate.networks),
    ];
    for ki in 0..keys {
        progress_step(1);
        let key = hash64(&[b"validation", &(ki as u64).to_le_bytes()]);
        let Some(pl) = place(key, p, &cfg.topology.disks, salt) else {
            return (false, None);
        };
        for (domain, maxfail) in domains {
            if maxfail == 0 {
                continue;
            }
            let vals: Vec<String> = match domain {
                "disk" => pl
                    .iter()
                    .map(|i| cfg.topology.disks[*i].id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                "host" => pl
                    .iter()
                    .map(|i| cfg.topology.disks[*i].host.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                "rack" => pl
                    .iter()
                    .filter_map(|i| cfg.topology.disks[*i].rack.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                "site" => pl
                    .iter()
                    .filter_map(|i| cfg.topology.disks[*i].site.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                _ => pl
                    .iter()
                    .flat_map(|i| disk_networks(cfg, &cfg.topology.disks[*i]))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            };
            for n in 1..=maxfail.min(vals.len()) {
                for failed in combinations(&vals, n, 200_000) {
                    let set: BTreeSet<_> = failed.iter().cloned().collect();
                    let alive: Vec<bool> = pl
                        .iter()
                        .map(|i| {
                            let d = &cfg.topology.disks[*i];
                            if domain == "network" {
                                !network_unreachable(cfg, d, &set)
                            } else {
                                let id = match domain {
                                    "disk" => Some(d.id.as_str()),
                                    "host" => Some(d.host.as_str()),
                                    "rack" => d.rack.as_deref(),
                                    _ => d.site.as_deref(),
                                };
                                !id.map(|x| set.contains(x)).unwrap_or(false)
                            }
                        })
                        .collect();
                    if !p.protection.readable(&alive) {
                        return (
                            false,
                            Some(Counterexample {
                                key: format!("0x{key:016x}"),
                                domain: domain.into(),
                                failed,
                            }),
                        );
                    }
                }
            }
        }
    }
    (true, None)
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
        .max(3);
    let min_k = search
        .and_then(|s| s.min_data_fragments)
        .unwrap_or(2)
        .max(2)
        .min(max_total.saturating_sub(1));
    let max_k = search
        .and_then(|s| s.max_data_fragments)
        .unwrap_or(max_total.saturating_sub(1))
        .min(max_total.saturating_sub(1))
        .max(min_k);
    let min_parity = p
        .tolerate
        .disks
        .max(p.tolerate.hosts)
        .max(p.tolerate.racks)
        .max(p.tolerate.sites)
        .max(p.tolerate.networks)
        .max(1)
        .min(max_total.saturating_sub(min_k));
    (min_k, max_k, max_total, min_parity.max(1))
}
/// Implements the push unique step and keeps its validation and state transitions visible at the call site.
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
        "reed_solomon" => {
            for k in min_k..=max_k {
                for m in min_parity..=max_total.saturating_sub(k) {
                    if k + m <= max_total {
                        push_unique(&mut out, &mut seen, Protection::ReedSolomon { k, m })
                    }
                }
            }
            if let Some(s) = &p.optimize {
                for &k in &s.rs_k {
                    for &m in &s.rs_m {
                        if k >= 2 && m >= 1 && k + m <= max_total {
                            push_unique(&mut out, &mut seen, Protection::ReedSolomon { k, m })
                        }
                    }
                }
            }
        }
        "lrc" => {
            for k in min_k..=max_k {
                for groups in 1..=k.min(8) {
                    if !k.is_multiple_of(groups) {
                        continue;
                    }
                    for lp in 1..=2usize {
                        let local = groups * lp;
                        if k + local >= max_total {
                            continue;
                        }
                        for gp in 1..=max_total - k - local {
                            if local + gp < min_parity {
                                continue;
                            }
                            push_unique(
                                &mut out,
                                &mut seen,
                                Protection::Lrc {
                                    k,
                                    local_groups: groups,
                                    local_parity: lp,
                                    global_parity: gp,
                                },
                            );
                        }
                    }
                }
            }
            if let Some(s) = &p.optimize {
                for &k in &s.lrc_k {
                    for &g in &s.lrc_local_groups {
                        for &lp in &s.lrc_local_parity {
                            for &gp in &s.lrc_global_parity {
                                if g > 0
                                    && k >= 2
                                    && k.is_multiple_of(g)
                                    && k + g * lp + gp <= max_total
                                {
                                    push_unique(
                                        &mut out,
                                        &mut seen,
                                        Protection::Lrc {
                                            k,
                                            local_groups: g,
                                            local_parity: lp,
                                            global_parity: gp,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        "msr" => {
            for k in min_k..=max_k {
                let d = 2 * k - 2;
                for m in min_parity.max(k.saturating_sub(1))..=max_total.saturating_sub(k) {
                    let n = k + m;
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
                                && d == 2 * k - 2
                                && d < k + m
                                && k + m <= max_total
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
                    let n = k + m;
                    if n <= max_total && n > k {
                        push_unique(&mut out, &mut seen, Protection::Clay { k, m, d: n - 1 })
                    }
                }
            }
            if let Some(s) = &p.optimize {
                for &k in &s.clay_k {
                    for &m in &s.clay_m {
                        for &d in &s.clay_d {
                            if k >= 2 && m >= 1 && d >= k && d < k + m && k + m <= max_total {
                                push_unique(&mut out, &mut seen, Protection::Clay { k, m, d })
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    out
}
/// Implements the candidate placeable step and keeps its validation and state transitions visible at the call site.
fn candidate_placeable(cfg: &Config, p: &Policy, salt: u64) -> bool {
    (0..16u64).all(|i| {
        place(
            hash64(&[b"geometry-place", &i.to_le_bytes()]),
            p,
            &cfg.topology.disks,
            salt,
        )
        .is_some()
    })
}
/// Implements the scheme result from candidate step and keeps its validation and state transitions visible at the call site.
fn scheme_result_from_candidate(
    cfg: &Config,
    base: &Policy,
    prot: Protection,
    metrics: SchemeCandidateMetrics,
) -> SchemeOptimization {
    let mut p = base.clone();
    p.protection = prot.clone();
    SchemeOptimization {
        schema: prot.schema_name().into(),
        feasible: metrics.feasible,
        reason: if metrics.feasible {
            None
        } else {
            Some("no tested geometry in this schema satisfied the configured deterministic failure tolerance".into())
        },
        data_fragments: prot.data_fragments(),
        parity_fragments: prot.parity_fragments(),
        total_fragments: prot.fragments(),
        storage_overhead: prot.overhead(),
        selected_protection: Some(prot),
        simulated_unreadable_probability: metrics.loss,
        simulation_trials: metrics.trials,
        objective_score: metrics.score,
        tolerance_validated: metrics.feasible,
        minimum_counterexample: metrics.counterexample,
        estimated_repair_window_hours: repair_window(cfg, &p),
    }
}
/// Find the lowest simulated-loss geometry for one schema, using storage overhead as
/// the existing secondary objective.  Candidates are ranked by Monte Carlo first, then
/// checked against explicit disk/host/rack/site/network tolerance combinations.
fn optimize_scheme(
    cfg: &Config,
    name: &str,
    base: &Policy,
    schema: &str,
    run: SchemeSearchRun,
) -> SchemeOptimization {
    let SchemeSearchRun {
        salt,
        seed,
        trials,
        validation_keys,
        backend,
    } = run;
    let candidates = scheme_candidates(cfg, base, schema);
    let geometry_trials = (trials / 200).clamp(250, 2_000);
    let placeable: Vec<Protection> = candidates
        .into_iter()
        .filter(|prot| {
            let mut p = base.clone();
            p.protection = prot.clone();
            candidate_placeable(cfg, &p, salt)
        })
        .collect();
    progress_operation(
        format!(
            "geometry MC policy={name} schema={schema} candidates={}",
            placeable.len()
        ),
        geometry_trials.saturating_mul(placeable.len() as u64),
    );
    let mut ranked = Vec::<(f64, f64, Protection)>::new();
    let placeable_count = placeable.len();
    for (candidate_index, prot) in placeable.into_iter().enumerate() {
        progress_operation_label(format!(
            "geometry MC policy={name} schema={schema} candidate {}/{} {}",
            candidate_index + 1,
            placeable_count,
            protection_summary(&prot),
        ));
        let mut p = base.clone();
        p.protection = prot.clone();
        let e = evaluate_policy(
            cfg,
            name,
            &p,
            salt,
            geometry_trials,
            seed ^ hash64(&[
                name.as_bytes(),
                schema.as_bytes(),
                format!("{:?}", prot).as_bytes(),
            ]),
            backend,
        );
        let loss = e.losses as f64 / e.trials.max(1) as f64;
        let score = cfg.optimization.loss_weight * loss
            + cfg.optimization.overhead_weight * prot.overhead();
        progress_best_schema(
            loss,
            format!(
                "loss={loss:.3e} policy={name} {} objective={score:.6e}",
                protection_summary(&prot)
            ),
        );
        ranked.push((score, loss, prot));
    }
    ranked.sort_by(|a, b| {
        a.1.total_cmp(&b.1)
            .then_with(|| a.0.total_cmp(&b.0))
            .then_with(|| a.2.fragments().cmp(&b.2.fragments()))
    });
    if ranked.is_empty() {
        return SchemeOptimization {
            schema: schema.into(),
            feasible: false,
            reason: Some(
                "no chunk geometry can be placed under the current host/disk locality limits"
                    .into(),
            ),
            selected_protection: None,
            data_fragments: 0,
            parity_fragments: 0,
            total_fragments: 0,
            simulated_unreadable_probability: 1.0,
            simulation_trials: geometry_trials,
            objective_score: f64::INFINITY,
            storage_overhead: 0.0,
            tolerance_validated: false,
            minimum_counterexample: None,
            estimated_repair_window_hours: 0.0,
        };
    }
    let mut best_invalid = None;
    for (score, loss, prot) in ranked {
        let mut p = base.clone();
        p.protection = prot.clone();
        progress_operation(
            format!(
                "tolerance validation policy={name} {}",
                protection_summary(&prot)
            ),
            validation_keys as u64,
        );
        let (ok, ce) = validate_policy(cfg, &p, salt, validation_keys);
        if ok {
            return scheme_result_from_candidate(
                cfg,
                base,
                prot,
                SchemeCandidateMetrics {
                    loss,
                    trials: geometry_trials,
                    score,
                    feasible: true,
                    counterexample: None,
                },
            );
        }
        if best_invalid.is_none() {
            best_invalid = Some((score, loss, prot, ce));
        }
    }
    let (score, loss, prot, ce) = best_invalid.expect("ranked candidate exists");
    scheme_result_from_candidate(
        cfg,
        base,
        prot,
        SchemeCandidateMetrics {
            loss,
            trials: geometry_trials,
            score,
            feasible: false,
            counterexample: ce,
        },
    )
}
/// Implements the schema preference step and keeps its validation and state transitions visible at the call site.
fn schema_preference(schema: &str) -> u8 {
    match schema {
        "clay" => 0,
        "msr" => 1,
        "lrc" => 2,
        "reed_solomon" => 3,
        _ => 4,
    }
}
/// Compare all supported EC families for every policy.  When auto_geometry is enabled,
/// the policy itself is updated to the feasible geometry with the lowest objective.
fn optimize_protections(
    cfg: &mut Config,
    salt: u64,
    seed: u64,
    trials: u64,
    validation_keys: usize,
    backend: McBackend,
) -> BTreeMap<String, BTreeMap<String, SchemeOptimization>> {
    let names: Vec<_> = cfg.policies.keys().cloned().collect();
    let mut reports = BTreeMap::new();
    for name in names {
        let base = cfg.policies[&name].clone();
        let mut per = BTreeMap::new();
        for schema in ["reed_solomon", "lrc", "msr", "clay"] {
            let r = optimize_scheme(
                cfg,
                &name,
                &base,
                schema,
                SchemeSearchRun {
                    salt,
                    seed,
                    trials,
                    validation_keys,
                    backend,
                },
            );
            per.insert(schema.into(), r);
        }
        if base
            .optimize
            .as_ref()
            .map(|s| s.auto_geometry)
            .unwrap_or(false)
        {
            if let Some(best) = per.values().filter(|r| r.feasible).min_by(|a, b| {
                a.simulated_unreadable_probability
                    .total_cmp(&b.simulated_unreadable_probability)
                    .then_with(|| a.objective_score.total_cmp(&b.objective_score))
                    .then_with(|| a.total_fragments.cmp(&b.total_fragments))
                    .then_with(|| schema_preference(&a.schema).cmp(&schema_preference(&b.schema)))
            }) {
                if let Some(prot) = &best.selected_protection {
                    cfg.policies.get_mut(&name).unwrap().protection = prot.clone();
                }
            }
        }
        reports.insert(name, per);
    }
    reports
}
// ---- Explicit slot/key-range deployment plan -------------------------------
fn slot_key_bounds(slot_bits: u8, start: u64, end: u64) -> (String, String) {
    let shift = 64 - slot_bits as u32;
    let sk = start << shift;
    let ek = if end == (1u64 << slot_bits) - 1 {
        u64::MAX
    } else {
        ((end + 1) << shift) - 1
    };
    (format!("0x{sk:016x}"), format!("0x{ek:016x}"))
}
/// Implements the slot range step and keeps its validation and state transitions visible at the call site.
fn slot_range(cfg: &Config, start: u64, end: u64, disk: &str) -> SlotRange {
    let (start_key, end_key) = slot_key_bounds(cfg.slot_bits, start, end);
    SlotRange {
        start_slot: start,
        end_slot: end,
        start_key,
        end_key,
        disk: disk.into(),
    }
}
/// Implements the slot map step and keeps its validation and state transitions visible at the call site.
fn slot_map(cfg: &Config, salt: u64) -> (Vec<SlotRange>, Vec<u64>, f64) {
    let slots = 1u64 << cfg.slot_bits;
    let mut owners = Vec::with_capacity(slots as usize);
    let mut counts = vec![0u64; cfg.topology.disks.len()];
    for s in 0..slots {
        let key = s << (64 - cfg.slot_bits);
        let (i, _) = cfg
            .topology
            .disks
            .iter()
            .enumerate()
            .map(|(i, d)| (i, score(key, 0, salt, d)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .unwrap();
        owners.push(i);
        counts[i] += 1;
    }
    let mut ranges = vec![];
    if !owners.is_empty() {
        let mut st = 0u64;
        let mut cur = owners[0];
        for (i, &owner) in owners.iter().enumerate().skip(1) {
            if owner != cur {
                ranges.push(slot_range(
                    cfg,
                    st,
                    i as u64 - 1,
                    &cfg.topology.disks[cur].id,
                ));
                st = i as u64;
                cur = owner;
            }
        }
        ranges.push(slot_range(
            cfg,
            st,
            owners.len() as u64 - 1,
            &cfg.topology.disks[cur].id,
        ));
    }
    let tw: f64 = cfg
        .topology
        .disks
        .iter()
        .map(|d| d.weight * d.capacity_bytes as f64)
        .sum();
    let imbalance = counts
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let target =
                (cfg.topology.disks[i].weight * cfg.topology.disks[i].capacity_bytes as f64) / tw;
            ((*c as f64 / slots as f64) - target).abs()
        })
        .fold(0.0, f64::max);
    (ranges, counts, imbalance)
}
/// Implements the repair window step and keeps its validation and state transitions visible at the call site.
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
        .map(|c| {
            let salt = hash64(&[&args.seed.to_le_bytes(), &c.to_le_bytes()]);
            let eval = evaluate(cfg, salt, args.trials, args.seed, false);
            let loss = eval.losses as f64 / eval.trials.max(1) as f64;
            progress_best_keyspace(
                loss,
                format!(
                    "loss={loss:.3e} salt=0x{salt:016x} {}",
                    policy_schema_summary(cfg)
                ),
            );
            (salt, eval)
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
        let (_, _, imb) = slot_map(cfg, *salt);
        let p = rare.weighted_loss / rare.trials.max(1) as f64;
        let overhead = cfg
            .policies
            .values()
            .map(|x| x.protection.overhead())
            .sum::<f64>();
        let obj = cfg.optimization.loss_weight * p
            + cfg.optimization.overhead_weight * overhead
            + cfg.optimization.imbalance_weight * imb;
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
    best.map(|x| x.1).context("no optimizer candidates")
}
#[derive(Serialize, Deserialize)]
struct SavedRun {
    version: String,
    args: Args,
    config: Config,
    admission_key: String,
}
// ---- Program orchestration --------------------------------------------------
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
            let config = run_wizard(&mut args)?;
            checkpoint::atomic_write(
                &args.wizard_config_output,
                serde_yaml::to_string(&config)?.as_bytes(),
            )?;
            config
        } else {
            let path = args
                .config
                .as_ref()
                .context("--config is required unless --wizard or --resume is used")?;
            serde_yaml::from_str(&fs::read_to_string(path).context("read config")?)
                .context("parse YAML")?
        };
        normalize_topology(&mut config, args.mount_root.as_deref());
        validate_config(&config)?;
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
    {
        bail!("trial/candidate/finalist counts must be positive");
    }
    validate_config(&cfg)?;
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
    const PHASES: u64 = 9;
    // Alternate placement-salt and chunk-geometry optimization. Two geometry passes
    // make the selected k/m/group/d values respond to their eventual placement.
    progress_phase(1, PHASES, "placement search pass 1");
    let first_salt = select_best_salt(&cfg, &args)?;
    progress_phase(2, PHASES, "erasure geometry search pass 1");
    let _ = optimize_protections(
        &mut cfg,
        first_salt,
        args.seed,
        args.trials,
        args.validation_keys,
        args.mc_backend,
    );
    progress_phase(3, PHASES, "placement search pass 2");
    let salt = select_best_salt(&cfg, &args)?;
    progress_phase(4, PHASES, "erasure geometry search pass 2");
    let scheme_reports = optimize_protections(
        &mut cfg,
        salt,
        args.seed ^ 0x31415926,
        args.trials,
        args.validation_keys,
        args.mc_backend,
    );
    progress_phase(5, PHASES, "final ordinary Monte Carlo");
    progress_operation("final ordinary Monte Carlo", args.trials);
    let mc = evaluate(&cfg, salt, args.trials, args.seed, false);
    progress_phase(6, PHASES, "final rare-event Monte Carlo");
    progress_operation("final importance-sampled Monte Carlo", args.rare_trials);
    let rare = evaluate(&cfg, salt, args.rare_trials, args.seed ^ 0xA5A5A5A5, true);
    progress_phase(
        7,
        PHASES,
        "deployment-plan and deterministic tolerance validation",
    );
    progress_operation("building explicit keyspace slot map", 0);
    let (ranges, counts, imbalance) = slot_map(&cfg, salt);
    let objective = cfg.optimization.loss_weight * (rare.weighted_loss / rare.trials.max(1) as f64)
        + cfg.optimization.overhead_weight
            * cfg
                .policies
                .values()
                .map(|x| x.protection.overhead())
                .sum::<f64>()
        + cfg.optimization.imbalance_weight * imbalance;
    let slots = 1u64 << cfg.slot_bits;
    let tw: f64 = cfg
        .topology
        .disks
        .iter()
        .map(|d| d.weight * d.capacity_bytes as f64)
        .sum();
    let disks = cfg
        .topology
        .disks
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let w = d.weight * d.capacity_bytes as f64;
            let f = w / tw;
            let dr = ranges
                .iter()
                .filter(|r| r.disk == d.id)
                .map(|r| DiskSlotRange {
                    start_slot: r.start_slot,
                    end_slot: r.end_slot,
                    start_key: r.start_key.clone(),
                    end_key: r.end_key.clone(),
                })
                .collect();
            DiskShare {
                id: d.id.clone(),
                host: d.host.clone(),
                class: d.class.clone(),
                ordinal: d.ordinal,
                mount_name: d.mount_name.clone(),
                path: d.path.clone(),
                device_path: d.device_path.clone(),
                weight: w,
                expected_fraction: f,
                expected_slots: (f * slots as f64).round() as u64,
                actual_slots: counts[i],
                slot_ranges: dr,
            }
        })
        .collect();
    let mut po = BTreeMap::new();
    for (name, p) in &cfg.policies {
        progress_operation(
            format!(
                "final tolerance validation policy={name} {}",
                protection_summary(&p.protection)
            ),
            args.validation_keys as u64,
        );
        let (ok, ce) = validate_policy(&cfg, p, salt, args.validation_keys);
        po.insert(
            name.clone(),
            PolicyOutput {
                selected_protection: p.protection.clone(),
                fragments: p.protection.fragments(),
                storage_overhead: p.protection.overhead(),
                tolerance_validated: ok,
                minimum_counterexample: ce,
                estimated_repair_window_hours: repair_window(&cfg, p),
                erasure_scheme_optimization: scheme_reports.get(name).cloned().unwrap_or_default(),
            },
        );
    }
    progress_phase(8, PHASES, "adaptive importance sampling");
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
    progress_phase(9, PHASES, "continuous-time failure and repair simulation");
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
        format_version: 6,
        infrastructure: InfrastructureOutput {
            mount_root: cfg.topology.mount_root.clone(),
            network_domains: cfg.topology.network_domains.clone(),
            disk_classes: cfg.topology.disk_classes.clone(),
            hosts: cfg.topology.hosts.clone(),
        },
        keyspace: AddressSpacePlan {
            bits: 64,
            min: "0x0000000000000000".into(),
            max: "0xffffffffffffffff".into(),
            slot_bits: cfg.slot_bits,
            slots,
            mapping: "capacity_weighted_rendezvous_with_explicit_slot_map".into(),
            salt,
            slot_assignment: ranges,
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
                slot_imbalance: imbalance,
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
    let yaml = serde_yaml::to_string(&out)?;
    checkpoint::flush()?;
    checkpoint::atomic_write(&args.output, yaml.as_bytes())?;
    drop(progress);
    println!("{yaml}");
    Ok(())
}
// ---- Unit tests -------------------------------------------------------------
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
            hosts.push(HostTopology {
                name: host.clone(),
                site: Some("s1".into()),
                rack: Some("r1".into()),
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
                    rack: Some("r1".into()),
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
                        disks: 2,
                        hosts: 2,
                        racks: 0,
                        sites: 0,
                        networks: 2,
                    },
                    optimize: Some(default_auto_search()),
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
    fn minimum_tolerance_targets_two_when_possible() {
        assert_eq!(minimum_tolerance_for_count(1), 0);
        assert_eq!(minimum_tolerance_for_count(2), 1);
        assert_eq!(minimum_tolerance_for_count(3), 2);
        assert_eq!(minimum_tolerance_for_count(99), 2)
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
    fn slot_ranges_cover_keyspace() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let (ranges, counts, _) = slot_map(&c, 42);
        assert_eq!(counts.iter().sum::<u64>(), 256);
        assert_eq!(ranges.first().unwrap().start_slot, 0);
        assert_eq!(ranges.last().unwrap().end_slot, 255);
        for w in ranges.windows(2) {
            assert_eq!(w[0].end_slot + 1, w[1].start_slot)
        }
    }
    #[test]
    fn slot_key_bounds_are_exact() {
        let (s, e) = slot_key_bounds(8, 0, 0);
        assert_eq!(s, "0x0000000000000000");
        assert_eq!(e, "0x00ffffffffffffff");
        let (_, last) = slot_key_bounds(8, 255, 255);
        assert_eq!(last, "0xffffffffffffffff")
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
        c.policies.get_mut("p").unwrap().tolerate.hosts = 1;
        normalize_topology(&mut c, None);
        assert!(validate_config(&c).is_err())
    }
    #[test]
    fn yaml_config_round_trip_preserves_topology() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let y = serde_yaml::to_string(&c).unwrap();
        let d: Config = serde_yaml::from_str(&y).unwrap();
        assert_eq!(d.topology.disks.len(), 36);
        assert_eq!(d.topology.network_domains.len(), 3);
    }
    #[test]
    fn per_disk_ranges_match_global_counts() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let (ranges, counts, _) = slot_map(&c, 7);
        for (i, d) in c.topology.disks.iter().enumerate() {
            let n: u64 = ranges
                .iter()
                .filter(|r| r.disk == d.id)
                .map(|r| r.end_slot - r.start_slot + 1)
                .sum();
            assert_eq!(n, counts[i]);
        }
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
    fn reed_solomon_four_plus_two_meets_two_host_tolerance() {
        let mut c = base_cfg();
        normalize_topology(&mut c, None);
        let p = c.policies["p"].clone();
        let (ok, ce) = validate_policy(&c, &p, 123, 4);
        assert!(ok, "counterexample: {ce:?}");
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

        let cases = [
            (
                Protection::ReedSolomon { k: 4, m: 2 },
                vec![
                    vec![true, true, true, true, false, false],
                    vec![true, true, true, false, false, false],
                    vec![false, true, true, true, true, false],
                    vec![false, false, true, true, true, true],
                ],
            ),
            (
                Protection::Lrc {
                    k: 4,
                    local_groups: 2,
                    local_parity: 1,
                    global_parity: 1,
                },
                vec![
                    vec![true, true, true, true, true, true, true],
                    vec![true, false, true, true, true, true, false],
                    vec![false, false, true, true, true, true, true],
                    vec![false, false, true, false, true, true, true],
                ],
            ),
        ];

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
