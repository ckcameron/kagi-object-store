Warning: truncated output (original token count: 39536)
Total output lines: 4344

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
struc…24536 tokens truncated…trary salt.
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
                serde_saphyr::to_string(&config)?.as_bytes(),
            )?;
            config
        } else {
            let path = args
                .config
                .as_ref()
                .context("--config is required unless --wizard or --resume is used")?;
            serde_saphyr::from_str(&fs::read_to_string(path).context("read config")?)
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
    let yaml = serde_saphyr::to_string(&out)?;
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
        let y = serde_saphyr::to_string(&c).unwrap();
        let d: Config = serde_saphyr::from_str(&y).unwrap();
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
