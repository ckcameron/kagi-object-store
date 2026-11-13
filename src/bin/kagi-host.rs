// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi single-host storage daemon and local placement CLI.
//!
//! This smaller daemon is useful for validating disk identity, exercising deterministic
//! local placement, and operating the host-local object API without the full cluster stack.
//! It preserves atomic temporary-write/sync/rename semantics so local testing follows the
//! same durability assumptions used by the distributed node.

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use blake3::Hasher;
use clap::{Parser, Subcommand};
use kagi_object_store::placement::{mask_position, PlacementPlan, KEYSPACE_BITS};
#[path = "../planner_output.rs"]
mod planner_output;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::IsTerminal,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

// CLI and local-host configuration
#[derive(Parser)]
#[command(
    name = "kagi-host",
    version,
    about = "Per-host daemon and CLI for Kagi distributed storage"
)]
struct Cli {
    #[arg(short, long, default_value = "/etc/kagi/host.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
/// Local disk initialization, inspection, and serving commands.
enum Command {
    Serve,
    Validate,
    Status,
    Disks,
    Locate { key: String },
    Put { key: String, file: PathBuf },
    Get { key: String, output: PathBuf },
    Delete { key: String },
}
#[derive(Debug, Clone, Deserialize)]
struct Config {
    cluster: Cluster,
    host: Host,
    #[serde(default)]
    server: Server,
    #[serde(default)]
    placement: Placement,
    #[serde(default)]
    planner_output: Option<planner_output::PlannerOutputRef>,
}
#[derive(Debug, Clone, Deserialize)]
struct Cluster {
    id: String,
    #[serde(default)]
    placement_salt: u64,
    #[serde(default)]
    placement_plan: Option<PlacementPlan>,
}
#[derive(Debug, Clone, Deserialize)]
struct Host {
    id: String,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    rack: Option<String>,
    disks: Vec<Disk>,
}
#[derive(Debug, Clone, Deserialize)]
struct Disk {
    id: String,
    path: PathBuf,
    #[serde(default = "one")]
    weight: f64,
    #[serde(default)]
    expected_capacity_bytes: Option<u64>,
}

fn one() -> f64 {
    1.0
}
#[derive(Debug, Clone, Deserialize)]
struct Server {
    #[serde(default = "listen_default")]
    listen: String,
    #[serde(default = "admin_default")]
    admin_listen: String,
}
impl Default for Server {
    fn default() -> Self {
        Self {
            listen: listen_default(),
            admin_listen: admin_default(),
        }
    }
}

fn listen_default() -> String {
    "0.0.0.0:7400".into()
}

fn admin_default() -> String {
    "127.0.0.1:7401".into()
}
#[derive(Debug, Clone, Deserialize)]
struct Placement {
    #[serde(default = "slot_bits")]
    slot_bits: u8,
    #[serde(default = "maxfrag")]
    max_fragments_per_disk: usize,
}
impl Default for Placement {
    fn default() -> Self {
        Self {
            slot_bits: slot_bits(),
            max_fragments_per_disk: maxfrag(),
        }
    }
}

fn slot_bits() -> u8 {
    24
}

fn maxfrag() -> usize {
    1
}

// Runtime status and local placement model
#[derive(Debug, Serialize)]
struct DiskStatus {
    id: String,
    path: String,
    mounted: bool,
    writable: bool,
    total_bytes: u64,
    available_bytes: u64,
    identity_ok: bool,
    state: String,
}
#[derive(Debug, Serialize)]
struct Status {
    cluster: String,
    host: String,
    site: Option<String>,
    rack: Option<String>,
    keyspace_bits: u8,
    slot_bits: u8,
    disks: Vec<DiskStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_loss_warning: Option<&'static str>,
}
#[derive(Clone)]
struct App {
    cfg: Arc<Config>,
}

// Deterministic 64-bit key position and disk selection
fn hash64(parts: &[&[u8]]) -> u64 {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap())
}

fn keypos(cluster: &str, key: &str) -> u64 {
    hash64(&[cluster.as_bytes(), b"\0", key.as_bytes()])
}

const SITE_LOSS_WARNING: &str =
    "Unsafe two-site layout. Losing a site can make stored objects unavailable.";

fn site_loss_warning(cfg: &Config) -> Option<&'static str> {
    cfg.cluster
        .placement_plan
        .as_ref()
        .filter(|plan| plan.unsafe_two_site())
        .map(|_| SITE_LOSS_WARNING)
}

fn print_site_loss_warning(cfg: &Config) {
    if let Some(message) = site_loss_warning(cfg) {
        if std::io::stderr().is_terminal() {
            eprintln!("\x1b[1;97;41m DANGER \x1b[0m {message}");
        } else {
            eprintln!("DANGER {message}");
        }
    }
}

fn locate_key(cfg: &Config, key: &str) -> Result<serde_json::Value> {
    let pos = keypos(&cfg.cluster.id, key);
    if let Some(plan) = &cfg.cluster.placement_plan {
        let pos = mask_position(pos);
        let mut fragments = Vec::new();
        for (fragment, disks) in plan.locations(pos)?.iter().enumerate() {
            for (replica, &disk_index) in disks.iter().enumerate() {
                let disk = &plan.disks[disk_index];
                let position = plan.chunk_position(pos, fragment, replica, disk_index)?;
                fragments.push(serde_json::json!({
                    "fragment": fragment,
                    "replica": replica,
                    "position": format!("0x{position:015x}"),
                    "site": disk.site,
                    "rack": disk.rack,
                    "host": disk.host,
                    "disk": disk.id,
                }));
            }
        }
        return Ok(serde_json::json!({
            "key": key,
            "position": format!("0x{pos:015x}"),
            "keyspace_bits": KEYSPACE_BITS,
            "fragments": fragments,
        }));
    }
    let disk = local_disk(cfg, pos).map(|disk| &disk.id);
    Ok(serde_json::json!({
        "key": key,
        "position": format!("0x{pos:016x}"),
        "slot": pos >> (64 - cfg.placement.slot_bits),
        "local_disk": disk,
    }))
}

fn local_object_access(cfg: &Config) -> Result<()> {
    anyhow::ensure!(
        cfg.cluster.placement_plan.is_none(),
        "use kagi-cluster-host for objects protected by a cluster placement plan"
    );
    Ok(())
}
fn u01(x: u64) -> f64 {
    ((x as f64) + 1.0) / ((u64::MAX as f64) + 2.0)
}

fn score(pos: u64, salt: u64, d: &Disk) -> f64 {
    let h = hash64(&[&pos.to_le_bytes(), &salt.to_le_bytes(), d.id.as_bytes()]);
    u01(h).powf(1.0 / d.weight.max(1e-12))
}

/// Choose the highest-scoring configured local disk for a key position.
fn local_disk(cfg: &Config, pos: u64) -> Option<&Disk> {
    cfg.host.disks.iter().max_by(|a, b| {
        score(pos, cfg.cluster.placement_salt, a).total_cmp(&score(
            pos,
            cfg.cluster.placement_salt,
            b,
        ))
    })
}

fn object_path(d: &Disk, pos: u64, key: &str) -> PathBuf {
    let digest = blake3::hash(key.as_bytes()).to_hex().to_string();
    d.path
        .join(".keyspace")
        .join("objects")
        .join(format!("{:02x}", pos >> 56))
        .join(format!("{:02x}", (pos >> 48) & 0xff))
        .join(digest)
}

fn identity_path(d: &Disk) -> PathBuf {
    d.path.join(".keyspace").join("disk-id")
}
#[cfg(unix)]
fn statvfs(path: &FsPath) -> (u64, u64) {
    use std::process::Command;
    let out = Command::new("df")
        .args(["-Pk", path.to_string_lossy().as_ref()])
        .output();
    if let Ok(o) = out {
        if let Ok(s) = String::from_utf8(o.stdout) {
            if let Some(line) = s.lines().last() {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() >= 6 {
                    let total = f[1].parse::<u64>().unwrap_or(0) * 1024;
                    let avail = f[3].parse::<u64>().unwrap_or(0) * 1024;
                    return (total, avail);
                }
            }
        }
    }
    (0, 0)
}
#[cfg(not(unix))]
fn statvfs(_: &FsPath) -> (u64, u64) {
    (0, 0)
}

fn disk_status(d: &Disk) -> DiskStatus {
    let mounted = d.path.exists();
    let writable = if mounted {
        let p = d.path.join(".keyspace").join(".write-test");
        fs::create_dir_all(d.path.join(".keyspace")).is_ok() && fs::write(&p, b"ok").is_ok() && {
            let _ = fs::remove_file(&p);
            true
        }
    } else {
        false
    };
    let identity_ok = fs::read_to_string(identity_path(d))
        .map(|x| x.trim() == d.id)
        .unwrap_or(false);
    let (total, avail) = statvfs(&d.path);
    let state = if !mounted {
        "offline"
    } else if !identity_ok {
        "identity_mismatch"
    } else if !writable {
        "read_only"
    } else {
        "online"
    };
    DiskStatus {
        id: d.id.clone(),
        path: d.path.display().to_string(),
        mounted,
        writable,
        total_bytes: total,
        available_bytes: avail,
        identity_ok,
        state: state.into(),
    }
}

fn validate(cfg: &Config) -> Result<()> {
    if cfg.host.disks.is_empty() {
        bail!("host has no disks")
    }
    if !(8..=32).contains(&cfg.placement.slot_bits) {
        bail!("slot_bits must be 8..=32")
    }
    if cfg.placement.max_fragments_per_disk == 0 {
        bail!("max_fragments_per_disk must be at least 1")
    }
    let _: SocketAddr = cfg.server.listen.parse().context("invalid server.listen")?;
    let _: SocketAddr = cfg
        .server
        .admin_listen
        .parse()
        .context("invalid server.admin_listen")?;
    let mut ids = std::collections::BTreeSet::new();
    for d in &cfg.host.disks {
        if !ids.insert(&d.id) {
            bail!("duplicate disk id {}", d.id)
        }
        if !d.path.is_absolute() {
            bail!("disk {} path must be absolute", d.id)
        }
        if !d.path.exists() {
            bail!("disk {} path {} does not exist", d.id, d.path.display())
        }
        let ip = identity_path(d);
        if !ip.exists() {
            fs::create_dir_all(ip.parent().unwrap())?;
            fs::write(&ip, format!("{}\n", d.id))?;
        }
        let got = fs::read_to_string(&ip)?;
        if got.trim() != d.id {
            bail!("disk {} identity mismatch at {}", d.id, d.path.display())
        }
        if let Some(expected) = d.expected_capacity_bytes {
            let (actual, _) = statvfs(&d.path);
            if actual > 0 && actual < expected {
                bail!(
                    "disk {} capacity {} is below expected {}",
                    d.id,
                    actual,
                    expected
                )
            }
        }
        fs::create_dir_all(d.path.join(".kagi/objects"))?;
        fs::create_dir_all(d.path.join(".kagi/tmp"))?;
    }
    Ok(())
}

fn load(path: &PathBuf) -> Result<Config> {
    let mut cfg: Config = serde_saphyr::from_str(
        &fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse host YAML")?;
    if let Some(reference) = &cfg.planner_output {
        anyhow::ensure!(
            cfg.cluster.placement_plan.is_none(),
            "choose planner_output or cluster.placement_plan"
        );
        cfg.cluster.placement_plan = Some(reference.load(path)?.0);
    }
    if let Some(plan) = &cfg.cluster.placement_plan {
        plan.validate_tolerance()?;
        let planned_disks: std::collections::BTreeSet<_> = plan
            .disks
            .iter()
            .filter(|disk| disk.host == cfg.host.id)
            .map(|disk| (disk.id.as_str(), disk.site.as_deref(), disk.rack.as_deref()))
            .collect();
        let local_disks = cfg
            .host
            .disks
            .iter()
            .map(|disk| {
                (
                    disk.id.as_str(),
                    cfg.host.site.as_deref(),
                    cfg.host.rack.as_deref(),
                )
            })
            .collect();
        anyhow::ensure!(
            planned_disks == local_disks,
            "local host topology does not match the placement plan"
        );
    }
    Ok(cfg)
}

fn host_status(cfg: &Config, disks: Vec<DiskStatus>) -> Status {
    Status {
        cluster: cfg.cluster.id.clone(),
        host: cfg.host.id.clone(),
        site: cfg.host.site.clone(),
        rack: cfg.host.rack.clone(),
        keyspace_bits: if cfg.cluster.placement_plan.is_some() {
            KEYSPACE_BITS
        } else {
            64
        },
        slot_bits: cfg.placement.slot_bits,
        disks,
        site_loss_warning: site_loss_warning(cfg),
    }
}

async fn health(State(a): State<App>) -> impl IntoResponse {
    let disks = a.cfg.host.disks.iter().map(disk_status).collect::<Vec<_>>();
    let ok = disks.iter().all(|d| d.state == "online");
    let body = serde_json::to_string(&host_status(&a.cfg, disks)).unwrap();
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
}

async fn locate(State(a): State<App>, Path(key): Path<String>) -> impl IntoResponse {
    match locate_key(&a.cfg, &key) {
        Ok(locations) => axum::Json(locations).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

/// Sync a temporary file on the target disk before publishing it with rename.
async fn put_obj(
    State(a): State<App>,
    Path(key): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let pos = keypos(&a.cfg.cluster.id, &key);
    let Some(d) = local_disk(&a.cfg, pos) else {
        return (StatusCode::INSUFFICIENT_STORAGE, "no local disk").into_response();
    };
    let p = object_path(d, pos, &key);
    if let Some(parent) = p.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    }
    let tmp = d
        .path
        .join(".kagi/tmp")
        .join(format!("{}.tmp", blake3::hash(key.as_bytes()).to_hex()));
    match tokio::fs::File::create(&tmp).await {
        Ok(mut f) => {
            if let Err(e) = f.write_all(&body).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
            if let Err(e) = f.sync_all().await {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
            if let Err(e) = tokio::fs::rename(&tmp, &p).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
            (
                StatusCode::CREATED,
                [
                    ("x-kagi-position", format!("0x{pos:016x}")),
                    ("x-kagi-disk", d.id.clone()),
                ],
                "",
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_obj(State(a): State<App>, Path(key): Path<String>) -> Response {
    let pos = keypos(&a.cfg.cluster.id, &key);
    let Some(d) = local_disk(&a.cfg, pos) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::fs::read(object_path(d, pos, &key)).await {
        Ok(v) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            v,
        )
            .into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn head_obj(State(a): State<App>, Path(key): Path<String>) -> Response {
    let pos = keypos(&a.cfg.cluster.id, &key);
    let Some(d) = local_disk(&a.cfg, pos) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::fs::metadata(object_path(d, pos, &key)).await {
        Ok(m) => {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_LENGTH, m.len().into());
            (StatusCode::OK, h, Body::empty()).into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_obj(State(a): State<App>, Path(key): Path<String>) -> Response {
    let pos = keypos(&a.cfg.cluster.id, &key);
    let Some(d) = local_disk(&a.cfg, pos) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::fs::remove_file(object_path(d, pos, &key)).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn serve(cfg: Config) -> Result<()> {
    validate(&cfg)?;
    print_site_loss_warning(&cfg);
    let addr: SocketAddr = cfg.server.listen.parse().context("invalid server.listen")?;
    let appstate = App { cfg: Arc::new(cfg) };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/locate/*key", get(locate));
    let app = if appstate.cfg.cluster.placement_plan.is_none() {
        app.route(
            "/v1/object/*key",
            put(put_obj).get(get_obj).head(head_obj).delete(delete_obj),
        )
    } else {
        app
    }
    .with_state(appstate);
    let l = TcpListener::bind(addr).await?;
    println!("kagi-host listening on {addr}");
    axum::serve(l, app).await?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load(&cli.config)?;
    match cli.command {
        Command::Serve => serve(cfg).await?,
        Command::Validate => {
            validate(&cfg)?;
            print_site_loss_warning(&cfg);
            println!("OK: {} / {}", cfg.cluster.id, cfg.host.id);
        }
        Command::Status => {
            validate(&cfg)?;
            print_site_loss_warning(&cfg);
            let s = host_status(&cfg, cfg.host.disks.iter().map(disk_status).collect());
            println!("{}", serde_json::to_string_pretty(&s)?);
        }
        Command::Disks => {
            for d in &cfg.host.disks {
                println!("{}", serde_json::to_string(&disk_status(d))?);
            }
        }
        Command::Locate { key } => {
            if cfg.cluster.placement_plan.is_some() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&locate_key(&cfg, &key)?)?
                );
                return Ok(());
            }
            let p = keypos(&cfg.cluster.id, &key);
            let d = local_disk(&cfg, p).map(|x| x.id.as_str()).unwrap_or("-");
            println!(
                "key={key} position=0x{p:016x} slot={} disk={d}",
                p >> (64 - cfg.placement.slot_bits)
            );
        }
        Command::Put { key, file } => {
            local_object_access(&cfg)?;
            validate(&cfg)?;
            let p = keypos(&cfg.cluster.id, &key);
            let d = local_disk(&cfg, p).context("no disk")?;
            let dst = object_path(d, p, &key);
            fs::create_dir_all(dst.parent().unwrap())?;
            fs::copy(file, &dst)?;
            println!("stored 0x{p:016x} {} {}", d.id, dst.display());
        }
        Command::Get { key, output } => {
            local_object_access(&cfg)?;
            let p = keypos(&cfg.cluster.id, &key);
            let d = local_disk(&cfg, p).context("no disk")?;
            fs::copy(object_path(d, p, &key), output)?;
        }
        Command::Delete { key } => {
            local_object_access(&cfg)?;
            let p = keypos(&cfg.cluster.id, &key);
            let d = local_disk(&cfg, p).context("no disk")?;
            let path = object_path(d, p, &key);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}
