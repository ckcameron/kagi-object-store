Warning: truncated output (original token count: 36518)
Total output lines: 3966

// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi cluster daemon and administrative CLI.
//!
//! This is the runtime composition root. It loads and validates node configuration, starts
//! the Raft metadata service and object data plane, exposes public/admin/internal HTTP routes,
//! runs health and maintenance loops, and hosts the operations console. CLI subcommands use
//! the same state and validation rules as the long-running daemon wherever practical.

// Link native accelerator libraries used by this daemon's embedded erasure module.
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
use kagi_object_store as _;

// Full Kagi cluster daemon and administrative CLI for distributed storage nodes.
#[path = "../block.rs"]
mod block;
#[path = "../cluster.rs"]
mod cluster;
#[path = "../erasure.rs"]
mod erasure;
#[path = "../filesystem.rs"]
mod filesystem;
#[path = "../identity.rs"]
mod identity;
#[path = "../maintenance.rs"]
mod maintenance;
#[path = "../monitoring.rs"]
mod monitoring;
#[path = "../pq.rs"]
mod pq;
#[cfg(feature = "quic")]
#[path = "../quic_transport.rs"]
mod quic_transport;
#[path = "../raftmeta.rs"]
mod raftmeta;
#[path = "../recovery.rs"]
mod recovery;
#[path = "../runtime_security.rs"]
mod runtime_security;
#[path = "../s3.rs"]
mod s3;
#[cfg(any(test, feature = "scsi-target"))]
#[path = "../scsi_pr.rs"]
mod scsi_pr;
#[path = "../security.rs"]
mod security;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
#[path = "../security_ebpf.rs"]
mod security_ebpf;
#[path = "../storage.rs"]
mod storage;
#[path = "../telemetry.rs"]
mod telemetry;
#[path = "../tls.rs"]
mod tls;
#[path = "../webui.rs"]
mod webui;
#[cfg(any(test, feature = "quic"))]
#[path = "../wire.rs"]
mod wire;
use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, put},
    Json, Router,
};
use block::{PrOut, VolumeCreate, VolumeRecord};
use clap::{Parser, Subcommand};
use cluster::*;
use erasure::AdaptiveBackend;
use filesystem::{
    now_ms, reconstruct_bottom_up, Ace, AuthIdentity, ChildRef, FsIndex, FsMetadata, FsObjectType,
    IndexEntry, IndexSnapshot, ObjectAcl,
};
use maintenance::{MaintenanceConfig, MaintenanceManager};
use pq::{LocalPqIdentity, RuntimeKeyring, TrustedPqKey};
use raftmeta::{
    AppendRequest, BucketRecord, GarbageRecord, Membership, MetadataCommand, MetadataStore,
    NamespaceMutation, RaftNode, RaftPeer, RaftTiming, SnapshotMode, SnapshotObject,
    SnapshotRecord, VoteRequest,
};
use recovery::{object_risk, HealthMap, Heartbeat, RecoveryConfig};
use serde::Deserialize;
use serde::Serialize;
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock};
use webui::{ConsoleRole, WebConsoleConfig};
#[derive(Parser)]
// ---- CLI, node configuration, and security bootstrap -------------------------
struct Cli {
    /// Node YAML configuration file.
    #[arg(short, long, default_value = "/etc/kagi/node.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
/// Administrative and data-path commands exposed by the cluster-host binary.
enum Cmd {
    /// Run the node API, web console, metadata service and background controllers.
    Serve,
    /// Print the local node/cluster health summary.
    Status,
    /// Validate and print the effective security policy without serving traffic.
    Audit,
    /// Store FILE as the immutable/versioned object KEY.
    Put {
        /// Logical object key.
        key: String,
        /// Local file whose bytes will be stored.
        file: PathBuf,
    },
    /// Retrieve KEY and write its bytes to OUTPUT.
    Get {
        /// Logical object key.
        key: String,
        /// Local output path.
        output: PathBuf,
    },
    /// Repair missing/damaged fragments for KEY using its current protection policy.
    Repair {
        /// Logical object key to repair.
        key: String,
    },
    /// Verify checksums/readability for KEY and report corruption.
    Scrub {
        /// Logical object key to scrub.
        key: String,
    },
    /// Print the current fragment placement/locality for KEY.
    Locate {
        /// Logical object key to locate.
        key: String,
    },
    /// Clear flap/quarantine health state for a resource after operator validation.
    ClearHealth {
        /// Resource identifier understood by the recovery health map.
        resource: String,
    },
    /// Generate a new ML-DSA-87 application identity for this node.
    GeneratePqIdentity {
        /// Destination for the public identity.
        #[arg(long)]
        public: PathBuf,
        /// Destination for the private identity; protect this file as a secret.
        #[arg(long)]
        secret: PathBuf,
    },
    /// Add/update a local web-console user using a password read from a file.
    WebUserAdd {
        /// Console login name.
        username: String,
        /// Console role. Default: viewer; supported roles: viewer, admin.
        #[arg(long, default_value = "viewer")]
        role: String,
        /// File containing the password; avoids exposing it in process arguments.
        #[arg(long)]
        password_file: PathBuf,
    },
    /// Change Raft membership/failure-domain metadata.
    Membership {
        /// Membership operation accepted by the membership controller.
        action: String,
        /// Failure-domain scope for the operation.
        scope: String,
        /// Node/site/rack identifier affected by the operation.
        id: String,
        /// Optional peer HTTPS endpoint.
        #[arg(long)]
        endpoint: Option<String>,
        /// Optional site label.
        #[arg(long)]
        site: Option<String>,
        /// Optional rack label.
        #[arg(long)]
        rack: Option<String>,
        /// Optional file containing the peer ML-DSA public key.
        #[arg(long)]
        pq_public_key: Option<PathBuf>,
    },
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Complete top-level node configuration. Unknown keys are rejected so typos cannot silently disable policy.
struct NodeConfig {
    #[serde(default)]
    s3: Option<s3::Config>,
    #[serde(default)]
    security: security::Config,
    cluster: ClusterConfig,
    metadata: MetadataConfig,
    #[serde(default)]
    tls: Option<TlsConfig>,
    #[serde(default)]
    post_quantum: Option<PostQuantumConfig>,
    #[serde(default)]
    recovery: RecoveryConfig,
    #[serde(default)]
    garbage_collection: GarbageCollectionConfig,
    #[serde(default)]
    snapshots: SnapshotConfig,
    #[serde(default)]
    maintenance: MaintenanceConfig,
    #[serde(default)]
    web_console: WebConsoleConfig,
    #[serde(default)]
    telemetry: telemetry::TelemetryConfig,
    local_host: String,
    data_root: PathBuf,
    #[serde(default = "listen")]
    listen: String,
    join_key_b64: String,
}
/// Implements the listen step and keeps its validation and state transitions visible at the call site.
fn listen() -> String {
    "0.0.0.0:7400".into()
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Raft identity, peer set and timing configuration.
struct MetadataConfig {
    node_id: String,
    peers: Vec<RaftPeer>,
    #[serde(default = "election_min")]
    election_min_ms: u64,
    #[serde(default = "election_max")]
    election_max_ms: u64,
    #[serde(default = "raft_heartbeat")]
    heartbeat_ms: u64,
}
/// Implements the election min step and keeps its validation and state transitions visible at the call site.
fn election_min() -> u64 {
    1500
}
/// Implements the election max step and keeps its validation and state transitions visible at the call site.
fn election_max() -> u64 {
    3000
}
/// Implements the raft heartbeat step and keeps its validation and state transitions visible at the call site.
fn raft_heartbeat() -> u64 {
    400
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Fenced physical garbage-collection policy.
struct GarbageCollectionConfig {
    #[serde(default = "gc_enabled")]
    enabled: bool,
    #[serde(default = "gc_grace_ms")]
    grace_period_ms: u64,
    #[serde(default = "gc_interval_ms")]
    interval_ms: u64,
    #[serde(default = "gc_batch")]
    max_versions_per_cycle: usize,
}
impl Default for GarbageCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: gc_enabled(),
            grace_period_ms: gc_grace_ms(),
            interval_ms: gc_interval_ms(),
            max_versions_per_cycle: gc_batch(),
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Point-in-time snapshot materialization policy.
struct SnapshotConfig {
    #[serde(default = "snap_enabled")]
    enabled: bool,
    #[serde(default = "snap_interval")]
    check_interval_ms: u64,
    #[serde(default = "snap_delta_bytes")]
    archive_after_delta_bytes: u64,
    #[serde(default = "snap_delta_ratio")]
    archive_after_delta_ratio: f64,
}
impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_ms: 30000,
            archive_after_delta_bytes: 10 * 1024 * 1024 * 1024,
            archive_after_delta_ratio: 0.50,
        }
    }
}
/// Implements the snap enabled step and keeps its validation and state transitions visible at the call site.
fn snap_enabled() -> bool {
    true
}
/// Implements the snap interval step and keeps its validation and state transitions visible at the call site.
fn snap_interval() -> u64 {
    30000
}
/// Implements the snap delta bytes step and keeps its validation and state transitions visible at the call site.
fn snap_delta_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}
/// Implements the snap delta ratio step and keeps its validation and state transitions visible at the call site.
fn snap_delta_ratio() -> f64 {
    0.50
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotCreateRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
}
/// Implements the gc enabled step and keeps its validation and state transitions visible at the call site.
fn gc_enabled() -> bool {
    true
}
/// Implements the gc grace ms step and keeps its validation and state transitions visible at the call site.
fn gc_grace_ms() -> u64 {
    86_400_000
}
/// Implements the gc interval ms step and keeps its validation and state transitions visible at the call site.
fn gc_interval_ms() -> u64 {
    30_000
}
/// Implements the gc batch step and keeps its validation and state transitions visible at the call site.
fn gc_batch() -> usize {
    32
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcDeleteRequest {
    term: u64,
    leader_id: String,
    garbage_id: String,
    fence_index: u64,
    object_id: String,
    version: u64,
    fragment: u32,
    disk: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Native HTTPS/peer TLS identity and compatibility policy.
struct TlsConfig {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    /// Compatibility mode. Native Kagi listeners otherwise require TLS 1.3.
    #[serde(default)]
    allow_tls12: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// ML-DSA application identity and peer trust map.
struct PostQuantumConfig {
    #[serde(default = "pq_required")]
    required: bool,
    identity_secret: PathBuf,
    identity_public: PathBuf,
    #[serde(default)]
    peer_public_keys: BTreeMap<String, PathBuf>,
}
/// Implements the pq required step and keeps its validation and state transitions visible at the call site.
fn pq_required() -> bool {
    true
}
/// Implements the load step and keeps its validation and state transitions visible at the call site.
fn load(p: &PathBuf) -> Result<NodeConfig> {
    Ok(serde_saphyr::from_str(&fs::read_to_string(p)?)?)
}
/// Implements the validate pq step and keeps its validation and state transitions visible at the call site.
fn validate_pq(c: &NodeConfig) -> Result<()> {
    let q = c
        .post_quantum
        .as_ref()
        .context("post_quantum configuration is required in v16")?;
    if q.required {
        if !q.identity_secret.exists() {
            anyhow::bail!("ML-DSA-87 identity secret missing")
        };
        if !q.identity_public.exists() {
            anyhow::bail!("ML-DSA-87 identity public key missing")
        };
        for p in &c.metadata.peers {
            if !q.peer_public_keys.contains_key(&p.id) {
                anyhow::bail!("missing ML-DSA-87 public key for raft peer {}", p.id)
            }
        }
    }
    Ok(())
}
/// Implements the bootstrap pq step and keeps its validation and state transitions visible at the call site.
async fn bootstrap_pq(c: &NodeConfig) -> Result<(LocalPqIdentity, RuntimeKeyring)> {
    let q = c.post_quantum.as_ref().context("post_quantum required")?;
    let id = pq::local_identity(
        c.metadata.node_id.clone(),
        &q.identity_public,
        q.identity_secret.clone(),
        c.data_root.join("pq/sender-session.json"),
    )?;
    let ring = RuntimeKeyring::default();
    ring.configure_peer_sessions(c.data_root.join("pq/peer-sessions.json"))
        .await?;
    {
        let mut m = ring.keys.write().await;
        let selfpub = pq::public_key_b64(&q.identity_public)?;
        m.insert(
            id.key_id.clone(),
            TrustedPqKey {
                node_id: c.metadata.node_id.clone(),
                key_id: id.key_id.clone(),
                public_key_b64: selfpub,
                not_before_ms: 0,
                not_after_ms: None,
                revoked: false,
            },
        );
        for (peer, path) in &q.peer_public_keys {
            let pubb = pq::public_key_b64(path)?;
            let kid = pq::key_id_from_public_b64(&pubb)?;
            m.insert(
                kid.clone(),
                TrustedPqKey {
                    node_id: peer.clone(),
                    key_id: kid,
                    public_key_b64: pubb,
                    not_before_ms: 0,
                    not_after_ms: None,
                    revoked: false,
                },
            );
        }
    }
    Ok((id, ring))
}
/// Implements the sync pq keyring step and keeps its validation and state transitions visible at the call site.
async fn sync_pq_keyring(st: V6State) {
    let mut t = tokio::time::interval(std::time::Duration::from_millis(500));
    loop {
        t.tick().await;
        let state = st.meta.store.state().await;
        if !state.pq_keys.is_empty() {
            let mut r = st.data.pq_keys.keys.write().await;
            for (k, v) in state.pq_keys {
                r.insert(k, v);
            }
        }
    }
}
/// Named type used to keep the SignedJson data flow readable.
type SignedJson = (Vec<u8>, Vec<(&'static str, String)>);
/// Implements the signed json step and keeps its validation and state transitions visible at the call site.
fn signed_json<T: Serialize>(
    st: &ClusterState,
    method: &str,
    path: &str,
    value: &T,
) -> Result<SignedJson> {
    let body = serde_json::to_vec(value)?;
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let h = pq::signed_headers(id, method, path, &body)?;
    Ok((body, h))
}
/// Implements the verify json step and keeps its validation and state transitions visible at the call site.
async fn verify_json<T: Serialize>(
    st: &V6State,
    headers: &axum::http::HeaderMap,
    path: &str,
    value: &T,
) -> bool {
    let b = serde_json::to_vec(value).unwrap_or_default();
    pq::verify_request(headers, "POST", path, &b, &st.data.pq_keys)
        .await
        .is_ok()
}
/// Implements the validate runtime topology step and keeps its validation and state transitions visible at the call site.
fn validate_runtime_topology(c: &NodeConfig) -> Result<()> {
    if c.cluster.hosts.len() < 6 {
        anyhow::bail!(
            "Kagi requires at least 6 cluster hosts; configured {}",
            c.cluster.hosts.len()
        );
    }
    for h in &c.cluster.hosts {
        if h.disks.len() < 6 {
            anyhow::bail!(
                "Kagi host {} has {} disks; at least 6 are required",
                h.id,
                h.disks.len()
            );
        }
    }
    if !c.cluster.hosts.iter().any(|h| h.id == c.local_host) {
        anyhow::bail!(
            "local_host {} is not present in cluster.hosts",
            c.local_host
        );
    }
    if let Some(ec) = &c.cluster.erasure {
        let layout = erasure::ErasureLayout {
            scheme: ec.scheme,
            data_shards: ec.data_shards,
            parity_shards: ec.parity_shards,
            repair_helpers: ec.repair_helpers,
        };
        layout.validate()?;
        let disks = c.cluster.hosts.iter().map(|h| h.disks.len()).sum::<usize>();
        if layout.n() > disks {
            anyhow::bail!(
                "erasure layout needs {} chunks but topology has only {disks} disks",
                layout.n()
            );
        }
    }
    Ok(())
}
/// Implements the validate join key step and keeps its validation and state transitions visible at the call site.
fn validate_join_key(c: &NodeConfig) -> Result<()> {
    use base64::Engine;
    let expected = c
        .cluster
        .join_key_hash_hex
        .as_deref()
        .context("cluster.join_key_hash_hex is required")?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&c.join_key_b64)
        .context("join_key_b64 must be base64")?;
    if raw.len() != 32 {
        anyhow::bail!("join_key_b64 must decode to 32 bytes");
    }
    if blake3::hash(&raw).to_hex().to_string() != expected {
        anyhow::bail!("join key does not match this keyspace; host admission denied");
    }
    Ok(())
}
/// Implements the request authorized step and keeps its validation and state transitions visible at the call site.
fn request_authorized(c: &ClusterConfig, h: &axum::http::HeaderMap) -> bool {
    use base64::Engine;
    let (Some(want), Some(raw)) = (
        c.join_key_hash_hex.as_deref(),
        h.get("x-kagi-join-key").and_then(|x| x.to_str().ok()),
    ) else {
        return false;
    };
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .ok()
        .map(|v| blake3::hash(&v).to_hex().to_string() == want)
        .unwrap_or(false)
}
/// Implements the http client step and keeps its validation and state transitions visible at the call site.
fn http_client(c: &NodeConfig) -> Result<reqwest::Client> {
    tls::install_pq_provider()?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "x-kagi-join-key",
        reqwest::header::HeaderValue::from_str(&c.join_key_b64)?,
    );
    let mut b = reqwest::Client::builder()
        .default_headers(headers)
        .https_only(c.tls.is_some());
    if let Some(t) = &c.tls {
        b = b
            .min_tls_version(if t.allow_tls12 {
                reqwest::tls::Version::TLS_1_2
            } else {
                reqwest::tls::Version::TLS_1_3
            })
            .max_tls_version(reqwest::tls::Version::TLS_1_3);
    }
    if let Some(t) = &c.tls {
        let ca = reqwest::Certificate::from_pem(&fs::read(&t.ca)?)?;
        let mut pem = fs::read(&t.cert)?;
        pem.extend_from_slice(&fs::read(&t.key)?);
        let id = reqwest::Identity::from_pem(&pem)?;
        b = b.add_root_certificate(ca).identity(id);
    }
    Ok(b.build()?)
}
/// Implements the state step and keeps its validation and state transitions visible at the call site.
fn state(
    c: &NodeConfig,
    client: reqwest::Client,
    pq_identity: LocalPqIdentity,
    pq_keys: RuntimeKeyring,
) -> Result<ClusterState> {
    validate_at_rest_keys(&c.cluster)?;
    #[cfg(feature = "quic")]
    let quic = if c.cluster.transport.prefer_quic
        && c.cluster
            .hosts
            .iter()
            .any(|host| host.quic_endpoint.is_some())
    {
        let tls = c
            .tls
            .as_ref()
            .context("QUIC is configured but node TLS/CA configuration is missing")?;
        Some(Arc::new(quic_transport::Client::new(
            &tls.ca,
            c.cluster.transport.max_frame_bytes,
        )?))
    } else {
        None
    };

    Ok(ClusterState {
        cfg: Arc::new(c.cluster.clone()),
        local_host: c.local_host.clone(),
        root: c.data_root.clone(),
        client,
        manifests: Arc::new(RwLock::new(BTreeMap::new())),
        erasure: Arc::new(AdaptiveBackend::new(
            c.cluster.erasure.clone().unwrap_or_default(),
        )),
        pq_identity: Some(pq_identity),
        pq_keys,
        join_key_b64: Some(c.join_key_b64.clone()),
        #[cfg(feature = "quic")]
        quic,
    })
}
// ---- Legacy/public object handlers (superseded paths retained for compatibility) ----
async fn api_get(State(st): State<ClusterState>, Path(key): Path<String>) -> impl IntoResponse {
    match get_object(&st, &key).await {
        Ok(v) => (StatusCode::OK, v).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}
#[derive(Clone)]
// ---- Unified cluster runtime state and linearizable commit helpers ------------
struct V6State {
    security: security::Security,
    monitor: monitoring::Monitor,
    node_config: Arc<NodeConfig>,
    data: ClusterState,
    meta: RaftNode,
    health: HealthMap,
    recovery: RecoveryConfig,
    gc: GarbageCollectionConfig,
    snapshots: SnapshotConfig,
    maintenance: MaintenanceManager,
    fs_index: FsIndex,
    namespace_lock: Arc<tokio::sync::Mutex<()>>,
    web_console: WebConsoleConfig,
    telemetry: telemetry::TelemetryStore,
}
/// Implements the effective cluster config step and keeps its validation and state transitions visible at the call site.
async fn effective_cluster_config(st: &V6State) -> ClusterConfig {
    let mut c = (*st.data.cfg).clone();
    let ms = st.meta.store.state().await;
    for (host, disks) in ms.capacity_additions {
        if let Some(h) = c.hosts.iter_mut().find(|h| h.id == host) {
            for d in disks.into_values() {
                if let Some(existing) = h.disks.iter_mut().find(|x| x.id == d.id) {
                    *existing = d
                } else {
                    h.disks.push(d)
                }
            }
        }
    }
    c
}
/// Implements the effective data step and keeps its validation and state transitions visible at the call site.
async fn effective_data(st: &V6State) -> ClusterState {
    let mut d = st.data.clone();
    d.cfg = Arc::new(effective_cluster_config(st).await);
    d
}
/// Implements the committed step and keeps its validation and state transitions visible at the call site.
async fn committed(st: &V6State, cmd: MetadataCommand) -> Result<u64> {
    let i = st.meta.propose(cmd).await?;
    st.meta.linearizable_barrier(i).await?;
    Ok(i)
}
#[derive(Debug, Clone, Serialize, Deserialize)] // ---- Filesystem namespace, ACL, and decentralized-index operations ------------
/// Kagi state or configuration used by the MkdirRequest path.
struct MkdirRequest {
    #[serde(default)]
    acl: Option<ObjectAcl>,
}
/// Implements the default acl step and keeps its validation and state transitions visible at the call site.
fn default_acl(headers: &axum::http::HeaderMap) -> ObjectAcl {
    use std::collections::BTreeSet;
    let owner = headers
        .get("x-kagi-unix-uid")
        .and_then(|v| v.to_str().ok())
        .map(|v| format!("unix:{v}"))
        .or_else(|| {
            headers
                .get("x-kagi-ad-sid")
                .and_then(|v| v.to_str().ok())
                .map(|v| format!("ad:{v}"))
        })
        .unwrap_or_else(|| "unix:0".into());
    let group = headers
        .get("x-kagi-unix-gids")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| format!("unix-group:{}", v.trim()))
        .or_else(|| {
            headers
                .get("x-kagi-ad-group-sids")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| format!("ad-group:{}", v.trim()))
        })
        .unwrap_or_else(|| "unix-group:0".into());
    let all = [
        "read_data",
        "write_data",
        "append_data",
        "read_named_attrs",
        "write_named_attrs",
        "execute",
        "delete_child",
        "read_attributes",
        "write_attributes",
        "delete",
        "read_acl",
        "write_acl",
        "write_owner",
        "synchronize",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    let read = [
        "read_data",
        "read_named_attrs",
        "execute",
        "read_attributes",
        "read_acl",
        "synchronize",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    ObjectAcl {
        owner,
        group,
        entries: vec![
            Ace {
                ace_type: "allow".into(),
                who: "OWNER@".into(),
                permissions: all,
                flags: BTreeSet::new(),
            },
            Ace {
                ace_type: "allow".into(),
                who: "GROUP@".into(),
                permissions: read.clone(),
                flags: BTreeSet::new(),
            },
            Ace {
                ace_type: "allow".into(),
                who: "EVERYONE@".into(),
                permissions: read,
                flags: BTreeSet::new(),
            },
        ],
    }
}
/// Implements the parent key for step and keeps its validation and state transitions visible at the call site.
fn parent_key_for(key: &str) -> Option<String> {
    let k = key.trim_matches('/');
    k.rsplit_once('/')
        .map(|(p, _)| p.to_string())
        .filter(|p| !p.is_empty())
        .or_else(|| if k.is_empty() { None } else { Some("/".into()) })
}
/// Implements the name for step and keeps its validation and state transitions visible at the call site.
fn name_for(key: &str) -> String {
    let k = key.trim_matches('/');
    if k.is_empty() {
        "/".into()
    } else {
        k.rsplit('/').next().unwrap_or(k).to_string()
    }
}
/// Implements the prepare parent directory step and keeps its validation and state transitions visible at the call site.
async fn prepare_parent_directory(
    st: &V6State,
    child: &ObjectManifest,
) -> Result<Option<ObjectManifest>> {
    let Some(cfs) = &child.fs else {
        return Ok(None);
    };
    let Some(pk) = &cfs.parent_key else {
        return Ok(None);
    };
    let Some(parent) = st.meta.store.get(pk).await else {
        return Ok(None);
    };
    let Some(mut pfs) = parent.fs.clone() else {
        return Ok(None);
    };
    if pfs.object_type != FsObjectType::Directory {
        return Ok(None);
    }
    pfs.children.retain(|c| c.key != child.key);
    pfs.children.push(ChildRef {
        name: cfs.name.clone(),
        object_id: child.object_id.clone(),
        key: child.key.clone(),
        object_type: cfs.object_type.clone(),
    });
    pfs.children.sort_by(|a, b| a.name.cmp(&b.name));
    pfs.contents = pfs.children.iter().map(|c| c.key.clone()).collect();
    Ok(Some(
        put_filesystem_object(
            &st.data,
            pk,
            &[],
            Some(&st.health),
            parent.worm.clone(),
            pfs,
        )
        .await?,
    ))
}
/// Implements the commit child parent step and keeps its validation and state transitions visible at the call site.
async fn commit_child_parent(st: &V6State, child: ObjectManifest) -> Result<u64> {
    let _guard = st.namespace_lock.lock().await;
    let parent = prepare_parent_directory(st, &child).await?;
    let mut mutations = vec![NamespaceMutation::PutManifest {
        key: child.key.clone(),
        manifest: Box::new(child.clone()),
    }];
    if let Some(pm) = parent.clone() {
        mutations.push(NamespaceMutation::PutManifest {
            key: pm.key.clone(),
            manifest: Box::new(pm.clone()),
        });
    }
    let txid = uuid::Uuid::new_v4().to_string();
    let idx = committed(
        st,
        MetadataCommand::NamespaceTransaction { txid, mutations },
    )
    .await?;
    index_manifest(st, &child).await;
    if let Some(pm) = parent {
        index_manifest(st, &pm).await;
    }
    Ok(idx)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetAclRequest {
    acl: ObjectAcl,
}
/// Implements the fs set acl step and keeps its validation and state transitions visible at the call site.
async fn fs_set_acl(
    State(st): State<V6State>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SetAclRequest>,
) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let Some(old) = st.meta.store.get(&key).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(mut fs) = old.fs.clone() else {
        return (StatusCode::CONFLICT, "object has no filesystem metadata").into_response();
    };
    if !AuthIdentity::from_headers(&headers).allows(&fs.acl, "write_acl") {
        return StatusCode::FORBIDDEN.into_response();
    }
    fs.acl = req.acl;
    let data = if fs.object_type == FsObjectType::File {
        match get_object_version(&st.data, &old).await {
            Ok(v) => v,
            Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        }
    } else {
        vec![]
    };
    match put_filesystem_object(
        &st.data,
        &key,
        &data,
        Some(&st.health),
        old.worm.clone(),
        fs,
    )
    .await
    {
        Ok(m) => match committed(
            &st,
            Meta…21518 tokens truncated…rity.check(
                &m.key,
                security::common::OP_GETATTR,
                m.fs.as_ref().is_some_and(|fs| fs.privileged),
            )
        })
        .take(1000)
        .map(|m| {
            serde_json::json!( {
                "key":m.key,
                    "object_id":m.object_id,
                    "version":m.version,
                    "bytes":m.bytes,
                    "erasure_scheme":m.erasure_scheme,
                    "data_shards":m.data_shards,
                    "parity_shards":m.parity_shards,
                    "worm":m.worm
            }
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    Json(rows).into_response()
}
/// Implements the ui object step and keeps its validation and state transitions visible at the call site.
async fn ui_object(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    let ms = st.meta.store.state().await;
    let Some(m) = ms.manifests.get(&key).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let hs = st.health.snapshot().await;
    let chunks = cluster::normalize_chunks(&m)
        .into_iter()
        .map(|c| {
            let reps = c
                .replicas
                .into_iter()
                .map(|r| {
                    let host = st.data.cfg.hosts.iter().find(|h| h.id == r.host);
                    let health = hs
                        .get(&recovery::disk_key(&r.host, &r.disk))
                        .map(|x| format!("{:?}", x.state).to_lowercase())
                        .unwrap_or_else(|| "healthy".into());
                    serde_json::json!( {
                        "host":r.host,
                            "disk":r.disk,
                            "site":host.and_then(|h|h.site.clone()),
                            "rack":host.and_then(|h|h.rack.clone()),
                            "health":health,
                            "checksum":r.checksum
                    }
                    )
                })
                .collect::<Vec<_>>();
            serde_json::json!( {
                "chunk":c.chunk,"bytes":c.bytes,"checksum":c.checksum,"replicas":reps
            }
            )
        })
        .collect::<Vec<_>>();
    let mut pending = Vec::new();
    for g in ms.garbage.values().filter(|g| g.key == key) {
        pending.push(serde_json::json!( {
            "kind":"garbage_collection","id":g.id,"eligible_after_unix_ms":g.eligible_after_unix_ms,"attempts":g.attempts,"last_error":g.last_error
        }
        ))
    }
    for s in ms.snapshots.values() {
        if matches!(s.mode, SnapshotMode::Archiving) && s.objects.contains_key(&key) {
            pending.push(serde_json::json!( {
                "kind":"snapshot_archive","snapshot":s.id,"archived_bytes":s.archived_bytes,"logical_bytes":s.logical_bytes
            }
            ))
        }
    }
    let durability_margin = object_risk(&m, &st.health, &st.data.cfg.hosts).await;
    if durability_margin == 0 {
        pending.push(serde_json::json!( {
            "kind":"proactive_repair_candidate","reason":"object is at its minimum readable durability margin"
        }
        ))
    }
    Json(serde_json::json!( {
        "manifest":m,"chunks":chunks,"durability_margin":durability_margin,"placement_epoch":ms.placement_epoch,"pending_operations":pending
    }
    )).into_response()
}
#[derive(Deserialize)]
struct LogQuery {
    #[serde(default = "log_local")]
    scope: String,
}
/// Implements the log local step and keeps its validation and state transitions visible at the call site.
fn log_local() -> String {
    "local".into()
}
/// Implements the internal ui logs step and keeps its validation and state transitions visible at the call site.
async fn internal_ui_logs(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    let path = "/internal/v1/ui/logs";
    if pq::verify_request(&headers, "GET", path, &[], &st.data.pq_keys)
        .await
        .is_err()
        || !request_authorized(&st.data.cfg, &headers)
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(serde_json::json!( {
        "node":st.data.local_host,"lines":webui::tail_log(&st.web_console.log_path,st.web_console.max_log_lines)
    }
    )).into_response()
}
/// Implements the ui logs step and keeps its validation and state transitions visible at the call site.
async fn ui_logs(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Query(q): Query<LogQuery>,
) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    let mut lines = webui::tail_log(&st.web_console.log_path, st.web_console.max_log_lines);
    if q.scope == "cluster" {
        if let Some(id) = st.data.pq_identity.as_ref() {
            for h in &st.data.cfg.hosts {
                if h.id == st.data.local_host {
                    continue;
                }
                let path = "/internal/v1/ui/logs";
                if let Ok(auth) = pq::signed_headers(id, "GET", path, &[]) {
                    if let Ok(r) = pq::apply_headers(
                        st.data
                            .client
                            .get(format!("{}{}", h.endpoint.trim_end_matches('/'), path)),
                        auth,
                    )
                    .send()
                    .await
                    {
                        if let Ok(v) = r.json::<serde_json::Value>().await {
                            if let Some(a) = v["lines"].as_array() {
                                for l in a {
                                    if let Some(x) = l.as_str() {
                                        lines.push(x.into())
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        lines.sort();
        if lines.len() > st.web_console.max_log_lines {
            lines.drain(0..lines.len() - st.web_console.max_log_lines);
        }
    }
    Json(serde_json::json!( {
        "scope":q.scope,"lines":lines
    }
    ))
    .into_response()
}
/// Implements the ui buckets step and keeps its validation and state transitions visible at the call site.
async fn ui_buckets(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    Json(st.meta.store.state().await.buckets).into_response()
}
/// Implements the ui bucket put step and keeps its validation and state transitions visible at the call site.
async fn ui_bucket_put(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Json(mut bucket): Json<BucketRecord>,
) -> Response {
    let Some(who) = console_auth(&st, &headers, true) else {
        return webui::unauthorized();
    };
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    bucket.name = bucket.name.trim_matches('/').to_string();
    if bucket.name.is_empty() || bucket.name.contains('/') {
        return (
            StatusCode::BAD_REQUEST,
            "bucket name must be one path segment",
        )
            .into_response();
    }
    if bucket.created_at_unix_ms == 0 {
        bucket.created_at_unix_ms = now_ms()
    }
    match committed(
        &st,
        MetadataCommand::PutBucket {
            bucket: bucket.clone(),
        },
    )
    .await
    {
        Ok(i) => {
            webui::append_log(
                &st.web_console.log_path,
                &st.data.local_host,
                &format!(
                    "admin={} bucket={} updated raft_index={i}",
                    who.username, bucket.name
                ),
            );
            (StatusCode::OK, Json(bucket)).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::GeneratePqIdentity { public, secret } = &cli.command {
        pq::generate_identity(public, secret)?;
        println!("generated ML-DSA-87 identity: {}", public.display());
        return Ok(());
    }
    let cfg = load(&cli.config)?;
    security::validate(&cfg.security)?;
    if matches!(cli.command, Cmd::Audit) {
        println!(
            "{}",
            serde_json::to_string_pretty(&runtime_security::audit_config(&cfg))?
        );
        return Ok(());
    }
    if let Cmd::WebUserAdd {
        username,
        role,
        password_file,
    } = &cli.command
    {
        let password = fs::read_to_string(password_file)?.trim_end().to_string();
        let role = match role.as_str() {
            "admin" => ConsoleRole::Admin,
            "viewer" => ConsoleRole::Viewer,
            _ => anyhow::bail!("role must be viewer or admin"),
        };
        webui::upsert_user(&cfg.web_console.userdb, username, &password, role)?;
        println!(
            "Kagi console user {} updated in {}",
            username,
            cfg.web_console.userdb.display()
        );
        return Ok(());
    }
    validate_runtime_topology(&cfg)?;
    validate_join_key(&cfg)?;
    validate_pq(&cfg)?;
    let client = http_client(&cfg)?;
    let (pq_identity, pq_keys) = bootstrap_pq(&cfg).await?;
    let st = state(&cfg, client.clone(), pq_identity.clone(), pq_keys.clone())?;
    let mstore = MetadataStore::open(cfg.data_root.join("metadata")).await?;
    let meta = RaftNode::open(
        cfg.metadata.node_id.clone(),
        cfg.metadata.peers.clone(),
        mstore,
        cfg.data_root.join("raft"),
        client,
        RaftTiming {
            election_min_ms: cfg.metadata.election_min_ms,
            election_max_ms: cfg.metadata.election_max_ms,
            heartbeat_ms: cfg.metadata.heartbeat_ms,
        },
        pq_identity,
    )
    .await?;
    let health = HealthMap::default();
    let fs_index = FsIndex::open(cfg.data_root.join("index"), cfg.local_host.clone()).await?;
    let monitor = monitoring::Monitor::new(4096);
    let security = security::Security::new(cfg.security.clone(), monitor.clone())?;
    let telemetry = telemetry::TelemetryStore::new(cfg.telemetry.clone());
    let v6 = V6State {
        security,
        monitor,
        node_config: Arc::new(cfg.clone()),
        data: st.clone(),
        meta,
        health: health.clone(),
        recovery: cfg.recovery.clone(),
        gc: cfg.garbage_collection.clone(),
        snapshots: cfg.snapshots.clone(),
        maintenance: MaintenanceManager::new(cfg.maintenance.clone()),
        fs_index,
        namespace_lock: Arc::new(tokio::sync::Mutex::new(())),
        web_console: cfg.web_console.clone(),
        telemetry,
    };
    // Local administrative CLI object operations use the same configured rules.
    let cli_access = match &cli.command {
        Cmd::Put { key, .. } => Some((
            key,
            security::common::OP_WRITE | security::common::OP_CREATE,
        )),
        Cmd::Get { key, .. } => Some((key, security::common::OP_READ)),
        Cmd::Repair { key } => Some((key, security::common::OP_WRITE)),
        Cmd::Scrub { key } => Some((key, security::common::OP_READ)),
        _ => None,
    };
    if let Some((key, operation)) = cli_access {
        let privileged = v6
            .meta
            .store
            .get(key)
            .await
            .and_then(|m| m.fs)
            .is_some_and(|m| m.privileged);
        if !v6.security.check(key, operation, privileged) {
            anyhow::bail!("Kagi object policy denied CLI operation");
        }
    }
    match cli.command {
        Cmd::Audit => unreachable!("handled before runtime startup"),
        Cmd::Serve => {
            #[cfg(all(feature = "ebpf", target_os = "linux"))]
            let _kernel_guard = if cfg.security.kernel.enabled {
                Some(security_ebpf::start(v6.security.clone())?)
            } else {
                None
            };
            #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
            if cfg.security.kernel.enabled {
                anyhow::bail!("kernel security requires Linux and --features ebpf");
            }
            tokio::spawn(runtime_security::audit_loop(v6.clone()));
            fs::create_dir_all(&cfg.data_root)?;
            tokio::spawn(v6.meta.clone().run());
            tokio::spawn(run_cluster_controller(v6.clone(), cfg.clone()));
            tokio::spawn(send_heartbeats(v6.clone(), cfg.clone()));
            tokio::spawn(run_garbage_collector(v6.clone()));
            tokio::spawn(run_snapshot_controller(v6.clone()));
            tokio::spawn(run_background_scrubber(v6.clone()));
            tokio::spawn(run_rebalancer(v6.clone()));
            tokio::spawn(gossip_fs_index(v6.clone()));
            tokio::spawn(sync_pq_keyring(v6.clone()));
            if v6.telemetry.config().enabled {
                tokio::spawn(run_telemetry_sampler(v6.clone()));
            }
            #[cfg(feature = "quic")]
            if cfg.cluster.transport.prefer_quic {
                if let Some(endpoint) = cfg
                    .cluster
                    .hosts
                    .iter()
                    .find(|host| host.id == cfg.local_host)
                    .and_then(|host| host.quic_endpoint.as_deref())
                {
                    let address: std::net::SocketAddr = endpoint
                        .parse()
                        .with_context(|| format!("invalid local QUIC endpoint {endpoint}"))?;
                    let tls_config = cfg
                        .tls
                        .as_ref()
                        .context("QUIC listener requires node TLS configuration")?;
                    // QUIC v1 is TLS 1.3 only, regardless of the HTTPS compatibility policy.
                    let server_tls = tls::server_config(&tls_config.cert, &tls_config.key, false)?;
                    let quic_state = v6.data.clone();
                    let log_path = cfg.web_console.log_path.clone();
                    let node = cfg.local_host.clone();
                    tokio::spawn(async move {
                        webui::append_log(
                            &log_path,
                            &node,
                            &format!("Kagi QUIC data plane listening on {address}"),
                        );
                        if let Err(error) =
                            cluster::serve_quic(quic_state, address, server_tls).await
                        {
                            webui::append_log(
                                &log_path,
                                &node,
                                &format!("Kagi QUIC data plane stopped: {error}"),
                            );
                        }
                    });
                }
            }
            if let Some(s3_config) = &cfg.s3 {
                let router = s3::router(v6.clone(), s3_config.clone())?;
                let address: std::net::SocketAddr = s3_config.listen.parse()?;
                if let Some(tls_config) = &cfg.tls {
                    let tls = tls::server_config(
                        &tls_config.cert,
                        &tls_config.key,
                        tls_config.allow_tls12,
                    )?;
                    tokio::spawn(async move {
                        if let Err(error) = axum_server::bind_rustls(
                            address,
                            axum_server::tls_rustls::RustlsConfig::from_config(tls),
                        )
                        .serve(router.into_make_service())
                        .await
                        {
                            eprintln!("S3 listener stopped: {error}");
                        }
                    });
                } else {
                    anyhow::ensure!(
                        address.ip().is_loopback(),
                        "S3 requires TLS unless bound to loopback"
                    );
                    let listener = TcpListener::bind(address).await?;
                    tokio::spawn(async move {
                        if let Err(error) = axum::serve(listener, router).await {
                            eprintln!("S3 listener stopped: {error}");
                        }
                    });
                }
            }
            let public = Router::new()
                .route("/v1/monitor/events", get(runtime_security::history))
                .route("/v1/monitor/stream", get(runtime_security::stream))
                .route("/v1/monitor/status", get(runtime_security::status))
                .route("/v1/monitor/audit", get(runtime_security::audit))
                .route("/v1/monitor/logs", get(ui_logs))
                .route("/v1/object/*key", put(v6_put).get(v6_get).delete(v6_delete))
                .route(
                    "/v1/object-version/:version/*key",
                    get(v6_get_version).delete(v6_delete_version),
                )
                .route("/v1/object-versions/*key", get(v6_versions))
                .route("/v1/metadata/*key", get(meta_get))
                .route("/v1/fs/mkdir/*key", axum::routing::post(fs_mkdir))
                .route("/v1/fs/index", get(fs_index_get))
                .route("/v1/fs/acl/*key", put(fs_set_acl))
                .route("/v1/fs/reconstruct/*key", get(fs_reconstruct))
                .route("/v1/identity/:user", get(identity_resolve))
                .route(
                    "/internal/v1/fs-index/merge",
                    axum::routing::post(fs_index_merge),
                )
                .route("/internal/v1/raft/vote", axum::routing::post(raft_vote))
                .route("/internal/v1/raft/append", axum::routing::post(raft_append))
                .route("/v1/raft/status", get(raft_status))
                .route(
                    "/v1/raft/membership",
                    axum::routing::post(membership_change),
                )
                .route("/v1/pq/keys", get(pq_keys_get))
                .route("/v1/pq/rotate", axum::routing::post(pq_rotate))
                .route("/v1/pq/revoke", axum::routing::post(pq_revoke))
                .route(
                    "/internal/v1/health/heartbeat",
                    axum::routing::post(heartbeat_in),
                )
                .route("/internal/v1/gc/delete", axum::routing::post(gc_delete_in))
                .route("/v1/gc/status", get(gc_status))
                .route("/v1/snapshots", get(snapshot_list).post(snapshot_create))
                .route("/v1/snapshots/:id", get(snapshot_get))
                .route(
                    "/v1/snapshots/:id/archive",
                    axum::routing::post(snapshot_archive),
                )
                .route("/v1/snapshots/:id/object/*key", get(snapshot_object_get))
                .route("/v1/maintenance/status", get(maintenance_status))
                .route("/v1/volumes", get(volume_list).post(volume_create))
                .route("/v1/volumes/:id", get(volume_get).delete(volume_delete))
                .route("/v1/volumes/:id/info", get(volume_info))
                .route("/v1/volumes/:id/data/:offset/:length", get(volume_read))
                .route("/v1/volumes/:id/data/:offset", put(volume_write))
                .route("/v1/volumes/:id/read-only", put(volume_readonly))
                .route("/v1/volumes/:id/resize", put(volume_resize))
                .route("/v1/volumes/:id/unmap/:offset/:length", put(volume_unmap))
                .route("/v1/volumes/:id/pr", get(volume_pr_in).put(volume_pr_out))
                .route("/v1/capacity", get(capacity_get))
                .route("/v1/capacity/:host", axum::routing::post(capacity_add))
                .route("/v1/health", get(health_get))
                .route(
                    "/v1/health/clear/*resource",
                    axum::routing::post(health_clear),
                )
                .route("/", get(kagi_root))
                .route("/ui", get(kagi_ui))
                .route("/ui/api/summary", get(ui_summary))
                .route("/ui/api/telemetry", get(ui_telemetry))
                .route("/ui/api/disk/:disk/tune", axum::routing::post(ui_disk_tune))
                .route("/ui/api/objects", get(ui_objects))
                .route("/ui/api/object/*key", get(ui_object))
                .route("/ui/api/logs", get(ui_logs))
                .route("/ui/api/buckets", get(ui_buckets).post(ui_bucket_put))
                .route("/internal/v1/ui/node", get(internal_ui_node))
                .route("/internal/v1/ui/telemetry", get(internal_ui_telemetry))
                .route("/internal/v1/ui/logs", get(internal_ui_logs))
                .with_state(v6.clone());
            #[cfg(feature = "scsi-target")]
            let public = public.merge(
                Router::new()
                    .route("/v1/volumes/:id/pr/cdb", axum::routing::post(volume_pr_cdb))
                    .with_state(v6.clone()),
            );
            let maintenance = Router::new()
                .route("/v1/repair/*key", put(user_repair))
                .route("/v1/scrub/*key", get(user_scrub))
                .with_state(v6.clone());
            let app = public.merge(maintenance).merge(internal_router(st)).layer(
                axum::middleware::from_fn_with_state(v6.clone(), runtime_security::gate),
            );
            webui::append_log(
                &cfg.web_console.log_path,
                &cfg.local_host,
                &format!(
                    "Kagi node listening on {}{}",
                    cfg.listen,
                    if cfg.tls.is_some() {
                        " with native TLS"
                    } else {
                        ""
                    }
                ),
            );
            println!(
                "Kagi node {} listening {}{} (console: /ui)",
                cfg.local_host,
                cfg.listen,
                if cfg.tls.is_some() { " TLS" } else { "" }
            );
            if let Some(tls_config) = &cfg.tls {
                let address: std::net::SocketAddr = cfg.listen.parse()?;
                let rustls =
                    tls::server_config(&tls_config.cert, &tls_config.key, tls_config.allow_tls12)?;
                let rustls = axum_server::tls_rustls::RustlsConfig::from_config(rustls);
                axum_server::bind_rustls(address, rustls)
                    .serve(app.into_make_service())
                    .await?;
            } else {
                let listener = TcpListener::bind(&cfg.listen).await?;
                axum::serve(listener, app).await?;
            }
        }
        Cmd::Membership {
            action,
            scope,
            id,
            endpoint,
            site,
            rack,
            pq_public_key,
        } => {
            if !v6.meta.is_leader().await {
                anyhow::bail!("membership changes must be run on the current Raft leader")
            }
            let state = v6.meta.store.state().await;
            let mut m = if let Some(x) = state.membership {
                x
            } else {
                let mut voters = BTreeMap::new();
                voters.insert(
                    cfg.metadata.node_id.clone(),
                    RaftPeer {
                        id: cfg.metadata.node_id.clone(),
                        endpoint: format!("http://{}", cfg.listen),
                        site: None,
                        rack: None,
                        pq_public_key_b64: None,
                    },
                );
                for p in &cfg.metadata.peers {
                    voters.insert(p.id.clone(), p.clone());
                }
                Membership { voters }
            };
            match(action.as_str(),scope.as_str()) {
                ("add","node")=> {
                    let ep=endpoint.context("--endpoint required")? ;
                    let pk=if let Some(path)=pq_public_key {
                        Some(pq::public_key_b64(&path)?)
                    }
                    else {
                        None
                    } ;
                    let peer=RaftPeer {
                        id:id.clone(),endpoint:ep,site,rack,pq_public_key_b64:pk
                    } ;
                    for_member_add(&v6,&mut m,Some(peer)).await? ;
                },
                ("remove","node")=> {
                    m.voters.remove(&id) ;
                },
                ("remove","rack")=>m.voters.retain(|_,p|p.rack.as_deref()!=Some(id.as_str())),
                ("remove","site")=>m.voters.retain(|_,p|p.site.as_deref()!=Some(id.as_str())),
                _=>anyhow::bail!("CLI supports add node, remove node/rack/site; use POST /v1/raft/membership for batched rack/site adds")
            }
            let (joint, final_i) = v6.meta.change_membership(m).await?;
            println!(
                "joint consensus committed at {joint}; stable membership committed at {final_i}"
            );
        }
        Cmd::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "hosts": &cfg.cluster.hosts,
                    "transport": &cfg.cluster.transport,
                    "join_key_configured": st.join_key_b64.is_some(),
                    "erasure_acceleration": st.erasure.acceleration_status(),
                    "erasure_metrics": st.erasure.metrics_snapshot(),
                    "tls": cfg.tls.as_ref().map(|tls_config| tls::policy_summary(tls_config.allow_tls12)),
                }))?
            )
        }
        Cmd::Put { key, file } => {
            let previous = v6.meta.store.get(&key).await;
            if let Some(previous) = &previous {
                st.manifests
                    .write()
                    .await
                    .insert(key.clone(), previous.clone());
            }
            let body = fs::read(file)?;
            let m = if let Some(previous) = previous {
                if let Some(metadata) = previous.fs {
                    put_filesystem_object(
                        &st,
                        &key,
                        &body,
                        Some(&v6.health),
                        previous.worm,
                        metadata,
                    )
                    .await?
                } else {
                    put_object(&st, &key, &body).await?
                }
            } else {
                put_object(&st, &key, &body).await?
            };
            v6.meta
                .propose(MetadataCommand::PutManifest {
                    key,
                    manifest: m.clone(),
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&m)?)
        }
        Cmd::Get { key, output } => {
            if let Some(m) = v6.meta.store.get(&key).await {
                st.manifests.write().await.insert(key.clone(), m);
            }
            fs::write(output, get_object(&st, &key).await?)?
        }
        Cmd::Repair { key } => println!(
            "{}",
            serde_json::to_string_pretty(&repair_object(&st, &key).await?)?
        ),
        Cmd::Scrub { key } => println!(
            "{}",
            serde_json::to_string_pretty(&scrub_object(&st, &key).await?)?
        ),
        Cmd::ClearHealth { resource } => {
            if !v6.health.clear_flap(&resource).await {
                anyhow::bail!("unknown resource {resource}")
            }
            println!("cleared flap quarantine for {resource}");
        }
        Cmd::Locate { key } => {
            let mut h = blake3::Hasher::new();
            h.update(cfg.cluster.id.as_bytes());
            h.update(b"\0");
            h.update(key.as_bytes());
            let b = h.finalize();
            let pos = u64::from_le_bytes(b.as_bytes()[0..8].try_into().unwrap());
            println!(
                "{}",
                serde_json::to_string_pretty(&placement(
                    &cfg.cluster,
                    pos,
                    cfg.cluster.replication
                )?)?
            );
        }
        Cmd::GeneratePqIdentity { .. } => {
            unreachable!("GeneratePqIdentity is handled before configuration loading")
        }
        Cmd::WebUserAdd { .. } => {
            unreachable!("WebUserAdd is handled immediately after configuration loading")
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../security_integration_tests.rs"]
mod security_integration_tests;

#[cfg(test)]
mod documented_config_tests {
    use super::*;

    /// The canonical example is executable documentation: every key must remain
    /// accepted by the same deserializer used in production.
    #[test]
    fn canonical_node_example_deserializes() {
        let input = include_str!("../../examples/node-v6.example.yaml");
        let config: NodeConfig =
            serde_saphyr::from_str(input).expect("examples/node-v6.example.yaml must stay valid");
        assert_eq!(config.local_host, "host-a1");
        assert_eq!(config.cluster.transport.quic_min_bytes, 65_536);
        assert_eq!(config.telemetry.sample_interval_ms, 1_000);
    }

    /// Unknown top-level keys are rejected rather than silently turning a typo
    /// into an unexpected default.
    #[test]
    fn unknown_node_option_is_rejected() {
        let input = include_str!("../../examples/node-v6.example.yaml");
        let mutated = format!("{input}\nnot_a_kagi_option: true\n");
        assert!(serde_saphyr::from_str::<NodeConfig>(&mutated).is_err());
    }
}
