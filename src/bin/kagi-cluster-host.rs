// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi cluster daemon and administrative CLI.
//!
//! This is the runtime composition root. It loads and validates node configuration, starts
//! the Raft metadata service and object data plane, exposes public/admin/internal HTTP routes,
//! runs health and maintenance loops, and hosts the operations console. CLI subcommands use
//! the same state and validation rules as the long-running daemon wherever practical.

// Full Kagi cluster daemon and administrative CLI for distributed storage nodes.
#[path = "../block.rs"]
mod block;
#[path = "../cluster.rs"]
mod cluster;
#[path = "../erasure.rs"]
mod erasure;
#[path = "../filesystem.rs"]
mod filesystem;
#[path = "../maintenance.rs"]
mod maintenance;
#[path = "../monitoring.rs"]
mod monitoring;
#[path = "../pq.rs"]
mod pq;
#[path = "../raftmeta.rs"]
mod raftmeta;
#[path = "../recovery.rs"]
mod recovery;
#[path = "../runtime_security.rs"]
mod runtime_security;
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
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock};
use webui::{ConsoleRole, WebConsoleConfig};
#[derive(Parser)]
// ---- CLI, node configuration, and security bootstrap -------------------------
struct Cli {
    #[arg(short, long, default_value = "/etc/kagi/node.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
/// Supported Cmd states or operations.
enum Cmd {
    Serve,
    Status,
    Audit,
    Put {
        key: String,
        file: PathBuf,
    },
    Get {
        key: String,
        output: PathBuf,
    },
    Repair {
        key: String,
    },
    Scrub {
        key: String,
    },
    Locate {
        key: String,
    },
    ClearHealth {
        resource: String,
    },
    GeneratePqIdentity {
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        secret: PathBuf,
    },
    WebUserAdd {
        username: String,
        #[arg(long, default_value = "viewer")]
        role: String,
        #[arg(long)]
        password_file: PathBuf,
    },
    Membership {
        action: String,
        scope: String,
        id: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        rack: Option<String>,
        #[arg(long)]
        pq_public_key: Option<PathBuf>,
    },
}
#[derive(Clone, Deserialize)]
/// Kagi state or configuration used by the NodeConfig path.
struct NodeConfig {
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
/// Kagi state or configuration used by the MetadataConfig path.
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
/// Kagi state or configuration used by the GarbageCollectionConfig path.
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
/// Kagi state or configuration used by the SnapshotConfig path.
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
/// Kagi state or configuration used by the TlsConfig path.
struct TlsConfig {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    /// Compatibility mode. Native Kagi listeners otherwise require TLS 1.3.
    #[serde(default)]
    allow_tls12: bool,
}
#[derive(Clone, Deserialize)]
/// Kagi state or configuration used by the PostQuantumConfig path.
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
    Ok(serde_yaml::from_str(&fs::read_to_string(p)?)?)
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
            .tls_version_min(if t.allow_tls12 {
                reqwest::tls::Version::TLS_1_2
            } else {
                reqwest::tls::Version::TLS_1_3
            })
            .tls_version_max(reqwest::tls::Version::TLS_1_3);
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
) -> ClusterState {
    ClusterState {
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
    }
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
            MetadataCommand::PutManifest {
                key: key.clone(),
                manifest: m.clone(),
            },
        )
        .await
        {
            Ok(_) => {
                index_manifest(&st, &m).await;
                Json(m).into_response()
            }
            Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the index manifest step and keeps its validation and state transitions visible at the call site.
async fn index_manifest(st: &V6State, m: &ObjectManifest) {
    if let Some(fs) = &m.fs {
        let _ = st
            .fs_index
            .upsert(IndexEntry {
                path: fs.path.clone(),
                key: m.key.clone(),
                object_id: m.object_id.clone(),
                version: m.version,
                object_type: fs.object_type.clone(),
                parent_key: fs.parent_key.clone(),
                acl: fs.acl.clone(),
                updated_ms: now_ms(),
                origin: st.data.local_host.clone(),
            })
            .await;
    }
}
/// Implements the fs mkdir step and keeps its validation and state transitions visible at the call site.
async fn fs_mkdir(
    State(st): State<V6State>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MkdirRequest>,
) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let acl = req.acl.unwrap_or_else(|| default_acl(&headers));
    let parent_key = parent_key_for(&key);
    let parent = match &parent_key {
        Some(p) => st.meta.store.get(p).await,
        None => None,
    };
    if let Some(p) = &parent {
        if p.fs.as_ref().map(|f| f.object_type.clone()) != Some(FsObjectType::Directory) {
            return (StatusCode::CONFLICT, "parent is not a directory").into_response();
        }
        let id = AuthIdentity::from_headers(&headers);
        if !id.allows(&p.fs.as_ref().unwrap().acl, "write_data")
            && !id.allows(&p.fs.as_ref().unwrap().acl, "append_data")
        {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    let old_privileged = st
        .meta
        .store
        .get(&key)
        .await
        .and_then(|m| m.fs)
        .is_some_and(|m| m.privileged);
    let privileged = headers
        .get("x-kagi-privileged")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "true")
        .unwrap_or(old_privileged);
    let fs = FsMetadata {
        privileged,
        object_type: FsObjectType::Directory,
        name: name_for(&key),
        path: format!("/{}", key.trim_matches('/')),
        parent_object_id: parent.as_ref().map(|m| m.object_id.clone()),
        parent_key: parent_key.clone(),
        children: vec![],
        contents: vec![],
        acl,
    };
    match put_filesystem_object(
        &st.data,
        &key,
        &[],
        Some(&st.health),
        WormPolicy::default(),
        fs,
    )
    .await
    {
        Ok(m) => match commit_child_parent(&st, m.clone()).await {
            Ok(_) => (StatusCode::CREATED, Json(m)).into_response(),
            Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the fs index get step and keeps its validation and state transitions visible at the call site.
async fn fs_index_get(State(st): State<V6State>) -> impl IntoResponse {
    Json(st.fs_index.snapshot().await)
}
/// Implements the fs index merge step and keeps its validation and state transitions visible at the call site.
async fn fs_index_merge(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Json(snap): Json<IndexSnapshot>,
) -> impl IntoResponse {
    if !verify_json(&st, &headers, "/internal/v1/fs-index/merge", &snap).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !request_authorized(&st.data.cfg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match st.fs_index.merge(snap).await {
        Ok(n) => Json(serde_json::json!( {
            "merged":n
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
/// Implements the fs reconstruct step and keeps its validation and state transitions visible at the call site.
async fn fs_reconstruct(State(st): State<V6State>, Path(key): Path<String>) -> impl IntoResponse {
    let state = st.meta.store.state().await;
    let Some(leaf) = state.manifests.get(&key) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match reconstruct_bottom_up(leaf, &state.manifests) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::CONFLICT, e.to_string()).into_response(),
    }
}
/// Implements the gossip fs index step and keeps its validation and state transitions visible at the call site.
async fn gossip_fs_index(st: V6State) {
    let mut t = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        t.tick().await;
        let snap = st.fs_index.snapshot().await;
        for h in &st.data.cfg.hosts {
            if h.id == st.data.local_host {
                continue;
            }
            if let Ok((body, auth)) =
                signed_json(&st.data, "POST", "/internal/v1/fs-index/merge", &snap)
            {
                let b = st
                    .data
                    .client
                    .post(format!(
                        "{}/internal/v1/fs-index/merge",
                        h.endpoint.trim_end_matches('/')
                    ))
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body);
                let _ = pq::apply_headers(b, auth).send().await;
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolvedIdentity {
    user: String,
    uid: Option<String>,
    gids: Vec<String>,
    ad_sid: Option<String>,
}
/// Implements the identity resolve step and keeps its validation and state transitions visible at the call site.
async fn identity_resolve(Path(user): Path<String>) -> impl IntoResponse {
    // Uses Linux NSS, so local /etc/passwd, LDAP/NIS, SSSD and winbind-backed AD users resolve identically.
    let uid = Command::new("id")
        .args(["-u", &user])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let gids = Command::new("id")
        .args(["-G", &user])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if uid.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Samba/winbind exposes the canonical AD SID when installed; SSSD-only installations can continue to use stable mapped UID/GID ACL principals.
    let ad_sid = Command::new("wbinfo")
        .arg("--name-to-sid")
        .arg(&user)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .map(String::from)
        });
    Json(ResolvedIdentity {
        user,
        uid,
        gids,
        ad_sid,
    })
    .into_response()
}
#[derive(Debug, Clone, Serialize, Deserialize)] // ---- Joint-consensus membership and post-quantum key administration ----------
/// Kagi state or configuration used by the MembershipRequest path.
struct MembershipRequest {
    action: String,
    scope: String,
    id: String,
    #[serde(default)]
    members: Vec<RaftPeer>,
}
/// Implements the membership change step and keeps its validation and state transitions visible at the call site.
async fn membership_change(
    State(st): State<V6State>,
    Json(req): Json<MembershipRequest>,
) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let state = st.meta.store.state().await;
    let mut m = if let Some(x) = state.membership {
        x
    } else {
        let mut voters = BTreeMap::new();
        voters.insert(
            st.data.local_host.clone(),
            RaftPeer {
                id: st.data.local_host.clone(),
                endpoint: String::new(),
                site: None,
                rack: None,
                pq_public_key_b64: None,
            },
        );
        for p in &st.meta.status().await.voters {
            if p != &st.data.local_host {
                if let Some(h) = st.data.cfg.hosts.iter().find(|h| &h.id == p) {
                    voters.insert(
                        p.clone(),
                        RaftPeer {
                            id: p.clone(),
                            endpoint: h.endpoint.clone(),
                            site: h.site.clone(),
                            rack: h.rack.clone(),
                            pq_public_key_b64: None,
                        },
                    );
                }
            }
        }
        Membership { voters }
    };
    let changed: Result<()> = match (req.action.as_str(), req.scope.as_str()) {
        ("add", "node") => for_member_add(&st, &mut m, req.members.into_iter().next()).await,
        ("add", "rack") | ("add", "site") => {
            for x in req.members {
                if let Err(e) = for_member_add(&st, &mut m, Some(x)).await {
                    return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
                }
            }
            Ok(())
        }
        ("remove", "node") => {
            m.voters.remove(&req.id);
            Ok(())
        }
        ("remove", "rack") => {
            m.voters
                .retain(|_, p| p.rack.as_deref() != Some(req.id.as_str()));
            Ok(())
        }
        ("remove", "site") => {
            m.voters
                .retain(|_, p| p.site.as_deref() != Some(req.id.as_str()));
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "action must be add/remove and scope node/rack/site"
        )),
    };
    if let Err(e) = changed {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if m.voters.is_empty() {
        return (StatusCode::BAD_REQUEST, "membership may not be empty").into_response();
    }
    match st.meta.change_membership(m).await {
        Ok((a, b)) => Json(serde_json::json!( {
            "joint_index":a,"final_index":b
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the for member add step and keeps its validation and state transitions visible at the call site.
async fn for_member_add(st: &V6State, m: &mut Membership, member: Option<RaftPeer>) -> Result<()> {
    let p = member.context("member required")?;
    if p.endpoint.is_empty() {
        anyhow::bail!("member endpoint required")
    };
    if let Some(pubk) = &p.pq_public_key_b64 {
        let kid = pq::key_id_from_public_b64(pubk)?;
        let key = TrustedPqKey {
            node_id: p.id.clone(),
            key_id: kid,
            public_key_b64: pubk.clone(),
            not_before_ms: now_ms(),
            not_after_ms: None,
            revoked: false,
        };
        st.meta
            .propose(MetadataCommand::RotatePqKey {
                key,
                retiring: None,
            })
            .await?;
    }
    m.voters.insert(p.id.clone(), p);
    Ok(())
}
#[derive(Debug, Clone, Serialize, Deserialize)] // ML-DSA trust rotation/revocation is committed through Raft so every voter
                                                // evaluates the same active and retiring key set.
struct RotatePqRequest {
    node_id: String,
    public_key_b64: String,
    #[serde(default)]
    retire_key_id: Option<String>,
    #[serde(default = "default_pq_grace")]
    grace_ms: u64,
}
/// Implements the default pq grace step and keeps its validation and state transitions visible at the call site.
fn default_pq_grace() -> u64 {
    300_000
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevokePqRequest {
    key_id: String,
}
/// Implements the pq rotate step and keeps its validation and state transitions visible at the call site.
async fn pq_rotate(
    State(st): State<V6State>,
    Json(req): Json<RotatePqRequest>,
) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let kid = match pq::key_id_from_public_b64(&req.public_key_b64) {
        Ok(x) => x,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let now = now_ms();
    let key = TrustedPqKey {
        node_id: req.node_id,
        key_id: kid.clone(),
        public_key_b64: req.public_key_b64,
        not_before_ms: now,
        not_after_ms: None,
        revoked: false,
    };
    let retire_after = req
        .retire_key_id
        .as_ref()
        .map(|_| now.saturating_add(req.grace_ms as u128));
    let retiring = if let Some(oldid) = &req.retire_key_id {
        let mut old = st.data.pq_keys.keys.read().await.get(oldid).cloned();
        if let Some(ref mut k) = old {
            k.not_after_ms = retire_after;
        }
        old
    } else {
        None
    };
    match st
        .meta
        .propose(MetadataCommand::RotatePqKey { key, retiring })
        .await
    {
        Ok(i) => Json(serde_json::json!( {
            "key_id":kid,"raft_index":i,"old_key_valid_until_ms":retire_after
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the pq revoke step and keeps its validation and state transitions visible at the call site.
async fn pq_revoke(
    State(st): State<V6State>,
    Json(req): Json<RevokePqRequest>,
) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    match st
        .meta
        .propose(MetadataCommand::RevokePqKey {
            key_id: req.key_id,
            revoked_at_ms: now_ms(),
        })
        .await
    {
        Ok(i) => Json(serde_json::json!( {
            "raft_index":i
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the pq keys get step and keeps its validation and state transitions visible at the call site.
async fn pq_keys_get(State(st): State<V6State>) -> impl IntoResponse {
    Json(st.meta.store.state().await.pq_keys)
}
/// Implements the raft vote step and keeps its validation and state transitions visible at the call site.
async fn raft_vote(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VoteRequest>,
) -> impl IntoResponse {
    if !verify_json(&st, &headers, "/internal/v1/raft/vote", &req).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !request_authorized(&st.data.cfg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match st.meta.request_vote(req).await {
        Ok(x) => Json(x).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
/// Implements the raft append step and keeps its validation and state transitions visible at the call site.
async fn raft_append(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AppendRequest>,
) -> impl IntoResponse {
    if !verify_json(&st, &headers, "/internal/v1/raft/append", &req).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !request_authorized(&st.data.cfg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match st.meta.append_entries(req).await {
        Ok(x) => Json(x).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
/// Implements the raft status step and keeps its validation and state transitions visible at the call site.
async fn raft_status(State(st): State<V6State>) -> impl IntoResponse {
    Json(st.meta.status().await)
}
/// Implements the meta get step and keeps its validation and state transitions visible at the call site.
async fn meta_get(State(st): State<V6State>, Path(key): Path<String>) -> impl IntoResponse {
    match st.meta.store.get(&key).await {
        Some(m) => Json(m).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
/// Implements the v6 put step and keeps its validation and state transitions visible at the call site.
async fn v6_put(
    State(st): State<V6State>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            format!(
                "not raft leader; status={:?}",
                st.meta.status().await.leader
            ),
        )
            .into_response();
    }
    let explicit_worm = headers.contains_key("x-kagi-retention-mode")
        || headers.contains_key("x-kagi-retain-until-ms")
        || headers.contains_key("x-kagi-legal-hold");
    let requested_mode = match headers
        .get("x-kagi-retention-mode")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
    {
        "governance" => RetentionMode::Governance,
        "compliance" => RetentionMode::Compliance,
        _ => RetentionMode::None,
    };
    let requested_until = headers
        .get("x-kagi-retain-until-ms")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u128>().ok());
    let requested_hold = headers
        .get("x-kagi-legal-hold")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);
    let bucket_name = key.trim_matches('/').split('/').next().unwrap_or("");
    let bucket_default = st
        .meta
        .store
        .state()
        .await
        .buckets
        .get(bucket_name)
        .map(|b| b.default_worm.clone())
        .unwrap_or_default();
    let worm = if explicit_worm {
        WormPolicy {
            mode: requested_mode,
            retain_until_unix_ms: requested_until,
            legal_hold: requested_hold,
        }
    } else {
        bucket_default
    };
    let parent_key = parent_key_for(&key);
    let parent = match &parent_key {
        Some(p) => st.meta.store.get(p).await,
        None => None,
    };
    if let Some(p) = &parent {
        if let Some(pfs) = &p.fs {
            let ident = AuthIdentity::from_headers(&headers);
            if !ident.allows(&pfs.acl, "write_data") && !ident.allows(&pfs.acl, "append_data") {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }
    let old_privileged = st
        .meta
        .store
        .get(&key)
        .await
        .and_then(|m| m.fs)
        .is_some_and(|m| m.privileged);
    let privileged = headers
        .get("x-kagi-privileged")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "true")
        .unwrap_or(old_privileged);
    let fs = FsMetadata {
        privileged,
        object_type: FsObjectType::File,
        name: name_for(&key),
        path: format!("/{}", key.trim_matches('/')),
        parent_object_id: parent.as_ref().map(|m| m.object_id.clone()),
        parent_key,
        children: vec![],
        contents: vec![],
        acl: default_acl(&headers),
    };
    let data = effective_data(&st).await;
    match put_filesystem_object(&data, &key, &body, Some(&st.health), worm, fs).await {
        Ok(m) => match commit_child_parent(&st, m.clone()).await {
            Ok(_) => (StatusCode::OK, Json(m)).into_response(),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("data written but namespace transaction failed: {e}"),
            )
                .into_response(),
        },
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the v6 get step and keeps its validation and state transitions visible at the call site.
async fn v6_get(
    State(st): State<V6State>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let Some(m) = st.meta.store.get(&key).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(fs) = &m.fs {
        if !AuthIdentity::from_headers(&headers).allows(&fs.acl, "read_data") {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    st.data.manifests.write().await.insert(key.clone(), m);
    api_get(State(st.data), Path(key)).await.into_response()
}
/// Implements the v6 get version step and keeps its validation and state transitions visible at the call site.
async fn v6_get_version(
    State(st): State<V6State>,
    Path((version, key)): Path<(u64, String)>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    match st.meta.store.get_version(&key, version).await {
        Some(m) => match get_object_version(&st.data, &m).await {
            Ok(v) => (StatusCode::OK, v).into_response(),
            Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
/// Implements the v6 versions step and keeps its validation and state transitions visible at the call site.
async fn v6_versions(State(st): State<V6State>, Path(key): Path<String>) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    Json(st.meta.store.versions(&key).await).into_response()
}
/// Implements the v6 delete step and keeps its validation and state transitions visible at the call site.
async fn v6_delete(
    State(st): State<V6State>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    if let Some(m) = st.meta.store.get(&key).await {
        if let Some(fs) = &m.fs {
            if !AuthIdentity::from_headers(&headers).allows(&fs.acl, "delete") {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }
    let v = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    match committed(
        &st,
        MetadataCommand::PutDeleteMarker {
            key,
            version: v,
            created_unix_ms: v as u128 / 1_000_000,
        },
    )
    .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the v6 delete version step and keeps its validation and state transitions visible at the call site.
async fn v6_delete_version(
    State(st): State<V6State>,
    Path((version, key)): Path<(u64, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let Some(m) = st.meta.store.get_version(&key, version).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let bypass = headers
        .get("x-kagi-bypass-governance")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if m.worm.legal_hold {
        return (StatusCode::LOCKED, "version is under legal hold").into_response();
    }
    if m.worm
        .retain_until_unix_ms
        .map(|x| x > now)
        .unwrap_or(false)
    {
        match m.worm.mode {
            RetentionMode::Compliance => {
                return (StatusCode::LOCKED, "compliance retention is active").into_response()
            }
            RetentionMode::Governance if !bypass => {
                return (
                    StatusCode::LOCKED,
                    "governance retention is active; privileged bypass required",
                )
                    .into_response()
            }
            _ => {}
        }
    }
    let deleted_at = now;
    let eligible_after = deleted_at.saturating_add(st.gc.grace_period_ms as u128);
    match committed(
        &st,
        MetadataCommand::DeleteManifest {
            key,
            version,
            deleted_at_unix_ms: deleted_at,
            eligible_after_unix_ms: eligible_after,
        },
    )
    .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume list step and keeps its validation and state transitions visible at the call site.
async fn volume_list(State(st): State<V6State>) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    Json(st.meta.store.state().await.volumes).into_response()
}
/// Implements the volume get step and keeps its validation and state transitions visible at the call site.
async fn volume_get(State(st): State<V6State>, Path(id): Path<String>) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    match st.meta.store.state().await.volumes.get(&id).cloned() {
        Some(v) => Json(v).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
/// Implements the volume create step and keeps its validation and state transitions visible at the call site.
async fn volume_create(
    State(st): State<V6State>,
    Json(req): Json<VolumeCreate>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    if let Err(e) = block::validate_create(&req) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let id = req
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let state = st.meta.store.state().await;
    if state.volumes.contains_key(&id) {
        return (StatusCode::CONFLICT, "volume already exists").into_response();
    }
    drop(state);
    let v = VolumeRecord {
        id: id.clone(),
        name: req.name,
        size_bytes: req.size_bytes,
        logical_block_bytes: req.logical_block_bytes,
        extent_bytes: req.extent_bytes,
        generation: 0,
        created_at_unix_ms: now_ms(),
        read_only: false,
        thin_provisioned: req.thin_provisioned,
        scsi: block::make_scsi_identity(&id),
        presentations: req.presentations,
        extents: BTreeMap::new(),
        persistent_reservation: Default::default(),
    };
    match committed(&st, MetadataCommand::CreateVolume { volume: v.clone() }).await {
        Ok(i) => (
            StatusCode::CREATED,
            Json(serde_json::json!( {
                "volume":v,"raft_index":i
            }
            )),
        )
            .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume read step and keeps its validation and state transitions visible at the call site.
async fn volume_read(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Path((id, offset, length)): Path<(String, u64, u64)>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let Some(v) = st.meta.store.state().await.volumes.get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let initiator = headers
        .get("x-kagi-initiator")
        .and_then(|x| x.to_str().ok());
    if !block::pr_allows_read(&v.persistent_reservation, initiator) {
        return (StatusCode::CONFLICT, "SCSI reservation conflict").into_response();
    }
    let data = effective_data(&st).await;
    match block::read_range(&data, &v, offset, length).await {
        Ok(b) => (StatusCode::OK, b).into_response(),
        Err(e) => (StatusCode::RANGE_NOT_SATISFIABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume write step and keeps its validation and state transitions visible at the call site.
async fn volume_write(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Path((id, offset)): Path<(String, u64)>,
    body: Bytes,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let _serial = st.namespace_lock.lock().await;
    let Some(v) = st.meta.store.state().await.volumes.get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let initiator = headers
        .get("x-kagi-initiator")
        .and_then(|x| x.to_str().ok());
    if !block::pr_allows_write(&v.persistent_reservation, initiator) {
        return (StatusCode::CONFLICT, "SCSI reservation conflict").into_response();
    }
    let generation = v.generation.saturating_add(1);
    let data = effective_data(&st).await;
    let extents = match block::stage_write(&data, &v, offset, &body, generation).await {
        Ok(x) => x,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match committed(
        &st,
        MetadataCommand::CommitVolumeWrite {
            id: id.clone(),
            generation,
            extents,
        },
    )
    .await
    {
        Ok(i) => Json(serde_json::json!( {
            "id":id,"generation":generation,"raft_index":i,"bytes":body.len()
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume readonly step and keeps its validation and state transitions visible at the call site.
async fn volume_readonly(
    State(st): State<V6State>,
    Path(id): Path<String>,
    Json(v): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let ro = v.get("read_only").and_then(|x| x.as_bool()).unwrap_or(true);
    match committed(
        &st,
        MetadataCommand::SetVolumeReadOnly { id, read_only: ro },
    )
    .await
    {
        Ok(i) => Json(serde_json::json!( {
            "raft_index":i,"read_only":ro
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume resize step and keeps its validation and state transitions visible at the call site.
async fn volume_resize(
    State(st): State<V6State>,
    Path(id): Path<String>,
    Json(v): Json<serde_json::Value>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let Some(size) = v.get("size_bytes").and_then(|x| x.as_u64()) else {
        return (StatusCode::BAD_REQUEST, "size_bytes required").into_response();
    };
    let Some(cur) = st.meta.store.state().await.volumes.get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if size < cur.size_bytes {
        return (StatusCode::BAD_REQUEST, "online shrink is not supported").into_response();
    }
    match committed(
        &st,
        MetadataCommand::ResizeVolume {
            id,
            size_bytes: size,
        },
    )
    .await
    {
        Ok(i) => Json(serde_json::json!( {
            "raft_index":i,"size_bytes":size
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume unmap step and keeps its validation and state transitions visible at the call site.
async fn volume_unmap(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Path((id, offset, length)): Path<(String, u64, u64)>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let _serial = st.namespace_lock.lock().await;
    let Some(v) = st.meta.store.state().await.volumes.get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let initiator = headers
        .get("x-kagi-initiator")
        .and_then(|x| x.to_str().ok());
    if !block::pr_allows_write(&v.persistent_reservation, initiator) {
        return (StatusCode::CONFLICT, "SCSI reservation conflict").into_response();
    }
    let generation = v.generation.saturating_add(1);
    let data = effective_data(&st).await;
    let (remove, replace) = match block::stage_unmap(&data, &v, offset, length, generation).await {
        Ok(x) => x,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match committed(
        &st,
        MetadataCommand::UnmapVolume {
            id,
            generation,
            remove,
            replace,
        },
    )
    .await
    {
        Ok(i) => Json(serde_json::json!( {
            "raft_index":i,"generation":generation
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the volume pr in step and keeps its validation and state transitions visible at the call site.
async fn volume_pr_in(State(st): State<V6State>, Path(id): Path<String>) -> impl IntoResponse {
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    match st.meta.store.state().await.volumes.get(&id).cloned() {
        Some(v) => Json(block::PrIn {
            generation: v.persistent_reservation.generation,
            registrations: v.persistent_reservation.registrations,
            reservation: v.persistent_reservation.reservation,
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
/// Implements the volume pr out step and keeps its validation and state transitions visible at the call site.
async fn volume_pr_out(
    State(st): State<V6State>,
    Path(id): Path<String>,
    Json(op): Json<PrOut>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let _serial = st.namespace_lock.lock().await;
    let Some(v) = st.meta.store.state().await.volumes.get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut trial = v.persistent_reservation.clone();
    if let Err(e) = block::apply_pr_out(&mut trial, &op) {
        return (StatusCode::CONFLICT, e.to_string()).into_response();
    }
    match committed(
        &st,
        MetadataCommand::PersistentReserveOut {
            id,
            expected_generation: v.persistent_reservation.generation,
            op,
        },
    )
    .await
    {
        Ok(i) => Json(serde_json::json!( {
            "raft_index":i,"pr_generation":trial.generation
        }
        ))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the gc delete in step and keeps its validation and state transitions visible at the call site.
async fn gc_delete_in(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Json(req): Json<GcDeleteRequest>,
) -> impl IntoResponse {
    if !verify_json(&st, &headers, "/internal/v1/gc/delete", &req).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !request_authorized(&st.data.cfg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let status = st.meta.status().await;
    if status.term != req.term || status.leader.as_deref() != Some(req.leader_id.as_str()) {
        return (StatusCode::CONFLICT, "stale or non-leader GC fence").into_response();
    }
    let ms = st.meta.store.state().await;
    let committed = ms.applied_index >= req.fence_index
        && ms
            .garbage
            .get(&req.garbage_id)
            .map(|g| g.fence_index == req.fence_index)
            .unwrap_or(false);
    if !committed {
        return (
            StatusCode::CONFLICT,
            "GC authorization not committed/applied on this voter",
        )
            .into_response();
    }
    let p = fragment_path(
        &st.data.root,
        &req.disk,
        &req.object_id,
        req.version,
        req.fragment,
    );
    match tokio::fs::remove_file(&p).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
/// Implements the gc status step and keeps its validation and state transitions visible at the call site.
async fn gc_status(State(st): State<V6State>) -> impl IntoResponse {
    let state = st.meta.store.state().await;
    Json(state.garbage).into_response()
}
/// Implements the delete gc replica step and keeps its validation and state transitions visible at the call site.
async fn delete_gc_replica(
    st: &V6State,
    g: &GarbageRecord,
    chunk: u32,
    r: &FragmentReplica,
    term: u64,
) -> Result<()> {
    let req = GcDeleteRequest {
        term,
        leader_id: st.meta.node_id.clone(),
        garbage_id: g.id.clone(),
        fence_index: g.fence_index,
        object_id: g.manifest.object_id.clone(),
        version: g.version,
        fragment: chunk,
        disk: r.disk.clone(),
    };
    if r.host == st.data.local_host {
        let p = fragment_path(
            &st.data.root,
            &r.disk,
            &g.manifest.object_id,
            g.version,
            chunk,
        );
        match tokio::fs::remove_file(p).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    } else {
        let peer = st
            .data
            .cfg
            .hosts
            .iter()
            .find(|h| h.id == r.host)
            .context("GC replica host missing from topology")?;
        let u = format!(
            "{}/internal/v1/gc/delete",
            peer.endpoint.trim_end_matches('/')
        );
        let (body, auth) = signed_json(&st.data, "POST", "/internal/v1/gc/delete", &req)?;
        let resp = pq::apply_headers(
            st.data
                .client
                .post(u)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body),
            auth,
        )
        .send()
        .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!(
                "GC delete {}/{} chunk {} failed: {}",
                r.host,
                r.disk,
                chunk,
                resp.status()
            )
        }
    }
}
/// Implements the run garbage collector step and keeps its validation and state transitions visible at the call site.
async fn run_garbage_collector(st: V6State) {
    if !st.gc.enabled {
        return;
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(
        st.gc.interval_ms.max(1000),
    ));
    loop {
        tick.tick().await;
        if !st.meta.is_leader().await {
            continue;
        }
        let status = st.meta.status().await;
        let term = status.term;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let ms = st.meta.store.state().await;
        let pinned: std::collections::BTreeSet<(String, u64)> = ms
            .snapshots
            .values()
            .filter(|x| x.mode != SnapshotMode::Archived)
            .flat_map(|x| {
                x.objects
                    .values()
                    .map(|o| (o.source.object_id.clone(), o.version))
            })
            .collect();
        let pending = ms
            .garbage
            .into_values()
            .filter(|g| {
                g.eligible_after_unix_ms <= now
                    && !pinned.contains(&(g.manifest.object_id.clone(), g.version))
            })
            .take(st.gc.max_versions_per_cycle)
            .collect::<Vec<_>>();
        for g in pending {
            let Ok(_permit) = st
                .maintenance
                .acquire("garbage_collection", g.manifest.bytes.min(64 * 1024 * 1024))
                .await
            else {
                break;
            };
            let started = std::time::Instant::now();
            st.maintenance.charge_network(g.manifest.bytes).await;
            if !st.meta.is_leader().await || st.meta.status().await.term != term {
                break;
            }
            // Defense in depth: a queued record is never reclaimed while its captured WORM policy is active.
            if g.manifest.worm.immutable(now) {
                continue;
            }
            // Commit a per-record destructive-operation fence before touching bytes.
            // Followers must have applied this exact authorization index before accepting deletion.
            let fence_index = match st
                .meta
                .propose(MetadataCommand::AuthorizeGarbage { id: g.id.clone() })
                .await
            {
                Ok(i) => i,
                Err(_) => break,
            };
            let mut g = g;
            g.fence_index = fence_index;
            let mut err = None;
            for c in normalize_chunks(&g.manifest) {
                for r in &c.replicas {
                    if let Err(e) = delete_gc_replica(&st, &g, c.chunk, r, term).await {
                        err = Some(e.to_string());
                        break;
                    }
                }
                if err.is_some() {
                    break;
                }
            }
            if !st.meta.is_leader().await || st.meta.status().await.term != term {
                break;
            }
            match err {
                Some(error) => {
                    let _ = st
                        .meta
                        .propose(MetadataCommand::GarbageFailed {
                            id: g.id.clone(),
                            error,
                        })
                        .await;
                }
                None => {
                    let _ = st
                        .meta
                        .propose(MetadataCommand::GarbageCollected { id: g.id.clone() })
                        .await;
                }
            }
            st.maintenance.cpu_yield(started.elapsed()).await;
        }
    }
}
/// Implements the snapshot create step and keeps its validation and state transitions visible at the call site.
async fn snapshot_create(
    State(st): State<V6State>,
    Json(req): Json<SnapshotCreateRequest>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "snapshot creation requires Raft leader",
        )
            .into_response();
    }
    let ms = st.meta.store.state().await;
    let id = uuid::Uuid::new_v4().to_string();
    let prefix = req.prefix.clone();
    let mut objects = BTreeMap::new();
    let mut logical = 0u64;
    for (k, m) in ms.manifests.iter() {
        if prefix.as_ref().map(|p| k.starts_with(p)).unwrap_or(true) {
            logical = logical.saturating_add(m.bytes);
            objects.insert(
                k.clone(),
                SnapshotObject {
                    key: k.clone(),
                    version: m.version,
                    source: m.clone(),
                    archived: None,
                },
            );
        }
    }
    let snap = SnapshotRecord {
        id: id.clone(),
        name: req.name.unwrap_or_else(|| id.clone()),
        created_at_unix_ms: now_ms(),
        raft_index: ms.applied_index,
        prefix,
        mode: SnapshotMode::PointInTime,
        objects,
        logical_bytes: logical,
        delta_bytes: 0,
        archived_bytes: 0,
    };
    match committed(
        &st,
        MetadataCommand::CreateSnapshot {
            snapshot: snap.clone(),
        },
    )
    .await
    {
        Ok(_) => (StatusCode::OK, Json(snap)).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the snapshot list step and keeps its validation and state transitions visible at the call site.
async fn snapshot_list(State(st): State<V6State>) -> impl IntoResponse {
    Json(st.meta.store.state().await.snapshots).into_response()
}
/// Implements the snapshot get step and keeps its validation and state transitions visible at the call site.
async fn snapshot_get(State(st): State<V6State>, Path(id): Path<String>) -> impl IntoResponse {
    match st.meta.store.state().await.snapshots.get(&id).cloned() {
        Some(x) => Json(x).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
/// Implements the snapshot object get step and keeps its validation and state transitions visible at the call site.
async fn snapshot_object_get(
    State(st): State<V6State>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let key = key.trim_start_matches('/');
    let ms = st.meta.store.state().await;
    let Some(s) = ms.snapshots.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(o) = s.objects.get(key) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let m = o.archived.as_ref().unwrap_or(&o.source);
    match get_object_version(&st.data, m).await {
        Ok(v) => (StatusCode::OK, v).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the materialize snapshot step and keeps its validation and state transitions visible at the call site.
async fn materialize_snapshot(st: &V6State, id: &str) -> Result<()> {
    let snap = st
        .meta
        .store
        .state()
        .await
        .snapshots
        .get(id)
        .cloned()
        .context("snapshot not found")?;
    if snap.mode == SnapshotMode::Archived {
        return Ok(());
    }
    st.meta
        .propose(MetadataCommand::BeginSnapshotArchive { id: id.into() })
        .await?;
    for (key, o) in snap.objects {
        if o.archived.is_some() {
            continue;
        }
        let data = get_object_version(&st.data, &o.source).await?;
        let hidden = format!(
            ".kagi/archive/{}/{}",
            id,
            blake3::hash(key.as_bytes()).to_hex()
        );
        let mut m = put_object(&st.data, &hidden, &data).await?;
        m.key = key.clone();
        st.meta
            .propose(MetadataCommand::ArchiveSnapshotObject {
                id: id.into(),
                key,
                manifest: m,
            })
            .await?;
    }
    st.meta
        .propose(MetadataCommand::FinishSnapshotArchive { id: id.into() })
        .await?;
    Ok(())
}
/// Implements the snapshot archive step and keeps its validation and state transitions visible at the call site.
async fn snapshot_archive(State(st): State<V6State>, Path(id): Path<String>) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    match materialize_snapshot(&st, &id).await {
        Ok(_) => StatusCode::ACCEPTED.into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the run snapshot controller step and keeps its validation and state transitions visible at the call site.
async fn run_snapshot_controller(st: V6State) {
    if !st.snapshots.enabled {
        return;
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(
        st.snapshots.check_interval_ms.max(1000),
    ));
    loop {
        tick.tick().await;
        if !st.meta.is_leader().await {
            continue;
        }
        let ms = st.meta.store.state().await;
        for snap in ms
            .snapshots
            .values()
            .filter(|x| x.mode == SnapshotMode::PointInTime)
        {
            let mut delta = 0u64;
            for (k, o) in &snap.objects {
                if ms.manifests.get(k).map(|m| m.version) != Some(o.version) {
                    delta = delta.saturating_add(o.source.bytes)
                }
            }
            if delta != snap.delta_bytes {
                let _ = st
                    .meta
                    .propose(MetadataCommand::UpdateSnapshotDelta {
                        id: snap.id.clone(),
                        delta_bytes: delta,
                    })
                    .await;
            }
            let ratio = if snap.logical_bytes == 0 {
                0.0
            } else {
                delta as f64 / snap.logical_bytes as f64
            };
            if delta >= st.snapshots.archive_after_delta_bytes
                || ratio >= st.snapshots.archive_after_delta_ratio
            {
                if let Ok(_permit) = st
                    .maintenance
                    .acquire(
                        "snapshot_archive",
                        snap.logical_bytes.min(256 * 1024 * 1024),
                    )
                    .await
                {
                    let started = std::time::Instant::now();
                    st.maintenance.charge_network(snap.logical_bytes).await;
                    let _ = materialize_snapshot(&st, &snap.id).await;
                    st.maintenance.cpu_yield(started.elapsed()).await;
                }
            }
        }
    }
}
/// Implements the user repair step and keeps its validation and state transitions visible at the call site.
async fn user_repair(State(st): State<V6State>, Path(key): Path<String>) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    let data = effective_data(&st).await;
    if let Some(m) = st.meta.store.get(&key).await {
        data.manifests.write().await.insert(key.clone(), m);
    }
    match repair_object_with_health(&data, &key, &st.health).await {
        Ok(m) => match committed(
            &st,
            MetadataCommand::PutManifest {
                key: key.clone(),
                manifest: m.clone(),
            },
        )
        .await
        {
            Ok(i) => {
                webui::append_log(
                    &st.web_console.log_path,
                    &st.data.local_host,
                    &format!("repair key={key} raft_index={i}"),
                );
                (StatusCode::OK, Json(m)).into_response()
            }
            Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
/// Implements the user scrub step and keeps its validation and state transitions visible at the call site.
async fn user_scrub(State(st): State<V6State>, Path(key): Path<String>) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    match scrub_object(&st.data, &key).await {
        Ok(x) => {
            webui::append_log(
                &st.web_console.log_path,
                &st.data.local_host,
                &format!("scrub key={key}"),
            );
            if x.values().any(|ok| !*ok) {
                st.monitor.emit(
                    "error",
                    "integrity",
                    &key,
                    "scrub found an invalid or unavailable fragment",
                );
            }
            Json(x).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}
/// Implements the maintenance status step and keeps its validation and state transitions visible at the call site.
async fn maintenance_status(State(st): State<V6State>) -> impl IntoResponse {
    Json(st.maintenance.status())
}
/// Implements the run background scrubber step and keeps its validation and state transitions visible at the call site.
async fn run_background_scrubber(st: V6State) {
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(
        st.maintenance.scrub_interval_ms().max(1000),
    ));
    loop {
        tick.tick().await;
        if !st.meta.is_leader().await || !st.maintenance.allowed_now("scrub") {
            continue;
        }
        let manifests: Vec<_> = st
            .meta
            .store
            .state()
            .await
            .manifests
            .into_values()
            .collect();
        for m in manifests {
            let Ok(_permit) = st
                .maintenance
                .acquire("scrub", m.bytes.min(256 * 1024 * 1024))
                .await
            else {
                break;
            };
            let started = std::time::Instant::now();
            st.maintenance.charge_network(m.bytes).await;
            st.data
                .manifests
                .write()
                .await
                .insert(m.key.clone(), m.clone());
            match scrub_object(&st.data, &m.key).await {
                Ok(chunks) if chunks.values().all(|ok| *ok) => {}
                Ok(_) => st.monitor.emit(
                    "error",
                    "integrity",
                    &m.key,
                    "background scrub found an invalid or unavailable fragment",
                ),
                Err(error) => st.monitor.emit(
                    "error",
                    "integrity",
                    &m.key,
                    &format!("background scrub failed: {error}"),
                ),
            }
            st.maintenance.cpu_yield(started.elapsed()).await;
        }
    }
}
#[derive(Debug, Deserialize)]
struct AddCapacityRequest {
    disk: PeerDisk,
}
/// Implements the capacity add step and keeps its validation and state transitions visible at the call site.
async fn capacity_add(
    State(st): State<V6State>,
    Path(host): Path<String>,
    Json(req): Json<AddCapacityRequest>,
) -> impl IntoResponse {
    let _foreground = st.maintenance.foreground();
    if !st.meta.is_leader().await {
        return StatusCode::TEMPORARY_REDIRECT.into_response();
    }
    if !st.data.cfg.hosts.iter().any(|h| h.id == host) {
        return (StatusCode::NOT_FOUND, "unknown host").into_response();
    }
    if req.disk.capacity_bytes == 0 || req.disk.weight <= 0.0 {
        return (
            StatusCode::BAD_REQUEST,
            "capacity_bytes and weight must be positive",
        )
            .into_response();
    }
    if host == st.data.local_host {
        let dh = storage::probe(
            req.disk.device_path.as_deref(),
            &req.disk.storage_kind,
            req.disk.serial_number.as_deref(),
            req.disk.wwn.as_deref(),
        );
        if !dh.ok {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "backend device health/identity check failed: {}",
                    dh.reason.unwrap_or_else(|| "unknown".into())
                ),
            )
                .into_response();
        }
    }
    let epoch = st
        .meta
        .store
        .state()
        .await
        .placement_epoch
        .saturating_add(1);
    match committed(&st,MetadataCommand::AddCapacity {
        host:host.clone(),disk:req.disk.clone()
    }
    ).await {
        Ok(_)=>match committed(&st,MetadataCommand::SetPlacementEpoch {
            epoch
        }
        ).await {
            Ok(i)=>(StatusCode::OK,Json(serde_json::json!( {
                "host":host,"disk":req.disk,"placement_epoch":epoch,"raft_index":i,"rebalance":"scheduled"
            }
            ))).into_response(),Err(e)=>(StatusCode::SERVICE_UNAVAILABLE,e.to_string()).into_response()
        },
        Err(e)=>(StatusCode::SERVICE_UNAVAILABLE,e.to_string()).into_response()
    }
}
/// Implements the capacity get step and keeps its validation and state transitions visible at the call site.
async fn capacity_get(State(st): State<V6State>) -> impl IntoResponse {
    Json(serde_json::json!( {
        "placement_epoch":st.meta.store.state().await.placement_epoch,"capacity_additions":st.meta.store.state().await.capacity_additions
    }
    ))
}
// ---- Background durability, rebalance, snapshot, GC, and maintenance loops ----
async fn run_rebalancer(st: V6State) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut completed_epoch = 0u64;
    loop {
        tick.tick().await;
        if !st.meta.is_leader().await {
            continue;
        }
        let ms = st.meta.store.state().await;
        if ms.placement_epoch <= completed_epoch {
            continue;
        }
        let epoch = ms.placement_epoch;
        let manifests: Vec<_> = ms.manifests.values().cloned().collect();
        drop(ms);
        let data = effective_data(&st).await;
        let mut complete = true;
        for old in manifests {
            let Ok(_permit) = st
                .maintenance
                .acquire("rebalance", old.bytes.min(256 * 1024 * 1024))
                .await
            else {
                complete = false;
                break;
            };
            let started = std::time::Instant::now();
            st.maintenance.charge_network(old.bytes).await;
            data.manifests
                .write()
                .await
                .insert(old.key.clone(), old.clone());
            match repair_object_with_health(&data, &old.key, &st.health).await {
                Ok(new) => match committed(
                    &st,
                    MetadataCommand::PutManifest {
                        key: old.key.clone(),
                        manifest: new.clone(),
                    },
                )
                .await
                {
                    Ok(_) => {
                        let _ = cleanup_rebalanced_replicas(&data, &old, &new).await;
                    }
                    Err(_) => {
                        complete = false;
                        break;
                    }
                },
                Err(_) => {
                    complete = false;
                    break;
                }
            }
            st.maintenance.cpu_yield(started.elapsed()).await;
        }
        if complete {
            completed_epoch = epoch
        }
    }
}
/// Implements the run cluster controller step and keeps its validation and state transitions visible at the call site.
async fn run_cluster_controller(st: V6State, cfg: NodeConfig) {
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(
        cfg.recovery.repair_interval_ms,
    ));
    loop {
        tick.tick().await;
        if !st.meta.is_leader().await {
            continue;
        }
        st.health.age(&cfg.cluster.hosts, &cfg.recovery).await;
        let snap = st.health.snapshot().await;
        for (resource, h) in &snap {
            let _ = st
                .meta
                .propose(MetadataCommand::SetResourceHealth {
                    resource: resource.clone(),
                    health: h.clone(),
                })
                .await;
        }
        let manifests: Vec<_> = st.data.manifests.read().await.values().cloned().collect();
        let mut ranked = Vec::new();
        for m in manifests {
            ranked.push((
                object_risk(&m, &st.health, &cfg.cluster.hosts).await,
                m.key.clone(),
            ));
        }
        ranked.sort_by_key(|x| x.0);
        for (risk, key) in ranked.into_iter().take(cfg.recovery.max_parallel_repairs) {
            let bytes = st
                .data
                .manifests
                .read()
                .await
                .get(&key)
                .map(|m| m.bytes)
                .unwrap_or(0);
            if risk == 0 {
                /* system-necessary durability repair: never waits on maintenance policy */
                if let Ok(m) = repair_object_with_health(&st.data, &key, &st.health).await {
                    let _ = st
                        .meta
                        .propose(MetadataCommand::PutManifest { key, manifest: m })
                        .await;
                }
            } else if let Ok(_permit) = st
                .maintenance
                .acquire("proactive_repair", bytes.min(256 * 1024 * 1024))
                .await
            {
                let started = std::time::Instant::now();
                st.maintenance.charge_network(bytes).await;
                if let Ok(m) = repair_object_with_health(&st.data, &key, &st.health).await {
                    let _ = st
                        .meta
                        .propose(MetadataCommand::PutManifest { key, manifest: m })
                        .await;
                }
                st.maintenance.cpu_yield(started.elapsed()).await;
            }
        }
    }
}
/// Implements the heartbeat in step and keeps its validation and state transitions visible at the call site.
async fn heartbeat_in(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Json(hb): Json<Heartbeat>,
) -> impl IntoResponse {
    if !verify_json(&st, &headers, "/internal/v1/health/heartbeat", &hb).await {
        return StatusCode::UNAUTHORIZED;
    }
    if !request_authorized(&st.data.cfg, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    st.health.apply_heartbeat(&hb, &st.recovery).await;
    StatusCode::NO_CONTENT
}
/// Implements the health clear step and keeps its validation and state transitions visible at the call site.
async fn health_clear(
    State(st): State<V6State>,
    Path(resource): Path<String>,
) -> impl IntoResponse {
    let resource = resource.trim_start_matches('/');
    if st.health.clear_flap(resource).await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}
/// Implements the health get step and keeps its validation and state transitions visible at the call site.
async fn health_get(State(st): State<V6State>) -> impl IntoResponse {
    Json(st.health.snapshot().await)
}
/// Implements the send heartbeats step and keeps its validation and state transitions visible at the call site.
async fn send_heartbeats(st: V6State, cfg: NodeConfig) {
    let period = std::time::Duration::from_millis(cfg.recovery.heartbeat_ms);
    let mut tick = tokio::time::interval(period);
    loop {
        tick.tick().await;
        let mut disks = BTreeMap::new();
        let mut disk_serials = BTreeMap::new();
        let mut disk_media_errors = BTreeMap::new();
        let mut disk_critical_warning = BTreeMap::new();
        if let Some(h) = cfg.cluster.hosts.iter().find(|h| h.id == cfg.local_host) {
            for d in &h.disks {
                let p = cfg.data_root.join("disks").join(&d.id);
                let fs_ok = tokio::fs::create_dir_all(&p).await.is_ok()
                    && tokio::fs::metadata(&p).await.is_ok();
                let dh = storage::probe(
                    d.device_path.as_deref(),
                    &d.storage_kind,
                    d.serial_number.as_deref(),
                    d.wwn.as_deref(),
                );
                disks.insert(d.id.clone(), fs_ok && dh.ok);
                if let Some(x) = dh.serial {
                    disk_serials.insert(d.id.clone(), x);
                }
                disk_media_errors.insert(
                    d.id.clone(),
                    dh.media_errors
                        .saturating_add(dh.pending_sectors)
                        .saturating_add(dh.uncorrectable_sectors),
                );
                disk_critical_warning.insert(
                    d.id.clone(),
                    dh.critical_warning
                        .saturating_add(if dh.smart_passed == Some(false) { 1 } else { 0 }),
                );
            }
        }
        let hb = Heartbeat {
            host: cfg.local_host.clone(),
            boot_id: std::process::id().to_string(),
            disks,
            disk_serials,
            disk_media_errors,
            disk_critical_warning,
            free_bytes: BTreeMap::new(),
            io_pressure: 0.0,
            unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        };
        st.health.apply_heartbeat(&hb, &cfg.recovery).await;
        for h in &cfg.cluster.hosts {
            if h.id == cfg.local_host {
                continue;
            }
            let u = format!(
                "{}/internal/v1/health/heartbeat",
                h.endpoint.trim_end_matches('/')
            );
            if let Ok((body, auth)) =
                signed_json(&st.data, "POST", "/internal/v1/health/heartbeat", &hb)
            {
                let b = st
                    .data
                    .client
                    .post(u)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body);
                let _ = pq::apply_headers(b, auth).send().await;
            }
        }
    }
}
// ---- Kagi web operations console -------------------------------------------
fn console_auth(
    st: &V6State,
    headers: &axum::http::HeaderMap,
    admin: bool,
) -> Option<webui::ConsoleIdentity> {
    webui::authenticate_basic(headers, &st.web_console.userdb, admin)
}
/// Implements the kagi root step and keeps its validation and state transitions visible at the call site.
async fn kagi_root() -> Redirect {
    Redirect::temporary("/ui")
}
/// Implements the kagi ui step and keeps its validation and state transitions visible at the call site.
async fn kagi_ui(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    if !st.web_console.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    Html(webui::INDEX_HTML).into_response()
}
/// Implements the host site rack step and keeps its validation and state transitions visible at the call site.
fn host_site_rack(st: &V6State) -> (Option<String>, Option<String>) {
    st.data
        .cfg
        .hosts
        .iter()
        .find(|h| h.id == st.data.local_host)
        .map(|h| (h.site.clone(), h.rack.clone()))
        .unwrap_or_default()
}
/// Implements the local console summary step and keeps its validation and state transitions visible at the call site.
async fn local_console_summary(st: &V6State) -> serde_json::Value {
    let ms = st.meta.store.state().await;
    let raft = st.meta.status().await;
    let hs = st.health.snapshot().await;
    let objects = ms.manifests.len();
    let logical_bytes = ms.manifests.values().map(|m| m.bytes).sum::<u64>();
    let fragments = ms
        .manifests
        .values()
        .map(|m| {
            cluster::normalize_chunks(m)
                .iter()
                .map(|c| c.replicas.len())
                .sum::<usize>()
        })
        .sum::<usize>();
    let physical_bytes = ms
        .manifests
        .values()
        .map(|m| {
            cluster::normalize_chunks(m)
                .iter()
                .map(|c| c.bytes.saturating_mul(c.replicas.len() as u64))
                .sum::<u64>()
        })
        .sum::<u64>();
    let healthy = hs
        .values()
        .filter(|x| {
            matches!(
                x.state,
                recovery::ResourceState::Healthy | recovery::ResourceState::Recovering
            )
        })
        .count();
    let capacity = st
        .data
        .cfg
        .hosts
        .iter()
        .flat_map(|h| h.disks.iter())
        .map(|d| d.capacity_bytes)
        .sum::<u64>();
    let (site, rack) = host_site_rack(st);
    serde_json::json!( {
        "node_id":st.data.local_host,"site":site,"rack":rack,"role":format!("{:?}",raft.role).to_lowercase(),"term":raft.term,"leader":raft.leader,"objects":objects,"logical_bytes":logical_bytes,"physical_bytes":physical_bytes,"fragments":fragments,"healthy_resources":healthy,"capacity_bytes":capacity,"placement_epoch":ms.placement_epoch,"pending_gc":ms.garbage.len(),"snapshots":ms.snapshots.len(),"buckets":ms.buckets.len(),"system":webui::system_stats(),"telemetry":st.telemetry.current(),"maintenance":st.maintenance.status()
    }
    )
}
/// Implements the internal ui node step and keeps its validation and state transitions visible at the call site.
async fn internal_ui_node(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    let path = "/internal/v1/ui/node";
    if pq::verify_request(&headers, "GET", path, &[], &st.data.pq_keys)
        .await
        .is_err()
        || !request_authorized(&st.data.cfg, &headers)
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(local_console_summary(&st).await).into_response()
}
/// Implements the cluster console summaries step and keeps its validation and state transitions visible at the call site.
async fn cluster_console_summaries(st: &V6State) -> Vec<serde_json::Value> {
    let mut out = vec![local_console_summary(st).await];
    let Some(id) = st.data.pq_identity.as_ref() else {
        return out;
    };
    for h in &st.data.cfg.hosts {
        if h.id == st.data.local_host {
            continue;
        }
        let path = "/internal/v1/ui/node";
        let Ok(auth) = pq::signed_headers(id, "GET", path, &[]) else {
            continue;
        };
        let req = st
            .data
            .client
            .get(format!("{}{}", h.endpoint.trim_end_matches('/'), path));
        if let Ok(r) = pq::apply_headers(req, auth).send().await {
            if r.status().is_success() {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    out.push(v)
                }
            }
        }
    }
    out
}
/// Implements the ui summary step and keeps its validation and state transitions visible at the call site.
async fn ui_summary(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    let nodes = cluster_console_summaries(&st).await;
    let objects = nodes
        .iter()
        .map(|n| n["objects"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let logical_bytes = nodes
        .iter()
        .map(|n| n["logical_bytes"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let fragments = nodes
        .iter()
        .map(|n| n["fragments"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let physical_bytes = nodes
        .iter()
        .map(|n| n["physical_bytes"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let capacity_bytes = nodes
        .iter()
        .map(|n| n["capacity_bytes"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let healthy_resources = nodes
        .iter()
        .map(|n| n["healthy_resources"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let local = nodes.first().cloned().unwrap_or_default();
    Json(serde_json::json!( {
        "product":"Kagi","local":local,"nodes":nodes,"cluster": {
            "objects":objects,"logical_bytes":logical_bytes,"physical_bytes":physical_bytes,"capacity_bytes":capacity_bytes,"fragments":fragments,"healthy_resources":healthy_resources
        }
    }
    )).into_response()
}

#[derive(Debug, Deserialize, Default)]
struct TelemetryQuery {
    #[serde(default)]
    after_ms: u128,
}

/// Periodically sample kernel/device/network state. Sampling stays off the request path so
/// a slow SMART/sysfs device never delays the browser or object I/O.
async fn run_telemetry_sampler(st: V6State) {
    let interval = std::time::Duration::from_millis(st.telemetry.config().sample_interval_ms);
    loop {
        let cfg = effective_cluster_config(&st).await;
        st.telemetry.sample(&cfg, &st.data.local_host);
        tokio::time::sleep(interval).await;
    }
}

/// Internal history endpoint used for authenticated cluster-wide dashboard aggregation.
async fn internal_ui_telemetry(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Query(query): Query<TelemetryQuery>,
) -> Response {
    let path = "/internal/v1/ui/telemetry";
    if pq::verify_request(&headers, "GET", path, &[], &st.data.pq_keys)
        .await
        .is_err()
        || !request_authorized(&st.data.cfg, &headers)
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(serde_json::json!({
        "node": st.data.local_host,
        "samples": st.telemetry.history(query.after_ms)
    }))
    .into_response()
}

/// Return local and peer telemetry histories.  The hierarchy is explicit in every sample
/// (site/rack/node/disk) so clients can aggregate without guessing topology names.
async fn ui_telemetry(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Query(query): Query<TelemetryQuery>,
) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }

    let mut nodes = vec![serde_json::json!({
        "node": st.data.local_host,
        "samples": st.telemetry.history(query.after_ms)
    })];

    if let Some(identity) = st.data.pq_identity.as_ref() {
        for peer in &st.data.cfg.hosts {
            if peer.id == st.data.local_host {
                continue;
            }
            let path = "/internal/v1/ui/telemetry";
            let Ok(auth) = pq::signed_headers(identity, "GET", path, &[]) else {
                continue;
            };
            let url = format!(
                "{}{}?after_ms={}",
                peer.endpoint.trim_end_matches('/'),
                path,
                query.after_ms
            );
            let request = st.data.client.get(url);
            if let Ok(response) = pq::apply_headers(request, auth).send().await {
                if response.status().is_success() {
                    if let Ok(value) = response.json::<serde_json::Value>().await {
                        nodes.push(value);
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "after_ms": query.after_ms,
        "nodes": nodes
    }))
    .into_response()
}

/// Change scheduler/cache policy only for a disk configured on this node.  The operation
/// requires an administrator identity and emits a security/operations event for auditability.
async fn ui_disk_tune(
    State(st): State<V6State>,
    Path(disk): Path<String>,
    headers: axum::http::HeaderMap,
    Json(tuning): Json<storage::QueueTuning>,
) -> Response {
    let Some(identity) = console_auth(&st, &headers, true) else {
        return webui::unauthorized();
    };
    let Some(host) = st.data.cfg.hosts.iter().find(|host| host.id == st.data.local_host) else {
        return (StatusCode::NOT_FOUND, "local host is not in topology").into_response();
    };
    let Some(configured) = host.disks.iter().find(|candidate| candidate.id == disk) else {
        return (StatusCode::NOT_FOUND, "disk is not configured on this node").into_response();
    };
    let Some(device) = configured.device_path.as_deref() else {
        return (StatusCode::BAD_REQUEST, "disk has no block device path").into_response();
    };

    match storage::apply_queue_tuning(device, &tuning) {
        Ok(settings) => {
            st.monitor.emit(
                "info",
                "storage",
                &format!("disk/{disk}"),
                &format!(
                    "administrator {} changed block queue/cache settings",
                    identity.username
                ),
            );
            Json(serde_json::json!({
                "disk": disk,
                "device": device,
                "settings": settings
            }))
            .into_response()
        }
        Err(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unable to change disk settings: {error}"),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PrefixQuery {
    #[serde(default)]
    prefix: String,
}
/// Implements the ui objects step and keeps its validation and state transitions visible at the call site.
async fn ui_objects(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Query(q): Query<PrefixQuery>,
) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    let ms = st.meta.store.state().await;
    let mut rows = ms
        .manifests
        .values()
        .filter(|m| m.key.starts_with(&q.prefix))
        .filter(|m| {
            st.security.check(
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
    let st = state(&cfg, client.clone(), pq_identity.clone(), pq_keys.clone());
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
                .route("/v1/volumes/:id", get(volume_get))
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
                    if cfg.tls.is_some() { " with native TLS" } else { "" }
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
                let rustls = tls::server_config(
                    &tls_config.cert,
                    &tls_config.key,
                    tls_config.allow_tls12,
                )?;
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
        Cmd::Status => println!("{}", serde_json::to_string_pretty(&cfg.cluster.hosts)?),
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
