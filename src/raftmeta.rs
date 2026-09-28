// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi Raft-replicated metadata state machine.
//!
//! The metadata layer serializes namespace mutations, immutable object manifests, bucket
//! policy, snapshots, garbage-collection fences, cluster membership, PQ key state, block
//! volumes, and reservations. Mutations are applied in log order and persisted before they
//! become visible, which keeps every metadata consumer working from the same committed view.

// Raft metadata state machine, joint-consensus membership, snapshots, GC fencing, topology and volume metadata.
//! Durable Raft metadata consensus for manifests, placement epochs and health state.
//! Implements leader election, RequestVote, AppendEntries, majority commit, ordered
//! state-machine application and persistent term/vote/log state.
use crate::{
    block::{apply_pr_out, PrOut, VolumeExtent, VolumeRecord},
    cluster::{ObjectManifest, PeerDisk, WormPolicy},
    pq::{LocalPqIdentity, TrustedPqKey},
    recovery::ResourceHealth,
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
// ---- Consensus identities, membership, and durable state ----------------------
pub type NodeId = String;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RaftPeer {
    pub id: NodeId,
    pub endpoint: String,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub rack: Option<String>,
    #[serde(default)]
    pub pq_public_key_b64: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    pub voters: BTreeMap<NodeId, RaftPeer>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JointMembership {
    pub old: Membership,
    pub new: Membership,
}
impl Membership {
    pub fn from_local_and_peers(
        local_id: &str,
        local_endpoint: String,
        peers: &[RaftPeer],
    ) -> Self {
        let mut voters = BTreeMap::new();
        voters.insert(
            local_id.to_string(),
            RaftPeer {
                id: local_id.to_string(),
                endpoint: local_endpoint,
                site: None,
                rack: None,
                pq_public_key_b64: None,
            },
        );
        for p in peers {
            voters.insert(p.id.clone(), p.clone());
        }
        Self { voters }
    }
    pub fn quorum(&self) -> usize {
        self.voters.len() / 2 + 1
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMode {
    PointInTime,
    Archiving,
    Archived,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotObject {
    pub key: String,
    pub version: u64,
    pub source: ObjectManifest,
    #[serde(default)]
    pub archived: Option<ObjectManifest>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: String,
    pub name: String,
    pub created_at_unix_ms: u128,
    pub raft_index: u64,
    pub prefix: Option<String>,
    pub mode: SnapshotMode,
    pub objects: BTreeMap<String, SnapshotObject>,
    pub logical_bytes: u64,
    pub delta_bytes: u64,
    pub archived_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageRecord {
    pub id: String,
    pub key: String,
    pub version: u64,
    pub manifest: ObjectManifest,
    pub deleted_at_unix_ms: u128,
    pub eligible_after_unix_ms: u128,
    #[serde(default)]
    pub attempts: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub fence_index: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BucketRecord {
    pub name: String,
    #[serde(default)]
    pub created_at_unix_ms: u128,
    #[serde(default)]
    pub default_worm: WormPolicy,
    #[serde(default)]
    pub versioning: bool,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamespaceMutation {
    PutManifest {
        key: String,
        manifest: Box<ObjectManifest>,
    },
    DeleteManifest {
        key: String,
        version: u64,
        deleted_at_unix_ms: u128,
        eligible_after_unix_ms: u128,
    },
    PutDeleteMarker {
        key: String,
        version: u64,
        created_unix_ms: u128,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)] // ---- Replicated state-machine commands -----------------------------------------
                                                // Every externally visible metadata mutation is represented here so commit/apply
                                                // ordering can be shared by objects, snapshots, topology, volumes, and PR state.
pub enum MetadataCommand {
    NamespaceTransaction {
        txid: String,
        mutations: Vec<NamespaceMutation>,
    },
    PutManifest {
        key: String,
        manifest: ObjectManifest,
    },
    DeleteManifest {
        key: String,
        version: u64,
        deleted_at_unix_ms: u128,
        eligible_after_unix_ms: u128,
    },
    AuthorizeGarbage {
        id: String,
    },
    GarbageCollected {
        id: String,
    },
    GarbageFailed {
        id: String,
        error: String,
    },
    PutDeleteMarker {
        key: String,
        version: u64,
        created_unix_ms: u128,
    },
    SetPlacementEpoch {
        epoch: u64,
    },
    SetResourceHealth {
        resource: String,
        health: ResourceHealth,
    },
    RotatePqKey {
        key: TrustedPqKey,
        retiring: Option<TrustedPqKey>,
    },
    RevokePqKey {
        key_id: String,
        revoked_at_ms: u128,
    },
    BeginJointMembership {
        joint: JointMembership,
    },
    FinalizeMembership {
        membership: Membership,
    },
    CreateSnapshot {
        snapshot: SnapshotRecord,
    },
    UpdateSnapshotDelta {
        id: String,
        delta_bytes: u64,
    },
    BeginSnapshotArchive {
        id: String,
    },
    ArchiveSnapshotObject {
        id: String,
        key: String,
        manifest: ObjectManifest,
    },
    FinishSnapshotArchive {
        id: String,
    },
    AddCapacity {
        host: String,
        disk: PeerDisk,
    },
    CreateVolume {
        volume: VolumeRecord,
    },
    CommitVolumeWrite {
        id: String,
        generation: u64,
        extents: Vec<VolumeExtent>,
    },
    SetVolumeReadOnly {
        id: String,
        read_only: bool,
    },
    ResizeVolume {
        id: String,
        size_bytes: u64,
    },
    UnmapVolume {
        id: String,
        generation: u64,
        remove: Vec<u64>,
        replace: Vec<VolumeExtent>,
    },
    PersistentReserveOut {
        id: String,
        expected_generation: u64,
        op: PrOut,
    },
    DeleteVolume {
        id: String,
    },
    PutBucket {
        bucket: BucketRecord,
    },
    DeleteBucket {
        name: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetadataState {
    pub manifests: BTreeMap<String, ObjectManifest>,
    #[serde(default)]
    pub versions: BTreeMap<String, Vec<ObjectManifest>>,
    #[serde(default)]
    pub delete_markers: BTreeMap<String, u64>,
    #[serde(default)]
    pub garbage: BTreeMap<String, GarbageRecord>,
    pub placement_epoch: u64,
    pub applied_index: u64,
    #[serde(default)]
    pub resources: BTreeMap<String, ResourceHealth>,
    #[serde(default)]
    pub pq_keys: BTreeMap<String, TrustedPqKey>,
    #[serde(default)]
    pub membership: Option<Membership>,
    #[serde(default)]
    pub joint_membership: Option<JointMembership>,
    #[serde(default)]
    pub snapshots: BTreeMap<String, SnapshotRecord>,
    #[serde(default)]
    pub capacity_additions: BTreeMap<String, BTreeMap<String, PeerDisk>>,
    #[serde(default)]
    pub volumes: BTreeMap<String, VolumeRecord>,
    #[serde(default)]
    pub buckets: BTreeMap<String, BucketRecord>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub command: MetadataCommand,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistentRaft {
    current_term: u64,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    commit_index: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}
#[derive(Debug, Clone, Serialize)]
pub struct RaftStatus {
    pub node_id: String,
    pub role: Role,
    pub term: u64,
    pub leader: Option<String>,
    pub commit_index: u64,
    pub last_applied: u64,
    pub last_log_index: u64,
    pub quorum: usize,
    pub voters: Vec<String>,
    pub joint: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendRequest {
    pub term: u64,
    pub leader_id: String,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}
/// Implements the now ms step and keeps its validation and state transitions visible at the call site.
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
#[derive(Clone)]
pub struct MetadataStore {
    root: PathBuf,
    state: Arc<RwLock<MetadataState>>,
}
/// Implements the apply namespace mutation step and keeps its validation and state transitions visible at the call site.
fn apply_namespace_mutation(s: &mut MetadataState, m: NamespaceMutation) {
    match m {
        NamespaceMutation::PutManifest { key, manifest } => {
            let manifest = *manifest;
            let vs = s.versions.entry(key.clone()).or_default();
            if !vs.iter().any(|m| m.version == manifest.version) {
                vs.push(manifest.clone());
                vs.sort_by_key(|m| m.version);
            }
            s.delete_markers.remove(&key);
            s.manifests.insert(key, manifest);
        }
        NamespaceMutation::DeleteManifest {
            key,
            version,
            deleted_at_unix_ms,
            eligible_after_unix_ms,
        } => {
            let victim = s
                .versions
                .get(&key)
                .and_then(|vs| vs.iter().find(|m| m.version == version).cloned());
            if let Some(m) = victim {
                let id = format!("{}:{}", m.object_id, version);
                s.garbage.entry(id.clone()).or_insert(GarbageRecord {
                    id,
                    key: key.clone(),
                    version,
                    manifest: m,
                    deleted_at_unix_ms,
                    eligible_after_unix_ms,
                    attempts: 0,
                    last_error: None,
                    fence_index: 0,
                });
            }
            if let Some(vs) = s.versions.get_mut(&key) {
                vs.retain(|m| m.version != version);
            }
            if s.manifests.get(&key).map(|m| m.version) == Some(version) {
                s.manifests.remove(&key);
            }
        }
        NamespaceMutation::PutDeleteMarker { key, version, .. } => {
            s.delete_markers.insert(key.clone(), version);
            s.manifests.remove(&key);
        }
    }
}
// ---- Metadata state-machine persistence and ordered application ----------------
impl MetadataStore {
    pub async fn open(root: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&root).await?;
        let p = root.join("state.json");
        let mut state: MetadataState = match tokio::fs::read(&p).await {
            Ok(v) => serde_json::from_slice(&v)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => MetadataState::default(),
            Err(e) => return Err(e.into()),
        };
        for (k, m) in state.manifests.clone() {
            let v = state.versions.entry(k).or_default();
            if !v.iter().any(|x| x.version == m.version) {
                v.push(m);
            }
        }
        Ok(Self {
            root,
            state: Arc::new(RwLock::new(state)),
        })
    }
    pub async fn apply(&self, index: u64, cmd: MetadataCommand) -> Result<()> {
        let mut s = self.state.write().await;
        if index <= s.applied_index {
            return Ok(());
        }
        match cmd {
            MetadataCommand::NamespaceTransaction { txid: _, mutations } => {
                for m in mutations {
                    apply_namespace_mutation(&mut s, m);
                }
            }
            MetadataCommand::PutManifest { key, manifest } => {
                let vs = s.versions.entry(key.clone()).or_default();
                if !vs.iter().any(|m| m.version == manifest.version) {
                    vs.push(manifest.clone());
                    vs.sort_by_key(|m| m.version);
                }
                s.delete_markers.remove(&key);
                s.manifests.insert(key, manifest);
            }
            MetadataCommand::DeleteManifest {
                key,
                version,
                deleted_at_unix_ms,
                eligible_after_unix_ms,
            } => {
                let victim = s
                    .versions
                    .get(&key)
                    .and_then(|vs| vs.iter().find(|m| m.version == version).cloned());
                if let Some(m) = victim {
                    let id = format!("{}:{}", m.object_id, version);
                    s.garbage.entry(id.clone()).or_insert(GarbageRecord {
                        id,
                        key: key.clone(),
                        version,
                        manifest: m,
                        deleted_at_unix_ms,
                        eligible_after_unix_ms,
                        attempts: 0,
                        last_error: None,
                        fence_index: 0,
                    });
                }
                if let Some(vs) = s.versions.get_mut(&key) {
                    vs.retain(|m| m.version != version);
                }
                if s.manifests.get(&key).map(|m| m.version) == Some(version) {
                    s.manifests.remove(&key);
                }
            }
            MetadataCommand::AuthorizeGarbage { id } => {
                if let Some(g) = s.garbage.get_mut(&id) {
                    g.fence_index = index;
                }
            }
            MetadataCommand::GarbageCollected { id } => {
                s.garbage.remove(&id);
            }
            MetadataCommand::GarbageFailed { id, error } => {
                if let Some(g) = s.garbage.get_mut(&id) {
                    g.attempts = g.attempts.saturating_add(1);
                    g.last_error = Some(error);
                }
            }
            MetadataCommand::PutDeleteMarker { key, version, .. } => {
                s.delete_markers.insert(key.clone(), version);
                s.manifests.remove(&key);
            }
            MetadataCommand::SetPlacementEpoch { epoch } => s.placement_epoch = epoch,
            MetadataCommand::SetResourceHealth { resource, health } => {
                s.resources.insert(resource, health);
            }
            MetadataCommand::RotatePqKey { key, retiring } => {
                if let Some(old) = retiring {
                    s.pq_keys.insert(old.key_id.clone(), old);
                }
                s.pq_keys.insert(key.key_id.clone(), key);
            }
            MetadataCommand::RevokePqKey {
                key_id,
                revoked_at_ms: _,
            } => {
                if let Some(k) = s.pq_keys.get_mut(&key_id) {
                    k.revoked = true;
                }
            }
            MetadataCommand::BeginJointMembership { joint } => {
                s.joint_membership = Some(joint);
            }
            MetadataCommand::FinalizeMembership { membership } => {
                s.membership = Some(membership);
                s.joint_membership = None;
            }
            MetadataCommand::CreateSnapshot { snapshot } => {
                s.snapshots.insert(snapshot.id.clone(), snapshot);
            }
            MetadataCommand::UpdateSnapshotDelta { id, delta_bytes } => {
                if let Some(x) = s.snapshots.get_mut(&id) {
                    x.delta_bytes = delta_bytes;
                }
            }
            MetadataCommand::BeginSnapshotArchive { id } => {
                if let Some(x) = s.snapshots.get_mut(&id) {
                    x.mode = SnapshotMode::Archiving;
                }
            }
            MetadataCommand::ArchiveSnapshotObject { id, key, manifest } => {
                if let Some(x) = s.snapshots.get_mut(&id) {
                    if let Some(o) = x.objects.get_mut(&key) {
                        x.archived_bytes = x.archived_bytes.saturating_add(manifest.bytes);
                        o.archived = Some(manifest);
                    }
                }
            }
            MetadataCommand::FinishSnapshotArchive { id } => {
                if let Some(x) = s.snapshots.get_mut(&id) {
                    x.mode = SnapshotMode::Archived;
                    x.delta_bytes = 0;
                }
            }
            MetadataCommand::AddCapacity { host, disk } => {
                s.capacity_additions
                    .entry(host)
                    .or_default()
                    .insert(disk.id.clone(), disk);
            }
            MetadataCommand::CreateVolume { volume } => {
                s.volumes.insert(volume.id.clone(), volume);
            }
            MetadataCommand::CommitVolumeWrite {
                id,
                generation,
                extents,
            } => {
                let accept = s
                    .volumes
                    .get(&id)
                    .map(|v| generation > v.generation)
                    .unwrap_or(false);
                if accept {
                    for e in &extents {
                        let k = e.manifest.key.clone();
                        let m = e.manifest.clone();
                        let vs = s.versions.entry(k.clone()).or_default();
                        if !vs.iter().any(|x| x.version == m.version) {
                            vs.push(m.clone());
                            vs.sort_by_key(|x| x.version);
                        }
                        s.manifests.insert(k, m);
                    }
                    if let Some(v) = s.volumes.get_mut(&id) {
                        for e in extents {
                            v.extents.insert(e.extent, e);
                        }
                        v.generation = generation;
                    }
                }
            }
            MetadataCommand::SetVolumeReadOnly { id, read_only } => {
                if let Some(v) = s.volumes.get_mut(&id) {
                    v.read_only = read_only;
                }
            }
            MetadataCommand::ResizeVolume { id, size_bytes } => {
                if let Some(v) = s.volumes.get_mut(&id) {
                    if size_bytes >= v.size_bytes {
                        v.size_bytes = size_bytes;
                        v.generation = v.generation.saturating_add(1);
                    }
                }
            }
            MetadataCommand::UnmapVolume {
                id,
                generation,
                remove,
                replace,
            } => {
                let accept = s
                    .volumes
                    .get(&id)
                    .map(|v| generation > v.generation)
                    .unwrap_or(false);
                if accept {
                    for e in &replace {
                        let k = e.manifest.key.clone();
                        let m = e.manifest.clone();
                        let vs = s.versions.entry(k.clone()).or_default();
                        if !vs.iter().any(|x| x.version == m.version) {
                            vs.push(m.clone());
                            vs.sort_by_key(|x| x.version);
                        }
                        s.manifests.insert(k, m);
                    }
                    if let Some(v) = s.volumes.get_mut(&id) {
                        for n in remove {
                            v.extents.remove(&n);
                        }
                        for e in replace {
                            v.extents.insert(e.extent, e);
                        }
                        v.generation = generation;
                    }
                }
            }
            MetadataCommand::PersistentReserveOut {
                id,
                expected_generation,
                op,
            } => {
                if let Some(v) = s.volumes.get_mut(&id) {
                    if v.persistent_reservation.generation == expected_generation {
                        apply_pr_out(&mut v.persistent_reservation, &op)?;
                    }
                }
            }
            MetadataCommand::DeleteVolume { id } => {
                s.volumes.remove(&id);
            }
            MetadataCommand::PutBucket { bucket } => {
                s.buckets.insert(bucket.name.clone(), bucket);
            }
            MetadataCommand::DeleteBucket { name } => {
                s.buckets.remove(&name);
            }
        }
        s.applied_index = index;
        let tmp = self.root.join("state.tmp");
        tokio::fs::write(&tmp, serde_json::to_vec(&*s)?).await?;
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .await?
            .sync_all()
            .await?;
        tokio::fs::rename(tmp, self.root.join("state.json")).await?;
        Ok(())
    }
    pub async fn get(&self, key: &str) -> Option<ObjectManifest> {
        self.state.read().await.manifests.get(key).cloned()
    }
    pub async fn get_version(&self, key: &str, version: u64) -> Option<ObjectManifest> {
        self.state
            .read()
            .await
            .versions
            .get(key)
            .and_then(|v| v.iter().find(|m| m.version == version).cloned())
    }
    pub async fn versions(&self, key: &str) -> Vec<ObjectManifest> {
        self.state
            .read()
            .await
            .versions
            .get(key)
            .cloned()
            .unwrap_or_default()
    }
    pub async fn state(&self) -> MetadataState {
        self.state.read().await.clone()
    }
}
#[derive(Debug, Clone, Copy)]
pub struct RaftTiming {
    pub election_min_ms: u64,
    pub election_max_ms: u64,
    pub heartbeat_ms: u64,
}
#[derive(Clone)]
pub struct RaftNode {
    pub node_id: String,
    pub peers: Arc<RwLock<Vec<RaftPeer>>>,
    pub store: MetadataStore,
    root: PathBuf,
    client: reqwest::Client,
    persistent: Arc<RwLock<PersistentRaft>>,
    role: Arc<RwLock<Role>>,
    leader: Arc<RwLock<Option<String>>>,
    last_contact_ms: Arc<RwLock<u128>>,
    election_min_ms: u64,
    election_max_ms: u64,
    heartbeat_ms: u64,
    pq_identity: LocalPqIdentity,
}
// ---- Raft election, replication, barriers, and joint consensus -----------------
impl RaftNode {
    pub async fn open(
        node_id: String,
        peers: Vec<RaftPeer>,
        store: MetadataStore,
        root: PathBuf,
        client: reqwest::Client,
        timing: RaftTiming,
        pq_identity: LocalPqIdentity,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(&root).await?;
        let p = root.join("raft.json");
        let persistent = match tokio::fs::read(&p).await {
            Ok(v) => serde_json::from_slice(&v)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PersistentRaft::default(),
            Err(e) => return Err(e.into()),
        };
        let n = Self {
            node_id,
            peers: Arc::new(RwLock::new(peers)),
            store,
            root,
            client,
            persistent: Arc::new(RwLock::new(persistent)),
            role: Arc::new(RwLock::new(Role::Follower)),
            leader: Arc::new(RwLock::new(None)),
            last_contact_ms: Arc::new(RwLock::new(now_ms())),
            election_min_ms: timing.election_min_ms,
            election_max_ms: timing.election_max_ms,
            heartbeat_ms: timing.heartbeat_ms,
            pq_identity,
        };
        n.apply_committed().await?;
        Ok(n)
    }
    async fn membership(&self) -> Membership {
        let s = self.store.state().await;
        if let Some(j) = s.joint_membership {
            let mut voters = j.old.voters.clone();
            voters.extend(j.new.voters.clone());
            return Membership { voters };
        }
        if let Some(m) = s.membership {
            return m;
        }
        let peers = self.peers.read().await.clone();
        Membership::from_local_and_peers(&self.node_id, String::new(), &peers)
    }
    async fn joint(&self) -> Option<JointMembership> {
        self.store.state().await.joint_membership
    }
    async fn quorum(&self) -> usize {
        self.membership().await.quorum()
    }
    async fn persist(&self) -> Result<()> {
        let p = self.persistent.read().await.clone();
        let tmp = self.root.join("raft.tmp");
        tokio::fs::write(&tmp, serde_json::to_vec(&p)?).await?;
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .await?
            .sync_all()
            .await?;
        tokio::fs::rename(tmp, self.root.join("raft.json")).await?;
        Ok(())
    }
    async fn apply_committed(&self) -> Result<()> {
        loop {
            let applied = self.store.state().await.applied_index;
            let e = {
                let p = self.persistent.read().await;
                if applied >= p.commit_index {
                    None
                } else {
                    p.log.iter().find(|e| e.index == applied + 1).cloned()
                }
            };
            match e {
                Some(e) => self.store.apply(e.index, e.command).await?,
                None => break,
            }
        }
        Ok(())
    }
    pub async fn is_leader(&self) -> bool {
        *self.role.read().await == Role::Leader
    }
    pub async fn status(&self) -> RaftStatus {
        let p = self.persistent.read().await;
        let s = self.store.state().await;
        RaftStatus {
            node_id: self.node_id.clone(),
            role: self.role.read().await.clone(),
            term: p.current_term,
            leader: self.leader.read().await.clone(),
            commit_index: p.commit_index,
            last_applied: s.applied_index,
            last_log_index: p.log.last().map(|x| x.index).unwrap_or(0),
            quorum: self.quorum().await,
            voters: self.membership().await.voters.keys().cloned().collect(),
            joint: self.joint().await.is_some(),
        }
    }
    async fn step_down(&self, term: u64, leader: Option<String>) -> Result<()> {
        {
            let mut p = self.persistent.write().await;
            if term > p.current_term {
                p.current_term = term;
                p.voted_for = None
            }
        }
        *self.role.write().await = Role::Follower;
        *self.leader.write().await = leader;
        *self.last_contact_ms.write().await = now_ms();
        self.persist().await
    }
    pub async fn request_vote(&self, r: VoteRequest) -> Result<VoteResponse> {
        let members = self.membership().await;
        if !members.voters.contains_key(&r.candidate_id) {
            return Ok(VoteResponse {
                term: self.persistent.read().await.current_term,
                vote_granted: false,
            });
        }
        let mut p = self.persistent.write().await;
        if r.term < p.current_term {
            return Ok(VoteResponse {
                term: p.current_term,
                vote_granted: false,
            });
        }
        if r.term > p.current_term {
            p.current_term = r.term;
            p.voted_for = None;
            *self.role.write().await = Role::Follower
        }
        let li = p.log.last().map(|e| e.index).unwrap_or(0);
        let lt = p.log.last().map(|e| e.term).unwrap_or(0);
        let up_to_date =
            (r.last_log_term > lt) || (r.last_log_term == lt && r.last_log_index >= li);
        let grant = up_to_date
            && (p.voted_for.is_none() || p.voted_for.as_deref() == Some(&r.candidate_id));
        if grant {
            p.voted_for = Some(r.candidate_id);
            *self.last_contact_ms.write().await = now_ms()
        }
        let term = p.current_term;
        drop(p);
        self.persist().await?;
        Ok(VoteResponse {
            term,
            vote_granted: grant,
        })
    }
    pub async fn append_entries(&self, r: AppendRequest) -> Result<AppendResponse> {
        let current = self.persistent.read().await.current_term;
        if r.term < current {
            return Ok(AppendResponse {
                term: current,
                success: false,
                match_index: 0,
            });
        }
        self.step_down(r.term, Some(r.leader_id)).await?;
        let mut p = self.persistent.write().await;
        if r.prev_log_index > 0 {
            match p.log.iter().find(|e| e.index == r.prev_log_index) {
                Some(e) if e.term == r.prev_log_term => {}
                _ => {
                    return Ok(AppendResponse {
                        term: p.current_term,
                        success: false,
                        match_index: p.log.last().map(|e| e.index).unwrap_or(0),
                    })
                }
            }
        }
        for e in r.entries {
            if let Some(pos) = p.log.iter().position(|x| x.index == e.index) {
                if p.log[pos].term != e.term {
                    p.log.truncate(pos);
                    p.log.push(e)
                }
            } else {
                p.log.push(e)
            }
        }
        let last = p.log.last().map(|e| e.index).unwrap_or(0);
        p.commit_index = p.commit_index.max(r.leader_commit.min(last));
        let term = p.current_term;
        drop(p);
        self.persist().await?;
        self.apply_committed().await?;
        Ok(AppendResponse {
            term,
            success: true,
            match_index: last,
        })
    }
    async fn post_json<T: Serialize>(
        &self,
        url: String,
        path: &str,
        value: &T,
    ) -> Result<reqwest::Response> {
        let body = serde_json::to_vec(value)?;
        let auth = crate::pq::signed_headers(&self.pq_identity, "POST", path, &body)?;
        Ok(crate::pq::apply_headers(
            self.client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body),
            auth,
        )
        .send()
        .await?)
    }
    pub async fn propose(&self, cmd: MetadataCommand) -> Result<u64> {
        if !self.is_leader().await {
            bail!("not raft leader; leader={:?}", *self.leader.read().await)
        }
        let (entry, prev_i, prev_t) = {
            let mut p = self.persistent.write().await;
            let index = p.log.last().map(|e| e.index + 1).unwrap_or(1);
            let e = LogEntry {
                term: p.current_term,
                index,
                command: cmd,
            };
            let pi = p.log.last().map(|x| x.index).unwrap_or(0);
            let pt = p.log.last().map(|x| x.term).unwrap_or(0);
            p.log.push(e.clone());
            (e, pi, pt)
        };
        self.persist().await?;
        let joint = self.joint().await;
        let members = self.membership().await;
        let peers: Vec<_> = if let Some(j) = &joint {
            let mut m = j.old.voters.clone();
            m.extend(j.new.voters.clone());
            m.remove(&self.node_id);
            m.into_values().collect()
        } else {
            self.peers.read().await.clone()
        };
        let mut acked = std::collections::BTreeSet::new();
        acked.insert(self.node_id.clone());
        let term = entry.term;
        for peer in peers {
            let req = AppendRequest {
                term,
                leader_id: self.node_id.clone(),
                prev_log_index: prev_i,
                prev_log_term: prev_t,
                entries: vec![entry.clone()],
                leader_commit: self.persistent.read().await.commit_index,
            };
            let u = format!(
                "{}/internal/v1/raft/append",
                peer.endpoint.trim_end_matches('/')
            );
            if let Ok(resp) = self.post_json(u, "/internal/v1/raft/append", &req).await {
                if let Ok(ar) = resp.json::<AppendResponse>().await {
                    if ar.term > term {
                        self.step_down(ar.term, None).await?;
                        bail!("higher raft term observed")
                    }
                    if ar.success {
                        acked.insert(peer.id.clone());
                    }
                }
            }
        }
        let ok = if let Some(j) = joint {
            let oq = j.old.voters.keys().filter(|id| acked.contains(*id)).count();
            let nq = j.new.voters.keys().filter(|id| acked.contains(*id)).count();
            oq >= j.old.quorum() && nq >= j.new.quorum()
        } else {
            members
                .voters
                .keys()
                .filter(|id| acked.contains(*id))
                .count()
                >= members.quorum()
        };
        if !ok {
            bail!("raft quorum unavailable; acknowledgements={:?}", acked)
        }
        {
            let mut p = self.persistent.write().await;
            p.commit_index = entry.index
        }
        self.persist().await?;
        self.apply_committed().await?;
        self.send_heartbeat().await;
        Ok(entry.index)
    }
    pub async fn linearizable_barrier(&self, index: u64) -> Result<()> {
        if !self.is_leader().await {
            bail!("not raft leader")
        }
        let p = self.persistent.read().await.clone();
        if p.commit_index < index {
            bail!("requested barrier index is not committed")
        }
        let mut acked = std::collections::BTreeSet::new();
        acked.insert(self.node_id.clone());
        let members = self.membership().await;
        let joint = self.joint().await;
        let peers: Vec<_> = if let Some(j) = &joint {
            let mut m = j.old.voters.clone();
            m.extend(j.new.voters.clone());
            m.remove(&self.node_id);
            m.into_values().collect()
        } else {
            members
                .voters
                .values()
                .filter(|x| x.id != self.node_id)
                .cloned()
                .collect()
        };
        let last = p.log.last().map(|e| e.index).unwrap_or(0);
        let lt = p.log.last().map(|e| e.term).unwrap_or(0);
        for peer in peers {
            let req = AppendRequest {
                term: p.current_term,
                leader_id: self.node_id.clone(),
                prev_log_index: last,
                prev_log_term: lt,
                entries: vec![],
                leader_commit: index,
            };
            let u = format!(
                "{}/internal/v1/raft/append",
                peer.endpoint.trim_end_matches('/')
            );
            if let Ok(r) = self.post_json(u, "/internal/v1/raft/append", &req).await {
                if let Ok(ar) = r.json::<AppendResponse>().await {
                    if ar.term > p.current_term {
                        self.step_down(ar.term, None).await?;
                        bail!("higher raft term observed during consistency barrier")
                    }
                    if ar.success && ar.match_index >= index {
                        acked.insert(peer.id);
                    }
                }
            }
        }
        let ok = if let Some(j) = joint {
            let oq = j.old.voters.keys().filter(|id| acked.contains(*id)).count();
            let nq = j.new.voters.keys().filter(|id| acked.contains(*id)).count();
            oq >= j.old.quorum() && nq >= j.new.quorum()
        } else {
            members
                .voters
                .keys()
                .filter(|id| acked.contains(*id))
                .count()
                >= members.quorum()
        };
        if !ok {
            bail!(
                "linearizable commit barrier unavailable at index {index}; acknowledgements={:?}",
                acked
            )
        }
        Ok(())
    }
    async fn send_heartbeat(&self) {
        if !self.is_leader().await {
            return;
        }
        let p = self.persistent.read().await.clone();
        for peer in self.peers.read().await.clone().iter() {
            let last = p.log.last().map(|e| e.index).unwrap_or(0);
            let lt = p.log.last().map(|e| e.term).unwrap_or(0);
            let req = AppendRequest {
                term: p.current_term,
                leader_id: self.node_id.clone(),
                prev_log_index: last,
                prev_log_term: lt,
                entries: vec![],
                leader_commit: p.commit_index,
            };
            let u = format!(
                "{}/internal/v1/raft/append",
                peer.endpoint.trim_end_matches('/')
            );
            if let Ok(r) = self
                .post_json(u.clone(), "/internal/v1/raft/append", &req)
                .await
            {
                if let Ok(ar) = r.json::<AppendResponse>().await {
                    if ar.term > p.current_term {
                        let _ = self.step_down(ar.term, None).await;
                        return;
                    }
                    if !ar.success {
                        let from = ar.match_index;
                        let prev_term = if from == 0 {
                            0
                        } else {
                            p.log
                                .iter()
                                .find(|e| e.index == from)
                                .map(|e| e.term)
                                .unwrap_or(0)
                        };
                        let entries = p.log.iter().filter(|e| e.index > from).cloned().collect();
                        let catch = AppendRequest {
                            term: p.current_term,
                            leader_id: self.node_id.clone(),
                            prev_log_index: from,
                            prev_log_term: prev_term,
                            entries,
                            leader_commit: p.commit_index,
                        };
                        let _ = self
                            .post_json(u.clone(), "/internal/v1/raft/append", &catch)
                            .await;
                    }
                }
            }
        }
    }
    pub async fn change_membership(&self, new_membership: Membership) -> Result<(u64, u64)> {
        if !self.is_leader().await {
            bail!("not raft leader")
        }
        let state = self.store.state().await;
        if state.joint_membership.is_some() {
            bail!("membership change already in progress")
        }
        let old = if let Some(m) = state.membership {
            m
        } else {
            let peers = self.peers.read().await.clone();
            Membership::from_local_and_peers(&self.node_id, String::new(), &peers)
        };
        if !new_membership.voters.contains_key(&self.node_id) {
            /* leader may remove itself, but finalization must happen first */
        }
        let joint = JointMembership {
            old: old.clone(),
            new: new_membership.clone(),
        };
        let begin = self
            .propose_membership(
                MetadataCommand::BeginJointMembership {
                    joint: joint.clone(),
                },
                Some(&joint),
            )
            .await?;
        self.refresh_peers_from_membership(&joint.new).await;
        let finish = self
            .propose_membership(
                MetadataCommand::FinalizeMembership {
                    membership: new_membership.clone(),
                },
                Some(&joint),
            )
            .await?;
        self.refresh_peers_from_membership(&new_membership).await;
        Ok((begin, finish))
    }
    async fn refresh_peers_from_membership(&self, m: &Membership) {
        let mut p = self.peers.write().await;
        *p = m
            .voters
            .values()
            .filter(|x| x.id != self.node_id)
            .cloned()
            .collect();
    }
    async fn propose_membership(
        &self,
        cmd: MetadataCommand,
        joint: Option<&JointMembership>,
    ) -> Result<u64> {
        if !self.is_leader().await {
            bail!("not raft leader")
        }
        let (entry, prev_i, prev_t) = {
            let mut p = self.persistent.write().await;
            let index = p.log.last().map(|e| e.index + 1).unwrap_or(1);
            let e = LogEntry {
                term: p.current_term,
                index,
                command: cmd,
            };
            let pi = p.log.last().map(|x| x.index).unwrap_or(0);
            let pt = p.log.last().map(|x| x.term).unwrap_or(0);
            p.log.push(e.clone());
            (e, pi, pt)
        };
        self.persist().await?;
        let peers = if let Some(j) = joint {
            let mut m = j.old.voters.clone();
            m.extend(j.new.voters.clone());
            m.remove(&self.node_id);
            m.into_values().collect()
        } else {
            self.peers.read().await.clone()
        };
        let mut acked = std::collections::BTreeSet::new();
        acked.insert(self.node_id.clone());
        let term = entry.term;
        for peer in peers {
            let req = AppendRequest {
                term,
                leader_id: self.node_id.clone(),
                prev_log_index: prev_i,
                prev_log_term: prev_t,
                entries: vec![entry.clone()],
                leader_commit: self.persistent.read().await.commit_index,
            };
            let u = format!(
                "{}/internal/v1/raft/append",
                peer.endpoint.trim_end_matches('/')
            );
            if let Ok(resp) = self.post_json(u, "/internal/v1/raft/append", &req).await {
                if let Ok(ar) = resp.json::<AppendResponse>().await {
                    if ar.term > term {
                        self.step_down(ar.term, None).await?;
                        bail!("higher raft term observed")
                    }
                    if ar.success {
                        acked.insert(peer.id.clone());
                    }
                }
            }
        }
        let ok = if let Some(j) = joint {
            let oq = j.old.voters.keys().filter(|id| acked.contains(*id)).count();
            let nq = j.new.voters.keys().filter(|id| acked.contains(*id)).count();
            oq >= j.old.quorum() && nq >= j.new.quorum()
        } else {
            acked.len() >= self.quorum().await
        };
        if !ok {
            bail!(
                "joint-consensus quorum unavailable; acknowledgements={:?}",
                acked
            )
        }
        {
            let mut p = self.persistent.write().await;
            p.commit_index = entry.index
        }
        self.persist().await?;
        self.apply_committed().await?;
        self.send_heartbeat().await;
        Ok(entry.index)
    }
    pub async fn run(self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(self.heartbeat_ms)).await;
            if self.is_leader().await {
                self.send_heartbeat().await;
                continue;
            }
            let elapsed = now_ms().saturating_sub(*self.last_contact_ms.read().await) as u64;
            let span = self
                .election_max_ms
                .saturating_sub(self.election_min_ms)
                .max(1);
            let timeout = self.election_min_ms
                + (blake3::hash(
                    format!(
                        "{}:{}",
                        self.node_id,
                        self.persistent.read().await.current_term
                    )
                    .as_bytes(),
                )
                .as_bytes()[0] as u64
                    % span);
            if elapsed < timeout {
                continue;
            }
            let (term, li, lt) = {
                let mut p = self.persistent.write().await;
                p.current_term += 1;
                p.voted_for = Some(self.node_id.clone());
                (
                    p.current_term,
                    p.log.last().map(|e| e.index).unwrap_or(0),
                    p.log.last().map(|e| e.term).unwrap_or(0),
                )
            };
            let _ = self.persist().await;
            *self.role.write().await = Role::Candidate;
            *self.last_contact_ms.write().await = now_ms();
            let mut votes = std::collections::BTreeSet::new();
            votes.insert(self.node_id.clone());
            for peer in self.peers.read().await.clone().iter() {
                let r = VoteRequest {
                    term,
                    candidate_id: self.node_id.clone(),
                    last_log_index: li,
                    last_log_term: lt,
                };
                if let Ok(x) = self
                    .post_json(
                        format!(
                            "{}/internal/v1/raft/vote",
                            peer.endpoint.trim_end_matches('/')
                        ),
                        "/internal/v1/raft/vote",
                        &r,
                    )
                    .await
                {
                    if let Ok(v) = x.json::<VoteResponse>().await {
                        if v.term > term {
                            let _ = self.step_down(v.term, None).await;
                            break;
                        }
                        if v.vote_granted {
                            votes.insert(peer.id.clone());
                        }
                    }
                }
            }
            let election_ok = if let Some(j) = self.joint().await {
                let oq = j.old.voters.keys().filter(|id| votes.contains(*id)).count();
                let nq = j.new.voters.keys().filter(|id| votes.contains(*id)).count();
                oq >= j.old.quorum() && nq >= j.new.quorum()
            } else {
                votes.len() >= self.quorum().await
            };
            if election_ok && self.persistent.read().await.current_term == term {
                *self.role.write().await = Role::Leader;
                *self.leader.write().await = Some(self.node_id.clone());
                self.send_heartbeat().await
            } else {
                *self.role.write().await = Role::Follower
            }
        }
    }
}
