// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Authenticated path-style S3 adapter. Protocol parsing and signature validation
//! are provided by s3s; storage, retention and commit authority remain in Kagi.
use crate::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use md5::{Digest, Md5};
use s3s::{dto::*, s3_error, S3Request, S3Response, S3Result, S3};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Separate S3 socket; disabled when omitted. TLS uses the node certificate.
    pub listen: String,
    /// Hard memory bound for a single object, part, or completed upload.
    #[serde(default = "max_object")]
    pub max_object_bytes: usize,
    /// Explicit per-access-key bucket authorization and local ACL identity.
    pub credentials: BTreeMap<String, Credential>,
}
fn max_object() -> usize {
    64 * 1024 * 1024
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub secret_key: String,
    /// Fixed Unix identity, mutually exclusive with directory_user.
    pub uid: Option<u32>,
    /// Native NSS/SSSD/winbind identity resolved for every authenticated request.
    #[serde(default)]
    pub directory_user: Option<String>,
    #[serde(default)]
    pub gids: Vec<u32>,
    pub buckets: BTreeSet<String>,
    #[serde(default)]
    pub read_only: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Attributes {
    pub etag: String,
    pub content_type: Option<String>,
    pub metadata: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Upload {
    pub id: String,
    pub bucket: String,
    pub key: String,
    pub owner: String,
    pub attributes: Attributes,
    pub parts: BTreeMap<i32, PartRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartRecord {
    pub etag: String,
    pub manifest: ObjectManifest,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Mutation {
    Begin(Upload),
    Part {
        id: String,
        number: i32,
        part: Box<PartRecord>,
        now: u128,
        eligible: u128,
    },
    Abort {
        id: String,
        now: u128,
        eligible: u128,
    },
    Commit {
        manifest: Box<ObjectManifest>,
        parent: Option<Box<ObjectManifest>>,
        attributes: Attributes,
        upload_id: Option<String>,
        now: u128,
        eligible: u128,
    },
}
/// Applied in the same persisted Raft state as object visibility. Parts are never
/// exposed in listings and completion removes the upload atomically with publish.
pub fn apply(state: &mut raftmeta::MetadataState, mutation: Mutation) {
    fn garbage(state: &mut raftmeta::MetadataState, m: ObjectManifest, now: u128, eligible: u128) {
        let id = format!("{}:{}", m.object_id, m.version);
        state.garbage.insert(
            id.clone(),
            GarbageRecord {
                id,
                key: m.key.clone(),
                version: m.version,
                manifest: m,
                deleted_at_unix_ms: now,
                eligible_after_unix_ms: eligible,
                attempts: 0,
                last_error: None,
                fence_index: 0,
            },
        );
    }
    match mutation {
        Mutation::Begin(upload) => {
            state.s3_uploads.entry(upload.id.clone()).or_insert(upload);
        }
        Mutation::Part {
            id,
            number,
            part,
            now,
            eligible,
        } => {
            if let Some(upload) = state.s3_uploads.get_mut(&id) {
                if let Some(old) = upload.parts.insert(number, *part) {
                    // Replacement parts remain fenced until the configured GC grace.
                    garbage(state, old.manifest, now, eligible);
                }
            }
        }
        Mutation::Abort { id, now, eligible } => {
            if let Some(upload) = state.s3_uploads.remove(&id) {
                for part in upload.parts.into_values() {
                    garbage(state, part.manifest, now, eligible);
                }
            }
        }
        Mutation::Commit {
            manifest,
            parent,
            attributes,
            upload_id,
            now,
            eligible,
        } => {
            if let Some(id) = upload_id {
                let Some(upload) = state.s3_uploads.remove(&id) else {
                    return;
                };
                for part in upload.parts.into_values() {
                    garbage(state, part.manifest, now, eligible);
                }
            }
            state.s3_attributes.insert(
                format!("{}:{}", manifest.object_id, manifest.version),
                attributes,
            );
            if let Some(parent) = parent {
                raftmeta::apply_namespace_mutation(
                    state,
                    NamespaceMutation::PutManifest {
                        key: parent.key.clone(),
                        manifest: parent,
                    },
                );
            }
            raftmeta::apply_namespace_mutation(
                state,
                NamespaceMutation::PutManifest {
                    key: manifest.key.clone(),
                    manifest,
                },
            );
        }
    }
}
#[derive(Clone)]
struct Adapter {
    state: V6State,
    config: Config,
}
#[async_trait::async_trait]
impl s3s::auth::S3Auth for Config {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<s3s::auth::SecretKey> {
        self.credentials
            .get(access_key)
            .map(|c| c.secret_key.clone().into())
            .ok_or_else(|| s3_error!(InvalidAccessKeyId))
    }
}
/// Build an authenticated service only after validating its explicit allowlists.
pub fn router(state: V6State, config: Config) -> Result<Router> {
    anyhow::ensure!(!config.credentials.is_empty(), "S3 requires credentials");
    anyhow::ensure!(
        config.max_object_bytes > 0,
        "S3 object bound must be positive"
    );
    for (id, c) in &config.credentials {
        anyhow::ensure!(
            !id.is_empty() && c.secret_key.len() >= 32,
            "S3 credentials require an ID and at least 32 secret bytes"
        );
        anyhow::ensure!(
            c.uid.is_some() != c.directory_user.is_some(),
            "S3 requires exactly one of uid or directory_user"
        );
        anyhow::ensure!(
            !c.buckets.is_empty(),
            "S3 credentials require explicit bucket allowlists"
        );
    }
    let mut builder = s3s::service::S3ServiceBuilder::new(Adapter {
        state,
        config: config.clone(),
    });
    builder.set_auth(config);
    let service = builder.build();
    let admission = Arc::new(tokio::sync::Semaphore::new(8));
    Ok(
        Router::new().fallback(move |request: axum::extract::Request| {
            let service = service.clone();
            let admission = admission.clone();
            async move {
                let Ok(_permit) = admission.try_acquire_owned() else {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                };
                let request = request.map(s3s::Body::http_body_unsync);
                match service.call(request).await {
                    Ok(response) => response.map(axum::body::Body::new),
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
        }),
    )
}
fn unavailable(_: impl std::fmt::Display) -> s3s::S3Error {
    s3_error!(ServiceUnavailable)
}
fn timestamp(ms: u128) -> Timestamp {
    Timestamp::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.min(u64::MAX as u128) as u64),
    )
}
fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Md5::digest(bytes)))
}
/// Validate all supplied checksum headers and verified streaming trailers before
/// any Raft mutation. Merely accepting a checksum header is not validation.
fn validate_checksums<T>(req: &S3Request<T>, data: &[u8]) -> S3Result<()> {
    let mut headers = req.headers.clone();
    if let Some(trailers) = req.trailing_headers.as_ref().and_then(|t| t.take()) {
        headers.extend(trailers);
    }
    let mut hasher = s3s::checksum::ChecksumHasher {
        crc32: headers
            .contains_key("x-amz-checksum-crc32")
            .then(Default::default),
        crc32c: headers
            .contains_key("x-amz-checksum-crc32c")
            .then(Default::default),
        crc64nvme: headers
            .contains_key("x-amz-checksum-crc64nvme")
            .then(Default::default),
        sha1: headers
            .contains_key("x-amz-checksum-sha1")
            .then(Default::default),
        sha256: headers
            .contains_key("x-amz-checksum-sha256")
            .then(Default::default),
        sha512: headers
            .contains_key("x-amz-checksum-sha512")
            .then(Default::default),
        md5: headers
            .contains_key("x-amz-checksum-md5")
            .then(Default::default),
        xxhash64: headers
            .contains_key("x-amz-checksum-xxhash64")
            .then(Default::default),
        xxhash3: headers
            .contains_key("x-amz-checksum-xxhash3")
            .then(Default::default),
        xxhash128: headers
            .contains_key("x-amz-checksum-xxhash128")
            .then(Default::default),
    };
    hasher.update(data);
    let sums = hasher.finalize();
    for (name, value) in [
        ("crc32", sums.checksum_crc32),
        ("crc32c", sums.checksum_crc32c),
        ("crc64nvme", sums.checksum_crc64nvme),
        ("sha1", sums.checksum_sha1),
        ("sha256", sums.checksum_sha256),
        ("sha512", sums.checksum_sha512),
        ("md5", sums.checksum_md5),
        ("xxhash64", sums.checksum_xxhash64),
        ("xxhash3", sums.checksum_xxhash3),
        ("xxhash128", sums.checksum_xxhash128),
    ] {
        if let Some(value) = value {
            if headers
                .get(format!("x-amz-checksum-{name}"))
                .and_then(|v| v.to_str().ok())
                != Some(value.as_str())
            {
                return Err(s3_error!(BadDigest));
            }
        }
    }
    Ok(())
}

impl Adapter {
    async fn barrier(&self) -> S3Result<()> {
        let index = self.state.meta.status().await.commit_index;
        self.state
            .meta
            .linearizable_barrier(index)
            .await
            .map_err(unavailable)
    }
    async fn identity<T>(
        &self,
        req: &S3Request<T>,
        bucket: Option<&str>,
        write: bool,
    ) -> S3Result<axum::http::HeaderMap> {
        for name in req.headers.keys() {
            let n = name.as_str();
            if n.starts_with("x-amz-")
                && !n.starts_with("x-amz-meta-")
                && !n.starts_with("x-amz-checksum-")
                && !matches!(
                    n,
                    "x-amz-date"
                        | "x-amz-content-sha256"
                        | "x-amz-sdk-checksum-algorithm"
                        | "x-amz-trailer"
                        | "x-amz-decoded-content-length"
                )
            {
                return Err(s3_error!(NotImplemented));
            }
        }
        let credentials = req
            .credentials
            .as_ref()
            .ok_or_else(|| s3_error!(AccessDenied))?;
        let c = self
            .config
            .credentials
            .get(&credentials.access_key)
            .ok_or_else(|| s3_error!(AccessDenied))?;
        if (write && c.read_only) || bucket.is_some_and(|b| !c.buckets.contains(b)) {
            return Err(s3_error!(AccessDenied));
        }
        let resolved = if let Some(user) = &c.directory_user {
            Some(
                identity::resolve(user.clone())
                    .await
                    .map_err(|_| s3_error!(AccessDenied))?,
            )
        } else {
            None
        };
        let mut h = axum::http::HeaderMap::new();
        let uid = resolved
            .as_ref()
            .map(|i| i.uid.clone())
            .or_else(|| c.uid.map(|id| id.to_string()))
            .ok_or_else(|| s3_error!(AccessDenied))?;
        let gids = resolved
            .as_ref()
            .map(|i| i.gids.join(","))
            .unwrap_or_else(|| {
                c.gids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            });
        h.insert("x-kagi-unix-uid", uid.parse().map_err(unavailable)?);
        h.insert("x-kagi-unix-gids", gids.parse().map_err(unavailable)?);
        if let Some(resolved) = resolved {
            if let Some(sid) = resolved.ad_sid {
                h.insert("x-kagi-ad-sid", sid.parse().map_err(unavailable)?);
            }
            h.insert(
                "x-kagi-ad-group-sids",
                resolved
                    .ad_group_sids
                    .join(",")
                    .parse()
                    .map_err(unavailable)?,
            );
        }
        Ok(h)
    }
    async fn bucket(&self, name: &str) -> S3Result<BucketRecord> {
        self.barrier().await?;
        self.state
            .meta
            .store
            .state()
            .await
            .buckets
            .get(name)
            .cloned()
            .ok_or_else(|| s3_error!(NoSuchBucket))
    }
    async fn policy(
        &self,
        key: &str,
        h: &axum::http::HeaderMap,
        permission: &str,
        operation: u32,
    ) -> S3Result<()> {
        let m = self.state.meta.store.get(key).await;
        let privileged = m
            .as_ref()
            .and_then(|m| m.fs.as_ref())
            .is_some_and(|f| f.privileged);
        if !self.state.security.check(key, operation, privileged) {
            return Err(s3_error!(AccessDenied));
        }
        if m.as_ref()
            .and_then(|m| m.fs.as_ref())
            .is_some_and(|f| !AuthIdentity::from_headers(h).allows(&f.acl, permission))
        {
            return Err(s3_error!(AccessDenied));
        }
        Ok(())
    }
    async fn manifest(
        &self,
        bucket: &str,
        key: &str,
        h: &axum::http::HeaderMap,
    ) -> S3Result<(ObjectManifest, Attributes)> {
        self.bucket(bucket).await?;
        let key = format!("{bucket}/{key}");
        self.policy(&key, h, "read_data", security::common::OP_READ)
            .await?;
        let s = self.state.meta.store.state().await;
        let m = s
            .manifests
            .get(&key)
            .cloned()
            .ok_or_else(|| s3_error!(NoSuchKey))?;
        let attrs = s
            .s3_attributes
            .get(&format!("{}:{}", m.object_id, m.version))
            .cloned()
            .unwrap_or_else(|| Attributes {
                etag: format!("\"{}\"", m.checksum),
                ..Default::default()
            });
        Ok((m, attrs))
    }
    async fn collect(&self, body: Option<StreamingBlob>, length: Option<i64>) -> S3Result<Vec<u8>> {
        if length.is_some_and(|n| n < 0 || n as u64 > self.config.max_object_bytes as u64) {
            return Err(s3_error!(EntityTooLarge));
        }
        let mut out = Vec::new();
        if let Some(mut stream) = body {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| s3_error!(IncompleteBody))?;
                if chunk.len() > self.config.max_object_bytes.saturating_sub(out.len()) {
                    return Err(s3_error!(EntityTooLarge));
                }
                out.extend_from_slice(&chunk);
            }
        }
        if length.is_some_and(|n| n as usize != out.len()) {
            return Err(s3_error!(IncompleteBody));
        }
        Ok(out)
    }
    async fn commit(&self, mutation: Mutation) -> S3Result<()> {
        committed(&self.state, MetadataCommand::S3 { mutation })
            .await
            .map_err(unavailable)?;
        Ok(())
    }
    async fn publish(
        &self,
        bucket: &str,
        key: &str,
        h: &axum::http::HeaderMap,
        data: &[u8],
        attrs: Attributes,
        upload_id: Option<String>,
    ) -> S3Result<()> {
        let bucket = self.bucket(bucket).await?;
        let full = format!("{}/{key}", bucket.name);
        self.policy(
            &full,
            h,
            "write_data",
            security::common::OP_WRITE | security::common::OP_CREATE,
        )
        .await?;
        if let Some(parent) = parent_key_for(&full) {
            self.policy(&parent, h, "write_data", security::common::OP_WRITE)
                .await?;
        }
        let old_fs = self.state.meta.store.get(&full).await.and_then(|m| m.fs);
        let parent = match parent_key_for(&full) {
            Some(key) => self.state.meta.store.get(&key).await,
            None => None,
        };
        let fs = FsMetadata {
            object_type: FsObjectType::File,
            name: name_for(&full),
            path: format!("/{full}"),
            parent_key: parent_key_for(&full),
            parent_object_id: parent.map(|m| m.object_id),
            children: vec![],
            contents: vec![],
            acl: old_fs
                .as_ref()
                .map(|f| f.acl.clone())
                .unwrap_or_else(|| default_acl(h)),
            privileged: self
                .state
                .meta
                .store
                .get(&full)
                .await
                .and_then(|m| m.fs)
                .is_some_and(|f| f.privileged),
        };
        let state = effective_data(&self.state).await;
        let manifest = put_filesystem_object(
            &state,
            &full,
            data,
            Some(&self.state.health),
            bucket.default_worm,
            fs,
        )
        .await
        .map_err(unavailable)?;
        let parent = prepare_parent_directory(&self.state, &manifest)
            .await
            .map_err(unavailable)?;
        let now = now_ms();
        self.commit(Mutation::Commit {
            manifest: Box::new(manifest.clone()),
            parent: parent.clone().map(Box::new),
            attributes: attrs,
            upload_id,
            now,
            eligible: now.saturating_add(self.state.gc.grace_period_ms as u128),
        })
        .await?;
        index_manifest(&self.state, &manifest).await;
        if let Some(parent) = parent {
            index_manifest(&self.state, &parent).await;
        }
        Ok(())
    }
    async fn upload<T>(
        &self,
        req: &S3Request<T>,
        bucket: &str,
        key: &str,
        id: &str,
    ) -> S3Result<Upload> {
        self.bucket(bucket).await?;
        self.state
            .meta
            .store
            .state()
            .await
            .s3_uploads
            .get(id)
            .filter(|u| {
                u.bucket == bucket
                    && u.key == key
                    && req
                        .credentials
                        .as_ref()
                        .is_some_and(|c| c.access_key == u.owner)
            })
            .cloned()
            .ok_or_else(|| s3_error!(NoSuchUpload))
    }
}

#[async_trait::async_trait]
impl S3 for Adapter {
    async fn create_bucket(
        &self,
        req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        self.identity(&req, Some(&req.input.bucket), true).await?;
        let _guard = self.state.namespace_lock.lock().await;
        self.barrier().await?;
        if self
            .state
            .meta
            .store
            .state()
            .await
            .buckets
            .contains_key(&req.input.bucket)
        {
            return Err(s3_error!(BucketAlreadyOwnedByYou));
        }
        committed(
            &self.state,
            MetadataCommand::PutBucket {
                bucket: BucketRecord {
                    name: req.input.bucket,
                    created_at_unix_ms: now_ms(),
                    ..Default::default()
                },
            },
        )
        .await
        .map_err(unavailable)?;
        Ok(S3Response::new(CreateBucketOutput::default()))
    }
    async fn head_bucket(
        &self,
        req: S3Request<HeadBucketInput>,
    ) -> S3Result<S3Response<HeadBucketOutput>> {
        self.identity(&req, Some(&req.input.bucket), false).await?;
        self.bucket(&req.input.bucket).await?;
        Ok(S3Response::new(HeadBucketOutput::default()))
    }
    async fn list_buckets(
        &self,
        req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        self.identity(&req, None, false).await?;
        self.barrier().await?;
        let c = &self.config.credentials[&req
            .credentials
            .as_ref()
            .ok_or_else(|| s3_error!(AccessDenied))?
            .access_key];
        let buckets = self
            .state
            .meta
            .store
            .state()
            .await
            .buckets
            .into_values()
            .filter(|b| c.buckets.contains(&b.name))
            .map(|b| Bucket {
                name: Some(b.name),
                creation_date: Some(timestamp(b.created_at_unix_ms)),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(ListBucketsOutput {
            buckets: Some(buckets),
            ..Default::default()
        }))
    }
    async fn delete_bucket(
        &self,
        req: S3Request<DeleteBucketInput>,
    ) -> S3Result<S3Response<DeleteBucketOutput>> {
        self.identity(&req, Some(&req.input.bucket), true).await?;
        let _guard = self.state.namespace_lock.lock().await;
        self.bucket(&req.input.bucket).await?;
        let state = self.state.meta.store.state().await;
        if state
            .manifests
            .keys()
            .any(|k| k.starts_with(&format!("{}/", req.input.bucket)))
            || state
                .s3_uploads
                .values()
                .any(|u| u.bucket == req.input.bucket)
        {
            return Err(s3_error!(BucketNotEmpty));
        }
        committed(
            &self.state,
            MetadataCommand::DeleteBucket {
                name: req.input.bucket,
            },
        )
        .await
        .map_err(unavailable)?;
        Ok(S3Response::new(DeleteBucketOutput::default()))
    }
    async fn put_object(
        &self,
        mut req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        let h = self.identity(&req, Some(&req.input.bucket), true).await?;
        // Never silently accept options whose security/storage semantics are unsupported.
        if req.input.acl.is_some()
            || req.input.server_side_encryption.is_some()
            || req.input.sse_customer_key.is_some()
            || req.input.object_lock_mode.is_some()
            || req.input.object_lock_legal_hold_status.is_some()
            || req.input.tagging.is_some()
        {
            return Err(s3_error!(NotImplemented));
        }
        let data = self
            .collect(req.input.body.take(), req.input.content_length)
            .await?;
        validate_checksums(&req, &data)?;
        let tag = etag(&data);
        if let Some(expected) = &req.input.content_md5 {
            use base64::engine::general_purpose::STANDARD;
            if STANDARD.encode(Md5::digest(&data)) != *expected {
                return Err(s3_error!(BadDigest));
            }
        }
        let _guard = self.state.namespace_lock.lock().await;
        self.barrier().await?;
        let old = self
            .state
            .meta
            .store
            .get(&format!("{}/{}", req.input.bucket, req.input.key))
            .await;
        if req
            .input
            .if_none_match
            .as_ref()
            .is_some_and(|v| v.is_any() && old.is_some())
        {
            return Err(s3_error!(PreconditionFailed));
        }
        if let Some(condition) = &req.input.if_match {
            let tag = if let Some(m) = &old {
                self.state
                    .meta
                    .store
                    .state()
                    .await
                    .s3_attributes
                    .get(&format!("{}:{}", m.object_id, m.version))
                    .map(|a| a.etag.clone())
            } else {
                None
            };
            if old.is_none()
                || (!condition.is_any()
                    && condition.as_etag().and_then(ETag::as_strong)
                        != tag.as_deref().map(|s| s.trim_matches('"')))
            {
                return Err(s3_error!(PreconditionFailed));
            }
        }
        self.publish(
            &req.input.bucket,
            &req.input.key,
            &h,
            &data,
            Attributes {
                etag: tag.clone(),
                content_type: req.input.content_type,
                metadata: req.input.metadata.unwrap_or_default().into_iter().collect(),
            },
            None,
        )
        .await?;
        Ok(S3Response::new(PutObjectOutput {
            e_tag: Some(tag.parse().map_err(unavailable)?),
            ..Default::default()
        }))
    }
    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        let h = self.identity(&req, Some(&req.input.bucket), false).await?;
        if req.input.version_id.is_some()
            || req.input.part_number.is_some()
            || req.input.sse_customer_key.is_some()
        {
            return Err(s3_error!(NotImplemented));
        }
        let (m, attrs) = self.manifest(&req.input.bucket, &req.input.key, &h).await?;
        if req.input.if_match.as_ref().is_some_and(|v| {
            !v.is_any()
                && v.as_etag().and_then(ETag::as_strong) != Some(attrs.etag.trim_matches('"'))
        }) {
            return Err(s3_error!(PreconditionFailed));
        }
        if req.input.if_none_match.as_ref().is_some_and(|v| {
            v.is_any() || v.as_etag().map(ETag::value) == Some(attrs.etag.trim_matches('"'))
        }) {
            return Err(s3_error!(NotModified));
        }
        if req.input.if_modified_since.is_some() || req.input.if_unmodified_since.is_some() {
            return Err(s3_error!(NotImplemented));
        }
        let mut data = get_object_version(&self.state.data, &m)
            .await
            .map_err(unavailable)?;
        let mut content_range = None;
        if let Some(range) = req.input.range {
            let range = range
                .check(data.len() as u64)
                .map_err(|_| s3_error!(InvalidRange))?;
            content_range = Some(format!(
                "bytes {}-{}/{}",
                range.start,
                range.end - 1,
                data.len()
            ));
            data = data[range.start as usize..range.end as usize].to_vec();
        }
        let mut response = S3Response::new(GetObjectOutput {
            content_length: Some(data.len() as i64),
            body: Some(Bytes::from(data).into()),
            e_tag: Some(attrs.etag.parse().map_err(unavailable)?),
            content_type: attrs.content_type,
            metadata: Some(attrs.metadata.into_iter().collect()),
            content_range,
            accept_ranges: Some("bytes".into()),
            last_modified: Some(timestamp(m.committed_at_unix_ms)),
            ..Default::default()
        });
        if req.input.range.is_some() {
            response.status = Some(StatusCode::PARTIAL_CONTENT);
        }
        Ok(response)
    }
    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        let h = self.identity(&req, Some(&req.input.bucket), false).await?;
        if req.input.version_id.is_some()
            || req.input.range.is_some()
            || req.input.if_match.is_some()
            || req.input.if_none_match.is_some()
            || req.input.if_modified_since.is_some()
            || req.input.if_unmodified_since.is_some()
        {
            return Err(s3_error!(NotImplemented));
        }
        let (m, attrs) = self.manifest(&req.input.bucket, &req.input.key, &h).await?;
        Ok(S3Response::new(HeadObjectOutput {
            content_length: Some(m.bytes as i64),
            e_tag: Some(attrs.etag.parse().map_err(unavailable)?),
            content_type: attrs.content_type,
            metadata: Some(attrs.metadata.into_iter().collect()),
            last_modified: Some(timestamp(m.committed_at_unix_ms)),
            ..Default::default()
        }))
    }
    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        let h = self.identity(&req, Some(&req.input.bucket), true).await?;
        if req.input.version_id.is_some() {
            return Err(s3_error!(NotImplemented));
        }
        let _guard = self.state.namespace_lock.lock().await;
        self.bucket(&req.input.bucket).await?;
        let key = format!("{}/{}", req.input.bucket, req.input.key);
        self.policy(&key, &h, "delete", security::common::OP_DELETE)
            .await?;
        if self
            .state
            .meta
            .store
            .get(&key)
            .await
            .is_some_and(|m| m.worm.immutable(now_ms()))
        {
            return Err(s3_error!(AccessDenied));
        }
        committed(
            &self.state,
            MetadataCommand::PutDeleteMarker {
                key,
                version: now_ms() as u64,
                created_unix_ms: now_ms(),
            },
        )
        .await
        .map_err(unavailable)?;
        Ok(S3Response::new(DeleteObjectOutput::default()))
    }
    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let h = self.identity(&req, Some(&req.input.bucket), false).await?;
        self.bucket(&req.input.bucket).await?;
        if req.input.encoding_type.is_some() {
            return Err(s3_error!(NotImplemented));
        }
        let limit = req.input.max_keys.unwrap_or(1000);
        if !(0..=1000).contains(&limit) {
            return Err(s3_error!(InvalidArgument));
        }
        let prefix = req.input.prefix.clone().unwrap_or_default();
        let after = match &req.input.continuation_token {
            Some(token) => String::from_utf8(
                URL_SAFE_NO_PAD
                    .decode(token)
                    .map_err(|_| s3_error!(InvalidArgument))?,
            )
            .map_err(|_| s3_error!(InvalidArgument))?,
            None => req.input.start_after.clone().unwrap_or_default(),
        };
        let state = self.state.meta.store.state().await;
        let base = format!("{}/", req.input.bucket);
        let mut entries: BTreeMap<String, Option<Object>> = BTreeMap::new();
        for (full, m) in &state.manifests {
            let Some(key) = full.strip_prefix(&base) else {
                continue;
            };
            if !key.starts_with(&prefix) {
                continue;
            }
            if self
                .policy(full, &h, "read_data", security::common::OP_READ)
                .await
                .is_err()
            {
                continue;
            }
            if let Some(delimiter) = req.input.delimiter.as_ref().filter(|d| !d.is_empty()) {
                if let Some(i) = key[prefix.len()..].find(delimiter) {
                    let common = key[..prefix.len() + i + delimiter.len()].to_string();
                    if common > after {
                        entries.insert(common, None);
                    }
                    continue;
                }
            }
            if key <= after.as_str() {
                continue;
            }
            let tag = state
                .s3_attributes
                .get(&format!("{}:{}", m.object_id, m.version))
                .map(|a| a.etag.clone())
                .unwrap_or_else(|| format!("\"{}\"", m.checksum));
            entries.insert(
                key.into(),
                Some(Object {
                    key: Some(key.into()),
                    size: Some(m.bytes as i64),
                    e_tag: Some(tag.parse().map_err(unavailable)?),
                    last_modified: Some(timestamp(m.committed_at_unix_ms)),
                    ..Default::default()
                }),
            );
        }
        let truncated = limit > 0 && entries.len() > limit as usize;
        let mut contents = Vec::new();
        let mut common = Vec::new();
        let mut last = None;
        for (key, object) in entries.into_iter().take(limit as usize) {
            last = Some(URL_SAFE_NO_PAD.encode(key.as_bytes()));
            if let Some(object) = object {
                contents.push(object);
            } else {
                common.push(CommonPrefix { prefix: Some(key) });
            }
        }
        Ok(S3Response::new(ListObjectsV2Output {
            name: Some(req.input.bucket),
            prefix: Some(prefix),
            max_keys: Some(limit),
            key_count: Some((contents.len() + common.len()) as i32),
            is_truncated: Some(truncated),
            continuation_token: req.input.continuation_token,
            next_continuation_token: if truncated { last } else { None },
            delimiter: req.input.delimiter,
            contents: Some(contents),
            common_prefixes: Some(common),
            ..Default::default()
        }))
    }
    async fn list_objects(
        &self,
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        let marker = req.input.marker.clone();
        let response = self
            .list_objects_v2(req.map_input(|i| ListObjectsV2Input {
                bucket: i.bucket,
                prefix: i.prefix,
                delimiter: i.delimiter,
                max_keys: i.max_keys,
                start_after: i.marker,
                encoding_type: i.encoding_type,
                ..Default::default()
            }))
            .await?;
        let output = response.output;
        let next = output
            .next_continuation_token
            .map(|t| {
                URL_SAFE_NO_PAD
                    .decode(t)
                    .map_err(|_| s3_error!(InternalError))
                    .and_then(|v| String::from_utf8(v).map_err(|_| s3_error!(InternalError)))
            })
            .transpose()?;
        Ok(S3Response::new(ListObjectsOutput {
            name: output.name,
            prefix: output.prefix,
            marker,
            max_keys: output.max_keys,
            is_truncated: output.is_truncated,
            contents: output.contents,
            common_prefixes: output.common_prefixes,
            delimiter: output.delimiter,
            next_marker: next,
            ..Default::default()
        }))
    }
    async fn list_parts(
        &self,
        req: S3Request<ListPartsInput>,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        self.identity(&req, Some(&req.input.bucket), false).await?;
        let upload = self
            .upload(
                &req,
                &req.input.bucket,
                &req.input.key,
                &req.input.upload_id,
            )
            .await?;
        let limit = req.input.max_parts.unwrap_or(1000);
        let marker = req.input.part_number_marker.unwrap_or(0);
        if !(0..=1000).contains(&limit) || marker < 0 {
            return Err(s3_error!(InvalidArgument));
        }
        let remaining: Vec<_> = upload.parts.iter().filter(|(n, _)| **n > marker).collect();
        let truncated = limit > 0 && remaining.len() > limit as usize;
        let mut parts = Vec::new();
        let mut last = marker;
        for (number, part) in remaining.into_iter().take(limit as usize) {
            last = *number;
            parts.push(Part {
                part_number: Some(*number),
                size: Some(part.manifest.bytes as i64),
                e_tag: Some(part.etag.parse().map_err(unavailable)?),
                last_modified: Some(timestamp(part.manifest.committed_at_unix_ms)),
                ..Default::default()
            });
        }
        Ok(S3Response::new(ListPartsOutput {
            bucket: Some(req.input.bucket),
            key: Some(req.input.key),
            upload_id: Some(req.input.upload_id),
            parts: Some(parts),
            max_parts: Some(limit),
            is_truncated: Some(truncated),
            part_number_marker: Some(marker),
            next_part_number_marker: truncated.then_some(last),
            ..Default::default()
        }))
    }
    async fn list_multipart_uploads(
        &self,
        req: S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<ListMultipartUploadsOutput>> {
        self.identity(&req, Some(&req.input.bucket), false).await?;
        self.bucket(&req.input.bucket).await?;
        if req.input.delimiter.is_some() || req.input.encoding_type.is_some() {
            return Err(s3_error!(NotImplemented));
        }
        let limit = req.input.max_uploads.unwrap_or(1000);
        if !(0..=1000).contains(&limit) {
            return Err(s3_error!(InvalidArgument));
        }
        let owner = &req
            .credentials
            .as_ref()
            .ok_or_else(|| s3_error!(AccessDenied))?
            .access_key;
        let prefix = req.input.prefix.as_deref().unwrap_or("");
        let key_marker = req.input.key_marker.as_deref().unwrap_or("");
        let id_marker = req.input.upload_id_marker.as_deref();
        let mut uploads: Vec<_> = self
            .state
            .meta
            .store
            .state()
            .await
            .s3_uploads
            .into_values()
            .filter(|u| {
                u.bucket == req.input.bucket
                    && &u.owner == owner
                    && u.key.starts_with(prefix)
                    && (req.input.key_marker.is_none()
                        || u.key.as_str() > key_marker
                        || (u.key == key_marker && id_marker.is_some_and(|id| u.id.as_str() > id)))
            })
            .collect();
        uploads.sort_by(|a, b| (&a.key, &a.id).cmp(&(&b.key, &b.id)));
        let truncated = limit > 0 && uploads.len() > limit as usize;
        uploads.truncate(limit as usize);
        let next_key_marker = truncated.then(|| uploads.last().unwrap().key.clone());
        let next_upload_id_marker = truncated.then(|| uploads.last().unwrap().id.clone());
        Ok(S3Response::new(ListMultipartUploadsOutput {
            bucket: Some(req.input.bucket),
            prefix: req.input.prefix,
            key_marker: req.input.key_marker,
            upload_id_marker: req.input.upload_id_marker,
            max_uploads: Some(limit),
            is_truncated: Some(truncated),
            next_key_marker,
            next_upload_id_marker,
            uploads: Some(
                uploads
                    .into_iter()
                    .map(|u| MultipartUpload {
                        key: Some(u.key),
                        upload_id: Some(u.id),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }))
    }
    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.identity(&req, Some(&req.input.bucket), true).await?;
        if req.input.acl.is_some()
            || req.input.server_side_encryption.is_some()
            || req.input.sse_customer_key.is_some()
            || req.input.object_lock_mode.is_some()
            || req.input.tagging.is_some()
        {
            return Err(s3_error!(NotImplemented));
        }
        let _guard = self.state.namespace_lock.lock().await;
        self.bucket(&req.input.bucket).await?;
        let id = uuid::Uuid::new_v4().to_string();
        self.commit(Mutation::Begin(Upload {
            id: id.clone(),
            bucket: req.input.bucket.clone(),
            key: req.input.key.clone(),
            owner: req
                .credentials
                .ok_or_else(|| s3_error!(AccessDenied))?
                .access_key,
            attributes: Attributes {
                etag: String::new(),
                content_type: req.input.content_type,
                metadata: req.input.metadata.unwrap_or_default().into_iter().collect(),
            },
            parts: BTreeMap::new(),
        }))
        .await?;
        Ok(S3Response::new(CreateMultipartUploadOutput {
            bucket: Some(req.input.bucket),
            key: Some(req.input.key),
            upload_id: Some(id),
            ..Default::default()
        }))
    }
    async fn upload_part(
        &self,
        mut req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        let h = self.identity(&req, Some(&req.input.bucket), true).await?;
        if !(1..=10000).contains(&req.input.part_number) {
            return Err(s3_error!(InvalidArgument));
        }
        let data = self
            .collect(req.input.body.take(), req.input.content_length)
            .await?;
        validate_checksums(&req, &data)?;
        let tag = etag(&data);
        if let Some(expected) = &req.input.content_md5 {
            use base64::engine::general_purpose::STANDARD;
            if STANDARD.encode(Md5::digest(&data)) != *expected {
                return Err(s3_error!(BadDigest));
            }
        }
        let _guard = self.state.namespace_lock.lock().await;
        self.upload(
            &req,
            &req.input.bucket,
            &req.input.key,
            &req.input.upload_id,
        )
        .await?;
        self.policy(
            &format!("{}/{}", req.input.bucket, req.input.key),
            &h,
            "write_data",
            security::common::OP_WRITE,
        )
        .await?;
        let state = effective_data(&self.state).await;
        let manifest = cluster::put_object(
            &state,
            &format!(
                ".s3-upload/{}/{}",
                req.input.upload_id, req.input.part_number
            ),
            &data,
        )
        .await
        .map_err(unavailable)?;
        self.commit(Mutation::Part {
            now: now_ms(),
            eligible: now_ms().saturating_add(self.state.gc.grace_period_ms as u128),
            id: req.input.upload_id,
            number: req.input.part_number,
            part: Box::new(PartRecord {
                etag: tag.clone(),
                manifest,
            }),
        })
        .await?;
        Ok(S3Response::new(UploadPartOutput {
            e_tag: Some(tag.parse().map_err(unavailable)?),
            ..Default::default()
        }))
    }
    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.identity(&req, Some(&req.input.bucket), true).await?;
        let _guard = self.state.namespace_lock.lock().await;
        self.upload(
            &req,
            &req.input.bucket,
            &req.input.key,
            &req.input.upload_id,
        )
        .await?;
        let now = now_ms();
        self.commit(Mutation::Abort {
            id: req.input.upload_id,
            now,
            eligible: now.saturating_add(self.state.gc.grace_period_ms as u128),
        })
        .await?;
        Ok(S3Response::new(AbortMultipartUploadOutput::default()))
    }
    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        let h = self.identity(&req, Some(&req.input.bucket), true).await?;
        if req.input.if_match.is_some() || req.input.if_none_match.is_some() {
            return Err(s3_error!(NotImplemented));
        }
        let _guard = self.state.namespace_lock.lock().await;
        let upload = self
            .upload(
                &req,
                &req.input.bucket,
                &req.input.key,
                &req.input.upload_id,
            )
            .await?;
        let parts = req
            .input
            .multipart_upload
            .and_then(|u| u.parts)
            .ok_or_else(|| s3_error!(InvalidPart))?;
        if parts.is_empty() {
            return Err(s3_error!(InvalidPart));
        }
        let mut data = Vec::new();
        let mut digests = Vec::new();
        let mut previous = 0;
        for (index, part) in parts.iter().enumerate() {
            let number = part.part_number.ok_or_else(|| s3_error!(InvalidPart))?;
            if number <= previous {
                return Err(s3_error!(InvalidPartOrder));
            }
            previous = number;
            let stored = upload
                .parts
                .get(&number)
                .ok_or_else(|| s3_error!(InvalidPart))?;
            if part.e_tag.as_ref().and_then(ETag::as_strong) != Some(stored.etag.trim_matches('"'))
            {
                return Err(s3_error!(InvalidPart));
            }
            if index + 1 < parts.len() && stored.manifest.bytes < 5 * 1024 * 1024 {
                return Err(s3_error!(EntityTooSmall));
            }
            if stored.manifest.bytes
                > self.config.max_object_bytes.saturating_sub(data.len()) as u64
            {
                return Err(s3_error!(EntityTooLarge));
            }
            let bytes = get_object_version(&self.state.data, &stored.manifest)
                .await
                .map_err(unavailable)?;
            digests.extend_from_slice(&Md5::digest(&bytes));
            data.extend_from_slice(&bytes);
        }
        let tag = format!("\"{}-{}\"", hex::encode(Md5::digest(&digests)), parts.len());
        let mut attrs = upload.attributes;
        attrs.etag = tag.clone();
        self.publish(
            &req.input.bucket,
            &req.input.key,
            &h,
            &data,
            attrs,
            Some(req.input.upload_id),
        )
        .await?;
        Ok(S3Response::new(CompleteMultipartUploadOutput {
            bucket: Some(req.input.bucket),
            key: Some(req.input.key),
            e_tag: Some(tag.parse().map_err(unavailable)?),
            ..Default::default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    /// curl's SigV4 implementation is independent of the server's s3s verifier.
    async fn signed(base: &str, method: &str, path: &str, body: &[u8]) -> (u16, String) {
        signed_headers(base, method, path, body, &[]).await
    }
    async fn signed_headers(
        base: &str,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[&str],
    ) -> (u16, String) {
        let mut command = tokio::process::Command::new("curl");
        for header in headers {
            command.arg("--header").arg(header);
        }
        let mut child = command
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "20",
                "--aws-sigv4",
                "aws:amz:us-east-1:s3",
                "--user",
                &format!("test:{SECRET}"),
                "--request",
                method,
                "--data-binary",
                "@-",
                "--write-out",
                "\n%{http_code}",
                &format!("{base}{path}"),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("curl with SigV4 support is required");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(body).await.unwrap();
        drop(stdin);
        let output = child.wait_with_output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let (body, status) = text.rsplit_once('\n').unwrap();
        (status.parse().unwrap(), body.to_owned())
    }
    fn element<'a>(xml: &'a str, name: &str) -> &'a str {
        xml.split_once(&format!("<{name}>"))
            .unwrap()
            .1
            .split_once(&format!("</{name}>"))
            .unwrap()
            .0
    }
    #[tokio::test]
    async fn signed_http_storage_multipart_restart_and_denials() {
        let (mut state, root) = crate::security_integration_tests::fixture().await;
        let mut cfg = (*state.data.cfg).clone();
        cfg.replication = 1;
        cfg.write_quorum = 1;
        cfg.chunk_replicas = 1;
        cfg.erasure = None;
        cfg.hosts.truncate(1);
        cfg.hosts[0].id = state.data.local_host.clone();
        cfg.hosts[0].disks.truncate(1);
        state.data.cfg = Arc::new(cfg);
        let config = Config {
            listen: "127.0.0.1:0".into(),
            max_object_bytes: 8 * 1024 * 1024,
            credentials: BTreeMap::from([(
                "test".into(),
                Credential {
                    secret_key: SECRET.into(),
                    uid: Some(1000),
                    directory_user: None,
                    gids: vec![1000],
                    buckets: BTreeSet::from(["allowed".into()]),
                    read_only: false,
                },
            )]),
        };
        let raft = tokio::spawn(state.meta.clone().run());
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !state.meta.is_leader().await {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = router(state.clone(), config).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        assert_eq!(
            reqwest::get(format!("{base}/")).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(signed(&base, "PUT", "/forbidden", b"").await.0, 403);
        assert_eq!(signed(&base, "PUT", "/allowed", b"").await.0, 200);
        assert_eq!(
            signed(&base, "PUT", "/allowed/a%2Bb%20%25/x", b"hello")
                .await
                .0,
            200
        );
        assert_eq!(
            signed(&base, "GET", "/allowed/a%2Bb%20%25/x", b"").await,
            (200, "hello".into())
        );
        assert_eq!(
            signed_headers(
                &base,
                "GET",
                "/allowed/a%2Bb%20%25/x",
                b"",
                &["Range: bytes=1-3"]
            )
            .await,
            (206, "ell".into())
        );
        assert_eq!(
            signed_headers(
                &base,
                "GET",
                "/allowed/a%2Bb%20%25/x",
                b"",
                &["Range: bytes=10-20"]
            )
            .await
            .0,
            416
        );
        assert_eq!(
            signed_headers(
                &base,
                "PUT",
                "/allowed/a%2Bb%20%25/x",
                b"overwrite",
                &["If-None-Match: *"]
            )
            .await
            .0,
            412
        );
        assert_eq!(
            signed_headers(
                &base,
                "PUT",
                "/allowed/rejected",
                b"hello",
                &["Content-MD5: AAAAAAAAAAAAAAAAAAAAAA=="]
            )
            .await
            .0,
            400
        );
        assert_eq!(signed(&base, "GET", "/allowed/rejected", b"").await.0, 404);
        assert_eq!(
            signed_headers(
                &base,
                "PUT",
                "/allowed/rejected",
                b"hello",
                &["x-amz-acl: public-read"]
            )
            .await
            .0,
            501
        );
        assert_eq!(
            signed(&base, "GET", "/allowed/a%2Bb%20%25/x", b"").await,
            (200, "hello".into())
        );
        assert_eq!(signed(&base, "DELETE", "/allowed", b"").await.0, 409);
        let (code, listing) = signed(&base, "GET", "/allowed?list-type=2&max-keys=1", b"").await;
        assert_eq!(code, 200);
        assert!(listing.contains("a+b %/x"));
        let (code, initiated) = signed(&base, "POST", "/allowed/multi?uploads", b"").await;
        assert_eq!(code, 200, "{initiated}");
        let id = element(&initiated, "UploadId");
        assert_eq!(
            signed(
                &base,
                "PUT",
                &format!("/allowed/multi?partNumber=1&uploadId={id}"),
                b"hello"
            )
            .await
            .0,
            200
        );
        let (status, parts) =
            signed(&base, "GET", &format!("/allowed/multi?uploadId={id}"), b"").await;
        assert_eq!(status, 200);
        assert!(parts.contains("<PartNumber>1</PartNumber>"));
        let (status, uploads) = signed(&base, "GET", "/allowed?uploads", b"").await;
        assert_eq!(status, 200);
        assert!(uploads.contains(id));
        let reopened = MetadataStore::open(root.join("metadata")).await.unwrap();
        let saved = reopened.state().await;
        let upload = &saved.s3_uploads[id];
        assert_eq!(
            get_object_version(&state.data, &upload.parts[&1].manifest)
                .await
                .unwrap(),
            b"hello"
        );
        let bad = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"wrong\"</ETag></Part></CompleteMultipartUpload>";
        assert_eq!(
            signed(&base, "POST", &format!("/allowed/multi?uploadId={id}"), bad)
                .await
                .0,
            400
        );
        let good = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag></Part></CompleteMultipartUpload>";
        let (code, response) = signed(
            &base,
            "POST",
            &format!("/allowed/multi?uploadId={id}"),
            good,
        )
        .await;
        assert_eq!(code, 200, "{response}");
        assert_eq!(
            signed(&base, "GET", "/allowed/multi", b"").await,
            (200, "hello".into())
        );
        let reopened = MetadataStore::open(root.join("metadata")).await.unwrap();
        assert!(!reopened.state().await.s3_uploads.contains_key(id));
        assert!(!reopened.state().await.garbage.is_empty());
        assert_eq!(signed(&base, "DELETE", "/allowed/multi", b"").await.0, 204);
        assert_eq!(signed(&base, "GET", "/allowed/multi", b"").await.0, 404);
        let (_, initiated) = signed(&base, "POST", "/allowed/abort?uploads", b"").await;
        let id = element(&initiated, "UploadId");
        assert_eq!(
            signed(
                &base,
                "DELETE",
                &format!("/allowed/abort?uploadId={id}"),
                b""
            )
            .await
            .0,
            204
        );
        assert_eq!(
            signed(&base, "DELETE", "/allowed/a%2Bb%20%25/x", b"")
                .await
                .0,
            204
        );
        assert_eq!(signed(&base, "DELETE", "/allowed", b"").await.0, 204);
        server.abort();
        raft.abort();
        let _ = server.await;
        let _ = raft.await;
        fs::remove_dir_all(root).unwrap();
    }
}
