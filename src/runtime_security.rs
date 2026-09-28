// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Runtime wiring for access policy, authenticated monitoring, and actionable audits.
use crate::{monitoring::Filter, security::common::*, *};
use axum::{
    extract::Request,
    middleware::Next,
    response::sse::{Event as SseEvent, KeepAlive, Sse},
};
use std::{convert::Infallible, time::Duration};

/// Findings are stable identifiers plus a concrete remediation, suitable for automation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub resource: String,
    pub message: String,
    pub recommendation: String,
}
/// Keep a consistent finding schema for CLI, API and change notifications.
fn finding(
    id: &str,
    severity: &str,
    resource: &str,
    message: &str,
    recommendation: &str,
) -> Finding {
    Finding {
        id: id.into(),
        severity: severity.into(),
        resource: resource.into(),
        message: message.into(),
        recommendation: recommendation.into(),
    }
}

/// Configuration-only checks also work through the audit CLI before a node is started.
pub fn audit_config(cfg: &NodeConfig) -> Vec<Finding> {
    let mut findings = vec![finding("baseline.backups", "info", "cluster", "Durability modeling does not replace backups or restore exercises.", "Keep an independent backup, test restores, and protect configuration/key material from rollback.")];
    if !cfg.listen.starts_with("127.0.0.1:") && !cfg.listen.starts_with("[::1]:") {
        findings.push(finding("transport.public_listener", "warning", "listener", "The HTTP listener binds beyond loopback; tls config currently protects the internal client, not axum::serve.", "Bind loopback behind a TLS-authenticating reverse proxy or restrict the listener to a trusted private network. Never send Basic credentials over untrusted plaintext links."));
    }
    if cfg.tls.is_none() {
        findings.push(finding(
            "transport.no_mtls",
            "warning",
            "cluster",
            "Internal client transport has no mTLS configuration.",
            "Configure CA, certificate and private key, and HTTPS peer endpoints.",
        ));
    }
    if cfg
        .cluster
        .hosts
        .iter()
        .any(|h| !h.endpoint.starts_with("https://"))
    {
        findings.push(finding(
            "transport.peer_plaintext",
            "warning",
            "cluster",
            "One or more peers use a non-HTTPS endpoint.",
            "Use authenticated TLS termination for every peer endpoint.",
        ));
    }
    if cfg.cluster.metadata_key_b64.is_none() {
        findings.push(finding(
            "metadata.unencrypted",
            "warning",
            "metadata",
            "Metadata encryption key is absent.",
            "Configure a protected 256-bit metadata key and retain a secure recovery copy.",
        ));
    }
    if !cfg.maintenance.enabled || !cfg.maintenance.scrub.enabled {
        findings.push(finding(
            "integrity.scrub_disabled",
            "warning",
            "maintenance",
            "Background scrub is disabled.",
            "Enable scrub and schedule enough maintenance time to detect latent corruption.",
        ));
    }
    if cfg.garbage_collection.grace_period_ms < 86_400_000 {
        findings.push(finding(
            "integrity.short_gc_grace",
            "warning",
            "garbage_collection",
            "Garbage collection grace is less than one day.",
            "Keep grace longer than the expected recovery and operator-response window.",
        ));
    }
    if cfg.cluster.write_quorum == 0 || cfg.cluster.write_quorum > cfg.cluster.replication {
        findings.push(finding("integrity.write_quorum", "error", "cluster", "Write quorum is zero or exceeds replication.", "Choose a nonzero write quorum no larger than replication and validate the selected layout."));
    }
    let sites: std::collections::BTreeSet<_> = cfg
        .cluster
        .hosts
        .iter()
        .filter_map(|h| h.site.as_ref())
        .collect();
    if sites.len() < 2 {
        findings.push(finding("integrity.single_site", "warning", "cluster", "Fewer than two explicit site failure domains are configured.", "Place protected fragments across independent sites if site-loss tolerance is required."));
    }
    if !cfg.security.kernel.enabled || cfg.security.kernel.audit_only {
        findings.push(finding("security.kernel_not_enforcing", "warning", "kernel", "Kernel policy is disabled or audit-only.", "Build with --features ebpf, configure inode policies, and enable enforcement after target-kernel verification."));
    }
    if cfg.security.kernel.enabled && cfg.security.kernel.rules.is_empty() {
        findings.push(finding(
            "security.empty_kernel_policy",
            "warning",
            "kernel",
            "Kernel hooks are enabled with no protected inodes.",
            "Add explicit policies for data, metadata, key, and configuration paths.",
        ));
    }
    if cfg.security.objects.is_empty() {
        findings.push(finding("security.empty_object_policy", "warning", "objects", "No logical-object policy is configured.", "Add rules for sensitive key prefixes and privileged objects; marking an object privileged alone does not deny access."));
    }
    findings.push(finding("security.identity_headers", "warning", "public_api", "Legacy ACL principals are supplied in request headers.", "Use a trusted authenticating gateway that strips and supplies identity headers; do not expose the public object API directly to untrusted clients."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut paths = vec![cfg.data_root.clone(), cfg.web_console.userdb.clone()];
        if let Some(pq) = &cfg.post_quantum {
            paths.push(pq.identity_secret.clone());
        }
        if let Some(tls) = &cfg.tls {
            paths.push(tls.key.clone());
        }
        for path in paths {
            if let Ok(metadata) = fs::metadata(&path) {
                if metadata.permissions().mode() & 0o077 != 0 {
                    findings.push(finding("security.file_permissions", "warning", &path.display().to_string(), "Security state is accessible to group or other users.", "Restrict ownership and permissions to the service account and explicitly trusted operators."));
                }
            }
        }
    }
    findings
}

/// Combine startup configuration risks with authoritative object-manifest findings.
pub async fn audit_runtime(st: &V6State) -> Vec<Finding> {
    let mut findings = audit_config(&st.node_config);
    let state = st.meta.store.state().await;
    for manifest in state.manifests.values() {
        if let Some(metadata) = &manifest.fs {
            if metadata.acl.entries.iter().any(|ace| {
                ace.ace_type.eq_ignore_ascii_case("allow")
                    && ace.who == "EVERYONE@"
                    && ace
                        .permissions
                        .iter()
                        .any(|p| matches!(p.as_str(), "write_data" | "delete" | "write_acl"))
            }) {
                findings.push(finding("security.world_write", "warning", &manifest.key, "An ACL grants a write/delete/ACL permission to EVERYONE@.", "Limit write permissions to authenticated owners or groups and review any deny ACEs."));
            }
        }
        if manifest.data_shards > 0
            && manifest.parity_shards == 0
            && cluster::normalize_chunks(manifest)
                .iter()
                .any(|c| c.replicas.len() < 2)
        {
            findings.push(finding(
                "integrity.no_redundancy",
                "error",
                &manifest.key,
                "A data chunk has neither parity nor a second replica.",
                "Increase protection and rewrite/repair the object before losing a disk.",
            ));
        }
        if findings.len() >= 1024 {
            break;
        }
    }
    findings
}

/// Emit only changes so a periodic audit cannot flood subscribed clients.
pub async fn audit_loop(st: V6State) {
    let mut previous = Vec::new();
    let mut timer = tokio::time::interval(Duration::from_secs(60));
    loop {
        timer.tick().await;
        let current = audit_runtime(&st).await;
        for item in &current {
            if !previous.contains(item) {
                st.monitor.emit(
                    &item.severity,
                    "audit",
                    &item.resource,
                    &format!("{}: {} {}", item.id, item.message, item.recommendation),
                );
            }
        }
        for item in &previous {
            if !current.contains(item) {
                st.monitor.emit(
                    "info",
                    "audit",
                    &item.resource,
                    &format!("resolved: {}", item.id),
                );
            }
        }
        previous = current;
    }
}

/// Expose bounded node telemetry only to authenticated console operators.
pub async fn history(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Query(filter): Query<Filter>,
) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    Json(st.monitor.history(&filter)).into_response()
}
/// Refresh recommendations on demand, with no mutation of the configuration.
pub async fn audit(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    Json(serde_json::json!({"findings": audit_runtime(&st).await, "finding_limit": 1024}))
        .into_response()
}
/// Report active startup policy settings without disclosing configured commands or secrets.
pub async fn status(State(st): State<V6State>, headers: axum::http::HeaderMap) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    Json(serde_json::json!({
        "kernel_enabled": st.security.config.kernel.enabled,
        "kernel_audit_only": st.security.config.kernel.audit_only,
        "kernel_rule_count": st.security.config.kernel.rules.len(),
        "object_rule_count": st.security.config.objects.len(),
        "events": st.monitor.history(&Filter { after: u64::MAX, ..Default::default() }),
        "action_delivery": "bounded, best effort, asynchronous; no syscall substitution"
    }))
    .into_response()
}

/// Authenticated SSE with bounded replay, explicit loss notices, and periodic revocation.
pub async fn stream(
    State(st): State<V6State>,
    headers: axum::http::HeaderMap,
    Query(mut filter): Query<Filter>,
) -> Response {
    if console_auth(&st, &headers, false).is_none() {
        return webui::unauthorized();
    }
    if let Some(value) = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
    {
        filter.after = value;
    }
    let receiver = st.monitor.subscribe();
    let history = st.monitor.history(&filter);
    let mut replay = std::collections::VecDeque::new();
    if history["gap"] == true {
        replay.push_back(
            SseEvent::default()
                .event("gap")
                .data("history expired or node restarted; refresh history/status"),
        );
    }
    for event in history["events"].as_array().into_iter().flatten() {
        replay.push_back(
            SseEvent::default()
                .event("kagi")
                .id(event["id"].to_string())
                .data(event.to_string()),
        );
    }
    // Live records <= this ID already belong to the captured replay snapshot.
    filter.after = history["latest_id"].as_u64().unwrap_or(0);
    let authenticated_at = std::time::Instant::now();
    let stream = futures_util::stream::unfold(
        (receiver, replay, filter, st, headers, authenticated_at),
        |(mut receiver, mut replay, mut filter, st, headers, mut authenticated_at)| async move {
            if authenticated_at.elapsed() >= Duration::from_secs(30) {
                console_auth(&st, &headers, false)?;
                authenticated_at = std::time::Instant::now();
            }
            if let Some(event) = replay.pop_front() {
                return Some((
                    Ok::<_, Infallible>(event),
                    (receiver, replay, filter, st, headers, authenticated_at),
                ));
            }
            loop {
                if authenticated_at.elapsed() >= Duration::from_secs(30) {
                    console_auth(&st, &headers, false)?;
                    authenticated_at = std::time::Instant::now();
                }
                let event = tokio::select! {
                    result = receiver.recv() => match result {
                        Ok(event) if filter.matches(&event) => {
                            filter.after = event.id;
                            SseEvent::default().event("kagi").id(event.id.to_string()).json_data(event).unwrap()
                        }
                        Ok(_) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => SseEvent::default().event("gap").data(format!("missed {count} events; query history")),
                        Err(_) => return None,
                    },
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        console_auth(&st, &headers, false)?;
                        SseEvent::default().comment("authenticated keepalive")
                    }
                };
                return Some((
                    Ok(event),
                    (receiver, replay, filter, st, headers, authenticated_at),
                ));
            }
        },
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Decode the same key Axum passes to handlers, including encoded slash characters.
fn object_resource(path: &str) -> Option<(String, Option<u64>)> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    for prefix in [
        "/v1/object/",
        "/v1/object-versions/",
        "/v1/metadata/",
        "/v1/fs/mkdir/",
        "/v1/fs/acl/",
        "/v1/fs/reconstruct/",
        "/v1/repair/",
        "/v1/scrub/",
        "/ui/api/object/",
    ] {
        if let Some(key) = decoded.strip_prefix(prefix) {
            return Some((key.into(), None));
        }
    }
    if let Some(rest) = decoded.strip_prefix("/v1/object-version/") {
        let (version, key) = rest.split_once('/')?;
        return Some((key.into(), version.parse().ok()));
    }
    if let Some(rest) = decoded.strip_prefix("/v1/snapshots/") {
        let (_, suffix) = rest.split_once('/')?;
        if let Some(key) = suffix.strip_prefix("object/") {
            return Some((key.into(), None));
        }
    }
    None
}

/// Cover object reads, historical reads, metadata, namespace writes and maintenance APIs.
/// This runs before handlers; an allow decision still proceeds through their ACL/WORM checks.
pub async fn gate(State(st): State<V6State>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let decoded_path = match percent_encoding::percent_decode_str(&path).decode_utf8() {
        Ok(path) => path.into_owned(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let method = request.method().clone();
    let mut resource = path.clone();
    if let Some((key, version)) = object_resource(&path) {
        resource = key.clone();
        let manifest = if let Some(rest) = decoded_path.strip_prefix("/v1/snapshots/") {
            let id = rest.split('/').next().unwrap_or("");
            st.meta
                .store
                .state()
                .await
                .snapshots
                .get(id)
                .and_then(|snapshot| snapshot.objects.get(key.trim_start_matches('/')))
                .map(|object| object.source.clone())
        } else if let Some(version) = version {
            st.meta.store.get_version(&key, version).await
        } else {
            st.meta.store.get(&key).await
        };
        let current_privileged = st
            .meta
            .store
            .get(&key)
            .await
            .and_then(|m| m.fs)
            .is_some_and(|m| m.privileged);
        let requested_privileged = request
            .headers()
            .get("x-kagi-privileged")
            .is_some_and(|value| value == "true");
        let privileged = requested_privileged
            || current_privileged
            || manifest
                .as_ref()
                .and_then(|m| m.fs.as_ref())
                .is_some_and(|m| m.privileged);
        let operation = if method == axum::http::Method::DELETE {
            OP_DELETE
        } else if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
            if path.starts_with("/v1/metadata/")
                || path.starts_with("/v1/object-versions/")
                || path.starts_with("/v1/fs/")
                || path.starts_with("/ui/")
            {
                OP_GETATTR
            } else {
                OP_READ
            }
        } else if path.starts_with("/v1/fs/mkdir/") {
            OP_CREATE
        } else {
            OP_WRITE | if manifest.is_none() { OP_CREATE } else { 0 }
        };
        if !st.security.check(&key, operation, privileged) {
            return (StatusCode::FORBIDDEN, "Kagi object policy denied operation").into_response();
        }
        if let Some(value) = request.headers().get("x-kagi-privileged") {
            if value != "true" && value != "false" {
                return (
                    StatusCode::BAD_REQUEST,
                    "x-kagi-privileged must be true or false",
                )
                    .into_response();
            }
            if console_auth(&st, request.headers(), true).is_none() {
                return webui::unauthorized();
            }
        }
    } else if path.starts_with("/v1/") && !path.starts_with("/v1/monitor/") {
        // Reserved resources let administrators protect management APIs independently
        // of distributed object keys, e.g. @api/v1/pq or @api/v1/volumes.
        resource = format!("@api{}", path);
        let operation = if method == axum::http::Method::GET {
            OP_GETATTR
        } else {
            OP_WRITE
        };
        if !st.security.check(&resource, operation, true) {
            return (
                StatusCode::FORBIDDEN,
                "Kagi privileged-resource policy denied operation",
            )
                .into_response();
        }
    }
    let response = next.run(request).await;
    let status = response.status();
    if !path.starts_with("/v1/monitor/") && !path.starts_with("/ui/api/logs") {
        st.monitor.emit(
            if status.is_server_error() {
                "error"
            } else if status.is_client_error() {
                "warning"
            } else {
                "info"
            },
            if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
                "security"
            } else {
                "system"
            },
            &resource,
            &format!("{} {}", method, status.as_u16()),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoded_keys_and_versions_use_same_policy_identity() {
        assert_eq!(
            object_resource("/v1/object/secret%2Fitem"),
            Some(("secret/item".into(), None))
        );
        assert_eq!(
            object_resource("/v1/object-version/12/secret/item"),
            Some(("secret/item".into(), Some(12)))
        );
        assert_eq!(
            object_resource("/v1/snapshots/snap/object/secret/item"),
            Some(("secret/item".into(), None))
        );
    }
}
