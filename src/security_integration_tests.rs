// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! HTTP regression checks for enforcement and authenticated monitoring.
use crate::runtime_security;
use crate::*;

/// Use a real HTTP router and isolated metadata store without starting a cluster.
pub(crate) async fn fixture() -> (V6State, PathBuf) {
    let root = std::env::temp_dir().join(format!("kagi-security-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let mut cfg: NodeConfig =
        serde_yaml::from_str(include_str!("../examples/node-v6.example.yaml")).unwrap();
    cfg.data_root = root.clone();
    cfg.cluster.metadata_key_b64 = Some(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [0x5au8; 32],
    ));
    // This fixture exercises the HTTP security gate only. Keep its transport local so
    // feature-enabled test builds do not attempt to initialize the example QUIC peer
    // with the documentation-only /etc/kagi PKI paths.
    cfg.cluster.transport.prefer_quic = false;
    for host in &mut cfg.cluster.hosts {
        host.quic_endpoint = None;
    }
    cfg.web_console.userdb = root.join("users.yaml");
    cfg.security = serde_yaml::from_str("objects:\n - {key: secret, recursive: true, operations: [all], decision: deny}\n - {key: classified, recursive: true, privileged_only: true, operations: [all], decision: deny}\n").unwrap();
    webui::upsert_user(
        &cfg.web_console.userdb,
        "viewer",
        "test-only-password",
        ConsoleRole::Viewer,
    )
    .unwrap();
    let public = root.join("public");
    let secret = root.join("secret");
    pq::generate_identity(&public, &secret).unwrap();
    let identity =
        pq::local_identity("test".into(), &public, secret, root.join("session")).unwrap();
    let client = reqwest::Client::new();
    let data = state(
        &cfg,
        client.clone(),
        identity.clone(),
        RuntimeKeyring::default(),
    )
    .unwrap();
    let meta = RaftNode::open(
        "test".into(),
        vec![],
        MetadataStore::open(root.join("metadata")).await.unwrap(),
        root.join("raft"),
        client,
        RaftTiming {
            election_min_ms: 1500,
            election_max_ms: 3000,
            heartbeat_ms: 400,
        },
        identity,
    )
    .await
    .unwrap();
    let monitor = monitoring::Monitor::new(16);
    let security = security::Security::new(cfg.security.clone(), monitor.clone()).unwrap();
    let st = V6State {
        data,
        meta,
        monitor,
        security,
        health: HealthMap::default(),
        recovery: cfg.recovery.clone(),
        gc: cfg.garbage_collection.clone(),
        snapshots: cfg.snapshots.clone(),
        maintenance: MaintenanceManager::new(cfg.maintenance.clone()),
        fs_index: FsIndex::open(root.join("index"), "test".into())
            .await
            .unwrap(),
        namespace_lock: Arc::new(tokio::sync::Mutex::new(())),
        web_console: cfg.web_console.clone(),
        telemetry: telemetry::TelemetryStore::new(cfg.telemetry.clone()),
        node_config: Arc::new(cfg),
    };
    (st, root)
}

#[tokio::test]
async fn http_gate_and_monitoring_authentication() {
    let (st, root) = fixture().await;
    let manifest: ObjectManifest = serde_json::from_value(serde_json::json!({
        "key":"classified/item", "object_id":"test", "version":1, "bytes":0,
        "checksum":"test", "committed_at_unix_ms":0,
        "fs":{"object_type":"file","name":"item","path":"/classified/item","privileged":true}
    }))
    .unwrap();
    st.meta
        .store
        .apply(
            1,
            MetadataCommand::PutManifest {
                key: manifest.key.clone(),
                manifest,
            },
        )
        .await
        .unwrap();
    let app = Router::new()
        .route("/v1/monitor/events", get(runtime_security::history))
        .route("/v1/monitor/stream", get(runtime_security::stream))
        .route("/v1/monitor/audit", get(runtime_security::audit))
        .route("/v1/monitor/status", get(runtime_security::status))
        .fallback(|| async { "handler reached" })
        .with_state(st.clone())
        .layer(axum::middleware::from_fn_with_state(
            st.clone(),
            runtime_security::gate,
        ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    for path in [
        "/v1/object/secret/item",
        "/v1/object/secret%2Fitem",
        "/v1/object-version/1/secret/item",
        "/v1/snapshots/id/object/secret/item",
        "/v1/metadata/secret/item",
        "/ui/api/object/secret/item",
        "/v1/object/classified/item",
        "/v1/object-version/1/classified/item",
    ] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    for method in [reqwest::Method::PUT, reqwest::Method::DELETE] {
        assert_eq!(
            client
                .request(method, format!("{base}/v1/object/secret/item"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        client
            .get(format!("{base}/v1/object/secretary/item"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .put(format!("{base}/v1/object/ordinary"))
            .header("x-kagi-privileged", "true")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for endpoint in ["events", "stream", "audit", "status"] {
        assert_eq!(
            client
                .get(format!("{base}/v1/monitor/{endpoint}"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let history: serde_json::Value = client
        .get(format!("{base}/v1/monitor/events?category=security"))
        .basic_auth("viewer", Some("test-only-password"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!history["events"].as_array().unwrap().is_empty());
    let mut stream = client
        .get(format!("{base}/v1/monitor/stream?category=security"))
        .basic_auth("viewer", Some("test-only-password"))
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    assert!(stream.headers()["content-type"]
        .to_str()
        .unwrap()
        .contains("text/event-stream"));
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), stream.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&chunk).contains("event: kagi"));
    drop(stream);
    server.abort();
    drop(st);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn console_roles_and_bucket_state_survive_reopen() {
    let (st, root) = fixture().await;
    webui::upsert_user(
        &st.web_console.userdb,
        "admin",
        "admin-test-password",
        ConsoleRole::Admin,
    )
    .unwrap();
    let raft = tokio::spawn(st.meta.clone().run());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !st.meta.is_leader().await {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let app = Router::new()
        .route("/ui/api/buckets", get(ui_buckets).post(ui_bucket_put))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ui/api/buckets", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let bucket = serde_json::json!({"name":"protected", "versioning":true});
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(&url)
            .basic_auth("viewer", Some("test-only-password"))
            .json(&bucket)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(&url)
            .basic_auth("admin", Some("admin-test-password"))
            .json(&bucket)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let result: serde_json::Value = client
        .get(&url)
        .basic_auth("viewer", Some("test-only-password"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["protected"]["versioning"], true);
    let reopened = MetadataStore::open(root.join("metadata")).await.unwrap();
    assert!(reopened.state().await.buckets["protected"].versioning);
    server.abort();
    raft.abort();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "scsi-target")]
#[tokio::test]
async fn scsi_bridge_authentication_conflict_and_persistence() {
    let (st, root) = fixture().await;
    webui::upsert_user(
        &st.web_console.userdb,
        "admin",
        "admin-test-password",
        ConsoleRole::Admin,
    )
    .unwrap();
    let raft = tokio::spawn(st.meta.clone().run());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !st.meta.is_leader().await {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let volume: VolumeCreate = serde_json::from_value(
        serde_json::json!({"id":"test-volume", "name":"test", "size_bytes":4194304}),
    )
    .unwrap();
    assert_eq!(
        volume_create(State(st.clone()), Json(volume))
            .await
            .into_response()
            .status(),
        StatusCode::CREATED
    );
    let app = Router::new()
        .route("/pr/:id", axum::routing::post(volume_pr_cdb))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/pr/test-volume", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let mut cdb = vec![0u8; 10];
    cdb[0] = 0x5f;
    cdb[8] = 24;
    let mut params = vec![0u8; 24];
    params[8..16].copy_from_slice(&123u64.to_be_bytes());
    let register = serde_json::json!({"cdb":cdb,"parameters":params,"initiator":"initiator-a"});
    assert_eq!(
        client
            .post(&url)
            .json(&register)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(&url)
            .basic_auth("admin", Some("admin-test-password"))
            .json(&register)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    cdb[1] = 1;
    cdb[2] = 1;
    params[0..8].copy_from_slice(&999u64.to_be_bytes());
    let conflict = serde_json::json!({"cdb":cdb,"parameters":params,"initiator":"initiator-a"});
    assert_eq!(
        client
            .post(&url)
            .basic_auth("admin", Some("admin-test-password"))
            .json(&conflict)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let read = serde_json::json!({"cdb":[94,0,0,0,0,0,0,0,16,0],"initiator":"initiator-a"});
    let response = client
        .post(&url)
        .basic_auth("admin", Some("admin-test-password"))
        .json(&read)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await.unwrap();
    assert_eq!(&bytes[8..16], &123u64.to_be_bytes());
    let reopened = MetadataStore::open(root.join("metadata")).await.unwrap();
    assert_eq!(
        reopened.state().await.volumes["test-volume"]
            .persistent_reservation
            .registrations["initiator-a"]
            .key,
        123
    );
    server.abort();
    raft.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn gc_fence_binds_replica_and_rechecks_retention_after_restart() {
    let (st, root) = fixture().await;
    let raft = tokio::spawn(st.meta.clone().run());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !st.meta.is_leader().await {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let manifest: ObjectManifest = serde_json::from_value(serde_json::json!({
        "key":"bucket/gc", "object_id":"gc-victim", "version":1, "bytes":4,
        "checksum":"test", "committed_at_unix_ms":0,
        "chunks":[{"chunk":0,"bytes":4,"checksum":"test","replicas":[{"host":st.data.local_host,"disk":"gc-disk","checksum":"test"}]}]
    })).unwrap();
    st.meta
        .propose(MetadataCommand::PutManifest {
            key: manifest.key.clone(),
            manifest: manifest.clone(),
        })
        .await
        .unwrap();
    st.meta
        .propose(MetadataCommand::DeleteManifest {
            key: manifest.key.clone(),
            version: 1,
            deleted_at_unix_ms: 0,
            eligible_after_unix_ms: 0,
        })
        .await
        .unwrap();
    st.meta
        .propose(MetadataCommand::AuthorizeGarbage {
            id: "gc-victim:1".into(),
        })
        .await
        .unwrap();
    let restored = MetadataStore::open(root.join("metadata"))
        .await
        .unwrap()
        .state()
        .await;
    let g = restored.garbage["gc-victim:1"].clone();
    let term = st.meta.status().await.term;
    let req = GcDeleteRequest {
        term,
        leader_id: st.meta.node_id.clone(),
        garbage_id: g.id.clone(),
        fence_index: g.fence_index,
        object_id: g.manifest.object_id.clone(),
        version: 1,
        fragment: 0,
        disk: "gc-disk".into(),
    };
    assert!(gc_delete_authorized(
        &restored,
        &req,
        &st.data.local_host,
        10
    ));
    assert!(!gc_delete_authorized(&restored, &req, "other-host", 10));
    let mut altered = restored.clone();
    altered.applied_index = g.fence_index - 1;
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    let mut altered = restored.clone();
    altered
        .garbage
        .get_mut(&g.id)
        .unwrap()
        .eligible_after_unix_ms = 11;
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    altered
        .garbage
        .get_mut(&g.id)
        .unwrap()
        .eligible_after_unix_ms = 0;
    altered
        .garbage
        .get_mut(&g.id)
        .unwrap()
        .manifest
        .worm
        .legal_hold = true;
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    let mut altered = restored.clone();
    altered
        .versions
        .insert(manifest.key.clone(), vec![manifest.clone()]);
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    let mut altered = restored.clone();
    altered.snapshots.insert(
        "snapshot".into(),
        SnapshotRecord {
            id: "snapshot".into(),
            name: "snapshot".into(),
            created_at_unix_ms: 0,
            raft_index: 1,
            prefix: None,
            mode: SnapshotMode::PointInTime,
            logical_bytes: 4,
            delta_bytes: 0,
            archived_bytes: 0,
            objects: BTreeMap::from([(
                manifest.key.clone(),
                SnapshotObject {
                    key: manifest.key.clone(),
                    version: 1,
                    source: manifest.clone(),
                    archived: None,
                },
            )]),
        },
    );
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    altered.snapshots.get_mut("snapshot").unwrap().mode = SnapshotMode::Archived;
    // An incomplete historical archive record must retain its source bytes.
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    let mut archive = manifest.clone();
    archive.object_id = "separate-archive".into();
    altered
        .snapshots
        .get_mut("snapshot")
        .unwrap()
        .objects
        .get_mut(&manifest.key)
        .unwrap()
        .archived = Some(archive);
    assert!(gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));
    altered
        .snapshots
        .get_mut("snapshot")
        .unwrap()
        .objects
        .get_mut(&manifest.key)
        .unwrap()
        .archived = Some(manifest.clone());
    assert!(!gc_delete_authorized(
        &altered,
        &req,
        &st.data.local_host,
        10
    ));

    let replica = manifest.chunks[0].replicas[0].clone();
    let path = fragment_path(&st.data.root, &replica.disk, &manifest.object_id, 1, 0);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"keep").unwrap();
    let mut wrong = g.clone();
    wrong.manifest.object_id = "another-object".into();
    assert!(delete_gc_replica(&st, &wrong, 0, &replica, term)
        .await
        .is_err());
    wrong = g.clone();
    wrong.version = 2;
    assert!(delete_gc_replica(&st, &wrong, 0, &replica, term)
        .await
        .is_err());
    wrong = g.clone();
    wrong.fence_index = 0;
    assert!(delete_gc_replica(&st, &wrong, 0, &replica, term)
        .await
        .is_err());
    assert!(delete_gc_replica(&st, &g, 1, &replica, term).await.is_err());
    let mut wrong_disk = replica.clone();
    wrong_disk.disk = "another-disk".into();
    assert!(delete_gc_replica(&st, &g, 0, &wrong_disk, term)
        .await
        .is_err());
    assert!(delete_gc_replica(&st, &g, 0, &replica, term + 1)
        .await
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), b"keep");
    delete_gc_replica(&st, &g, 0, &replica, term).await.unwrap();
    assert!(!path.exists());
    delete_gc_replica(&st, &g, 0, &replica, term).await.unwrap();
    raft.abort();
    let _ = raft.await;
    fs::remove_dir_all(root).unwrap();
}
