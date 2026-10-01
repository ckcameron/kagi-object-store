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
    cfg.cluster.metadata_key_b64 = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x5au8; 32]));
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
