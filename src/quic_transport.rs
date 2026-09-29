// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi's QUIC data-plane framing.
//!
//! QUIC is used as a persistent, multiplexed transport for fragment-sized traffic.
//! The transport does not replace Kagi's application authentication: the same ML-DSA
//! request envelope and cluster admission header used by internal HTTP requests are
//! carried in each QUIC request.  This means changing transport cannot bypass policy,
//! WORM, replay, or peer-identity checks.
//!
//! QUIC v1 always uses TLS 1.3.  The rustls/AWS-LC configuration supplied by Kagi
//! prefers hybrid X25519+ML-KEM key exchange and modern AEAD suites.  0-RTT is not
//! enabled here because object mutations must never be replayable merely because a
//! transport session resumed.

#![cfg(feature = "quic")]

use anyhow::{bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use tokio::sync::Mutex;

const ALPN: &[u8] = b"kagi-fragment/1";
const MAX_META_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMeta {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub meta: RequestMeta,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseMeta {
    status: u16,
    message: String,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub message: String,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            message: "ok".into(),
            body,
        }
    }

    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            body: Vec::new(),
        }
    }

    pub fn ensure_success(self) -> Result<Vec<u8>> {
        if (200..300).contains(&self.status) {
            Ok(self.body)
        } else {
            bail!("QUIC peer returned {}: {}", self.status, self.message)
        }
    }
}

#[async_trait::async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: Request) -> Response;
}

#[derive(Clone)]
pub struct Client {
    endpoint: quinn::Endpoint,
    connections: Arc<Mutex<BTreeMap<String, quinn::Connection>>>,
    max_body_bytes: usize,
}

impl Client {
    pub fn new(ca: &Path, max_body_bytes: usize) -> Result<Self> {
        crate::tls::install_pq_provider()?;
        let mut roots = rustls::RootCertStore::empty();
        let mut reader = BufReader::new(
            File::open(ca).with_context(|| format!("open QUIC CA {}", ca.display()))?,
        );
        for certificate in rustls_pemfile::certs(&mut reader) {
            roots.add(certificate?)?;
        }

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        // Deliberately leave early data disabled.
        crypto.enable_early_data = false;

        let quic_crypto = QuicClientConfig::try_from(crypto)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(1024_u32.into());
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("[::]:0".parse()?)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            connections: Arc::new(Mutex::new(BTreeMap::new())),
            max_body_bytes: max_body_bytes.max(1024 * 1024),
        })
    }

    async fn connection(&self, address: SocketAddr, server_name: &str) -> Result<quinn::Connection> {
        let key = format!("{server_name}@{address}");
        if let Some(connection) = self.connections.lock().await.get(&key).cloned() {
            if connection.close_reason().is_none() {
                return Ok(connection);
            }
        }

        let connection = self
            .endpoint
            .connect(address, server_name)?
            .await
            .with_context(|| format!("connect QUIC peer {server_name}@{address}"))?;
        self.connections
            .lock()
            .await
            .insert(key, connection.clone());
        Ok(connection)
    }

    pub async fn request(
        &self,
        address: SocketAddr,
        server_name: &str,
        meta: RequestMeta,
        body: &[u8],
    ) -> Result<Response> {
        if body.len() > self.max_body_bytes {
            bail!(
                "QUIC body is {} bytes, above configured limit {}",
                body.len(),
                self.max_body_bytes
            );
        }

        let connection = self.connection(address, server_name).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        write_request(&mut send, &meta, body).await?;
        send.finish()?;
        read_response(&mut recv, self.max_body_bytes).await
    }
}

pub fn server_endpoint(
    address: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    max_body_bytes: usize,
) -> Result<(quinn::Endpoint, usize)> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // QUIC must not accept early data for authenticated storage mutations.
    tls.max_early_data_size = 0;
    let quic_crypto = QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1024_u32.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    config.transport_config(Arc::new(transport));
    Ok((
        quinn::Endpoint::server(config, address)?,
        max_body_bytes.max(1024 * 1024),
    ))
}

pub async fn serve(
    endpoint: quinn::Endpoint,
    max_body_bytes: usize,
    handler: Arc<dyn Handler>,
) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let handler = handler.clone();
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let response = match read_request(&mut recv, max_body_bytes).await {
                        Ok(request) => handler.handle(request).await,
                        Err(error) => Response::error(400, error.to_string()),
                    };
                    let _ = write_response(&mut send, &response).await;
                    let _ = send.finish();
                });
            }
        });
    }
    Ok(())
}

async fn write_request(
    send: &mut quinn::SendStream,
    meta: &RequestMeta,
    body: &[u8],
) -> Result<()> {
    let encoded = serde_json::to_vec(meta)?;
    if encoded.len() > MAX_META_BYTES {
        bail!("QUIC request metadata too large");
    }
    send.write_all(&(encoded.len() as u32).to_be_bytes()).await?;
    send.write_all(&(body.len() as u64).to_be_bytes()).await?;
    send.write_all(&encoded).await?;
    send.write_all(body).await?;
    Ok(())
}

async fn read_request(recv: &mut quinn::RecvStream, max_body_bytes: usize) -> Result<Request> {
    let mut meta_len = [0u8; 4];
    let mut body_len = [0u8; 8];
    recv.read_exact(&mut meta_len).await?;
    recv.read_exact(&mut body_len).await?;
    let (meta_len, body_len) = crate::wire::validate_frame_lengths(
        u32::from_be_bytes(meta_len) as u64,
        u64::from_be_bytes(body_len),
        MAX_META_BYTES,
        max_body_bytes,
    )
    .map_err(|error| anyhow::anyhow!("QUIC request rejected: {error}"))?;
    let mut meta = vec![0; meta_len];
    let mut body = vec![0; body_len];
    recv.read_exact(&mut meta).await?;
    recv.read_exact(&mut body).await?;
    Ok(Request {
        meta: serde_json::from_slice(&meta)?,
        body,
    })
}

async fn write_response(send: &mut quinn::SendStream, response: &Response) -> Result<()> {
    let meta = serde_json::to_vec(&ResponseMeta {
        status: response.status,
        message: response.message.clone(),
    })?;
    send.write_all(&(meta.len() as u32).to_be_bytes()).await?;
    send.write_all(&(response.body.len() as u64).to_be_bytes()).await?;
    send.write_all(&meta).await?;
    send.write_all(&response.body).await?;
    Ok(())
}

async fn read_response(recv: &mut quinn::RecvStream, max_body_bytes: usize) -> Result<Response> {
    let mut meta_len = [0u8; 4];
    let mut body_len = [0u8; 8];
    recv.read_exact(&mut meta_len).await?;
    recv.read_exact(&mut body_len).await?;
    let (meta_len, body_len) = crate::wire::validate_frame_lengths(
        u32::from_be_bytes(meta_len) as u64,
        u64::from_be_bytes(body_len),
        MAX_META_BYTES,
        max_body_bytes,
    )
    .map_err(|error| anyhow::anyhow!("QUIC response rejected: {error}"))?;
    let mut meta = vec![0; meta_len];
    let mut body = vec![0; body_len];
    recv.read_exact(&mut meta).await?;
    recv.read_exact(&mut body).await?;
    let meta: ResponseMeta = serde_json::from_slice(&meta)?;
    Ok(Response {
        status: meta.status,
        message: meta.message,
        body,
    })
}
