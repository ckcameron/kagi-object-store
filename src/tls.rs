// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi TLS provider and server configuration.
//!
//! The AWS-LC rustls provider gives Kagi modern AEAD cipher suites and hybrid
//! X25519+ML-KEM key exchange.  Native HTTPS is configured here so the web/API
//! listener never silently drops back to legacy TLS. TLS 1.3 is preferred and
//! can be made mandatory; TLS 1.2 is retained only when explicitly requested
//! for compatibility.  The provider's TLS 1.2 suites are ECDHE suites, so all
//! enabled handshakes retain perfect forward secrecy.
//!
//! Certificate signature strength is intentionally kept separate from key
//! exchange strength.  A hybrid ML-KEM handshake does not make an ECDSA/RSA
//! certificate post-quantum.  Kagi's certificate helper can create ML-DSA-87
//! X.509 identities where the local OpenSSL/rustls/client stack supports them.

use anyhow::{Context, Result};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::{fs::File, io::BufReader, path::Path, sync::Arc};

/// Install the process-wide AWS-LC provider.  Rustls' prefer-post-quantum feature
/// places hybrid ML-KEM key exchange ahead of classical-only groups.
pub fn install_pq_provider() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Ok(())
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open TLS certificate {}", path.display()))?,
    );
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse TLS certificate chain")?;
    anyhow::ensure!(!certificates.is_empty(), "TLS certificate chain is empty");
    Ok(certificates)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open TLS private key {}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut reader)?
        .context("TLS PEM does not contain a supported private key")
}

/// Build the native HTTPS configuration used by the Axum server.
///
/// The cipher-suite ordering comes from the AWS-LC provider: TLS 1.3 AES-256-GCM
/// first, followed by AES-128-GCM and ChaCha20-Poly1305.  TLS 1.2, when enabled,
/// is constrained to rustls' ECDHE+AEAD suites.  HTTP/2 and HTTP/1.1 are both
/// advertised through ALPN.
pub fn server_config(cert: &Path, key: &Path, allow_tls12: bool) -> Result<Arc<ServerConfig>> {
    install_pq_provider()?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let versions: &[&'static rustls::SupportedProtocolVersion] = if allow_tls12 {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_single_cert(read_certificates(cert)?, read_private_key(key)?)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Return a compact description suitable for status/monitoring APIs.
pub fn policy_summary(allow_tls12: bool) -> serde_json::Value {
    serde_json::json!({
        "provider": "aws-lc-rs",
        "tls_versions": if allow_tls12 { vec!["TLS1.3", "TLS1.2"] } else { vec!["TLS1.3"] },
        "pfs_required": true,
        "preferred_key_exchange": "X25519+ML-KEM-768",
        "certificate_note": "certificate signature strength is independent of hybrid key exchange"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_only_policy_is_explicit() {
        let summary = policy_summary(false);
        assert_eq!(summary["tls_versions"], serde_json::json!(["TLS1.3"]));
        assert_eq!(summary["pfs_required"], true);
    }

    #[test]
    fn compatibility_policy_never_enables_pre_tls12() {
        let summary = policy_summary(true);
        assert_eq!(
            summary["tls_versions"],
            serde_json::json!(["TLS1.3", "TLS1.2"])
        );
    }
}
