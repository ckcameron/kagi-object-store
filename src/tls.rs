// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi TLS provider initialization.
//!
//! The node installs the rustls AWS-LC provider so hybrid X25519 + ML-KEM key exchange is
//! available to peer transports. Certificate loading remains at the reqwest/tokio-rustls
//! boundary; this module only owns process-wide cryptographic provider selection.

use anyhow::Result;
/// Install the aws-lc provider. In rustls 0.23 this provider offers the hybrid
/// X25519+ML-KEM-768 key exchange at highest priority. Certificate and identity
/// loading is handled by reqwest/tokio-rustls at the active transport boundary.
pub fn install_pq_provider() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Ok(())
}
