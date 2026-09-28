<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Security Notes

Kagi is licensed under CC BY-NC-SA 4.0; see `LICENSE` and `THIRD-PARTY-NOTICES.md` for upstream exceptions.

Internal cluster operations use ML-DSA authenticated envelopes, per-node persistent session epochs, sequence windows, random nonces, replay caches, and Raft-managed key rotation/revocation. The shared join key is defense in depth and must not be treated as a substitute for node identity.

Protect Raft state, node PQ private keys, metadata encryption keys, admission keys, and persistent anti-replay state from rollback and unauthorized disclosure. Files in `data_root/pq/` are security state, not disposable caches.

Use mTLS for cluster transport and keep the rustls/aws-lc provider configuration aligned with the post-quantum transport policy. Do not expose internal fragment/Raft endpoints to untrusted networks.


## security and monitoring

See [security policy and monitoring](SECURITY-POLICY.md) for node YAML rules, the
optional BPF build, privileged metadata, authenticated REST/SSE endpoints, the
audit CLI and deployment boundaries.
