# Source Code Map

The source files carry module-level comments; this document provides an additional map for reviewers navigating the code.

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | `kagi-config`: CLI/config parser, interactive infrastructure wizard, failure-domain model, rare-event simulation, protection search, and explicit keyspace slot-plan output. |
| `src/bin/kagi-cluster-host.rs` | Full distributed node daemon, REST/admin CLI, Raft wiring, snapshots, maintenance, topology/capacity operations, filesystem namespace, block volumes, and SCSI PR administrative paths. |
| `src/bin/kagi-host.rs` | Simpler host-local object endpoint and deterministic local-disk routing. |
| `src/bin/kagi-volume-nbd.rs` | NBD protocol frontend translating block operations into Kagi volume requests. |
| `src/cluster.rs` | Object manifests, immutable versions, fragment placement/RPC, erasure-code data path, metadata encryption, repair and scrub. |
| `src/raftmeta.rs` | Persistent Raft term/log/state machine, linearizable commit barriers, joint-consensus membership, snapshot/GC/topology/volume metadata. |
| `src/recovery.rs` | Resource health states, heartbeat processing, failure-domain inference, quarantine/reinclusion, repair risk. |
| `src/maintenance.rs` | Schedules, network/CPU/memory/concurrency budgets, and maintenance-vs-foreground priority. |
| `src/pq.rs` | ML-DSA identities, signed request envelopes, key IDs, Raft-fed keyring, nonce replay cache, persistent session epoch/sequence anti-replay. |
| `src/tls.rs` | rustls TLS/mTLS provider and certificate/key loading. |
| `src/erasure.rs` | Reed-Solomon, canonical product-matrix MSR, CLAY reference/linearized transforms, exact-repair plans, CPU/GPU adaptive dispatch and metrics. |
| `src/storage.rs` | NVMe/SATA/SAS/FC device type detection, SMART/SCSI health normalization and identity matching. |
| `src/filesystem.rs` | File/directory metadata, NFSv4-like ACL evaluation, local overlay index and bottom-up tree reconstruction. |
| `src/block.rs` | Sparse object-backed zvol-like volume extents, SCSI identity, UNMAP, SCSI-3 PR state/semantics. |
| `src/scsi_pr.rs` | SCSI Persistent Reserve IN/OUT wire parsing and response encoding. |

## Review order

For placement work start with `src/main.rs`, then `src/cluster.rs`. For consistency and topology changes start with `src/raftmeta.rs`, then `kagi-cluster-host.rs`. For VM storage start with `src/block.rs`, `src/scsi_pr.rs`, and `kagi-volume-nbd.rs`. For security review start with `src/pq.rs`, `src/tls.rs`, and the internal endpoint handlers in `cluster.rs`/`kagi-cluster-host.rs`.

## Monte Carlo additions

`src/main.rs` now contains three distinct planning layers:

1. **Topology acquisition and normalization** — quick/full wizard input, deterministic names/mounts, sequential private IPv4 allocation, disk-class AFR resolution, and six-host/six-disk validation.
2. **Failure simulation and placement** — capacity-weighted rendezvous placement, site/rack/host/disk/network failure sampling, correlated events, importance sampling, repair trajectories, and explicit slot maps.
3. **Protection-geometry optimization** — topology-bounded Reed-Solomon/LRC/MSR/CLAY candidate generation, per-policy isolated Monte Carlo scoring, deterministic failure-tolerance validation, per-schema reporting, and optional automatic policy selection.

The planner and runtime codec remain separate layers. Runtime support exists for Reed-Solomon, product-matrix MSR and CLAY; LRC remains planner-only. Monte Carlo output still describes policy geometry and placement rather than directly mutating a running cluster.

## Monte Carlo progress subsystem

The progress implementation lives in `src/main.rs` next to CLI parsing because it is a presentation concern of the `kagi-config` binary, not part of the storage runtime.

Key pieces:

- `ProgressState` contains atomic phase/current/simulation counters plus mutex-protected human-readable summaries for the current phase, operation, best placement, and best EC geometry.
- `ProgressGuard` starts and joins the sole terminal-renderer thread and guarantees a final refresh/terminal newline on scope exit.
- `SimulationTick` is an RAII per-trial completion guard used by Rayon closures. Its `Drop` implementation increments both current-operation and cumulative simulation counters, including closures that return early.
- `progress_best_keyspace` and `progress_best_schema` perform synchronized minimum updates as candidates complete.
- `progress_operation_label` can change the visible description of a subcandidate without resetting its aggregate counter.

The renderer writes ANSI line-clearing/cursor movement only to stderr and only when stderr reports `IsTerminal`. Non-TTY execution keeps the simulation/output path clean and bypasses counter updates.

### `src/webui.rs`
Kagi embedded operations-console support: Argon2id local user database, viewer/admin role verification, system telemetry, bounded log tailing, and the embedded dark teal/electric-blue browser application. The live API handlers are in `kagi-cluster-host.rs` because they operate directly on the daemon's Raft/health/data-plane state.

### `cuda/montecarlo.cu`
Optional CUDA bulk-readability evaluator for Monte Carlo EC geometry search. CPU/Rayon code generates topology-aware failure/placement scenarios; the GPU evaluates batched fragment-survival vectors for replication, MDS-style Reed-Solomon/MSR/CLAY, and LRC readability.
