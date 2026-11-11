<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Source Code Map

Start at a binary for command-line or service wiring. Follow the relevant module
for the persistence, protocol, or compute path.

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | `kagi-config`: CLI/config parser, interactive infrastructure wizard, failure-domain model, rare-event simulation, protection search, and explicit keyspace slot-plan output. |
| `src/bin/kagi-cluster-host.rs` | Full distributed node daemon, REST/admin CLI, Raft wiring, snapshots, maintenance, topology/capacity operations, filesystem namespace, block volumes, and SCSI PR administrative paths. |
| `src/bin/kagi-host.rs` | Simpler host-local object endpoint and deterministic local-disk routing. |
| `src/bin/kagi-volume-nbd.rs` | NBD protocol frontend translating block operations into Kagi volume requests. |
| `src/s3.rs` | Authenticated S3 protocol adapter, bucket allowlists, multipart Raft state and bounded object operations. |
| `src/identity.rs` | Native NSS user/group lookup, bounded winbind SID resolution and provider execution tests. |
| `src/cluster.rs` | Object manifests, immutable versions, fragment placement/RPC, erasure-code data path, metadata encryption, repair and scrub. |
| `src/raftmeta.rs` | Persistent Raft term/log/state machine, linearizable commit barriers, joint-consensus membership, snapshot/GC/topology/volume metadata. |
| `src/recovery.rs` | Resource health states, heartbeat processing, failure-domain inference, quarantine/reinclusion, repair risk. |
| `src/maintenance.rs` | Schedules, network/CPU/memory/concurrency budgets, and maintenance-vs-foreground priority. |
| `src/pq.rs` | ML-DSA identities, signed request envelopes, key IDs, Raft-fed keyring, nonce replay cache, persistent session epoch/sequence anti-replay. |
| `src/tls.rs` | rustls/AWS-LC provider, native TLS server configuration, and certificate/key loading. |
| `src/quic_transport.rs`, `src/wire.rs` | Optional QUIC client, stream framing, and frame-length limits. |
| `src/erasure.rs` | Reed-Solomon, canonical product-matrix MSR, CLAY reference/linearized transforms, LRC rank reconstruction/local repair, exact-repair plans, CPU/GPU adaptive dispatch and metrics. |
| `src/storage.rs` | NVMe/SATA/SAS/FC device type detection, SMART/SCSI health normalization and identity matching. |
| `src/filesystem.rs` | File/directory metadata, NFSv4-like ACL evaluation, local overlay index and bottom-up tree reconstruction. |
| `src/block.rs` | Sparse object-backed zvol-like volume extents, SCSI identity, UNMAP, SCSI-3 PR state/semantics. |
| `src/scsi_pr.rs` | SCSI Persistent Reserve IN/OUT wire parsing and response encoding. |
| `src/security.rs`, `src/runtime_security.rs` | Logical rules, side actions, request gates, and configuration/runtime audits. |
| `src/security_ebpf.rs`, `security/kagi-guard-ebpf/` | Userspace kernel-policy loader, event reader, and target-kernel BPF program. |
| `src/checkpoint.rs`, `src/durability.rs` | Atomic planner checkpoints and loss/durability reporting. |
| `src/monitoring.rs`, `src/telemetry.rs`, `src/webui.rs` | Security events, bounded node telemetry, console authentication, and embedded UI. |
| `src/cpu_isa.rs`, `src/cpu_libraries.rs` | SIMD feature detection, CPU arithmetic, and optional runtime-loaded compute libraries. |
| `src/bin/kagi-bench.rs`, `benches/erasure.rs` | Correctness-checked compute benchmarks and Criterion regression benchmarks. |
| `src/bin/kagi-run.rs` | Linux scheduler and affinity launcher. |
| `deploy/kubernetes/csi/main.go` | CSI controller and node service, including reservation fencing and NBD staging. |

## Review order

For placement work start with `src/main.rs`, then `src/cluster.rs`. For consistency and topology changes start with `src/raftmeta.rs`, then `kagi-cluster-host.rs`. For VM or Kubernetes storage, start with `src/block.rs`, `src/scsi_pr.rs`, and
`src/bin/kagi-volume-nbd.rs`. Follow the CSI entry points in
`deploy/kubernetes/csi/main.go` when tracing a Kubernetes publish request. For security review start with `src/pq.rs`, `src/tls.rs`, and the internal endpoint handlers in `cluster.rs`/`kagi-cluster-host.rs`.

## Planner

`src/main.rs` organizes planning into three layers.

1. **Topology acquisition and normalization** — quick/full wizard input, deterministic names/mounts, sequential private IPv4 allocation, disk-class AFR resolution, and six-host/six-disk validation.
2. **Failure simulation and placement** — capacity-weighted rendezvous placement, site/rack/host/disk/network failure sampling, correlated events, importance sampling, repair trajectories, and explicit slot maps.
3. **Protection-geometry optimization** — topology-bounded Reed-Solomon/LRC/MSR/CLAY candidate generation, per-policy isolated Monte Carlo scoring, deterministic failure-tolerance validation, per-schema reporting, and optional automatic policy selection.

The planner and runtime codec remain separate layers. Runtime support exists for Reed-Solomon, product-matrix MSR, CLAY and the documented LRC v1 geometry. The planner can model broader LRC geometries than the runtime codec. Monte Carlo output still describes policy geometry and placement rather than directly mutating a running cluster.

## Monte Carlo progress subsystem

The progress implementation lives in `src/main.rs` next to CLI parsing because it is a presentation concern of the `kagi-config` binary, not part of the storage runtime.

Key pieces:

- `ProgressState` contains atomic phase/current/simulation counters plus mutex-protected human-readable summaries for the current phase, operation, best placement, and best EC geometry.
- `ProgressGuard` starts and joins the sole terminal-renderer thread and guarantees a final refresh/terminal newline on scope exit.
- `SimulationTick` is an RAII per-trial completion guard used by Rayon closures. Its `Drop` implementation increments both current-operation and cumulative simulation counters, including closures that return early.
- `progress_best_keyspace` and `progress_best_schema` perform synchronized minimum updates as candidates complete.
- `progress_operation_label` can change the visible description of a subcandidate without resetting its aggregate counter.

The renderer writes ANSI line-clearing/cursor movement only to stderr and only when stderr reports `IsTerminal`. Non-TTY execution keeps the simulation/output path clean and bypasses counter updates.

### Operations console

`src/webui.rs` owns the Argon2id user database, viewer/admin role verification,
bounded log tailing, and the embedded browser application. Live API handlers
in `src/bin/kagi-cluster-host.rs` read Raft, health, and storage state.

### Accelerator boundaries

The planner generates failure and placement scenarios on the CPU with Rayon.
The CUDA kernel in `cuda/montecarlo.cu` evaluates batches of fragment-survival
vectors. HIP/ROCm and OpenCL have parallel implementations in `hip/montecarlo.hip.cpp`
and `native/opencl.cpp`. See [acceleration](ACCELERATION.md) for backend requirements.
