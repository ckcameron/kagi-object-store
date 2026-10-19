<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi

**Development release 0.39.0 — experimental; not production-ready.**

Kagi: a GPU-accelerated, CPU-optimized, CLAY/MSR Erasure-coded Enterprise Object Store.
**Kagi** is a distributed object-storage, filesystem, block-volume, durability-planning, and cluster-operations system written primarily in Rust.

> **Licensed under [CC BY-NC-SA 4.0](LICENSE).** Copyright (c) 2026 CK Cameron. Third-party exceptions are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Current source edition: **0.39.0**.

The planner is now `kagi-config`, with atomic periodic checkpoints and resume.
Optional HIP/ROCm, OpenCL, ISA-L, IPP and AOCL paths supplement CUDA and the
runtime-dispatched x86-64 CPU implementation. See [acceleration details](docs/ACCELERATION.md)
for implemented paths and explicitly deferred frameworks, and [scheduling](docs/SCHEDULING.md)
for the opt-in `kagi-run` real-time launcher.

Kagi distributes a deterministic 64-bit keyspace across failure-aware storage locations, protects data with replication or erasure coding, keeps authoritative metadata in Raft, and exposes the same storage substrate through object, namespace, and virtual-block abstractions. The project also includes a Monte Carlo topology planner, CUDA acceleration paths, failure/recovery control, lifecycle and immutability features, post-quantum authenticated internal traffic, and an embedded browser-based operations console.

## What is in this edition

The security subsystem integrates the supplied fileguard eBPF/LSM code with the distributed
Kagi runtime. It adds configured inode and logical-object allow/deny policies,
bounded asynchronous log/exec/signal side actions, privileged object metadata,
authenticated REST/SSE monitoring, configuration/integrity auditing, and a Security
& Integrity console tab. The planner now reports scientific loss probabilities,
decimal durability percentages and fractional nines without rounding 1e-20 loss to
100% durability. Zero estimated loss remains explicitly unresolved.

See [security policy, build and monitoring](docs/SECURITY-POLICY.md),
[example security configuration](examples/security.example.yaml), and
[validation results and limitations](BUILD-VALIDATION.md). Kernel protection is
opt-in and requires the separate BPF build plus target-kernel validation. The
existing v35 architecture, features, prior fixes and release history are retained.

## Implementation status

The inventory below describes the implemented 0.39 source tree, but not every item has the same
runtime or validation status. The following boundaries are material:

- **Runtime complete:** replication, Reed-Solomon, product-matrix MSR, CLAY, exact repair,
  deterministic failure-domain placement, Raft metadata/membership, object versioning,
  WORM/retention, fenced GC, snapshots/archive state, filesystem namespace/ACL evaluation,
  sparse block volumes, persistent reservations, the web console, and chunked
  XChaCha20-Poly1305 fragment encryption are wired into runtime paths.
- **Runtime LRC:** the CPU LRC v1 codec persists its scheme/k/m, reconstructs by
  matrix rank and repairs through local helpers. Its geometry is narrower than
  the planner's LRC family; see [runtime LRC](docs/LRC.md).
- **Directory integration:** native NSS user/group resolution supports configured
  LDAP/SSSD/winbind providers and optional AD user/group SIDs. LDAP binds and
  Kerberos authentication remain with the host provider. See
  [directory identities](docs/DIRECTORY-IDENTITY.md). Fibre Channel consumes
  Linux-visible SCSI LUNs; VMware/Hyper-V use external integration helpers.
- **Experimental S3 subset:** a separately authenticated listener implements core
  bucket/object/list/multipart operations over Kagi storage and Raft. It is not
  full AWS S3/IAM conformance; see [supported operations and limits](docs/S3.md).
- **At-rest key generations:** keyring-based rotation preserves legacy reads and
  authenticated chunk range reads. Retiring keys still requires migration of all
  historical versions, snapshots and backups. See [rotation](docs/AT-REST-ROTATION.md).
- **PQ boundary:** internal requests use ML-DSA-87 and the rustls provider prefers hybrid
  post-quantum key exchange, but Kagi does not claim that every certificate signature,
  compatibility transport, or at-rest key-management operation is strictly post-quantum-only.
- **Hardware/kernel validation boundary:** optional GPU/CPU-library and eBPF paths require the
  corresponding hardware, libraries, kernel bindings, and privileges for execution validation.
  A compile/fallback result is not treated as proof that the accelerator or kernel enforcement
  path executed.

See `BUILD-VALIDATION.md` for the validation environment and known execution limitations.

## SysML architecture and planning

Kagi's architecture/planning workflow includes a **SysML v2 modelling integration design** for expressing system structure, interfaces, requirements, constraints, and verification evidence alongside the existing topology and durability planner. This is an architecture-planning layer, not a claim that a SysML parser, solver, or model execution engine is already bundled into the runtime.

The intended model exchange uses the OMG SysML v2 textual notation and machine-readable API representations where supported. Models should describe:
- requirements and traceability to implementation, tests, and validation evidence;
- logical components and ports, including object, namespace, block-volume, metadata/Raft, security, and maintenance services;
- deployment topology and constraints across site/rack/host/disk and network failure domains;
- protection-policy parameters and resource budgets, linked to—but not replacing—the Monte Carlo planner's calculations;
- verification cases, assumptions, unresolved risks, and evidence provenance.

The integration boundary should remain tool-neutral: version SysML models with the source, validate them with a declared compatible SysML v2 toolchain, and exchange derived constraints with `kagi-config` through a documented schema. Do not treat generated diagrams or an unvalidated model as proof of runtime behavior or durability. SysML validation must report tool/version, model revision, checks run, and failures.

## SysML modelling workflow

Kagi now includes a version-controlled SysML v2 architecture model, requirement traceability map, versioned planner-interchange schema, structural validator, regression tests, and CI validation. The structural validator is not a full SysML v2 semantic validator; see [the SysML workflow](docs/SYSML.md) for scope and commands.

## Feature inventory

### Distributed object storage

- 64-bit object keyspace with deterministic placement.
- Capacity-weighted distribution across sites, racks, hosts, and disks.
- Failure-domain-aware placement to avoid concentrating fragments on correlated resources.
- Replicated object mode with configurable replication factor and write quorum.
- Immutable object versions with persistent manifests.
- Fragment checksums on write and read.
- Read from surviving replicas/fragments.
- Repair of under-protected objects.
- Object scrub with checksum validation.
- Health-aware placement and recovery decisions.
- Linearizable foreground mutation path backed by committed Raft metadata before acknowledgement.

### Erasure coding and repair

- Reed-Solomon runtime coding.
- Local Reconstruction Code geometry in the topology planner for smaller/ephemeral policy selection.
- Product-matrix MSR runtime coding and exact repair.
- CLAY runtime coding and exact repair.
- CLAY as the default runtime erasure family.
- Configurable `k`, parity count, and repair-helper fan-in.
- CPU implementations for all normal runtime paths.
- Optional CUDA, HIP/ROCm, and OpenCL GF(2^8) matrix acceleration across Reed-Solomon, LRC, MSR, and CLAY encode/reconstruct/repair paths.
- Accelerator-aware exact repair transforms, including CLAY subchunk and MSR projection recovery.
- Adaptive CPU/GPU dispatch with configurable GPU threshold and inflight limit, runtime provider availability, execution counters, and fallback telemetry.
- Bounded matrix caches to prevent unbounded memory growth from large subpacketization.
- Backend fallback behavior that does not change the persisted object format.

### Monte Carlo topology planner

The `kagi-config` binary models a proposed installation before data is placed on it.

- Interactive infrastructure wizard or YAML configuration input.
- Quick-default topology questionnaire.
- Full topology/failure questionnaire.
- Site, rack, host, network, multi-homing, disk, and disk-class modeling.
- Minimum supported deployment validation of six hosts with six disks per host.
- Default 8 TB NVMe assumptions in quick mode.
- Automatic RFC1918 `/24` allocation in quick mode.
- Search across placement salts.
- Search across supported protection geometries.
- Deterministic failure-envelope validation with counterexamples.
- Ordinary Monte Carlo loss estimation.
- Adaptive importance sampling for rare events.
- Jeffreys confidence interval for ordinary Monte Carlo estimates.
- Weighted rare-event uncertainty estimate and effective sample size.
- Continuous-time failure/repair simulation using competing exponential clocks.
- Independent disk/host/rack/site MTTR handling.
- Repair-bandwidth/vulnerability-window estimation.
- Capacity-weighted slot ownership.
- Explicit global slot ranges and corresponding 64-bit key ranges.
- Per-disk slot-range output.
- Generated disk mount names and paths.
- Terminal progress display with phase, current work, simulation rate, elapsed time, best placement, and best EC geometry.
- `--run-mode full|quick30|quick60` presets. Quick modes intentionally trade statistical confidence for shorter runtime classes; the names are not wall-clock guarantees.
- `--mc-backend auto|cpu|cuda|hip|opencl` for Monte Carlo EC-readability scoring.

Example:

```sh
kagi-config \
  --wizard \
  --wizard-config-output kagi.wizard.yaml \
  --output kagi.generated.yaml \
  --run-mode full \
  --mc-backend auto
```

### Failure detection, quarantine, recovery, and rebalance

- Hierarchical resource state for site/rack/host/disk failure domains.
- Heartbeat-driven failure inference.
- Flapping detection.
- Quarantine of unstable resources.
- Minimum stable-uptime re-entry policy.
- Manual health-clear path.
- Object risk scoring.
- Repair prioritization.
- Health-aware fragment replacement.
- Online capacity admission.
- Rebalance support after capacity/topology changes.
- Background maintenance coordination so recovery work does not overwhelm foreground I/O.

### Metadata, consistency, and membership

- Durable Raft metadata state machine.
- Leader election, RequestVote, AppendEntries, majority commit, and ordered application.
- Persistent term/vote/log state.
- Committed placement epoch.
- Object manifests and version history in Raft state.
- Bucket metadata and lifecycle defaults in Raft state.
- Namespace transactions represented as single ordered Raft mutations.
- Snapshot metadata, garbage records, capacity additions, volume maps, and reservation state in the same authoritative metadata plane.
- Joint-consensus membership changes for node/rack/site topology transitions.
- Administrative membership CLI.

### Object versioning, WORM, retention, and garbage collection

- Immutable version history.
- Delete markers.
- Governance retention mode.
- Compliance retention mode.
- Retain-until timestamps.
- Legal holds.
- Governance-bypass control path.
- Bucket-level default WORM policy.
- Bucket versioning setting.
- Raft-fenced garbage collection.
- Grace periods before destructive reclamation.
- Leader-only GC authorization fences, bound to the recorded object, version, fragment, disk, and destination host.
- Deletion rechecks grace, WORM, live versions, multipart references, and snapshot/archive references in applied metadata; an incomplete archive keeps its source pinned.
- Idempotent physical deletion.
- Defense-in-depth checks that prevent reclaiming snapshot-pinned or retention-protected versions.

### Point-in-time snapshots and archival

- Raft-consistent point-in-time namespace snapshots.
- Snapshot object references and retained-delta accounting.
- GC pinning while a point-in-time snapshot depends on source versions.
- Snapshot read path.
- Manual snapshot materialization/archive operation.
- Automatic archive conversion based on changed-byte and changed-ratio thresholds.
- Maintenance-budget integration for snapshot archival.

### Filesystem namespace and ACLs

- Directory objects layered on the object store.
- Parent/child relationships stored in object metadata.
- Reconstructable decentralized filesystem index.
- Bottom-up index reconstruction.
- File and directory object types.
- NFSv4-inspired access-control entries.
- Ordered allow/deny ACL evaluation.
- OWNER@, GROUP@, EVERYONE@ principals.
- Unix UID/GID principals.
- Active Directory SID/group-SID principals.
- Namespace metadata protected by the same storage/consistency substrate as object data.

### Encryption and cluster security

- XChaCha20-Poly1305 protected metadata with BLAKE3-derived subkeys.
- Random 256-bit cluster admission/join key.
- BLAKE3 admission hash in cluster configuration.
- Rustls transport provider using AWS-LC.
- Hybrid X25519 + ML-KEM-capable TLS provider path.
- ML-DSA-87 identities for authenticated internal control traffic.
- Signed request envelopes covering node, key ID, session epoch, sequence, timestamp, nonce, method, path, and body hash.
- Raft-managed trusted PQ key state.
- Key validity windows.
- Key revocation.
- Overlapping keys for rotation.
- Per-peer nonce replay cache.
- Persistent per-peer session epochs.
- Per-session monotonic sequence windows.
- Restart-resistant replay protection.

### Physical storage backends

- NVMe.
- SATA HDD.
- SAS HDD.
- Fibre Channel HDD/LUN support boundary.
- Storage-kind validation.
- Device identity checks using configured serial/WWN/device path information.
- SMART/device discovery integration.
- Rotational-media validation.
- Unknown or mismatched volumes excluded from normal placement until explicitly admitted.

### Virtual block volumes

- Sparse zvol-like logical volumes backed by immutable Kagi objects.
- Raft-owned logical extent maps.
- Configurable logical block size.
- Stable SCSI identity.
- Online volume growth.
- Sparse-hole behavior.
- SCSI UNMAP/TRIM reclamation.
- Range read/write API.
- NBD frontend (`kagi-volume-nbd`).
- Linux NBD attach helper.
- QEMU/KVM SCSI presentation helper.
- Libvirt SCSI XML/configuration helper.
- Hypervisor integration notes for KVM/QEMU, VMware, and Hyper-V.
- Image materialization helper for qcow2/VMDK/VHDX through external `qemu-img` tooling.
- Linux LIO iSCSI export helper.

### SCSI-3 persistent reservations

- PR IN/OUT wire helpers.
- REGISTER.
- RESERVE.
- RELEASE.
- CLEAR.
- PREEMPT/PREEMPT-AND-ABORT model support.
- Supported reservation types including registrants-only and all-registrants variants.
- Stable initiator identity carried through the block frontend.
- Raft-replicated registration/reservation state.
- Reservation conflict enforcement on block I/O.
- Separation between SCSI wire decoding and the replicated reservation policy.

### Background maintenance and QoS

- Background scrub.
- Proactive repair.
- Rebalance.
- Garbage collection.
- Snapshot archival.
- Per-operation enable/disable policy.
- Time-zone-aware maintenance windows.
- Resource quotas.
- Foreground/system priority arbitration.
- Configurable scrub cadence.

### Embedded Kagi operations console

The full cluster daemon exposes a dark, teal/electric-blue web console on each node when enabled.

- Local Argon2id password database.
- Viewer and administrator roles.
- Administrative user bootstrap command.
- Live node/cluster overview.
- System telemetry.
- Object/prefix browser.
- Object manifest inspection.
- Chunk/fragment location and health display.
- Pending operation display.
- Local log console.
- Cluster-wide log aggregation through signed internal endpoints.
- Bucket creation/update.
- Bucket versioning controls.
- Bucket WORM defaults.
- Bounded log-line retention in responses.

Create an administrator:

```sh
kagi-cluster-host \
  --config /etc/kagi/node.yaml \
  web-user-add admin \
  --role admin \
  --password-file /root/kagi-admin.pass
```

### Deployment and operations tooling

- `kagi-install` SSH/bootstrap helper.
- Example host/node/topology YAML.
- Systemd unit for `kagi-host`.
- Standard build/test script.
- LLVM coverage helper.
- Man pages for binaries and operational helpers.
- Architecture, configuration, operations, security, testing, Monte Carlo, code-map, and web-console documentation.

## Binaries

| Binary | Purpose |
| --- | --- |
| `kagi-config` | Topology wizard, durability simulation, EC geometry search, and keyspace plan generation. |
| `kagi-cluster-host` | Full distributed node daemon and administrative CLI. |
| `kagi-host` | Smaller host-local storage daemon/validation endpoint. |
| `kagi-volume-nbd` | NBD frontend for Kagi sparse virtual volumes. |

## Helper scripts

- `scripts/kagi-install`
- `scripts/kagi-volume-attach`
- `scripts/kagi-volume-qemu-scsi`
- `scripts/kagi-volume-libvirt-scsi`
- `scripts/kagi-volume-iscsi-export`
- `scripts/kagi-volume-image`
- `scripts/kagi-volume-hypervisor-notes`
- `scripts/test-all`
- `scripts/coverage`

## Configuration and command documentation

The canonical runtime configuration is [`examples/node-v6.example.yaml`](examples/node-v6.example.yaml).
It is intentionally verbose: every currently supported node/cluster parameter is shown or
explained in-place with units, accepted values, security notes, and applicable defaults.
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) contains the corresponding reference tables,
planner configuration, runtime caveats, and queue-control semantics.

Command-line option descriptions are maintained in the Clap declarations themselves so
`--help` and the source documentation stay synchronized. Public runtime configuration types
carry Rustdoc explaining field semantics and defaults; new externally visible options should
not be added without updating both the canonical example and configuration reference.

## Build

Rust stable is expected. CUDA is optional.

```sh
rustup default stable
rustup component add rustfmt clippy
cargo build --release
```

Build CUDA paths when `nvcc` and the CUDA development environment are available:

```sh
cargo build --release --features cuda
```

## Validation

The standard suite is:

```sh
./scripts/test-all
```

It performs:

```text
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets
```

Set `STRICT=1` to promote default-path Clippy warnings to errors. On Linux the suite also compiles/tests/clippies the runtime-loaded ISA-L, IPP, and AOCL integrations. CUDA, HIP/ROCm, and OpenCL feature checks are added automatically when their development toolchains are present; physical accelerator execution is verified separately by the `hardware-execution` workflow.

The exact validation status of this packaged edition is recorded in `BUILD-VALIDATION.md`.

## Configuration and generated plans

Typical cluster configuration lives under `/etc/kagi`. The planner emits a deterministic slot plan rather than relying on implicit runtime ordering. A generated topology should be reviewed and then treated as deployment input: silently reordering disk identities after planning changes placement assumptions.

The generated YAML includes the full keyspace slot geometry, per-disk slot ranges, generated mount paths, selected protection policy, optimizer statistics, and cluster-admission material references.

## Source layout

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | Monte Carlo planner, wizard, optimizer, progress UI, and plan output. |
| `src/cluster.rs` | Distributed data plane, placement, object versions, fragment RPC, encryption, repair, and scrub. |
| `src/erasure.rs` | Reed-Solomon, MSR, CLAY, exact repair, and CPU/CUDA/HIP/OpenCL backends. |
| `src/raftmeta.rs` | Persistent Raft state machine and membership. |
| `src/recovery.rs` | Health, quarantine, risk, recovery, and rebalance decisions. |
| `src/maintenance.rs` | Background maintenance windows and resource arbitration. |
| `src/filesystem.rs` | Namespace/index and ACL model. |
| `src/storage.rs` | Physical device discovery/admission. |
| `src/block.rs` | Sparse volumes and replicated reservation model. |
| `src/scsi_pr.rs` | SCSI persistent-reservation wire helpers. |
| `src/pq.rs` | ML-DSA trust and replay protection. |
| `src/tls.rs` | TLS cryptographic-provider setup. |
| `src/webui.rs` | Local console authentication, telemetry/log helpers, and embedded UI. |
| `src/bin/kagi-cluster-host.rs` | Full runtime composition, routes, controllers, and admin CLI. |
| `src/bin/kagi-host.rs` | Host-local daemon. |
| `src/bin/kagi-volume-nbd.rs` | NBD protocol frontend. |

## Documentation index

- `docs/ARCHITECTURE.md` — architecture and subsystem boundaries.
- `docs/CONFIGURATION.md` — topology, policy, failure, repair, and runtime YAML reference.
- `docs/MONTECARLO.md` — optimizer, statistics, quick modes, CUDA scoring, and slot-plan semantics.
- `docs/OPERATIONS.md` — deployment, maintenance, capacity, snapshots, recovery, and virtual volumes.
- `docs/SECURITY.md` — admission, encryption, PQ signatures, replay protection, and transport notes.
- `docs/TESTING.md` — test/Clippy/CUDA/coverage procedures.
- `docs/SECURITY-VALIDATION.md` — Miri, sanitizers, fuzzing, dependency/exploit checks, and performance regression workflow.
- `docs/CODEMAP.md` — source responsibilities and review paths.
- `docs/WEB-CONSOLE.md` — console configuration and operations.
- `docs/man/` — command manual pages.
- `CHANGELOG.md` — release history.


## Security validation and performance analysis

The fast local robustness gate is `bash scripts/kagi-security-check quick`. The deep gate adds
RustSec/dependency checks, unsafe-code inventory, Miri, native sanitizers, and short libFuzzer
campaigns; see `docs/SECURITY-VALIDATION.md`. NVIDIA builds can additionally run
`bash scripts/kagi-gpu-sanitize` under Compute Sanitizer.

Kagi 0.39 also includes `kagi-bench`, a correctness-checked compute/data-path benchmark that
reports encoding/reconstruction throughput and latency plus actual CPU/GPU dispatch counters.
`bash scripts/kagi-perf-demo` builds for the selected CPU target, writes JSON/text results,
captures Linux `perf stat` counters when available, and runs the Criterion regression suite.

## Design boundaries

The planner is an engineering durability model, not a mathematical proof of a contractual durability SLA. Rare-event estimates should be calibrated against production failure traces and measured repair throughput before being used for contractual “nines.”

The repository includes integration boundaries for hypervisors, iSCSI, identity systems, and CUDA. Some of those rely on external operating-system/hypervisor tooling; Kagi keeps authoritative metadata, placement, and reservation state inside the cluster rather than treating those frontends as independent sources of truth.

## Warranty disclaimer

Kagi is provided **AS IS**, with **no warranty whatsoever**, express, implied, statutory, or otherwise. This includes, without limitation, any warranties of **merchantability**, fitness for a particular purpose, title, non-infringement, accuracy, reliability, availability, security, or freedom from defects. To the fullest extent permitted by applicable law, the authors, copyright holders, and contributors disclaim all warranties and make no representation that the software will meet any requirements or operate without interruption, error, data loss, or other failure.

## Licensing

Kagi source and documentation are licensed under CC BY-NC-SA 4.0; see `LICENSE`. Third-party Rust/CUDA dependencies retain their upstream licenses; see `THIRD-PARTY-NOTICES.md`.

## License

Copyright (c) 2026 CK Cameron. Kagi source code, scripts, configuration examples, and documentation are licensed under the [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](LICENSE). Attribute CK Cameron and Kagi, retain notices, identify modifications, and follow the noncommercial and share-alike terms of the license. The canonical project is https://github.com/ckcameron/kagi-object-store.

The fileguard-derived security workspace and third-party dependencies retain their upstream licenses; see [Third-Party Notices](THIRD-PARTY-NOTICES.md). Generated validation logs are historical evidence, not new license declarations.

## SysML v2 integration

The SysML v2 model is syntax-checked in CI and generates a versioned, schema-validated planner interchange. Apply the modelled topology minimums and protection family to a topology file before running `kagi-config`; see [the SysML workflow](docs/SYSML.md).

## VM lab and Kubernetes storage

An idempotent eight-VM Ubuntu/KVM lab deployment and a Kubernetes CSI driver for Kagi logical volumes are documented in [the VM and Kubernetes storage guide](deploy/kubernetes/csi/README.md). The CSI driver provisions volumes through the Kagi API, uses Raft-backed persistent reservations to fence a volume to one Kubernetes node, and publishes filesystem or raw-block devices through NBD.
