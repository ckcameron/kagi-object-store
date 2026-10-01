<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi Changelog

Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.

## 0.39.0 (development) — accelerated transports, hardened telemetry, validation and benchmarking

- Bind GC deletion fences to recorded local replicas and recheck retention and references on both local and remote deletion paths; preserve incomplete archive sources.
- Upgrade transitive cache dependencies to remove the LRU memory-safety advisory;
  remove unused statistical linear-algebra dependencies and advisory exceptions.
- Repair verifies replica contents before retaining placements, so missing or
  corrupt fragments on otherwise healthy disks are actually rebuilt.
- Added an experimental, separately authenticated S3 core API with explicit bucket allowlists,
  Raft-persisted multipart state, checksum checks, bounded buffering and compatibility tests.
- Added generation-tagged at-rest keyring envelopes while retaining legacy and authenticated
  range reads; key retirement still requires explicit historical-data migration.
- Added CPU runtime LRC v1 with persisted layout, rank-based reconstruction and local repair.
- Added native NSS user/group lookup and directory-backed S3 identities, retaining AD SID ACLs.
- Serialized Raft proposal/persistence paths and guarded commit authority against leadership
  changes; made snapshot archive accounting idempotent and completion conditional on all objects.
- Connected the optional SCSI PR wire decoder to an authenticated administrative CDB bridge.
- Added execution-only hardware/kernel/directory CI gates. RDMA remains unavailable as a backend;
  portable QUIC/HTTPS fallback remains explicit.
- Added a self-documenting runtime configuration example covering every accepted node/cluster option, units, bounds and defaults; configuration structs now reject unknown keys and CI tests the canonical example against the production deserializer.
- Expanded Rustdoc/CLI help for transport, erasure, recovery, maintenance, telemetry, console and cluster-host command options so defaults and operational effects live next to the implementation.

- Added TLS 1.3 QUIC as an optional authenticated fragment/repair transport with persistent
  multiplexed connections, disabled 0-RTT, strict frame-allocation bounds, ML-DSA request
  envelopes, cluster admission proof, and HTTPS fallback.
- Added direct-RDMA and FHE feature/configuration groundwork for the 0.39 acceleration layer;
  RDMA is reserved for large registered-buffer transfers and FHE backends are optional rather
  than changing the ordinary object format.
- Added native HTTPS serving with rustls/AWS-LC, TLS 1.3 by default, optional TLS 1.2
  compatibility, forward-secret AEAD suites, and preferred hybrid X25519+ML-KEM key exchange.
- Added hierarchical live/historical telemetry for keyspace/site/rack/host/disk views, including
  IOPS, throughput, queue depth, I/O latency, network rates/errors, operation state and alerts.
- Added authenticated block scheduler/write-cache/read-ahead administration with audit events.
- Added the `kagi-bench` correctness-checked performance demo, Criterion regression benchmarks,
  native-build/perf capture script, and acceleration byte/status reporting.
- Added fuzzable network frame guards, libFuzzer targets, Miri checks, ASan/TSan/leak sanitizer
  harnesses, RustSec/cargo-deny dependency scanning, unsafe-code inventory, and NVIDIA
  Compute Sanitizer support.
- Added `docs/SECURITY-VALIDATION.md` describing the release security/UB/exploit test model.
- 0.39 remains a development release until the complete feature matrix and hardware-dependent
  paths are validated and recorded in BUILD-VALIDATION.md.

## 0.38.0 licensing update

- License Kagi source and documentation under CC BY-NC-SA 4.0, replacing the proprietary/confidential notice.
- Preserve upstream fileguard and dependency licenses and the BPF kernel license marker.
- Prepare the development repository for public access; experimental status is unchanged.

## 0.38.0 (development release; not production-ready) — resumable configuration, optional acceleration and process scheduling

- Renamed the planner and operational references to `kagi-config`.
- Added versioned, checksummed, atomic trial-batch checkpoints, a single-writer lock, saved run settings and admission key, phase-boundary flushes, and deterministic resume.
- Added HIP/ROCm and OpenCL matrix/readability kernels with bounded GPU simulation batches and CPU fallback; retained CUDA as the first automatic GPU choice.
- Added runtime-dispatched AVX2 and AVX-512F/BW finite-field paths, restricted-target build options including AVX10, optional ISA-L matrix coding, IPP XOR, and AOCL LibMem source packing.
- Added `kagi-run` to launch processes under normal, round-robin or FIFO scheduling with validated priorities, CPU affinity, and explicit permission-failure reporting.
- Documented compiler integration and the limitations preventing validated cuObject, GPUDirect and QuickAssist integration; no transfer or cipher replacement is claimed.
- Preserved previous security, monitoring, storage-format and release history. See BUILD-VALIDATION.md for executed tests and hardware limitations.

## 0.36.0 — integrated access policy, monitoring, audits and durability presentation

- Integrated the uploaded fileguard inode/recursive LSM matcher as an optional Kagi runtime feature, preserving synchronous denial and asynchronous actions. Fixed stat-to-kernel device encoding and rejected duplicate inode policies.
- Added logical-key and privileged-resource rules, deny precedence, version/snapshot-aware checks, and admin-controlled privileged metadata that remains compatible with older manifests.
- Added bounded action dispatch with exit/timeout handling, event-loss accounting, authenticated REST history/status/log/audit routes and replayable SSE with filtering, gap notices and credential rechecks.
- Added baseline configuration and integrity findings, changed/resolved finding events, scrub-failure events, an offline audit CLI and console security view.
- Added stable scientific loss/decimal percentage/fractional-nines output, including 1.00e-20. Zero estimates do not claim infinite nines or perfect durability.
- Fixed the inherited CUDA planner compile failure where the `_backend` argument was referenced as `backend` under the CUDA feature.
- Applied rustfmt to the inherited source and expanded security/build/operations documentation, while retaining earlier release records.
- Added policy, authentication, HTTP-route, event delivery, device encoding and numeric regression tests. See BUILD-VALIDATION.md for actual executed checks and kernel/CUDA limits.

## 0.35.0 — source readability, Kagi naming consolidation, and compiler-error correction

- Corrected the `cargo check` E0308 failure in the web-console log handler by making the bounded-log `Vec::drain` call a statement; the handler now returns unit from the trimming branch before constructing its JSON response.
- Reflowed previously compressed Rust into explicit, indented control-flow blocks so conditionals, loops, matches, request handlers, and state transitions are reviewable without reconstructing minified expressions.
- Added module-level design notes across the Rust tree and documentation comments for every top-level function/type that did not already explain its purpose.
- Standardized product-facing naming on **Kagi** across Cargo binaries, Rust source paths, service names, scripts, manual pages, generated filenames, default `/etc/kagi` paths, internal `x-kagi-*` HTTP headers, the ML-DSA domain-separation label, and SCSI vendor strings. Lowercase `keyspace` remains only where it denotes the 64-bit address-space/data model.
- Renamed the planner binary to `kagi-montecarlo`; runtime binaries are `kagi-cluster-host`, `kagi-host`, and `kagi-volume-nbd`.
- Expanded `README.md` into a current architecture/feature inventory covering placement, coding, Monte Carlo modes, recovery, Raft, WORM/versioning, snapshots, ACLs, post-quantum security, storage backends, block volumes, SCSI PR, maintenance QoS, the web console, and deployment tooling.
- Updated the release validation notes and regenerated the source manifest for the 0.35.0 archive.

## 0.34.0 — Kagi branding, CUDA Monte Carlo path, runtime presets, and web operations console

- Added optional CUDA bulk readability scoring to Monte Carlo erasure-geometry evaluation (`--mc-backend auto|cpu|cuda`). Topology/failure generation remains CPU-side; CUDA evaluates batched independent EC readability outcomes. Automatic mode falls back to Rayon when CUDA is unavailable or a GPU call fails.
- Added `--run-mode full|quick30|quick60`. Quick modes reduce candidate counts, Monte Carlo/importance-sampling trials, deterministic validation samples, and time-domain trajectories. They are explicitly reported as reduced-confidence modes; “30” and “60” are runtime classes rather than guarantees.
- Renamed the product-facing project to **Kagi** while retaining current binary/config identifiers as compatibility interfaces.
- Added an embedded dark Kagi operations console on every cluster node, themed in teal/electric blue.
- Added Argon2id-backed local console user database with viewer/admin roles and `web-user-add` administrative bootstrap command.
- Added live cluster overview, node system statistics, object/prefix browsing, manifest inspection, fragment/chunk locality and health display, pending GC/snapshot operation display, and local/cluster log console.
- Added Raft-replicated bucket metadata. The console can create/update buckets, versioning state, and default WORM policies; object writes inherit the bucket WORM default when no per-object retention headers are supplied.
- Added signed internal console summary/log endpoints so any node can aggregate cluster-wide state using the existing ML-DSA/join-key trust boundary.
- Consolidated the historical `IMPLEMENTATION-v*.md` notes into this changelog.

## 0.33.2 — Clippy cleanup

- Removed the v33.1 Clippy warning set without crate-wide warning suppression.
- Adopted standard integer helpers, named complex types, derived defaults, `&Path`, grouped large argument sets, and boxed the large Raft namespace mutation payload while retaining Serde compatibility.

## 0.33.1 — Monte Carlo status formatter regression fix

- Corrected EC geometry display to emit explicit `k=`, `m=`, and `d=` labels.

## 0.33.0 — Monte Carlo live progress

- Added a terminal-native progress display with overall/current progress, simulation count/rate, elapsed time, best keyspace placement, and best erasure-code geometry.
- Progress renders on stderr and is disabled when stderr is not a TTY, preserving machine-readable YAML output.

## 0.32.0 — Runtime CLAY and product-matrix MSR

- Added runtime CLAY and product-matrix MSR codec support and exact-repair planning.
- Added CUDA-aware repair/linear-transform integration and expanded codec correctness tests.
- Object manifests persist the erasure-code family and repair fan-in while older manifests default to Reed–Solomon.

## 0.31.0 — Topology-driven EC geometry optimization and quick topology wizard

- Made erasure-code geometry an optimizer variable for Reed–Solomon, LRC, MSR, and CLAY.
- Added topology-bounded candidate search and deterministic tolerance validation.
- Added quick wizard defaults, generated RFC1918 `/24` networks/addresses, minimum six hosts, minimum six disks per host, 8-TB NVMe defaults, and minimum two-loss tolerance where topology permits.

## 0.30.1 — SCSI persistent-reservation decoder regression fix

- Corrected PR OUT service-action decoding where REGISTER/CLEAR legitimately use a zero SCOPE/TYPE field.
- Expanded PR wire-format regression coverage.

## 0.30.0 — Infrastructure wizard and explicit slot deployment plan

- Added CLI/config-file and interactive topology wizard input.
- Added site/rack/host/network/multi-homing/disk-class topology modeling.
- Added deterministic disk mount naming under a configurable mount root.
- Added explicit per-disk slot ranges and corresponding 64-bit key ranges to generated output.
- Added proprietary All Rights Reserved licensing with confidentiality terms, documentation, man pages, tests, and coverage tooling.

## 0.29.0 — Compiler cleanup

- Resolved the remaining command exhaustiveness error and removed safe unused imports/locals.

## 0.28.0 — Initial real compiler-fix pass

- Replaced problematic `include!` module wrappers with path modules.
- Corrected Monte Carlo tuple types, a rebalancer partial move, Raft equality derives, and a handler-name shadowing defect.

## 0.27.0 — SCSI-3 persistent reservations

- Added Raft-replicated SCSI PR registrations/reservations, PR IN/OUT semantics, enforcement on volume I/O, and stable initiator identity support.

## 0.26.0 — ZVOL-like virtual volumes

- Added first-class sparse LBA volumes, stable SCSI identity, online grow, UNMAP, and hypervisor-oriented presentation semantics.

## 0.25.0 — Virtual block volumes

- Added object-backed sparse block volumes, immutable extents, Raft extent maps, NBD presentation, iSCSI helper tooling, and image export helpers.

## 0.24.0 — Rotational storage backends

- Added SATA, SAS, and Fibre Channel HDD classes alongside NVMe, with identity/SMART validation and FC multipath integration boundaries.

## 0.23.0 — Capacity expansion and linearizable object operations

- Added online capacity admission/rebalance and quorum commit/apply barriers for acknowledged object mutations.

## 0.22.0 — Maintenance QoS

- Added scheduled and resource-limited scrub, proactive repair/rebalance, GC, and snapshot archive maintenance with foreground priority.

## 0.21.0 — Point-in-time snapshots

- Added Raft-consistent namespace snapshots, GC pins, retained-delta accounting, and resumable conversion to independent archived copies.

## 0.20.0 — Joint-consensus membership and installer

- Added two-phase Raft joint consensus for node/rack/site membership changes and SSH-based cluster bootstrap tooling.

## 0.19.0 — Persistent replay epochs

- Added persistent per-peer session epochs and sequence windows to close restart replay gaps in signed internal traffic.

## 0.18.0 — Per-peer replay cache

- Added bounded nonce replay protection after successful ML-DSA verification.

## 0.17.0 — Mandatory ML-DSA envelopes and PQ rotation

- Signed internal Raft, health, fragment, gossip, and GC HTTP requests with ML-DSA-87 and added Raft-managed key rotation/revocation.

## 0.16.0 — Post-quantum system foundations

- Added ML-DSA-87 node identities and hybrid X25519 + ML-KEM-768 transport configuration foundations.

## 0.15.0 — Atomic namespace transactions and protected metadata

- Added single-Raft-entry child/parent namespace mutations and XChaCha20-Poly1305 protected metadata with BLAKE3-derived subkeys.

## 0.14.0 — Filesystem namespace and ACLs

- Added directory objects, reconstructable decentralized filesystem index, NFSv4-style ACLs, and Unix/AD principal support.

## 0.13.0 — Raft-fenced garbage collection

- Added logical deletion records, grace periods, leader-only authorization fences, and idempotent destructive deletion.

## 0.12.0 — Object versioning and WORM

- Added immutable version history, delete markers, governance/compliance retention, and legal holds.

## 0.11.0 — Cluster admission

- Added a random 256-bit join key and BLAKE3 admission hash on internal cluster traffic.

## 0.10.0 — Durable Raft metadata consensus

- Replaced quorum-copy metadata with durable leader-elected Raft state, health-aware recovery controls, and NVMe identity checks.

## 0.9.0 — Failure-domain flap quarantine

- Added site/rack/host/disk flapping detection, quarantine, stable-uptime re-entry, and manual health clear.

## 0.8.0 — Hierarchical recovery controller

- Added hierarchical health states, heartbeat-driven failure inference, health-aware rendezvous placement, repair prioritization, and protected chunk metadata.
