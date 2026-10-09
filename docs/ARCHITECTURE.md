<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi Architecture

## Scope

Kagi is a distributed 64-bit-keyspace object-storage system with deterministic capacity-weighted placement, failure-domain-aware protection, Raft-replicated metadata, immutable object versions, WORM/retention controls, point-in-time snapshots, object-backed virtual block volumes, SCSI-3 persistent reservations, background maintenance QoS, and post-quantum-hardened internal authentication.

The codebase is divided into a simulation/planning plane and a runtime plane. `kagi-config` models a proposed installation and emits the placement salt, explicit slot ownership plan, mount layout, and selected protection policy. Runtime daemons consume compatible topology information and persist authoritative object/cluster state through Raft.

## SysML v2 architecture model

SysML is the system-model exchange layer for architecture decisions; it complements rather than replaces executable configuration, topology simulation, or runtime tests. The model should remain source-controlled and traceable to the Rust implementation.

The initial modelling scope is:
- **Requirements and verification:** stable requirement identifiers mapped to implementation modules, tests, acceptance criteria, and evidence.
- **Logical architecture:** components, ports, interfaces, flows, and trust boundaries for storage, Raft metadata, namespace, block volumes, security, and maintenance.
- **Deployment architecture:** site/rack/host/disk hierarchy, network domains, fault containment, and deployment constraints.
- **Parametric constraints:** capacity, protection geometry, repair bandwidth, resource budgets, and durability targets. Quantitative durability and failure probability remain calculated by `kagi-config`; SysML records assumptions and constraints but does not substitute for the Monte Carlo engine.
- **Verification cases:** expected properties, tool versions, model revisions, test links, and evidence status.

### Toolchain and exchange boundary

Use OMG SysML v2 textual models and standard machine-readable API representations where the selected tool supports them. Keep model validation behind a documented toolchain adapter so Kagi does not depend on one vendor's UI or proprietary project format. The adapter should emit a versioned, schema-validated interchange document for constraints that `kagi-config` can consume; it must reject unknown schema versions and preserve source model identifiers.

Until a compatible SysML v2 parser/validator, sample model, interchange schema, and automated validation job are checked into the repository, this is an **architecture integration specification**, not a claim of implemented SysML execution. A future implementation should add model examples, round-trip tests, invalid-model tests, traceability checks, and CI validation using a pinned tool version. Rendered diagrams alone are not validation evidence.

## Failure-domain hierarchy

The physical topology is modeled as site → rack → host → disk. Network domains are orthogonal to this hierarchy: a host may have one or more network paths. In Monte Carlo modeling, a multihomed host becomes network-unreachable only when every network domain attached to it is unavailable.

Disk classes describe media/transport characteristics and can override the global disk annual-failure probability. Current runtime storage probing understands NVMe, direct-attached SATA HDD, SAS HDD, Fibre Channel rotational LUNs, and directory-backed development storage.

## 64-bit keyspace and slots

The logical object keyspace is the complete unsigned 64-bit range. The simulator partitions it into `2^slot_bits` slots. For each slot, capacity-weighted rendezvous hashing chooses an owning disk. The generated plan records both the global contiguous slot ranges and the same ranges grouped per disk.

A disk's placement weight is `capacity_bytes × weight`. The optimizer searches candidate placement salts and evaluates failure probability, protection overhead, and slot imbalance. The output is deterministic for a fixed configuration, seed, and selected salt.

## Data protection

The simulation supports replication, Reed-Solomon, LRC, MSR, and CLAY policy modeling. The runtime data plane implements Reed-Solomon, canonical product-matrix MSR (`d=2k-2`), and CLAY. CLAY is the runtime EC default; LRC remains planner-only. A shared GF(2^8) matrix engine has CPU and optional CUDA execution paths. Failure tolerance is checked across configured disk, host, rack, site, and network domains.

## Metadata consistency

Externally visible metadata is committed through Raft. Membership changes use joint consensus, and object-changing REST operations do not return success until the mutation has crossed the configured commit/apply barrier. Background rebalance writes replacement data first, commits the new manifest, then removes superseded fragments.

## Snapshots and archival

Point-in-time snapshots initially pin immutable historical versions. As retained delta grows beyond configured thresholds, a snapshot can be materialized into independent full object copies. Conversion progress is Raft-tracked and resumable after leadership change.

## Virtual block storage

Sparse logical volumes map ranges to immutable Kagi object extents. Hypervisor-facing presentation is SCSI-oriented: virtio-scsi for KVM/QEMU, emulated SAS when desired, PVSCSI via VMware, synthetic SCSI via Hyper-V, and block-mode volumes for Kubernetes integration. SCSI-3 Persistent Reservation state is authoritative in Raft.

## Maintenance priority

Maintenance is intentionally subordinate to foreground and system-necessary work. Scrub, proactive rebalance, garbage collection, and automatic snapshot materialization obey configurable schedules and cooperative CPU/network/memory/concurrency budgets. Durability-critical repair can bypass ordinary maintenance windows.

## Security

Internal requests use ML-DSA-87 request authentication with signed method/path/body hashes, persistent session epochs and sequence windows, per-peer nonce replay caches, and Raft-managed signing-key rotation/revocation. Transport uses the configured rustls provider and mTLS/hybrid-PQ capabilities. Symmetric at-rest metadata protection uses 256-bit keys.

## Monte Carlo protection geometry

The planner treats protection geometry and placement salt as coupled variables. It first selects a placement salt for the seed policy, evaluates feasible chunk geometries for each EC family against that placement, then repeats placement selection with the improved geometry. Geometry candidates are bounded by the actual fragment capacity implied by host/disk locality limits. Deterministic tolerance validation is a hard feasibility gate; Monte Carlo probability is the primary ranking metric among feasible candidates.

The minimum supported simulated/runtime topology is six servers with six disks per server. This gives the placement layer enough independent host/disk domains to request two-loss host and disk tolerance while retaining readable fragments.


## exact-repair data path

For a single unavailable CLAY/MSR chunk, recovery avoids whole-object reconstruction. CLAY helpers perform positioned reads of only required subchunks. Product-matrix MSR helpers compute a beta=1 GF projection locally. The replacement node applies the codec recovery transform (CUDA when selected) and verifies the immutable chunk checksum. Multiple unavailable chunks fall back to ordinary MDS decode. Healthy encoded chunks are copied directly during rebalance rather than decoded and re-encoded.
