<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi Architecture

## Scope

Kagi is a distributed object store with deterministic 60-bit placement for planned deployments, failure-domain-aware protection, Raft-replicated metadata, immutable object versions, WORM/retention controls, point-in-time snapshots, object-backed virtual block volumes, SCSI-3 persistent reservations, background maintenance QoS, and post-quantum-hardened internal authentication.

The codebase is divided into a simulation/planning plane and a runtime plane. `kagi-config` models a proposed installation and emits equal host ranges, a placement salt, mount layout, and a deployment for each selected protection policy. Runtime daemons consume the deployment and persist authoritative object and cluster state through Raft.

## SysML v2 architecture model

The source-controlled SysML model records architecture decisions and traces requirements to the Rust implementation and its tests. Executable configuration and topology simulation remain part of the planner workflow.

The model covers the following areas.
- **Requirements and verification:** stable requirement identifiers mapped to implementation modules, tests, acceptance criteria, and evidence.
- **Logical architecture:** components, ports, interfaces, flows, and trust boundaries for storage, Raft metadata, namespace, block volumes, security, and maintenance.
- **Deployment architecture:** site/rack/host/disk hierarchy, network domains, fault containment, and deployment constraints.
- **Parametric constraints:** capacity, protection geometry, repair bandwidth, resource budgets, and durability targets. Quantitative durability and failure probability remain calculated by `kagi-config`; SysML records assumptions and constraints but does not substitute for the Monte Carlo engine.
- **Verification cases:** expected properties, tool versions, model revisions, test links, and evidence status.

### Toolchain and exchange boundary

The source-controlled model and requirement traceability map live under `models/sysml/`. The versioned JSON exchange contract is `schemas/sysml-planner-interchange.schema.json`. CI syntax-checks the model with the pinned `sysml2` CLI and validates the emitted interchange against JSON Schema. `scripts/apply-sysml-constraints.py` applies the model's host/disk minimums and protection family to an existing planner YAML before `kagi-config` runs. It preserves topology and seed geometry while enabling the existing geometry optimizer. Monte Carlo loss probability, placement feasibility, and final geometry remain the planner's responsibility; this integration does not claim full OMG semantic conformance or infer durability from the architecture model.

See [SysML modelling workflow](SYSML.md) for commands and limitations.

## Failure-domain hierarchy

The physical topology is modeled as site → rack → host → disk. Network domains are orthogonal to this hierarchy: a host may have one or more network paths. In Monte Carlo modeling, a multihomed host becomes network-unreachable only when every network domain attached to it is unavailable.

Disk classes describe media/transport characteristics and can override the global disk annual-failure probability. Current runtime storage probing understands NVMe, direct-attached SATA HDD, SAS HDD, Fibre Channel rotational LUNs, and directory-backed development storage.

## 60-bit keyspace

One object key maps to a position in the unsigned 60-bit keyspace. Every host
owns a contiguous range with a size that differs from any other host's range by
at most one address. The planner and runtime use the same algorithm to
derive the destination site, rack, host, and disk for each chunk and copy from
the key and placement plan. The derived chunk position falls in the disk's
subrange of its host's range. The runtime rotates among disks on the same host
with equivalent network paths while preserving the placement's failure
properties. The manifest records the actual locations so existing versions remain
readable when the plan changes. Deployments without a plan use legacy 64-bit
placement.

## Data protection

The planner and data plane support replication, Reed-Solomon, the [LRC v1](LRC.md)
geometry, canonical product-matrix MSR (`d=2k-2`), and CLAY. A shared GF(2^8)
matrix engine has CPU and [optional GPU execution paths](ACCELERATION.md). The planner verifies
reconstruction against concurrent failures of the configured disk, host, rack,
site, and network domains.

## Metadata consistency

Externally visible metadata is committed through Raft. Membership changes use
joint consensus, and object-changing REST operations do not return success until
the mutation has crossed the configured commit/apply barrier. Background repair
and rebalance update the same immutable version in current, historical, and
snapshot references. Planned rebalance retains obsolete physical copies for
in-flight readers that may still hold the previous locations. Those copies can
continue to consume disk space.

Reconstructing the chunks and serving the object are separate availability
conditions. When a site is lost, the metadata service still needs a surviving
Raft majority. With voters only in two sites, at least one site-loss scenario
leaves too few voters for a majority. Cluster status and the web console report
the site losses that threaten metadata quorum.

## Snapshots and archival

Point-in-time snapshots initially pin immutable historical versions. As retained delta grows beyond configured thresholds, a snapshot can be materialized into independent full object copies. Conversion progress is Raft-tracked and resumable after leadership change.

## Virtual block storage

Sparse logical volumes map ranges to immutable Kagi object extents. Hypervisor-facing presentation is SCSI-oriented: virtio-scsi for KVM/QEMU, emulated SAS when desired, PVSCSI via VMware, synthetic SCSI via Hyper-V, and block-mode volumes for Kubernetes integration. SCSI-3 Persistent Reservation state is authoritative in Raft.

## Maintenance priority

Maintenance is intentionally subordinate to foreground and system-necessary work. Scrub, proactive rebalance, garbage collection, and automatic snapshot materialization obey configurable schedules and cooperative CPU/network/memory/concurrency budgets. Durability-critical repair can bypass ordinary maintenance windows.

## Security

Internal requests use ML-DSA-87 request authentication with signed method/path/body hashes, persistent session epochs and sequence windows, per-peer nonce replay caches, and Raft-managed signing-key rotation/revocation. The native HTTPS listener uses rustls with AWS-LC and prefers hybrid X25519/ML-KEM key exchange. It presents a server certificate. Peers authenticate at the application layer with signed request envelopes and the cluster admission key. Symmetric at-rest metadata protection uses 256-bit keys.

## Monte Carlo protection geometry

The planner treats protection geometry and placement salt as coupled variables. It first selects a placement salt for the seed policy, evaluates feasible chunk geometries for each EC family against that placement, then repeats placement selection with the improved geometry. Geometry candidates are bounded by the actual fragment capacity implied by host/disk locality limits. Deterministic tolerance validation is a hard feasibility gate; Monte Carlo probability is the primary ranking metric among feasible candidates.

The minimum supported topology is six servers with six disks per server. A
placement plan additionally requires enough independent domains and fragments to
meet the concurrent failure budget.

## Exact-repair data path

For a single unavailable CLAY/MSR chunk, recovery avoids whole-object reconstruction. CLAY helpers perform positioned reads of only required subchunks. Product-matrix MSR helpers compute a beta=1 GF projection locally. The replacement node applies the codec recovery transform (CUDA when selected) and verifies the immutable chunk checksum. Multiple unavailable chunks fall back to ordinary MDS decode. Healthy encoded chunks are copied directly during rebalance rather than decoded and re-encoded.
