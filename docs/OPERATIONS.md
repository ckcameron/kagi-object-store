<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Operator Guide

## Planning a cluster

Run the [planner](MONTECARLO.md) with the wizard or a topology file. The
repository includes a topology to use as a starting point:

```sh
kagi-config --config examples/montecarlo-topology.yaml --output kagi.generated.yaml
```

Review `optimizer`, `policies`, and `keyspace.disks` before provisioning. Keep
the planned disk IDs, mount paths, and slot ranges stable during deployment.

## Preparing disks

Create/mount each physical device at the generated `path`. Use stable `/dev/disk/by-id` or multipath names in `device_path` rather than transient kernel names where practical. The runtime probes configured serial/WWN/transport information before admitting media for placement.

## Installing nodes

[`kagi-install`](man/kagi-install.1) creates local bootstrap files and can
configure additional hosts over SSH. Its generated one-host, one-disk YAML is
a starting point. Complete the configuration using the planned topology,
the [node example](../examples/node-v6.example.yaml), and the
[configuration reference](CONFIGURATION.md) before starting the cluster daemon.
Each node needs its own ML-DSA identity and persistent replay/session state.
Keep shared cluster admission credentials private.

Use the daemon's local audit and status commands to inspect the node:

```sh
kagi-cluster-host --config /etc/kagi/node.yaml audit
kagi-cluster-host --config /etc/kagi/node.yaml status
```

## Expanding capacity

Add a disk using the `POST /v1/capacity/:host` capacity endpoint. The leader validates the device, commits topology/placement epoch state, then background rebalance copies data to new destinations before committing updated manifests and removing superseded replicas. Rebalance obeys maintenance QoS unless durability repair makes the work system-necessary.

## Maintenance

Configure maintenance windows and quotas for scrub, proactive repair/rebalance, GC, and snapshot archival. Foreground REST and block-volume operations take priority. System-necessary repair can bypass ordinary maintenance restrictions.

## Snapshots and archival

List and create snapshots with `/v1/snapshots`. A snapshot pins immutable object
versions. Automatic materialization follows the configured snapshot thresholds.
Use `POST /v1/snapshots/:id/archive` to request archival explicitly. Keep keys
for archived or retained versions available during [key rotation](AT-REST-ROTATION.md).

## Block volumes

Use object-backed volumes as sparse logical SCSI disks. For KVM/QEMU prefer virtio-scsi. VMware guests should see PVSCSI-backed LUNs, and Hyper-V guests synthetic SCSI. SCSI-3 PR state lives in Raft. A SCSI target integration needs to route guest
reservation CDBs to the Kagi PR implementation. The
[VM lab and CSI guide](../deploy/kubernetes/csi/README.md) covers KVM test guests
and single-node Kubernetes filesystem or raw-block publishing over NBD.


## CLAY/MSR recovery

Single-chunk CLAY/MSR failures use exact repair. CLAY reads only required subchunks from each selected helper; product-matrix MSR computes one repair projection per helper on the helper node. With CUDA enabled, the heavy GF(256) transforms are GPU-dispatched above the configured threshold. Final repaired chunks are checksum-verified before placement metadata is updated. Multiple logical-chunk failures use full MDS reconstruction.


## Security and monitoring

See [security policy and monitoring](SECURITY-POLICY.md) for node YAML rules, the
optional BPF build, privileged metadata, authenticated REST/SSE endpoints, the
audit CLI and deployment boundaries.
