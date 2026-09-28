# Operator Guide

## Planning a cluster

Run the wizard or prepare a YAML topology, then execute `kagi-config`. Review `optimizer`, `policies`, and `keyspace.disks` before provisioning. The emitted mount names and slot ranges form the deployment plan; do not silently renumber disks after planning.

## Preparing disks

Create/mount each physical device at the generated `path`. Use stable `/dev/disk/by-id` or multipath names in `device_path` rather than transient kernel names where practical. The runtime probes configured serial/WWN/transport information before admitting media for placement.

## Installing nodes

`scripts/kagi-install` initializes a local node and can bootstrap additional hosts via SSH. Each host receives a unique ML-DSA identity and persistent replay/session state. Cluster admission credentials are shared secrets and should be handled as such.

## Expanding capacity

Add a disk through the capacity API/CLI. The leader validates the device, commits topology/placement epoch state, then background rebalance copies data to new destinations before committing updated manifests and removing superseded replicas. Rebalance obeys maintenance QoS unless durability repair makes the work system-necessary.

## Maintenance

Configure maintenance windows and quotas for scrub, proactive repair/rebalance, GC, and snapshot archival. Foreground REST and block-volume operations take priority. System-necessary repair can bypass ordinary maintenance restrictions.

## Block volumes

Use object-backed volumes as sparse logical SCSI disks. For KVM/QEMU prefer virtio-scsi. VMware guests should see PVSCSI-backed LUNs, and Hyper-V guests synthetic SCSI. SCSI-3 PR state lives in Raft, so transport frontends must map guest CDBs to the Kagi PR implementation rather than maintaining an independent reservation database.


## CLAY/MSR recovery

Single-chunk CLAY/MSR failures use exact repair. CLAY reads only required subchunks from each selected helper; product-matrix MSR computes one repair projection per helper on the helper node. With CUDA enabled, the heavy GF(256) transforms are GPU-dispatched above the configured threshold. Final repaired chunks are checksum-verified before placement metadata is updated. Multiple logical-chunk failures use full MDS reconstruction.


## security and monitoring

See [security policy and monitoring](SECURITY-POLICY.md) for node YAML rules, the
optional BPF build, privileged metadata, authenticated REST/SSE endpoints, the
audit CLI and deployment boundaries.
