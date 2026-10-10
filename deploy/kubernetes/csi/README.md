<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->
# Kagi VM and Kubernetes storage deployment

## Eight-VM KVM lab

`deploy/vm/deploy-kagi-lab.sh` creates Ubuntu 24.04 guests `kagi-a1..a4` and `kagi-b1..b4` using libvirt/KVM. Network A is NATed `10.1.0.0/24`, network B is NATed `10.2.0.0/24`; the guest L2 networks are separate. Each VM has UEFI, a virtio root disk, six virtual NVMe data disks (5 GiB each by default), cloud-init, guest agent, and SSH-key login from the host.

Prerequisites: KVM/libvirt, `virsh`, `virt-install`, `qemu-img`, `curl`, OVMF/UEFI firmware, and a matching SSH keypair. Example:

```sh
chmod +x deploy/vm/deploy-kagi-lab.sh
deploy/vm/deploy-kagi-lab.sh --ssh-key ~/.ssh/id_ed25519.pub
ssh kagi@10.1.0.11
virsh list --all
```

The script is idempotent for existing guests and networks; it does not delete or overwrite them. Existing libvirt network configuration is preserved, so check that its DHCP reservations match this lab before reusing networks. Data disks are qcow2-backed virtual NVMe devices, not physical NVMe. For isolated test networks, guests can reach the host through their libvirt bridges; inbound access from other LAN machines is not exposed.

## Kubernetes CSI driver

`deploy/kubernetes/csi` contains a CSI controller/node implementation. The controller creates thin-provisioned Kagi volumes through `POST /v1/volumes`. Controller publish/unpublish uses Kagi's Raft-backed SCSI persistent-reservation API to fence a volume to one Kubernetes node. Each node stages a volume by starting the Kagi NBD frontend locally, attaching an available `/dev/nbdN`, and then publishes either a raw block device or an ext4 filesystem into a pod. Node staging state and NBD logs live under the kubelet plugin directory.

Build and install:

```sh
docker build -f deploy/kubernetes/csi/Dockerfile -t ghcr.io/ckcameron/kagi-csi:dev .
# Push to a registry reachable by the cluster, or load the image into your local cluster.
```

Edit `deploy/kubernetes/csi/deployment.yaml` to use your image and set `KAGI_API_ENDPOINT` to a reachable Kagi cluster-host API service. The example assumes `kagi-cluster-host.kagi-system.svc.cluster.local:7400`; adapt this service DNS name to your deployment. Apply the manifests and StorageClass:

```sh
kubectl apply -f deploy/kubernetes/csi/deployment.yaml
kubectl apply -f deploy/kubernetes/csi/rbac.yaml
kubectl apply -f deploy/kubernetes/csi/storageclass.yaml
kubectl apply -f deploy/kubernetes/csi/pvc-examples.yaml
kubectl apply -f deploy/kubernetes/csi/pod-example.yaml
kubectl -n kagi-system get pods
kubectl get storageclass kagi-retain
```

Use the filesystem PVC with a normal pod volume mount, or the block PVC with `volumeDevices` and `devicePath`. The node plugin is privileged because it manages NBD devices and mounts; restrict scheduling to trusted storage nodes, limit cluster RBAC, and use TLS/network policy for the Kagi API in production. The controller uses the CSI external-attacher sidecar; the Kagi API's persistent reservation is the single-node write-fencing mechanism. The NBD endpoint is loopback-bound on the node and is not exposed as a network service.

### Lifecycle and safety limits

- The StorageClass uses `Retain`. Kagi refuses to delete a volume with allocated extents; explicit data reclamation is required before metadata deletion. This is intentional to avoid losing object-backed data.
- Filesystem mode formats a newly created, unformatted volume as ext4. Existing filesystem signatures are preserved; unsupported filesystems are not reformatted automatically.
- Online expansion is disabled. Resize/expand is not advertised as a CSI capability yet.
- Multi-node read/write is not supported. Use `ReadWriteOnce` and ensure a volume is not mounted by two nodes concurrently.
- The driver currently does not pass SCSI-3 persistent reservation commands through NBD; do not use it as a substitute for a SCSI target when guest PR semantics are required.
- The NBD frontend and API are synchronous per I/O operation; benchmark latency and throughput before production use.
- The Kubernetes API endpoint in the example is plaintext HTTP. Use an HTTPS endpoint and suitable authentication for production; do not expose the storage API publicly.
