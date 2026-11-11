<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi VM and Kubernetes storage deployment

## Eight-VM KVM lab

`deploy/vm/deploy-kagi-lab.sh` creates Ubuntu 24.04 guests `kagi-a1..a4` and `kagi-b1..b4` using libvirt/KVM. Network A is NATed `10.1.0.0/24`, network B is NATed `10.2.0.0/24`; the guest L2 networks are separate. Each VM has UEFI, a virtio root disk, six virtual NVMe data disks (5 GiB each by default), cloud-init, guest agent, and SSH-key login from the host.

Run from the repository root on a host with KVM/libvirt, `virsh`,
`virt-install`, `qemu-img`, `curl`, `ssh-keygen`, OVMF/UEFI firmware, and a matching SSH keypair.

```sh
bash deploy/vm/deploy-kagi-lab.sh --ssh-key ~/.ssh/id_ed25519.pub
ssh kagi@10.1.0.11
virsh list --all
```

The script preserves existing guests and networks. Check DHCP reservations
before reusing a network. The default guest addresses run from `.11` to `.14`
on each subnet. Data disks are qcow2-backed virtual NVMe devices. The two NAT
networks provide outbound access and separate guest L2 domains.

Use `--state-dir` to choose where the script stores disk images and cloud-init
files. It prepares VMs only. Plan the cluster and configure Kagi in the guests
using the [operator guide](../../../docs/OPERATIONS.md).

## Kubernetes CSI driver

`deploy/kubernetes/csi` contains a CSI controller/node implementation. The controller creates thin-provisioned Kagi volumes through `POST /v1/volumes`. Controller publish/unpublish uses Kagi's Raft-backed SCSI persistent-reservation API to fence a volume to one Kubernetes node. Each node stages a volume by starting the Kagi NBD frontend locally, attaching an available `/dev/nbdN`, and then publishes either a raw block device or an ext4 filesystem into a pod. Node staging state and NBD logs live under the kubelet plugin directory,
`/var/lib/kubelet/plugins/csi.kagi.io/volumes` in the example deployment.

### Build and deploy

Build from the repository root so Docker can copy the Rust frontend and Go
module. The container uses stable Rust and Go 1.25. Local driver builds and
tests require Go 1.25.0 or later, as declared in [`go.mod`](go.mod).

```sh
docker build -f deploy/kubernetes/csi/Dockerfile -t ghcr.io/ckcameron/kagi-csi:dev .
# Push to a registry reachable by the cluster, or load the image into your local cluster.
```

Edit [`deployment.yaml`](deployment.yaml) to use your image and set
`KAGI_API_ENDPOINT` in both workloads to the trusted Kagi cluster-host API.
The configured endpoint takes precedence over the PV's `apiEndpoint` attribute.
Keep the API destination under administrator control. The example uses
`kagi-cluster-host.kagi-system.svc.cluster.local:7400` as the service address.

Run the node plugin on Linux nodes with NBD kernel support and available
`/dev/nbd*` devices. The example manifests assume kubelet's root is
`/var/lib/kubelet`. Apply the workloads and StorageClass, then try the PVC and pod examples.

```sh
kubectl apply -f deploy/kubernetes/csi/deployment.yaml
kubectl apply -f deploy/kubernetes/csi/rbac.yaml
kubectl apply -f deploy/kubernetes/csi/storageclass.yaml
kubectl apply -f deploy/kubernetes/csi/pvc-examples.yaml
kubectl apply -f deploy/kubernetes/csi/pod-example.yaml
kubectl -n kagi-system get pods
kubectl get storageclass kagi-retain
```

The pod examples mount the filesystem PVC through `volumeMounts` and expose
the raw block PVC through `volumeDevices` and `devicePath`. The node plugin
runs privileged to manage host NBD devices and mounts. Restrict it to trusted
storage nodes and keep access to the Kagi volume API private. The
external-attacher calls the CSI controller, which holds the Kagi reservation
for the selected node. The NBD frontend binds to loopback on that node.

### Lifecycle and safety limits

- The StorageClass uses `Retain`. Kagi refuses to delete a volume with allocated extents; explicit data reclamation is required before metadata deletion. This is intentional to avoid losing object-backed data.
- Filesystem mode formats a writable volume as ext4 only when the probe finds
  no filesystem and Kagi reports zero allocated extents. A failed probe, an
  unsupported filesystem, or an unrecognized volume with extents stops staging.
- Online expansion is disabled. Resize/expand is not advertised as a CSI capability yet.
- Multi-node read/write is not supported. Use `ReadWriteOnce` and ensure a volume is not mounted by two nodes concurrently.
- The driver currently does not pass SCSI-3 persistent reservation commands through NBD; do not use it as a substitute for a SCSI target when guest PR semantics are required.
- The NBD frontend and API are synchronous per I/O operation; benchmark latency and throughput before production use.
- The example Kagi API endpoint uses plaintext HTTP. Use a trusted HTTPS
  endpoint where traffic crosses a shared network. The CSI client has no
  per-request credential configuration, so enforce access through trusted
  service routing and network controls.

### Local validation

```sh
(cd deploy/kubernetes/csi && go mod tidy && go test -race ./... && go vet ./...)
bash -n deploy/vm/deploy-kagi-lab.sh
cargo check --locked --bin kagi-volume-nbd
```

The [storage workflow](../../../.github/workflows/kubernetes-storage.yml) also
builds the image and parses the manifests. To exercise attach, write, and detach
end to end, run the sample workloads on an NBD-capable cluster.
