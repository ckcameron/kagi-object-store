#!/usr/bin/env bash
# SPDX-License-Identifier: CC-BY-NC-SA-4.0
# Copyright (c) 2026 CK Cameron.
# Creates an eight-guest Ubuntu 24.04 KVM lab; existing guests are never destroyed.
set -Eeuo pipefail
umask 077
VM_PREFIX="${VM_PREFIX:-kagi}"
VM_USER="${VM_USER:-kagi}"
MEMORY_MIB="${MEMORY_MIB:-4096}"
VCPUS="${VCPUS:-4}"
ROOT_DISK_GIB="${ROOT_DISK_GIB:-24}"
DATA_DISK_GIB="${DATA_DISK_GIB:-5}"
DATA_DISKS="${DATA_DISKS:-6}"
STATE_DIR="${STATE_DIR:-$HOME/.local/share/kagi-vm-lab}"
IMAGE_DIR="$STATE_DIR/images"
BASE_IMAGE="$IMAGE_DIR/noble-server-cloudimg-amd64.img"
IMAGE_URL="${IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-$HOME/.ssh/id_ed25519.pub}"
SSH_PRIVATE_KEY="${SSH_PRIVATE_KEY:-${SSH_PUBLIC_KEY%.pub}}"
while (($#)); do
  case "$1" in
    --state-dir) STATE_DIR="${2:?directory required}"; IMAGE_DIR="$STATE_DIR/images"; BASE_IMAGE="$IMAGE_DIR/noble-server-cloudimg-amd64.img"; shift 2 ;;
    --ssh-key) SSH_PUBLIC_KEY="${2:?public key path required}"; SSH_PRIVATE_KEY="${SSH_PUBLIC_KEY%.pub}"; shift 2 ;;
    --help|-h) echo "Usage: deploy-kagi-lab.sh [--state-dir DIR] [--ssh-key PUBLIC_KEY]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
for cmd in virsh virt-install qemu-img curl ssh-keygen; do
  command -v "$cmd" >/dev/null || { echo "missing required command: $cmd" >&2; exit 1; }
done
[[ -r "$SSH_PUBLIC_KEY" ]] || { echo "SSH public key not found: $SSH_PUBLIC_KEY" >&2; exit 1; }
ssh-keygen -y -f "$SSH_PRIVATE_KEY" >/dev/null 2>&1 || { echo "matching private key required: $SSH_PRIVATE_KEY" >&2; exit 1; }
[[ "$DATA_DISKS" =~ ^[1-9][0-9]*$ && "$DATA_DISK_GIB" =~ ^[1-9][0-9]*$ && "$ROOT_DISK_GIB" =~ ^[1-9][0-9]*$ ]] || { echo "disk counts/sizes must be positive integers" >&2; exit 2; }
mkdir -p "$IMAGE_DIR" "$STATE_DIR/cloud-init"
if [[ ! -s "$BASE_IMAGE" ]]; then
  echo "Downloading Ubuntu 24.04 cloud image..."
  curl --fail --location --retry 3 --output "$BASE_IMAGE.part" "$IMAGE_URL"
  mv "$BASE_IMAGE.part" "$BASE_IMAGE"
fi
qemu-img info "$BASE_IMAGE" >/dev/null
virsh uri >/dev/null

define_network() {
  local name="$1" bridge="$2" subnet="$3" letter="$4" octet="$5" xml
  if virsh net-info "$name" >/dev/null 2>&1; then
    echo "Network $name already exists; preserving configuration."
    virsh net-start "$name" >/dev/null 2>&1 || true
    virsh net-autostart "$name" >/dev/null
    return
  fi
  xml="$STATE_DIR/$name.xml"
  {
    printf "<network>\n <name>%s</name>\n <forward mode='nat'/>\n <bridge name='%s' stp='on' delay='0'/>\n" "$name" "$bridge"
    printf " <ip address='%s.1' netmask='255.255.255.0'>\n  <dhcp>\n   <range start='%s.100' end='%s.199'/>\n" "$subnet" "$subnet" "$subnet"
    for i in 1 2 3 4; do
      mac="52:54:00:10:$octet:$(printf '%02x' $((16+i)))"
      printf "   <host mac='%s' name='%s-%s%d' ip='%s.%d'/>\n" "$mac" "$VM_PREFIX" "$letter" "$i" "$subnet" "$((10+i))"
    done
    printf "  </dhcp>\n </ip>\n</network>\n"
  } > "$xml"
  virsh net-define "$xml"
  virsh net-start "$name"
  virsh net-autostart "$name"
}
define_network "$VM_PREFIX-net-a" virbr-kagi-a 10.1.0 a 01
define_network "$VM_PREFIX-net-b" virbr-kagi-b 10.2.0 b 02

PUBKEY="$(cat "$SSH_PUBLIC_KEY")"
for group in a b; do
  if [[ "$group" == a ]]; then net="$VM_PREFIX-net-a"; subnet=10.1.0; octet=01; else net="$VM_PREFIX-net-b"; subnet=10.2.0; octet=02; fi
  for i in 1 2 3 4; do
    name="$VM_PREFIX-$group$i"
    ip="$subnet.$((10+i))"
    mac="52:54:00:10:$octet:$(printf '%02x' $((16+i)))"
    root="$IMAGE_DIR/$name-root.qcow2"
    user_data="$STATE_DIR/cloud-init/$name-user-data.yaml"
    meta_data="$STATE_DIR/cloud-init/$name-meta-data.yaml"
    if virsh dominfo "$name" >/dev/null 2>&1; then echo "VM $name already exists; preserving it."; continue; fi
    [[ -e "$root" ]] || qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$root" "$ROOT_DISK_GIB"G
    cat > "$user_data" <<CLOUD
#cloud-config
hostname: $name
manage_etc_hosts: true
users:
  - name: $VM_USER
    groups: [adm, sudo, kvm, libvirt]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: true
    ssh_authorized_keys:
      - "$PUBKEY"
ssh_pwauth: false
disable_root: true
package_update: true
packages: [qemu-guest-agent, nbd-client, open-iscsi, nvme-cli, curl, jq]
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
CLOUD
    printf 'instance-id: %s\nlocal-hostname: %s\n' "$name" "$name" > "$meta_data"
    disks=(--disk "path=$root,format=qcow2,bus=virtio")
    for d in $(seq 1 "$DATA_DISKS"); do
      disk="$IMAGE_DIR/$name-nvme$d.qcow2"
      [[ -e "$disk" ]] || qemu-img create -f qcow2 "$disk" "$DATA_DISK_GIB"G
      disks+=(--disk "path=$disk,format=qcow2,bus=nvme,cache=none,discard=unmap")
    done
    echo "Creating $name at $ip on $net with $DATA_DISKS NVMe disks..."
    virt-install --name "$name" --import --os-variant ubuntu24.04 \
      --memory "$MEMORY_MIB" --vcpus "$VCPUS" --cpu host-passthrough \
      --machine q35 --boot uefi --network "network=$net,model=virtio,mac=$mac" \
      "${disks[@]}" --cloud-init "user-data=$user_data,meta-data=$meta_data" \
      --graphics none --console pty,target_type=serial --noautoconsole \
      --rng /dev/urandom --check path_in_use=off
  done
done
printf '\nVM lab configured. SSH targets:\n'
for group in a b; do
  [[ "$group" == a ]] && subnet=10.1.0 || subnet=10.2.0
  for i in 1 2 3 4; do printf '  ssh %s@%s.%d  (%s-%s%d)\n' "$VM_USER" "$subnet" "$((10+i))" "$VM_PREFIX" "$group" "$i"; done
done
cat <<'NOTES'
Both libvirt networks use NAT for internet access and isolate guest L2 networks from each other.
The six data disks are virtual NVMe devices backed by qcow2 files, not physical NVMe drives.
UEFI requires OVMF firmware installed on the host. This script preserves existing VMs and networks.
Inspect with: virsh list --all; virsh net-list --all
NOTES
