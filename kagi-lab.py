#!/usr/bin/env python3
"""Eight-node Ubuntu/QEMU/KVM Kagi lab. Python 3.10+, x86-64 Linux/systemd.

Host packages (install before running):
  Ubuntu/Debian:
    sudo apt install python3 qemu-system-x86 qemu-utils ovmf iproute2 nftables xorriso openssh-client curl git
  Arch/CachyOS:
    sudo pacman -S --needed python qemu-full edk2-ovmf iproute2 nftables xorriso openssh curl git

Usage:
  sudo python3 kagi-lab.py up
  sudo python3 kagi-lab.py wait --timeout 7200
  sudo python3 kagi-lab.py status
  sudo python3 kagi-lab.py stop
  sudo python3 kagi-lab.py ssh 1

Defaults: Ubuntu 24.04, 2 vCPU/4096 MiB RAM/80 GiB OS per VM;
six separate blank, sparse 5,000,000,000-byte NVMe namespaces per VM.
48 data disks = 240 GB logical capacity; OS overlays = 640 GiB logical.
RAM totals 32 GiB, excluding host overhead; each guest gets 4 GiB swap.
No data disk is formatted. UEFI NVRAM is separate for each VM.

admin/admin has passwordless sudo; root/admin works over SSH too.
These deliberately weak lab credentials must not be used on a shared network.
Host-only: kagi-01..04 = 10.1.0.11..14; kagi-05..08 = 10.2.0.11..14.
Host bridge addresses end in .1. The two host-only segments are not routed.
Each guest has its own QEMU user-mode NAT interface, with DHCP/default route.
No physical host NIC is bridged and no inbound NAT port is exposed.
Existing host firewall INPUT/OUTPUT rules may need to permit these subnets.
The dedicated nftables table blocks forwarding to/from lab bridges; it does
not flush or replace existing firewall tables. Same-segment L2 remains allowed.

Repository: https://github.com/ckcameron/kagi-object-store.git
Cargo.toml, build.rs and CI inspected at d58ed26d5cb3226c8bd7933f111914db20c92372.
Native packages cover the CPU build plus QUIC/eBPF; other packages include
storage development/debugging tools. Cargo resolves Rust dependencies.
Use --extra-package repeatedly for additional Ubuntu packages and --features
for Cargo features. --cuda-toolkit installs Ubuntu's nvidia-cuda-toolkit;
it does not provide a GPU, driver, passthrough, or CUDA runtime acceleration.
Default build: cargo build --locked --release --workspace --features quic,ebpf.
Use --features '' for only the repository default features. OpenCL adds its
headers/loader and CPU ICD automatically. CUDA requires --cuda-toolkit when
selected. HIP/ROCm/IPP/AOCL need separately provisioned vendor SDKs.
Build errors are retained and surfaced, never converted into successful status.

Private repo: on an authenticated checkout run:
  git bundle create /tmp/kagi.bundle --all
  sudo python3 kagi-lab.py up --repo-bundle /tmp/kagi.bundle
Bundles must be self-contained; submodules/private Cargo dependencies still
need their own guest-accessible authentication. No host tokens are copied.
--ref accepts a branch, tag or commit. Default is the source's HEAD. A network
clone is resolved once on the host and all eight VMs use the same commit.
Guest Git origin is restored to --repo after cloning the bundle.

Persistent state: /var/lib/kagi-lab; transient systemd services: kagi-lab-01..08.
After host reboot run 'up' again. Reruns preserve disks and configuration.
Creation options cannot change an existing lab. No destructive reset command.
stop shuts VMs down, retaining disks, bridges, firewall rules and configuration.
It uses ACPI via QMP, with SSH fallback. --force permits termination after
90 seconds if graceful shutdown fails; otherwise the disks are left running.
Host serial logs: STATE/node-NN/serial.log. Guest build log:
  /var/log/kagi-build.log; status: systemctl status kagi-build
Retry a failed guest build: sudo systemctl restart kagi-build
Success marker: /var/lib/kagi-build/success (contains built commit).

Implementation references:
https://www.qemu.org/docs/master/system/devices/nvme.html
https://www.qemu.org/docs/master/system/invocation.html
https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html
https://cloud-images.ubuntu.com/releases/noble/release/
"""
import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import shlex
import shutil
import socket
import subprocess
import sys
import time

STATE = Path('/var/lib/kagi-lab')
USER = 'kagi-vm'
BRIDGES = ['kagi-br1', 'kagi-br2']
REPO = 'https://github.com/ckcameron/kagi-object-store.git'
IMAGE_BASE = 'https://cloud-images.ubuntu.com/releases/noble/release/'
IMAGE_NAME = 'ubuntu-24.04-server-cloudimg-amd64.img'
PACKAGES = '''build-essential pkg-config cmake ninja-build clang llvm libclang-dev
libssl-dev libudev-dev libelf-dev zlib1g-dev libzstd-dev liblz4-dev libbz2-dev
libsnappy-dev libsasl2-dev liburing-dev libaio-dev libnuma-dev libfuse3-dev
protobuf-compiler autoconf automake libtool nasm git curl ca-certificates
python3 python3-dev openssh-server nvme-cli jq linux-tools-generic'''.split()


def run(*cmd, check=True, capture=False, input=None):
    return subprocess.run([str(x) for x in cmd], check=check, text=True,
                          capture_output=capture, input=input)


def write(path, data, mode=0o600):
    path.write_text(data)
    path.chmod(mode)


def node(i):
    segment = 1 if i <= 4 else 2
    return f'10.{segment}.0.{10 + (i-1) % 4 + 1}', BRIDGES[segment-1]


def active(i):
    return run('systemctl', 'is-active', '--quiet', f'kagi-lab-{i:02}',
               check=False, capture=True).returncode == 0


def firmware():
    pairs = [('/usr/share/OVMF/OVMF_CODE_4M.fd', '/usr/share/OVMF/OVMF_VARS_4M.fd'),
             ('/usr/share/edk2/x64/OVMF_CODE.4m.fd', '/usr/share/edk2/x64/OVMF_VARS.4m.fd'),
             ('/usr/share/edk2/x64/OVMF_CODE.fd', '/usr/share/edk2/x64/OVMF_VARS.fd'),
             ('/usr/share/OVMF/OVMF_CODE.fd', '/usr/share/OVMF/OVMF_VARS.fd')]
    for code, variables in pairs:
        if Path(code).is_file() and Path(variables).is_file():
            return code, variables
    raise RuntimeError('OVMF pair not found; supply --ovmf-code and --ovmf-vars')


def fetch(url, dest):
    run('curl', '--fail', '--location', '--retry', '4', '--proto', '=https',
        '--tlsv1.2', '--output', str(dest) + '.part', url)
    Path(str(dest) + '.part').replace(dest)


def base_image():
    dest = STATE / 'ubuntu.qcow2'
    if dest.exists():
        return dest
    sums = STATE / 'SHA256SUMS'
    fetch(IMAGE_BASE + 'SHA256SUMS', sums)
    entries = {line.split()[-1].lstrip('*'): line.split()[0]
               for line in sums.read_text().splitlines() if line.strip()}
    expected = entries[IMAGE_NAME]
    download = STATE / 'ubuntu.download'
    fetch(IMAGE_BASE + IMAGE_NAME, download)
    digest = hashlib.sha256()
    with download.open('rb') as source:
        for block in iter(lambda: source.read(8*1024*1024), b''):
            digest.update(block)
    if digest.hexdigest() != expected:
        download.unlink()
        raise RuntimeError('Ubuntu SHA256 mismatch; rerun (release may have rotated)')
    download.replace(dest)
    return dest


def build_script(config):
    packages = PACKAGES + config['extra_package']
    features = set(config['features'].replace(',', ' ').split())
    if 'opencl' in features:
        packages += ['ocl-icd-opencl-dev', 'opencl-headers', 'pocl-opencl-icd']
    if config['cuda_toolkit']:
        packages.append('nvidia-cuda-toolkit')
    build = ['cargo', 'build', '--locked', '--release', '--workspace',
             '--jobs', str(config['jobs'])]
    if config['features']:
        build += ['--features', config['features']]
    user_script = f'''set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export GIT_TERMINAL_PROMPT=0
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/kagi-rustup.sh
  sh /tmp/kagi-rustup.sh -y --profile minimal --default-toolchain stable
fi
if [ ! -d "$HOME/kagi-object-store/.git" ]; then
  git clone /opt/kagi-source.bundle "$HOME/kagi-object-store"
fi
cd "$HOME/kagi-object-store"
git remote set-url origin {shlex.quote(config['repo'])}
git checkout --detach {shlex.quote(config['commit'])}
git submodule update --init --recursive
# rustup honors a repository rust-toolchain.toml/rust-toolchain when present.
rustup show
rustup component add rustfmt clippy
{shlex.join(build)}
git rev-parse HEAD
'''
    return f'''#!/bin/bash
set -euo pipefail
exec > >(tee -a /var/log/kagi-build.log) 2>&1
mkdir -p /var/lib/kagi-build
rm -f /var/lib/kagi-build/success /var/lib/kagi-build/failed
trap 'echo failed > /var/lib/kagi-build/failed' ERR
test -d /sys/firmware/efi
python3 - <<'PY'
from pathlib import Path
disks = list(Path('/sys/block').glob('nvme*n1'))
if len(disks) != 6 or any(int((disk / 'size').read_text()) * 512 != 5_000_000_000 for disk in disks):
    raise SystemExit('Expected exactly six 5 GB NVMe disks')
print('Verified UEFI and six 5 GB NVMe disks')
PY
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=5 update
apt-get -o Acquire::Retries=5 install -y {shlex.join(packages)}
# Repo bundle is on the read-only NoCloud seed, not embedded into user-data.
mkdir -p /mnt/kagi-seed
mountpoint -q /mnt/kagi-seed || mount -o ro /dev/disk/by-label/cidata /mnt/kagi-seed
install -m 644 /mnt/kagi-seed/source.bundle /opt/kagi-source.bundle
umount /mnt/kagi-seed
runuser -u admin -- /bin/bash -lc {shlex.quote(user_script)}
for binary in kagi-config kagi-cluster-host kagi-host kagi-volume-nbd kagi-bench kagi-run; do
  install -m 755 "/home/admin/kagi-object-store/target/release/$binary" /usr/local/bin/
done
echo {shlex.quote(config['commit'])} > /var/lib/kagi-build/success
'''


def cloud_config(i, config, key):
    ip, _ = node(i)
    unit = '''[Unit]
Description=Install dependencies and build Kagi
Wants=network-online.target
After=network-online.target cloud-final.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/kagi-build
TimeoutStartSec=infinity
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
    def wf(path, content, mode='0644'):
        return dict(path=path, permissions=mode, encoding='b64',
                    content=base64.b64encode(content.encode()).decode())
    return {'hostname': f'kagi-{i:02}', 'manage_etc_hosts': True,
            'users': [{'name': 'admin', 'shell': '/bin/bash', 'groups': ['sudo'],
                       'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': False,
                       'ssh_authorized_keys': [key]}],
            'disable_root': False, 'ssh_pwauth': True,
            'chpasswd': {'expire': False, 'users': [
                {'name': 'admin', 'password': 'admin', 'type': 'text'},
                {'name': 'root', 'password': 'admin', 'type': 'text'}]},
            'swap': {'filename': '/swapfile', 'size': 4294967296, 'maxsize': 4294967296},
            'write_files': [wf('/usr/local/sbin/kagi-build', build_script(config), '0755'),
                            wf('/etc/systemd/system/kagi-build.service', unit),
                            wf('/etc/ssh/sshd_config.d/00-kagi-lab.conf',
                               f'PasswordAuthentication yes\nPermitRootLogin yes\nListenAddress {ip}\n')],
            'runcmd': [['systemctl', 'disable', '--now', 'ssh.socket'],
                       ['systemctl', 'enable', '--now', 'ssh.service'],
                       ['systemctl', 'restart', 'ssh.service'],
                       ['systemctl', 'daemon-reload'],
                       ['systemctl', 'enable', '--now', '--no-block', 'kagi-build.service']]}


def networks():
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all', capture=True).stdout)
    for segment, bridge in enumerate(BRIDGES, 1):
        target = ipaddress.ip_network(f'10.{segment}.0.0/24')
        for route in routes:
            dest = route.get('dst', 'default')
            if dest == 'default' or route.get('dev') == bridge:
                continue
            if ipaddress.ip_network(dest, strict=False).overlaps(target):
                raise RuntimeError(f'Network conflict: {route}; refusing to alter routing')
        if not Path('/sys/class/net/' + bridge).exists():
            run('ip', 'link', 'add', bridge, 'type', 'bridge')
            run('ip', 'link', 'set', bridge, 'alias', 'kagi-lab-owned')
        elif Path('/sys/class/net/' + bridge + '/ifalias').read_text().strip() != 'kagi-lab-owned':
            raise RuntimeError(f'Refusing to reuse unrelated interface {bridge}')
        run('ip', 'addr', 'replace', f'10.{segment}.0.1/24', 'dev', bridge)
        run('ip', 'link', 'set', bridge, 'up')
    # Atomic replacement of our own table only. No global forwarding changes.
    present = run('nft', 'list', 'table', 'inet', 'kagi_lab', check=False, capture=True)
    rules = 'delete table inet kagi_lab\n' if present.returncode == 0 else ''
    rules += '''table inet kagi_lab {
 chain forward {
  type filter hook forward priority -20; policy accept;
  iifname "kagi-br1" oifname "kagi-br1" accept
  iifname "kagi-br2" oifname "kagi-br2" accept
  iifname { "kagi-br1", "kagi-br2" } drop
  oifname { "kagi-br1", "kagi-br2" } drop
 }
}
'''
    run('nft', '-f', '-', input=rules)
    for i in range(1, 9):
        tap = f'kagi-tap{i}'
        if not Path('/sys/class/net/' + tap).exists():
            run('ip', 'tuntap', 'add', 'dev', tap, 'mode', 'tap', 'user', USER)
            run('ip', 'link', 'set', tap, 'alias', 'kagi-lab-owned')
        elif Path('/sys/class/net/' + tap + '/ifalias').read_text().strip() != 'kagi-lab-owned':
            raise RuntimeError(f'Refusing to reuse unrelated interface {tap}')
        run('ip', 'link', 'set', tap, 'master', node(i)[1])
        run('ip', 'link', 'set', tap, 'up')


def qemu_args(i, config):
    directory = STATE / f'node-{i:02}'
    cmd = ['qemu-system-x86_64', '-name', f'kagi-{i:02}', '-machine', 'q35,accel=kvm',
           '-cpu', 'host', '-smp', str(config['cpus']), '-m', str(config['memory']),
           '-display', 'none', '-monitor', 'none', '-serial', f'file:{directory}/serial.log',
           '-qmp', f'unix:{directory}/qmp.sock,server=on,wait=off',
           '-drive', f'if=pflash,format=raw,readonly=on,file={config["ovmf_code"]}',
           '-drive', f'if=pflash,format=raw,file={directory}/VARS.fd',
           '-drive', f'file={directory}/os.qcow2,if=virtio,format=qcow2',
           '-drive', f'file={directory}/seed.iso,if=none,id=seed,format=raw,readonly=on',
           '-device', 'virtio-blk-pci,drive=seed',
           '-netdev', f'tap,id=lab,ifname=kagi-tap{i},script=no,downscript=no',
           '-device', f'virtio-net-pci,netdev=lab,mac=52:54:00:11:00:{i:02x}',
           '-netdev', 'user,id=wan,ipv6=off',
           '-device', f'virtio-net-pci,netdev=wan,mac=52:54:00:22:00:{i:02x}']
    for disk in range(1, 7):
        cmd += ['-drive', f'file={directory}/nvme-{disk}.raw,if=none,id=nvme{disk},format=raw,discard=unmap',
                '-device', f'nvme,drive=nvme{disk},serial=KAGI{i:02}D{disk:02}']
    return cmd


def prepare_node(i, config):
    directory = STATE / f'node-{i:02}'
    directory.mkdir(exist_ok=True)
    if (directory / 'ready').exists():
        return
    if active(i):
        raise RuntimeError('Cannot provision an active incomplete VM')
    if not (directory / 'os.qcow2').exists():
        run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', STATE / 'ubuntu.qcow2',
            directory / 'os.qcow2', f'{config["os_gib"]}G')
    if not (directory / 'VARS.fd').exists():
        shutil.copyfile(config['ovmf_vars'], directory / 'VARS.fd')
    for disk in range(1, 7):
        path = directory / f'nvme-{disk}.raw'
        if not path.exists():
            with path.open('xb') as stream:
                stream.truncate(5_000_000_000)
    seed = directory / 'seed'
    seed.mkdir(exist_ok=True)
    write(seed / 'user-data', '#cloud-config\n' + json.dumps(cloud_config(i, config,
          (STATE / 'id_ed25519.pub').read_text().strip()), indent=2))
    write(seed / 'meta-data', json.dumps({'instance-id': f'kagi-lab-{i:02}',
                                        'local-hostname': f'kagi-{i:02}'}))
    write(seed / 'network-config', json.dumps({'version': 2, 'ethernets': {
        'lab0': {'match': {'macaddress': f'52:54:00:11:00:{i:02x}'}, 'set-name': 'lab0',
                 'dhcp4': False, 'dhcp6': False, 'accept-ra': False,
                 'addresses': [node(i)[0] + '/24']},
        'wan0': {'match': {'macaddress': f'52:54:00:22:00:{i:02x}'}, 'set-name': 'wan0',
                 'dhcp4': True, 'dhcp6': False, 'accept-ra': False}}}, indent=2))
    if not (seed / 'source.bundle').exists():
        os.link(STATE / 'source.bundle', seed / 'source.bundle')
    run('xorriso', '-as', 'mkisofs', '-quiet', '-volid', 'cidata', '-joliet', '-rock',
        '-output', directory / 'seed.iso', seed)
    account = pwd.getpwnam(USER)
    for path in [directory, *directory.rglob('*')]:
        os.chown(path, account.pw_uid, account.pw_gid)
    write(directory / 'ready', 'provisioned\n')


def powerdown(i):
    """Send ACPI power-button event without relying on a configured guest network."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(STATE / f'node-{i:02}' / 'qmp.sock'))
        with connection.makefile('rwb') as stream:
            greeting = json.loads(stream.readline())
            if 'QMP' not in greeting:
                raise RuntimeError('Invalid QMP greeting')
            for command in ('qmp_capabilities', 'system_powerdown'):
                stream.write((json.dumps({'execute': command, 'id': command}) + '\n').encode())
                stream.flush()
                while True:
                    reply = json.loads(stream.readline())
                    if reply.get('id') == command:
                        if 'error' in reply:
                            raise RuntimeError(str(reply['error']))
                        break


def ssh_cmd(i, command=None):
    cmd = ['ssh', '-i', str(STATE / 'id_ed25519'), '-o', 'IdentitiesOnly=yes',
           '-o', 'StrictHostKeyChecking=accept-new', '-o', f'UserKnownHostsFile={STATE}/known_hosts',
           '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=10',
           '-o', 'ServerAliveCountMax=2']
    if command is None:
        cmd += ['-t']
    return cmd + [f'admin@{node(i)[0]}'] + ([] if command is None else [command])


def up(args):
    if platform.machine() not in ('x86_64', 'amd64') or not Path('/dev/kvm').exists():
        raise RuntimeError('Requires an x86-64 Linux host with /dev/kvm enabled')
    for program in ('qemu-system-x86_64', 'qemu-img', 'ip', 'nft', 'xorriso', 'curl',
                    'ssh', 'ssh-keygen', 'git', 'systemd-run', 'systemctl'):
        if not shutil.which(program):
            raise RuntimeError(f'Missing {program}; see --help host package list (also install git)')
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', USER)
        account = pwd.getpwnam(USER)
    os.chown(STATE, 0, account.pw_gid)
    STATE.chmod(0o750)
    config_path = STATE / 'config.json'
    if config_path.exists():
        config = json.loads(config_path.read_text())
        print('Using saved configuration; creation options are ignored.', flush=True)
    else:
        config = vars(args).copy()
        if bool(args.ovmf_code) != bool(args.ovmf_vars):
            raise RuntimeError('Supply both firmware paths')
        code, variables = (args.ovmf_code, args.ovmf_vars) if args.ovmf_code else firmware()
        config.update(ovmf_code=str(Path(code).resolve()), ovmf_vars=str(Path(variables).resolve()))
        # Resolve and bundle once so every node builds the exact same revision.
        source = STATE / 'source.bundle'
        if args.repo_bundle:
            shutil.copyfile(Path(args.repo_bundle).resolve(), source)
        else:
            checkout = STATE / 'source-mirror.git'
            if checkout.exists():
                run('git', '-C', checkout, 'fetch', '--prune', 'origin')
            else:
                run('git', 'clone', '--mirror', '--', args.repo, checkout)
            run('git', '-C', checkout, 'bundle', 'create', source, '--all')
        inspect = STATE / 'bundle-inspect.git'
        if inspect.exists():
            shutil.rmtree(inspect)
        run('git', 'clone', '--bare', source, inspect)
        config['commit'] = run('git', '-C', inspect, 'rev-parse', '--verify',
                               (args.ref or 'HEAD') + '^{commit}', capture=True).stdout.strip()
        write(config_path, json.dumps(config, indent=2))
    image = base_image()
    image.chmod(0o644)
    if not (STATE / 'id_ed25519').exists():
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', STATE / 'id_ed25519')
    networks()
    for i in range(1, 9):
        prepare_node(i, config)
        if not active(i):
            run('systemctl', 'reset-failed', f'kagi-lab-{i:02}', check=False, capture=True)
            run('systemd-run', '--collect', f'--unit=kagi-lab-{i:02}',
                '--property=Type=exec', f'--property=User={USER}',
                '--property=SupplementaryGroups=kvm', '--property=KillSignal=SIGTERM',
                '--property=TimeoutStopSec=120', *qemu_args(i, config))
    print('VMs launched. Run wait to verify all eight guest builds. Credentials: admin/admin; root/admin.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['up', 'wait', 'status', 'stop', 'ssh'])
    parser.add_argument('node', nargs='?', type=int, choices=range(1, 9))
    parser.add_argument('--memory', type=int, default=4096, help='MiB per VM, first creation only')
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--jobs', type=int, default=2, help='Cargo build jobs per VM')
    parser.add_argument('--os-gib', type=int, default=80)
    parser.add_argument('--repo', default=REPO)
    parser.add_argument('--ref')
    parser.add_argument('--repo-bundle')
    parser.add_argument('--features', default='quic,ebpf')
    parser.add_argument('--extra-package', action='append', default=[])
    parser.add_argument('--cuda-toolkit', action='store_true')
    parser.add_argument('--ovmf-code')
    parser.add_argument('--ovmf-vars')
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--force', action='store_true', help='Permit forced stop after graceful shutdown timeout')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo; this script creates KVM services and host-only networks')
    if min(args.memory, args.cpus, args.jobs, args.os_gib, args.timeout) <= 0:
        parser.error('Resource sizes and timeout must be positive')
    if args.action == 'up' and 'cuda' in args.features.replace(',', ' ').split() and not args.cuda_toolkit:
        parser.error('--features cuda requires --cuda-toolkit')
    STATE.mkdir(mode=0o750, parents=True, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        # Monitoring/SSH must not prevent a concurrent status or stop command.
        if args.action in ('up', 'stop'):
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'up':
            up(args)
        elif args.action == 'stop':
            for i in range(1, 9):
                if active(i):
                    try:
                        powerdown(i)
                    except (OSError, RuntimeError, ValueError):
                        run(*ssh_cmd(i, 'sudo shutdown -h now'), check=False, capture=True)
            deadline = time.monotonic() + 90
            while any(active(i) for i in range(1, 9)) and time.monotonic() < deadline:
                time.sleep(2)
            remaining = [f'kagi-lab-{i:02}' for i in range(1, 9) if active(i)]
            if remaining:
                if not args.force:
                    raise RuntimeError(f'Graceful shutdown timed out: {remaining}; use stop --force to terminate')
                print('Guest shutdown timed out; stopping remaining QEMU processes:', remaining)
                run('systemctl', 'kill', '--signal=SIGTERM', *remaining)
        elif args.action == 'ssh':
            if args.node is None:
                parser.error('ssh requires a node number 1..8')
            return run(*ssh_cmd(args.node), check=False).returncode
        else:
            pending = set(range(1, 9))
            deadline = time.monotonic() + args.timeout
            probe = ('if test -f /var/lib/kagi-build/success; then echo BUILT; '
                     'cat /var/lib/kagi-build/success; '
                     'elif test -f /var/lib/kagi-build/failed; then echo FAILED; '
                     'elif systemctl is-failed --quiet kagi-build.service; then echo FAILED; '
                     'elif cloud-init status 2>/dev/null | grep -q "status: error"; then echo FAILED; '
                     'else echo PROVISIONING; fi')
            while pending:
                for i in sorted(pending):
                    result = run(*ssh_cmd(i, probe), check=False, capture=True) if active(i) else None
                    state = ('STOPPED' if result is None else
                             (result.stdout.strip() if result.returncode == 0 else 'SSH-NOT-READY'))
                    print(f'kagi-{i:02} {node(i)[0]:14} {state}', flush=True)
                    if state.startswith('BUILT'):
                        pending.remove(i)
                    elif state in ('FAILED', 'STOPPED') and args.action == 'wait':
                        raise RuntimeError(f'Node {i}: {state}; inspect serial.log and /var/log/kagi-build.log')
                if args.action == 'status' or not pending:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f'Timed out waiting for nodes {sorted(pending)}')
                time.sleep(15)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.CalledProcessError, KeyError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
