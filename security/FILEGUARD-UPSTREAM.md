# fileguard-rs

Rust + Aya eBPF LSM access control for Linux files and directories.

## What it does

The eBPF side attaches to Linux Security Module hooks and can synchronously
return `0` (allow) or `-EACCES` (deny). Matching events are emitted through a
BPF ring buffer to a Rust userspace daemon.

Covered operations:

- open
- read
- write
- append
- exec
- getattr/stat-like metadata access
- create/mkdir
- unlink/rmdir
- rename/move

Rules are stored in a BPF hash map keyed by `(superblock s_dev, inode number)`.
A `recursive = true` directory policy is inherited by descendants by walking
up to 32 dentry parents in the eBPF program.

The userspace daemon can perform side actions for matched events:

- `log`
- `exec`
- `signal`

## Important semantic boundary

BPF LSM can make a synchronous **allow/deny** decision. It cannot safely
replace an arbitrary `open(2)`, `read(2)`, `write(2)`, `stat(2)`, etc. with
another userspace operation and then return an emulated syscall result.

Accordingly, `decision = "deny"` plus an `exec`/`signal` action means:

1. the LSM hook denies the original filesystem operation synchronously;
2. a ring-buffer event is emitted;
3. the userspace daemon performs the configured side action.

If you need genuine syscall substitution/emulation, use a seccomp user-
notification supervisor (or a FUSE/overlay design) alongside this project.

## Requirements

- Linux kernel with `CONFIG_BPF_LSM=y`
- BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- `bpf` present in `/sys/kernel/security/lsm`
- Rust stable and nightly
- `bpf-linker`
- `aya-tool`

Current versions used here track the Aya 0.14 / aya-ebpf 0.2 generation.

Typical setup:

```bash
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install aya-tool
cargo binstall bpf-linker
```

Verify BPF LSM:

```bash
cat /sys/kernel/security/lsm
```

The output must include `bpf`.

## Build

Generate kernel type bindings from the build/target kernel:

```bash
make bindings
```

Build the eBPF object:

```bash
make ebpf
```

Build userspace:

```bash
make user
```

Or:

```bash
make build
```

## Run

Edit `fileguard.toml` so all configured paths exist, then:

```bash
sudo RUST_LOG=info target/release/fileguard \
  --ebpf target/bpfel-unknown-none/release/fileguard-ebpf \
  --config fileguard.toml
```

Audit without denying anything:

```bash
sudo target/release/fileguard \
  --audit-only \
  --ebpf target/bpfel-unknown-none/release/fileguard-ebpf \
  --config fileguard.toml
```

## Rule format

```toml
[[rules]]
path = "/srv/protected"
operations = ["read", "write", "create", "delete", "rename"]
decision = "deny"
recursive = true
action = "alert"

[actions.alert]
type = "exec"
program = "/usr/local/sbin/fileguard-alert"
args = ["--path", "{path}", "--tgid", "{tgid}", "--operation", "{operation}"]
```

Available operation names:

`open`, `read`, `write`, `append`, `exec`, `getattr`/`stat`,
`create`/`mkdir`, `delete`/`unlink`/`rmdir`, `rename`/`move`, `all`.

`exec` action placeholders:

- `{path}`
- `{pid}`
- `{tgid}`
- `{uid}`
- `{gid}`
- `{operation}`
- `{decision}`
- `{comm}`


## Event path semantics

The userspace `{path}` placeholder is the configured rule path that matched.
For a recursive directory rule, it is therefore the policy root, not a
reconstructed pathname of the descendant object. The kernel-side matcher uses
inode identity deliberately and does not reconstruct path strings in the hot
path.

## Limits / caveats

1. The `vmlinux.rs` bindings are generated from BTF. Generate them on the
   kernel you are building against. Rust-native CO-RE field relocation is
   still an evolving area, so do not assume arbitrary-kernel binary
   portability from these generated structure offsets.
2. Recursive dentry ancestry is bounded at 32 parents.
3. A dentry ancestry walk does not cross a mount root; a recursive rule does
   not automatically flow into separately mounted filesystems below it.
4. Device+inode identity applies to the inode across hardlinks and multiple
   mounts of the same filesystem.
5. `file_permission` mediates normal read/write paths but mmap-based access is
   a separate LSM surface. Add `mmap_file`/`file_mprotect` hooks if that is a
   policy requirement.
6. The daemon ignores its own TGID to reduce self-deadlock risk. Children
   spawned as configured actions are not automatically exempt.
7. Side actions are asynchronous relative to the denied/allowed syscall.
