# Kagi 0.36.0 build validation

Validated 2026-09-28 UTC using Cargo 1.99.0-beta.7 and rustc
1.99.0-beta.7 on x86_64 Linux. The original v35 archive first passed a baseline
`cargo check --offline`. Prior release records remain in the tree, including
`validation/BUILD-VALIDATION-v35.md`; they describe their original environments.

## Final executed checks

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --all-targets --locked` | PASS |
| `cargo test --all-targets --locked` | PASS: 70 tests |
| `cargo check --all-targets --features ebpf --locked` | PASS |
| `cargo test --all-targets --features ebpf --locked` | PASS: 71 tests |
| `cargo clippy --all-targets --locked -- -D warnings` | PASS |
| `cargo clippy --all-targets --features ebpf --locked -- -D warnings` | PASS |
| `cargo check --all-targets --features cuda --locked` | PASS, one inherited unused `gpu_repairs` field warning |
| `cargo test --all-targets --features cuda --locked` | PASS: 73 test functions; three GPU-specific functions return early without a usable device |
| Audit CLI against `examples/node-v6.example.yaml` | PASS, JSON findings emitted without starting the server |
| Shell syntax, Cargo TOML and example YAML parsing | PASS |
| Separate BPF source rustfmt | PASS |

Exact command arrays and exit codes are in `validation/results.json`. Complete
compiler/test/Clippy logs, the audit smoke-test output, and static-check output are
included under `validation/`. Dependencies were fetched into an isolated writable
Cargo cache because the existing user cache is read-only in this environment.
The ordinary and separate BPF workspace lockfiles are included.

## Regression coverage

New tests cover bounded history and gap detection, live delivery, deny precedence,
privileged-only rules, slash-boundary matching, safe single-pass argument
substitution, actual asynchronous exec actions for both allow and deny, invalid
operations/actions, kernel device encoding, and twenty/fractional-nines formatting.
A real local HTTP-router test exercises encoded keys, historical and snapshot
routes, metadata routes, privileged marking authentication, unauthenticated monitor
rejection, authenticated history, and SSE replay. Existing Raft, ACL, erasure,
repair, WORM, block, PQ and topology tests remain in the suite.

The available CUDA feature build exposed an inherited planner E0425 error:
`evaluate` accepted `_backend` but its CUDA branch referenced `backend`. The branch
now references the actual argument. CUDA source compilation and linking succeeded.
`cudaGetDeviceCount` returned status 35 and zero devices, so GPU execution itself
was not verified; the upstream CUDA tests intentionally return early in that case.

## Separate kernel build and live enforcement: not validated here

The Aya userspace adapter compiles and its tests pass. This does not establish
that the BPF object passes a deployment kernel's verifier or enforces real syscalls.

- `make -C security bindings` failed because `aya-tool` is not installed.
- `make -C security ebpf` failed because nightly Rust is not installed and rustup
  could not create a download temporary file in its read-only home.
- `bpf-linker` is not installed. Target-kernel `vmlinux.rs` is intentionally absent.
- Kernel BTF and a `bpf` LSM entry are present, but no BPF policies were attached
  to the user's running system. No live allow/deny, ancestry, rename or signal
  enforcement claim is made for this environment.

Raw failures are recorded in `validation/kernel-bindings.txt` and
`validation/kernel-build.txt`. Build the bundled BPF program and exercise all
configured hooks in a disposable target-kernel test environment before deployment.
The daemon refuses to start when kernel protection is enabled but cannot load or
attach. Kernel protection remains off in the example until explicitly enabled.

## Release provenance

The authoritative continuation was the supplied shared conversation:
https://chatgpt.com/s/cx_6ab9ffe2d13c819181fe619f116c0023
It recorded that the preceding model was blocked on missing archives; it contained
no later integrated source to resume. This release starts with the actual v35 tree
and adapts the supplied fileguard source, retaining the previous architecture,
release history and kernel/userspace decision boundary.

Input SHA-256:

- `kagi-v35.tar.gz`: `17afb4a674330ee2630a5cd360a90e801271c4c7ad07b2ef5d67d12fb1d9ac7e`
- `fileguard-rs.zip`: `a58fc0139455a3a4ee24cb3ccb42bf95e0ca7a69d8b241259a8bae257a9d90ae`

`MANIFEST.sha256` covers every shipped file except itself. Build targets, dependency
caches, generated secrets, and scratch files are excluded from the source archive.
