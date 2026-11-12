<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Testing and Coverage

## Fast validation

```sh
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets
```

For a warning-clean release gate, run `STRICT=1 scripts/test-all`; this promotes compiler/Clippy warnings to errors. The CUDA feature is intentionally separate because it requires an NVIDIA CUDA compiler/runtime:

```sh
cargo check --all-targets --features cuda
cargo test --all-targets --features cuda
```

## CI and coverage

The portable GitHub Actions matrix covers the default build, ISA-L/IPP/AOCL,
QUIC, the userspace eBPF loader, a combined feature build, and OpenCL. See
[hardware execution](HARDWARE-VALIDATION.md) for positive device or kernel tests
and [security validation](SECURITY-VALIDATION.md) for the supply-chain checks.

Install LLVM coverage support once:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

Then run:

```sh
scripts/coverage
```

Reports are written under `coverage/` as HTML and LCOV. Set `KAGI_COVERAGE_MIN_LINES` to a numeric percentage to make coverage generation fail below a required line-coverage threshold. Set `KAGI_COVERAGE_ALL_FEATURES=1` only on a machine with the development toolchains for the enabled GPU features.

## Test philosophy

Unit tests cover deterministic placement helpers, key-range boundaries, network multihoming behavior, disk-class AFR selection, mount normalization, erasure coding, ACL evaluation, virtual-volume geometry, SCSI persistent reservations, SCSI PR wire encoding/decoding, and physical storage-kind classification. Integration tests now cover authenticated PR CDB registration/reservation, persisted registration state, NBD stable-initiator forwarding, and reservation conflicts across block read/write/UNMAP endpoints. Remaining integration work includes multi-node Raft failure scenarios, joint-consensus membership churn, snapshot materialization interruption, recovery/rebalance under foreground load, and VM/CSI block-I/O tests.

## Monte Carlo tests

The test set covers the six-host/six-disk minimums, minimum failure-tolerance derivation, sequential quick-mode CIDR allocation, MDS-style two-loss readability, topology-bounded geometry generation, and deterministic two-host-loss validation for a 4+2 Reed-Solomon layout.


## Codec tests

The suite includes CPU reference tests for product-matrix MSR encode/reconstruct/exact repair, CLAY encode/decode/exact repair, linearized CLAY encode/decode equivalence, and distributed exact-repair plans. CUDA builds should additionally run `cargo test --all-targets --features cuda` on a host with nvcc and a compatible NVIDIA runtime. The CUDA path deliberately falls back to the CPU reference implementation on GPU errors rather than accepting unverified output.

## Warning and progress validation

Keep the default build warning-clean. Feature-specific production paths and
test helpers should use the configuration that owns them.

Recommended validation:

```bash
cargo check 2>&1 | tee cargo-check.txt
cargo test 2>&1 | tee cargo-test.txt
cargo clippy --all-targets 2>&1 | tee cargo-clippy.txt
cargo build --release 2>&1 | tee cargo-release.txt
```

Interactive progress should also be exercised on a real TTY:

```bash
cargo run --bin kagi-config -- --wizard --trials 10000 --rare-trials 10000
```

Verify that the terminal panel refreshes in place, simulation count increases during parallel trial loops, the best keyspace and EC rows change as candidates improve, and the final YAML remains valid. Also verify `--no-progress` and redirected stderr produce no ANSI progress panel.

## Planner and console validation

Test both normal and CUDA-capable builds when CUDA is available:

```sh
cargo test
cargo clippy --all-targets
cargo test --features cuda
cargo clippy --all-targets --features cuda
```

The web console has a unit test covering Argon2id user creation and HTTP Basic verification. Operator integration testing should additionally create a viewer and admin user, open `/ui` on at least two nodes, inspect a replicated object, create a bucket with WORM defaults, and verify local and cluster log views.

The CUDA Monte Carlo path should be compared against CPU mode with the same seed/topology. Because the GPU path accelerates readability evaluation after CPU topology/failure generation, loss counts for a fixed candidate should agree exactly for the same generated survival vectors.

## Checkpoints, acceleration, and scheduling

Run `scripts/test-checkpoint-resume target/debug/kagi-config` after building the
planner. It kills a running simulation, resumes it, compares it with a cold run
from the same manifest, and verifies corruption/conflicting-option rejection.

For optional paths, test with the desired features from
[ACCELERATION.md](ACCELERATION.md). Set `KAGI_REQUIRE_CPU_LIB_TESTS=1` when the
requested ISA-L, IPP or AOCL libraries must actually execute, and
`KAGI_REQUIRE_GPU_TESTS=1` when GPU fallback or a missing device must fail testing.
Do not combine required-library testing with an intentionally absent provider.
See [SCHEDULING.md](SCHEDULING.md) for policy and permission behavior.
