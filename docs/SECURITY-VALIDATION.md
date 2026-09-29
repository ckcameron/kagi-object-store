<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Security, undefined-behavior, and exploit validation

Kagi treats "security testing" as several independent layers. Passing one layer is not
evidence that the others are clean.

## Fast developer gate

Run:

```bash
bash scripts/kagi-security-check quick
```

This checks formatting, default tests, strict Clippy, and the QUIC/eBPF feature builds. It is
intended to run before every push.

## Deep robustness gate

Run:

```bash
KAGI_INSTALL_TOOLS=1 bash scripts/kagi-security-check deep
```

The deep gate adds:

- **RustSec / dependency policy** — `cargo audit` and `cargo deny` check known vulnerable,
  yanked, or unexpected dependency sources.
- **Unsafe-code inventory** — `cargo geiger` records where unsafe Rust and FFI enter the
  dependency graph. A nonzero count is not automatically a defect; it tells reviewers where
  UB-capable code exists.
- **Miri** — interprets pure frame/arithmetic invariants with Rust's UB checker. Miri is most
  useful for aliasing, invalid references, out-of-bounds access, uninitialized values, and
  invalid unsafe contracts. SIMD, kernel, device, and foreign-library paths require native
  sanitizers instead.
- **AddressSanitizer** — catches native memory corruption/use-after-free/stack and heap errors
  in executed Rust/FFI paths.
- **ThreadSanitizer** — checks executed native paths for data races. It runs in scheduled/manual
  CI because it is substantially slower and may expose scheduler-sensitive failures.
- **libFuzzer** — continuously mutates untrusted QUIC frame lengths and erasure-code inputs.
  The wire target asserts that untrusted 64-bit lengths never wrap into unsafe allocations;
  the erasure target asserts successful single-shard reconstruction for every accepted layout.
- **CUDA Compute Sanitizer** — `bash scripts/kagi-gpu-sanitize` runs memcheck, racecheck,
  initcheck, and synccheck on an NVIDIA host. GPU CI without a real CUDA device must not be
  counted as CUDA execution validation.

GitHub's `.github/workflows/security.yml` runs the portable parts automatically. Sanitizer,
Miri, fuzz, and dependency results should be treated as release evidence rather than a one-time
development check.

## Unexpected-behavior checks

Correctness bugs that are not language-level UB require different tests. Kagi's release gate
should include:

1. deterministic/property tests for coding, placement, durability math, request authentication,
   WORM rules, replay windows, and frame-size limits;
2. fault injection around partial writes, process death, short reads, checksum mismatch, peer
   timeout, duplicate/reordered requests, stale Raft terms, disk disappearance, and repair
   interruption;
3. malformed-input and state-machine fuzzing for every network/control protocol;
4. restart/recovery tests that compare pre-crash and post-recovery manifests and checksums;
5. repeated concurrency tests under ThreadSanitizer and high scheduler contention;
6. kernel eBPF verifier/load tests on supported kernels, not only userspace feature compilation.

A panic, timeout, deadlock, silent fallback, unexpected allocation spike, or accepted invalid
state counts as an unexpected-behavior failure even if no memory-safety defect is present.

## Exploit-oriented review

For externally reachable code, reviewers should explicitly test:

- authentication bypass and missing authorization on alternate transports;
- replay, reordering, downgrade, and cross-cluster request confusion;
- oversized length/allocation attacks and decompression/expansion bombs;
- path traversal or namespace confusion;
- integer overflow in offsets, lengths, erasure dimensions, and block ranges;
- resource exhaustion: connections, QUIC streams, GPU queues, memory registration, repair jobs,
  event subscribers, log/history retention, and file descriptors;
- malformed certificates, TLS downgrade attempts, 0-RTT replay, and trust-store mistakes;
- unsafe FFI lifetime violations around CUDA/HIP/OpenCL/RDMA/FHE buffers;
- eBPF policy bypasses through mmap, hardlinks, mount boundaries, rename, or unsupported hooks;
- unauthorized disk scheduler/cache changes and persistence assumptions.

Kagi's QUIC implementation keeps 0-RTT disabled and carries the existing ML-DSA request
envelope plus cluster admission proof on every fragment request. Alternate transports must
continue to satisfy that same application-level authorization boundary.

## Performance toolset

`kagi-bench` measures in-memory object coding/reconstruction and verifies correctness for each
timed sample:

```bash
cargo run --release --bin kagi-bench -- \
  --backend cpu --scheme all --sizes 1MiB,8MiB,64MiB --iterations 5 \
  --json validation/performance/manual.json
```

For a native-optimized demonstration with JSON, Linux hardware counters, and Criterion
statistical microbenchmarks:

```bash
bash scripts/kagi-perf-demo
```

Useful comparisons include portable vs `KAGI_CPU_TARGET=native`, CPU vs available GPU backend,
and feature sets such as ISA-L/AOCL. A backend is not considered accelerated merely because it
compiled; use the benchmark report's acceleration status and byte counters to confirm that work
actually executed on the requested path.

Performance tests must run separately from correctness/security acceptance: faster results never
justify accepting a failed checksum, reconstruction mismatch, sanitizer finding, authorization
failure, or fallback that the operator did not request.
