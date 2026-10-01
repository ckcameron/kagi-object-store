<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->
# Hardware and directory execution gates

`hardware-execution` is a manual workflow, never an untrusted pull-request job.
Use disposable dedicated runners labeled `self-hosted`, `linux` and
`kagi-<backend>`. Configure the `hardware-validation` environment with required
reviewers and restrict dispatch to reviewed revisions. Checkout does not persist
GitHub credentials. Each run uploads its execution log with the commit SHA.

Supported backend selections are CUDA, HIP, OpenCL, ISA-L, IPP, AOCL, eBPF and
directory. Install the corresponding SDK/runtime/library on its runner. GPU runs
set `KAGI_REQUIRE_GPU_TESTS=1`; CPU-library runs set
`KAGI_REQUIRE_CPU_LIB_TESTS=1`. Missing execution support fails those test modes;
compile success and CPU fallback do not establish accelerator execution.

The eBPF runner must expose kernel BTF and enable `bpf` in the LSM list, provide
BPF loading capabilities, `aya-tool`, `bpf-linker`, nightly Rust and rust-src.
The job generates target-kernel bindings, builds the object, attaches the real
LSM, checks child-process allow/deny, verifies a configured side action executes,
and confirms access returns after guard detach. Its policies target temporary
test files only. Missing prerequisites, failed attachment or absent side-action
delivery fail the run. Ordinary CI only compiles the userspace eBPF feature and
reports this execution test as ignored.

Directory runners use the explicit expected identity variables documented in
[DIRECTORY-IDENTITY.md](DIRECTORY-IDENTITY.md). Tests with no expected domain
identity cannot count as successful directory validation.

RDMA remains unavailable as a data backend. The development environment exposed
RDMA libraries but no RDMA device; no authenticated, portable transport could be
validated here. Configured RDMA preference falls through to the existing QUIC or
HTTPS path. Do not treat the Cargo feature or an advertised endpoint as an RDMA
execution claim. A future implementation requires device-backed correctness,
registration lifetime, disconnect/retry and authentication tests before enabling
selection. These constraints do not block portable builds.
