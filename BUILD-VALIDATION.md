<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi 0.39 development build validation

Current completion-branch evidence is recorded below. The 0.38 results are historical.

## Historical 0.38 validation

**Experimental development release; not production-ready.**

Validated on 2026-09-28 on x86-64 Linux, using Rust/Cargo 1.99.0-beta.7,
CUDA compiler 13.4.92, installed ROCm/HIP, and AMD Ryzen 7 8745HS / Radeon 780M.
AVX2 and AVX-512F/BW are exposed by this CPU. Earlier release evidence is retained
under `validation/v36/` and `validation/BUILD-VALIDATION-v35.md`; those records
are historical, not claims about this release.

## Executed checks

| Check | Result |
| --- | --- |
| Rust formatting | Pass |
| All targets, all features: `cargo check` | Pass; six inherited unused-code warnings in the optional SCSI frontend |
| Default tests | 77 passed |
| All-feature tests, including CUDA + HIP linked together | 84 reported passed; three GPU tests and one IPP test explicitly returned without hardware/library execution |
| Strict Clippy, default | Pass |
| Strict Clippy, `cuda,hip,opencl,isa-l,ipp,aocl,ebpf` | Pass |
| Strict Clippy, literally all features | Fails on the six inherited `scsi-target` unused-code warnings; no suppression was added for that frontend |
| Actual ISA-L and AOCL library tests with execution required | 2 passed; absent-library fallback cannot satisfy this test mode |
| AVX2 and AVX-512 arithmetic | Both executed; exhaustive byte/coefficient comparisons, unaligned slices and tails passed |
| OpenCL C 1.2 kernel syntax | Pass without a device |
| AOCC compilation of OpenCL host shim | Pass after avoiding an incompatible GCC 16 iterator instantiation |
| oneAPI host compiler attempt | Unavailable: installed `icx-cc` cannot find `/opt/intel/oneapi/compiler/2026.0/bin/clang` |
| AVX10.1 and AVX10.2 compiler probes | Accepted with unstable-target-feature warnings; execution not tested |
| Required-GPU execution probe | Explicit failure: no compiled backend exposes an available device in this sandbox |
| Planner interruption and resume | Pass: kill after committed batches, resume, compare byte-for-byte with a cold run from the same manifest; key stability, corruption rejection and conflicting-option rejection also passed |
| Process scheduling | Normal and round-robin priority 1 launched successfully and read back correctly; invalid priorities rejected before command execution |
| Binary names/version | `kagi-config 0.38.0` and `kagi-run 0.38.0` |

Raw logs are in `validation/v38/`. The final resume test also starts with relative
output paths and resumes from a different working directory. Checkpoint output
paths are saved as absolute paths. The reducer bounds its in-memory batch-result
window and retains identical global reduction order across worker counts.

ISA-L was built in the workspace solely for validation from upstream commit
`ebcec1aea3239108a67cc6309aaaeed6211fed89`. Its source and binaries are not bundled
in this release. AOCL was tested against the existing local installation. IPP
was not installed: its integration compiled and its absence/fallback path ran,
but the IPP function itself was not execution-tested.

## Scope and limitations

The release implements checkpoint/resume, the `kagi-config` rename, runtime
AVX2/AVX-512 dispatch, experimental restricted AVX10 build flags, HIP/ROCm and
OpenCL kernels, optional ISA-L/IPP/AOCL operations, AOCC compiler selection, and
the opt-in `kagi-run` scheduler launcher.

The existing CUDA path remains first in automatic GPU selection. No performance
ranking is claimed between new providers. The previous user-supplied host report
validated the translated HIP kernels on Radeon 780M; it does not establish
execution of this release's complete Rust GPU integration. This sandbox cannot
provide that GPU validation, and the required-GPU probe fails rather than
counting CPU fallback as a successful GPU run.

cuObject, GPUDirect Storage, GPUDirect RDMA and QuickAssist are **not implemented**.
The present host-buffer/HTTP architecture has no demonstrated cuObject advantage
over its current CUDA path; separate server SDK/RDMA execution prerequisites
were unavailable. No storage cipher or format was changed to fit QAT. Intel
oneAPI interoperability currently means a compatible OpenCL ICD and optional
host compiler selection; there is no separate SYCL kernel implementation.
See `docs/ACCELERATION.md` for the precise boundaries.

The eBPF userspace feature compiles/tests with the release. Kernel object build,
LSM attachment and enforcement still require generated target-kernel bindings,
BPF build tools and an appropriate test kernel; these were not executed here.
The new source archive contains source and evidence, not installed services,
secrets, build caches or third-party SDK binaries. No system services, kernel
settings or permanent scheduling policy were changed.

## Licensing-only update (2026-09-28)

Source comments, package license metadata, and documentation were updated to CC BY-NC-SA 4.0, preserving upstream security licenses. No executable statements were changed. Rust formatting, package metadata, notice coverage, and distribution checksums were checked for this update; runtime results above refer to the preceding development build.

## 0.39 completion status (2026-09-30)

This checklist distinguishes implemented runtime behavior from planner-only, integration-boundary,
and hardware-dependent work. A feature is not promoted to runtime-complete merely because its
configuration type or protocol structure exists.

| Area | Current status | 0.39 completion requirement |
| --- | --- | --- |
| Replication/object data path | Runtime complete | Keep end-to-end write/read/repair/scrub CI coverage green. |
| Reed-Solomon | Runtime complete | Maintain encode/reconstruct tests. |
| Product-matrix MSR | Runtime complete | Maintain round-trip and exact-repair tests. |
| CLAY | Runtime complete | Maintain round-trip, exact-repair, and partial-helper-read tests. |
| LRC | Runtime implemented, validation in progress | Fixed v1 local-XOR/global-parity geometry, persisted scheme, rank-aware reconstruction and repair. See docs/LRC.md; planner geometry is broader. |
| S3 compatibility | Experimental core API | Signature authentication, bucket/object/list/multipart operations and independent signed HTTP tests. See docs/S3.md for supported semantics and limits; full SDK conformance remains outstanding. |
| Native Kagi REST object API | Runtime complete | Maintain object/version/metadata routes and linearizable mutation behavior. |
| Fragment encryption at rest | Runtime complete | Maintain chunked-AEAD round-trip, tamper/identity, and cross-chunk range tests. |
| At-rest key rotation | Keyring envelopes implemented | Generation-tagged fragments and metadata, legacy reads, authenticated chunk ranges. Migration and key retirement require operator verification; see docs/AT-REST-ROTATION.md. |
| ML-DSA internal authentication | Runtime complete | Maintain signed-envelope/replay validation and key rotation/revocation tests. |
| Strict end-to-end PQ-only operation | Partial | Remove/segregate classical compatibility paths and define PQ certificate/key-management requirements before making this claim. |
| Raft metadata and membership | Runtime complete | Add/maintain multi-node failure/restart/joint-consensus integration tests. |
| Snapshots/archive/GC | Runtime implemented | Expand crash/restart and multi-node integration tests for archive and destructive GC fencing. |
| Filesystem namespace/NFSv4-style ACL model | Runtime implemented | Expand namespace transaction/rebuild integration coverage. |
| Active Directory | Native NSS resolution with external directory providers | User/group lookup uses NSS (including configured SSSD/winbind), with optional winbind SID expansion. LDAP binds and Kerberos authentication remain provider responsibilities. See docs/DIRECTORY-IDENTITY.md. |
| NVMe/SATA/SAS storage | Runtime implemented | Validate against representative physical devices. |
| Fibre Channel | Integration boundary | Validate Linux-visible FC LUN discovery/admission; a native FC protocol stack is out of scope unless explicitly required. |
| NBD/QEMU/libvirt block frontend | Runtime/integration implemented | Add VM-level persistence/restart tests. |
| VMware/Hyper-V | Integration boundary | Validate supported iSCSI/image workflows on those hypervisors before claiming native integration. |
| SCSI-3 PR | Runtime implemented | Clear all-feature `scsi-target` strict-Clippy warnings and add frontend-level reservation conflict tests. |
| CUDA/HIP/OpenCL/ISA-L/IPP/AOCL | Hardware/library dependent | Require execution-marked tests on matching CI runners; fallback/compile-only runs do not count as accelerator validation. |
| eBPF/LSM security | Kernel-dependent | Build, attach, exercise allow/deny and side actions on a supported kernel in privileged CI. |
| Web operations console | Runtime implemented | Add browser/API integration tests for auth, object inspection, logs, buckets and WORM controls. |
| QUIC | Runtime optional | Maintain feature CI and add multi-node transfer/failure/fallback integration coverage. |
| RDMA | Policy surface only | Implement a functional backend before advertising RDMA data movement. |

### Release gate

For 0.39, the repository should not describe planner-only or integration-boundary behavior as a
native runtime implementation. Hardware-dependent paths require positive execution evidence on
appropriate runners. The standard Rust CI passing is necessary but not sufficient for those
claims.

### Completion-branch validation evidence

Validated locally on x86-64 Linux with Rust/Cargo 1.99.0-beta.7:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --all-targets` | Passed |
| `cargo test --all-targets` | 125 passed; one real-directory test intentionally ignored |
| `cargo test --all-targets --features quic,ebpf,scsi-target,rdma` | 128 passed; real-directory and privileged LSM tests intentionally ignored |
| `cargo clippy --all-targets -- -D warnings` | Passed |
| `cargo clippy --all-targets --all-features -- -D warnings` | Passed |
| `cargo check --all-targets --all-features` | Passed |
| `cargo test --all-targets --all-features` | 140 reported passed; two ignored provider/kernel tests; accelerator fallback is not execution evidence |
| `cargo audit` | Passed with no advisory warnings |
| `cargo deny check advisories sources` | Passed without advisory exceptions |
| Repository CI/security workflow | Miri, ASan and supply-chain jobs passed on initial PR revision; fuzz and final CI still pending |

The S3 integration test uses curl's independent SigV4 implementation against the
actual HTTP service, including bucket/object operations, multipart completion,
persisted upload state, and authentication/authorization failures. Additional
passing tests cover generation selection and legacy ciphertext, runtime LRC object
repair, concurrent Raft proposals and joint-majority rejection, snapshot archive
replay/GC fences, console role enforcement and persisted buckets, SCSI CDB conflicts
and persisted registrations, and actual TLS QUIC transfers and failures.

Local QUIC validation uses the system OpenSSL on PATH: the unrelated installation
in /usr/local/bin cannot load its libompstub.so dependency on this machine.

The manual hardware workflow requires matching protected runners and records
positive execution evidence. No GPU, LSM attachment, or directory-provider
execution is claimed by fallback or ignored tests. RDMA remains unavailable,
with a configuration audit finding and HTTPS/QUIC transport as the fallback.
Native LDAP binds/Kerberos authentication, full S3 SDK conformance, and VM-level
block persistence tests remain integration boundaries or further validation work.

Raw local logs are retained under `validation/v39/`. The required-execution probes
correctly fail for unavailable GPU devices, ISA-L and IPP in this environment;
AOCL's copy test executed and passed. These are explicit environment limitations,
not waived passing hardware results. The expanded signed S3 test also verifies
206/416 ranges, failed conditional writes, checksum rejection with no object
published, unsupported ACL rejection, and multipart listings.
