# Kagi 0.38.0 development build validation

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
