# Acceleration and CPU targeting

Kagi targets Intel and AMD x86-64. The default build keeps scalar fallbacks and
compiles AVX2 and AVX-512F/BW field-arithmetic routines into the same binary. CPU
and OS register-state detection guards specialized instructions. AVX10 processors
can use their compatible AVX-512 subsets; the GF(256) operation does not benefit
from unrelated floating-point or neural-network instructions. The field remains
0x11d: substituting the AES field used by some instructions would corrupt parity.

`scripts/kagi-build` defaults to a portable x86-64 release. Set `KAGI_CPU_TARGET`
to `native`, `avx2`, `avx512`, `avx10.1`, or `avx10.2` for a deliberately restricted
build. These builds require matching deployment CPUs, including in dependencies;
they are not made portable by Kagi's own runtime checks. AVX10 flags require a
compiler advertising that target feature. The tested Rust compiler still marks
AVX10 target flags as unstable; those restricted builds are experimental, and no
AVX10-capable processor was available for execution testing. ARM is not part of this release's
validation target.

## Compiled optional paths

| Cargo feature | Operation | Runtime behavior |
| --- | --- | --- |
| `cuda` | GF matrix transforms for encode/reconstruct/repair; planner readability batches | NVIDIA device; existing CUDA path remains preferred by automatic GPU selection |
| `hip` / `rocm` | The same field transforms and planner batches | HIP runtime and AMD device; `ROCM_PATH` defaults to `/opt/rocm`; `KAGI_HIP_ARCH=gfx1103` builds for Radeon 780M |
| `opencl` | The same field transforms and planner batches | An available GPU through the OpenCL ICD; this includes compatible Intel oneAPI OpenCL runtimes |
| `isa-l` | Bulk CPU GF matrix transforms | Loads `libisal.so.2` or `libisal.so`; public ISA-L entry points dispatch CPU instructions |
| `ipp` | Bulk CPU XOR rows | Loads `libipps.so` or `libipps.so.11`; IPP dispatches CPU instructions |
| `aocl` | Large source-row packing copies | Loads AOCL LibMem's `memcpy` resolver from `libaocl-libmem.so` |

The optional CPU libraries are resolved through the system dynamic loader. Set
`LD_LIBRARY_PATH` to their installed library directories where necessary. Absent
libraries use the built-in CPU implementation. GPU selection accepts `auto`,
`cpu`, `cuda`, `hip`, and `opencl` in runtime configuration and `--mc-backend`.
Automatic GPU preference is CUDA, then HIP, then OpenCL; this is a deterministic
preference, not a claim that the first backend wins every benchmark. Existing
transfer thresholds and inflight limits remain in force for erasure coding.
Explicit GPU failure retains the CPU fallback. Planner GPU failures are reported.

AOCC is a compiler, not a runtime offload API. Select its installed compiler with
`CXX=/opt/aocc/bin/clang++ scripts/kagi-build --features opencl` to compile the
OpenCL host shim with AOCC. An installed oneAPI C++ compiler can be selected the
same way. This does not substitute floating-point BLAS for finite-field coding,
or change the simulator's deterministic ChaCha random streams. There is no new
SYCL implementation in this release; oneAPI GPU execution uses its OpenCL ICD.

## Transfer and cryptography frameworks evaluated

cuObject is NVIDIA's object-storage transfer SDK, not a replacement for CUDA
compute. No cuObject, GPUDirect Storage, or GPUDirect RDMA path is enabled here:
Kagi's current transform boundary accepts host byte buffers, and its fragment
transport is authenticated HTTP. Introducing GPU staging merely to transfer
those buffers has no demonstrated advantage over the current CUDA path. A real
cuObject integration also needs the separate cuObjServer SDK and RDMA hardware,
which were not available for validation. These frameworks remain unimplemented,
not advertised as working integrations. Any future path must preserve Kagi's
policy, authentication, versioning and WORM checks and demonstrate a benefit.

QuickAssist was assessed for compression and cryptography. Kagi currently has no
matching compression stage to offload, and this release does not replace its
ChaCha20-Poly1305 storage format or Rust TLS provider to fit a QAT API. IPP's byte
operations are the implemented Intel library path. QAT is not integrated or
hardware-tested.

## Verification

Run the ordinary suite with the desired feature combination. GPU tests without
a device announce that execution was skipped. Require actual GPU execution with:

```sh
KAGI_REQUIRE_GPU_TESTS=1 KAGI_HIP_ARCH=gfx1103 \
  cargo test --features hip gpu_ -- --nocapture
```

A failed GPU operation must not count as accelerated validation. Test one GPU
feature at a time to identify the executing provider. The earlier host Radeon
780M result validated the underlying translated HIP kernels; it does not by
itself validate the newly integrated Rust paths. See BUILD-VALIDATION.md for
checks actually executed for this release.

## API references

- [Intel ISA-L finite-field coding](https://github.com/intel/isa-l/blob/master/doc/functions.md)
- [Intel IPP XOR API](https://www.intel.com/content/www/us/en/docs/ipp/developer-guide-reference/2021-12/xor-001.html)
- [AMD AOCL](https://www.amd.com/en/developer/aocl.html)
- [NVIDIA cuObject](https://docs.nvidia.com/gpudirect-storage/cuobject/index.html)
- [Intel QuickAssist cryptographic services](https://intel.github.io/quickassist/PG/services_cryptography_api.html)
