// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0. HIP GF(2^8) matrix engine shared by RS, product-matrix MSR,
// and CLAY.
#include <hip/hip_runtime.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

// GF(2^8), primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
__device__ __forceinline__ uint8_t hip_gf_mul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
#pragma unroll
  for (int i = 0; i < 8; ++i) {
    if (b & 1)
      r ^= a;
    const bool hi = (a & 0x80) != 0;
    a <<= 1;
    if (hi)
      a ^= 0x1d;
    b >>= 1;
  }
  return r;
}

// One block owns one output row and 256 byte columns.  The coefficients for
// each 256-row input tile are staged once in shared memory and reused by all
// byte-column threads in the block.
__global__ void kagi_hip_matrix_kernel(const uint8_t *__restrict__ input,
                                       size_t in_rows,
                                       const uint8_t *__restrict__ coeff,
                                       size_t out_rows, size_t row_len,
                                       uint8_t *__restrict__ output) {
  const size_t out_row = (size_t)blockIdx.y;
  const size_t byte = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (out_row >= out_rows)
    return;

  __shared__ uint8_t tile_coeff[256];
  uint8_t acc = 0;
  for (size_t base = 0; base < in_rows; base += 256) {
    const size_t idx = base + threadIdx.x;
    tile_coeff[threadIdx.x] =
        idx < in_rows ? coeff[out_row * in_rows + idx] : 0;
    __syncthreads();
    if (byte < row_len) {
      const size_t count = (in_rows - base) < 256 ? (in_rows - base) : 256;
      for (size_t j = 0; j < count; ++j) {
        const uint8_t c = tile_coeff[j];
        if (c == 1)
          acc ^= input[(base + j) * row_len + byte];
        else if (c != 0)
          acc ^= hip_gf_mul(c, input[(base + j) * row_len + byte]);
      }
    }
    __syncthreads();
  }
  if (byte < row_len)
    output[out_row * row_len + byte] = acc;
}

extern "C" int kagi_hip_available() {
  int n = 0;
  return hipGetDeviceCount(&n) == hipSuccess && n > 0;
}

// Per-host-thread scratch storage avoids hipMalloc/hipFree and stream creation
// on every object/chunk transform. Tokio may schedule work on several OS
// threads; each thread therefore gets an independent stream and grow-only
// device buffers.
struct KagiHipScratch {
  hipStream_t stream = nullptr;
  uint8_t *input = nullptr;
  uint8_t *coeff = nullptr;
  uint8_t *output = nullptr;
  size_t input_cap = 0;
  size_t coeff_cap = 0;
  size_t output_cap = 0;

  int init() {
    if (stream)
      return 0;
    return hipStreamCreateWithFlags(&stream, hipStreamNonBlocking) == hipSuccess
               ? 0
               : 11;
  }
  int reserve(uint8_t **ptr, size_t *cap, size_t need) {
    if (*cap >= need)
      return 0;
    if (*ptr) {
      (void)hipFree(*ptr);
      *ptr = nullptr;
      *cap = 0;
    }
    if (hipMalloc(reinterpret_cast<void **>(ptr), need) != hipSuccess)
      return 12;
    *cap = need;
    return 0;
  }
  ~KagiHipScratch() {
    if (input)
      (void)hipFree(input);
    if (coeff)
      (void)hipFree(coeff);
    if (output)
      (void)hipFree(output);
    if (stream)
      (void)hipStreamDestroy(stream);
  }
};

static thread_local KagiHipScratch keyspace_scratch;

extern "C" int kagi_hip_matrix_apply(const uint8_t *input, size_t in_rows,
                                     const uint8_t *coeff, size_t out_rows,
                                     size_t row_len, uint8_t *output) {
  if (!input || !coeff || !output || !in_rows || !out_rows || !row_len)
    return 10;
  if (in_rows > SIZE_MAX / row_len || out_rows > SIZE_MAX / row_len ||
      in_rows > SIZE_MAX / out_rows)
    return 16;
  // HIP grid.y is 65535 on the devices this backend targets. Larger transforms
  // fail closed and are executed by the CPU reference path.
  if (out_rows > 65535)
    return 17;
  const size_t blocks_x = row_len / 256 + (row_len % 256 != 0);
  if (blocks_x == 0 || blocks_x > INT_MAX)
    return 18;
  const size_t input_bytes = in_rows * row_len;
  const size_t coeff_bytes = in_rows * out_rows;
  const size_t output_bytes = out_rows * row_len;

  int rc = keyspace_scratch.init();
  if (rc)
    return rc;
  if ((rc = keyspace_scratch.reserve(&keyspace_scratch.input,
                                     &keyspace_scratch.input_cap, input_bytes)))
    return rc;
  if ((rc = keyspace_scratch.reserve(&keyspace_scratch.coeff,
                                     &keyspace_scratch.coeff_cap, coeff_bytes)))
    return rc;
  if ((rc = keyspace_scratch.reserve(&keyspace_scratch.output,
                                     &keyspace_scratch.output_cap,
                                     output_bytes)))
    return rc;

  hipStream_t stream = keyspace_scratch.stream;
  // Drain submitted work on every return path before borrowed host buffers
  // expire.
  struct StreamDrain {
    hipStream_t value;
    ~StreamDrain() { (void)hipStreamSynchronize(value); }
  } drain{stream};
  if (hipMemcpyAsync(keyspace_scratch.input, input, input_bytes,
                     hipMemcpyHostToDevice, stream) != hipSuccess ||
      hipMemcpyAsync(keyspace_scratch.coeff, coeff, coeff_bytes,
                     hipMemcpyHostToDevice, stream) != hipSuccess)
    return 13;

  const dim3 block(256, 1, 1);
  const dim3 grid((unsigned)blocks_x, (unsigned)out_rows, 1);
  kagi_hip_matrix_kernel<<<grid, block, 0, stream>>>(
      keyspace_scratch.input, in_rows, keyspace_scratch.coeff, out_rows,
      row_len, keyspace_scratch.output);
  if (hipGetLastError() != hipSuccess)
    return 14;
  if (hipMemcpyAsync(output, keyspace_scratch.output, output_bytes,
                     hipMemcpyDeviceToHost, stream) != hipSuccess ||
      hipStreamSynchronize(stream) != hipSuccess)
    return 15;
  return 0;
}
