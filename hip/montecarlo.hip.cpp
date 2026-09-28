#include <hip/hip_runtime.h>
#include <stdint.h>

__global__ void kagi_hip_readability_kernel(const uint8_t *alive, uint8_t *lost,
                                            uint64_t trials, uint32_t fragments,
                                            uint32_t mode, uint32_t k,
                                            uint32_t local_groups,
                                            uint32_t local_parity,
                                            uint32_t global_parity) {
  uint64_t t = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (t >= trials)
    return;
  const uint8_t *a = alive + t * fragments;
  bool readable = false;
  if (mode == 0) {
    readable = false;
    for (uint32_t i = 0; i < fragments; ++i)
      if (a[i]) {
        readable = true;
        break;
      }
  } else if (mode == 1) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < fragments; ++i)
      n += a[i] ? 1u : 0u;
    readable = n >= k;
  } else {
    if (local_groups == 0 || k % local_groups != 0) {
      lost[t] = 1;
      return;
    }
    uint32_t per = k / local_groups, deficit = 0, idx = 0;
    for (uint32_t g = 0; g < local_groups; ++g) {
      uint32_t survivors = 0, len = per + local_parity;
      for (uint32_t j = 0; j < len; ++j)
        survivors += a[idx + j] ? 1u : 0u;
      deficit += survivors < per ? per - survivors : 0;
      idx += len;
    }
    uint32_t gp = 0;
    for (uint32_t j = 0; j < global_parity; ++j)
      gp += a[idx + j] ? 1u : 0u;
    readable = deficit <= gp;
  }
  lost[t] = readable ? 0 : 1;
}

extern "C" int kagi_mc_readability_hip(const uint8_t *alive, uint8_t *lost,
                                       uint64_t trials, uint32_t fragments,
                                       uint32_t mode, uint32_t k,
                                       uint32_t local_groups,
                                       uint32_t local_parity,
                                       uint32_t global_parity) {
  if (!alive || !lost || trials == 0 || fragments == 0)
    return 1;
  uint8_t *d_alive = nullptr, *d_lost = nullptr;
  size_t alive_bytes = (size_t)trials * fragments;
  if (hipMalloc(&d_alive, alive_bytes) != hipSuccess)
    return 2;
  if (hipMalloc(&d_lost, (size_t)trials) != hipSuccess) {
    (void)hipFree(d_alive);
    return 3;
  }
  if (hipMemcpy(d_alive, alive, alive_bytes, hipMemcpyHostToDevice) !=
      hipSuccess) {
    (void)hipFree(d_alive);
    (void)hipFree(d_lost);
    return 4;
  }
  int threads = 256;
  int blocks = (int)((trials + threads - 1) / threads);
  kagi_hip_readability_kernel<<<blocks, threads>>>(
      d_alive, d_lost, trials, fragments, mode, k, local_groups, local_parity,
      global_parity);
  int rc = 0;
  if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess)
    rc = 5;
  else if (hipMemcpy(lost, d_lost, (size_t)trials, hipMemcpyDeviceToHost) !=
           hipSuccess)
    rc = 6;
  (void)hipFree(d_alive);
  (void)hipFree(d_lost);
  return rc;
}
