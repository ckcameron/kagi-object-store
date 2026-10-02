// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Kagi GF(256) and protection-readability kernels; no object-format changes.
#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <vector>

static const char *source = R"CLC(
uchar gf(uchar a, uchar b) {
    uchar r=0;
    for(int bit=0;bit<8;++bit){if(b&1)r^=a; uchar hi=a&128;a<<=1;if(hi)a^=0x1d;b>>=1;}
    return r;
}
__kernel void matrix(__global const uchar *input,__global const uchar *coeff,
                     __global uchar *output,ulong inputs,ulong outputs,ulong width) {
    ulong x=get_global_id(0); if(x>=outputs*width)return;
    ulong row=x/width,column=x%width; uchar result=0;
    for(ulong i=0;i<inputs;++i)result^=gf(coeff[row*inputs+i],input[i*width+column]);
    output[x]=result;
}
__kernel void readable(__global const uchar *alive,__global uchar *lost,
                       ulong trials,uint fragments,uint mode,uint k,uint groups,uint local_parity,uint global_parity) {
    ulong t=get_global_id(0);if(t>=trials)return;
    __global const uchar *a=alive+t*fragments;uint count=0;
    for(uint i=0;i<fragments;++i)count+=a[i]!=0;
    if(mode==0){lost[t]=count==0;return;}
    if(mode==1){lost[t]=count<k;return;}
    uint missing=0,remaining=0,group_size=k/groups,index=0;
    for(uint g=0;g<groups;++g){uint survivors=0;
        for(uint j=0;j<group_size+local_parity;++j)survivors+=a[index+j]!=0;
        if(survivors<group_size)missing+=group_size-survivors;
        index+=group_size+local_parity;
    }
    for(uint j=0;j<global_parity;++j)remaining+=a[index+j]!=0;
    lost[t]=missing>remaining;
}
)CLC";
struct Runtime {
  std::mutex mutex;
  cl_context context = nullptr;
  cl_command_queue queue = nullptr;
  cl_program program = nullptr;
  Runtime() {
    cl_uint count = 0;
    if (clGetPlatformIDs(0, nullptr, &count) != CL_SUCCESS)
      return;
    std::vector<cl_platform_id> platforms(count);
    clGetPlatformIDs(count, platforms.data(), nullptr);
    for (size_t index = 0; index < platforms.size(); ++index) {
      const auto platform = platforms[index];
      cl_device_id device = nullptr;
      if (clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, nullptr) !=
          CL_SUCCESS)
        continue;
      cl_int error = 0;
      context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &error);
      if (error != CL_SUCCESS) {
        context = nullptr;
        continue;
      }
      queue = clCreateCommandQueue(context, device, 0, &error);
      if (error == CL_SUCCESS) {
        program =
            clCreateProgramWithSource(context, 1, &source, nullptr, &error);
        if (error == CL_SUCCESS &&
            clBuildProgram(program, 1, &device, "", nullptr, nullptr) ==
                CL_SUCCESS)
          return;
      }
      if (program)
        clReleaseProgram(program);
      if (queue)
        clReleaseCommandQueue(queue);
      clReleaseContext(context);
      program = nullptr;
      queue = nullptr;
      context = nullptr;
    }
  }
  ~Runtime() {
    if (program)
      clReleaseProgram(program);
    if (queue)
      clReleaseCommandQueue(queue);
    if (context)
      clReleaseContext(context);
  }
};
static Runtime &runtime() {
  static Runtime value;
  return value;
}
struct Buffer {
  cl_mem value = nullptr;
  ~Buffer() {
    if (value)
      clReleaseMemObject(value);
  }
};
struct Kernel {
  cl_kernel value = nullptr;
  ~Kernel() {
    if (value)
      clReleaseKernel(value);
  }
};
extern "C" int kagi_opencl_available() { return runtime().program != nullptr; }
extern "C" int kagi_opencl_matrix_apply(const uint8_t *input, size_t inputs,
                                        const uint8_t *coeff, size_t outputs,
                                        size_t width, uint8_t *output) {
  if (!input || !coeff || !output || !inputs || !outputs || !width)
    return 1;
  if (inputs > SIZE_MAX / width || outputs > SIZE_MAX / width ||
      inputs > SIZE_MAX / outputs)
    return 1;
  auto &rt = runtime();
  std::lock_guard<std::mutex> lock(rt.mutex);
  if (!rt.program)
    return 2;
  cl_int e = 0;
  Buffer a, b, c;
  Kernel kernel;
  a.value = clCreateBuffer(rt.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                           inputs * width, const_cast<uint8_t *>(input), &e);
  if (e)
    return 3;
  b.value = clCreateBuffer(rt.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                           inputs * outputs, const_cast<uint8_t *>(coeff), &e);
  if (e)
    return 3;
  c.value = clCreateBuffer(rt.context, CL_MEM_WRITE_ONLY, outputs * width,
                           nullptr, &e);
  if (e)
    return 3;
  kernel.value = clCreateKernel(rt.program, "matrix", &e);
  if (e)
    return 4;
  cl_ulong ni = inputs, no = outputs, w = width;
  e = clSetKernelArg(kernel.value, 0, sizeof(cl_mem), &a.value);
  e |= clSetKernelArg(kernel.value, 1, sizeof(cl_mem), &b.value);
  e |= clSetKernelArg(kernel.value, 2, sizeof(cl_mem), &c.value);
  e |= clSetKernelArg(kernel.value, 3, sizeof(ni), &ni);
  e |= clSetKernelArg(kernel.value, 4, sizeof(no), &no);
  e |= clSetKernelArg(kernel.value, 5, sizeof(w), &w);
  if (e)
    return 4;
  size_t work = outputs * width;
  e = clEnqueueNDRangeKernel(rt.queue, kernel.value, 1, nullptr, &work, nullptr,
                             0, nullptr, nullptr);
  if (e)
    return 5;
  return clEnqueueReadBuffer(rt.queue, c.value, CL_TRUE, 0, work, output, 0,
                             nullptr, nullptr) == CL_SUCCESS
             ? 0
             : 6;
}
extern "C" int kagi_mc_readability_opencl(const uint8_t *alive, uint8_t *lost,
                                          uint64_t trials, uint32_t fragments,
                                          uint32_t mode, uint32_t k,
                                          uint32_t groups,
                                          uint32_t local_parity,
                                          uint32_t global_parity) {
  if (!alive || !lost || !trials || !fragments ||
      trials > SIZE_MAX / fragments || mode > 2)
    return 1;
  if (mode == 2 &&
      (!groups || k % groups ||
       uint64_t(k) + uint64_t(groups) * local_parity + global_parity !=
           fragments))
    return 1;
  auto &rt = runtime();
  std::lock_guard<std::mutex> lock(rt.mutex);
  if (!rt.program)
    return 2;
  cl_int e = 0;
  Buffer a, b;
  Kernel kernel;
  a.value =
      clCreateBuffer(rt.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                     trials * fragments, const_cast<uint8_t *>(alive), &e);
  if (e)
    return 3;
  b.value = clCreateBuffer(rt.context, CL_MEM_WRITE_ONLY, trials, nullptr, &e);
  if (e)
    return 3;
  kernel.value = clCreateKernel(rt.program, "readable", &e);
  if (e)
    return 4;
  cl_ulong n = trials;
  e = clSetKernelArg(kernel.value, 0, sizeof(cl_mem), &a.value);
  e |= clSetKernelArg(kernel.value, 1, sizeof(cl_mem), &b.value);
  e |= clSetKernelArg(kernel.value, 2, sizeof(n), &n);
  uint32_t values[] = {fragments, mode, k, groups, local_parity, global_parity};
  for (int i = 0; i < 6; ++i)
    e |= clSetKernelArg(kernel.value, 3 + i, sizeof(uint32_t), &values[i]);
  if (e)
    return 4;
  size_t work = trials;
  e = clEnqueueNDRangeKernel(rt.queue, kernel.value, 1, nullptr, &work, nullptr,
                             0, nullptr, nullptr);
  if (e)
    return 5;
  return clEnqueueReadBuffer(rt.queue, b.value, CL_TRUE, 0, trials, lost, 0,
                             nullptr, nullptr) == CL_SUCCESS
             ? 0
             : 6;
}
