fn main() {
    if std::env::var_os("CARGO_FEATURE_CUDA").is_some() {
        println!("cargo:rerun-if-changed=cuda/erasure.cu");
        cc::Build::new()
            .cuda(true)
            .files(["cuda/erasure.cu", "cuda/montecarlo.cu"])
            .flag("-O3")
            .compile("keyspace_cuda");
        println!("cargo:rerun-if-changed=cuda/montecarlo.cu");
        println!("cargo:rustc-link-lib=cudart");
    }
    if std::env::var_os("CARGO_FEATURE_HIP").is_some() {
        println!("cargo:rerun-if-env-changed=ROCM_PATH");
        println!("cargo:rerun-if-env-changed=KAGI_HIP_ARCH");
        let rocm = std::env::var("ROCM_PATH").unwrap_or_else(|_| "/opt/rocm".into());
        let mut build = cc::Build::new();
        build
            .cpp(true)
            .compiler(format!("{rocm}/bin/hipcc"))
            .files(["hip/erasure.hip.cpp", "hip/montecarlo.hip.cpp"])
            .flag("-O3")
            .flag("-fPIC");
        if let Ok(arch) = std::env::var("KAGI_HIP_ARCH") {
            build.flag(format!("--offload-arch={arch}"));
        }
        build.compile("kagi_hip");
        println!("cargo:rerun-if-changed=hip/erasure.hip.cpp");
        println!("cargo:rerun-if-changed=hip/montecarlo.hip.cpp");
        println!("cargo:rustc-link-search=native={rocm}/lib");
        println!("cargo:rustc-link-lib=amdhip64");
    }
    if std::env::var_os("CARGO_FEATURE_OPENCL").is_some() {
        cc::Build::new()
            .cpp(true)
            .file("native/opencl.cpp")
            .flag("-O3")
            .compile("kagi_opencl");
        println!("cargo:rerun-if-changed=native/opencl.cpp");
        println!("cargo:rustc-link-lib=OpenCL");
    }
}
