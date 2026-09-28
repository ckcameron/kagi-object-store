SHELL := /bin/bash
.PHONY: bindings ebpf fmt
bindings:
	@command -v aya-tool >/dev/null || { echo "aya-tool is required: cargo install aya-tool" >&2; exit 1; }
	aya-tool generate file inode super_block dentry path linux_binprm > kagi-guard-ebpf/src/vmlinux.rs.tmp
	mv kagi-guard-ebpf/src/vmlinux.rs.tmp kagi-guard-ebpf/src/vmlinux.rs

ebpf:
	cargo +nightly build -p kagi-guard-ebpf --target bpfel-unknown-none -Z build-std=core --release

fmt:
	rustfmt --edition 2024 --config skip_children=true kagi-guard-ebpf/src/main.rs kagi-guard-common/src/lib.rs kagi-guard-common/src/types.rs
