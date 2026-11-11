<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi target-kernel bindings

`vmlinux.rs` is intentionally not bundled: generate Aya field bindings from the
BTF of the deployment kernel. From the Kagi repository root:

    make -C security bindings
    make -C security ebpf

Use the BPF object built for the deployment kernel with the userspace
`kagi-cluster-host` binary built with `--features ebpf`. Set
`security.kernel.object` to the built ELF path in the node configuration.
See [security policy and monitoring](../../../docs/SECURITY-POLICY.md#configuration-and-build)
for loader prerequisites and kernel limits.
