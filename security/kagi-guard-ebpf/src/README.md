# Kagi target-kernel bindings

`vmlinux.rs` is intentionally not bundled: generate Aya field bindings from the
BTF of the deployment kernel. From the Kagi repository root:

    make -C security bindings
    make -C security ebpf

See `docs/SECURITY-POLICY.md` for the loader, startup guarantees and kernel limits.
