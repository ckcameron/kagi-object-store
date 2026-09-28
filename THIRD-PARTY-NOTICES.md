# Third-Party Notices

Kagi itself is proprietary and confidential under the repository `LICENSE`. Third-party dependencies retain their own copyright and license terms; the Kagi license does not replace or restrict those upstream rights.

## clay-codes

`clay-codes` 0.2.x, maintained at `https://github.com/spool-labs/clay`, is licensed under the Apache License, Version 2.0. Kagi uses it as the CPU reference implementation for CLAY encoding, decoding, and repair-map semantics.

## reed-solomon-erasure

`reed-solomon-erasure` is used by the Reed-Solomon compatibility/runtime backend and remains subject to its upstream license terms.

## Other Cargo dependencies

All other Cargo dependencies listed in `Cargo.toml` and resolved by Cargo remain subject to their respective upstream licenses. Distribution of a binary must comply with the notices and attribution requirements of those dependencies in addition to the proprietary Kagi license.

## argon2

Kagi uses the Rust `argon2` crate for Argon2id password hashing in the optional local web-console user database. See the crate distribution for its license terms.

## fileguard-rs and Aya

The supplied fileguard-rs archive is the source for `security/kagi-guard-common`,
`security/kagi-guard-ebpf`, and the Aya loader/action semantics adapted into Kagi.
Its Cargo manifests declare MIT OR Apache-2.0 and its BPF license section declares
Dual MIT/GPL; those declarations are retained. The supplied archive included no
separate LICENSE file. `security/FILEGUARD-UPSTREAM.md` preserves its original
README and caveats. Aya and aya-ebpf retain their upstream license terms.
