# Kagi 0.35.0 build validation

This file records what was and was not executable in the artifact-generation environment used to prepare this source edition.

## Source correction applied

The supplied v0.34 compiler log reports Rust error `E0308` in the cluster-host web-console log handler. The `if` branch ended with `lines.drain(...)`, so the branch evaluated to `std::vec::Drain<'_, String>` even though an `if` expression without an `else` must evaluate to `()`.

The 0.35.0 source changes that expression to a statement:

```rust
if lines.len() > st.web_console.max_log_lines {
    lines.drain(0..lines.len() - st.web_console.max_log_lines) ;
}
```

That directly addresses the type mismatch described by the supplied compiler output.

## Validation available in this environment

The packaging environment does **not** contain `cargo` or `rustfmt`. I therefore cannot truthfully mark the release as compiler-verified here.

The release-preparation pass does perform static checks that do not require the Rust toolchain:

- Cargo manifest parses as TOML.
- YAML examples parse as YAML where a YAML parser is available.
- Rust source delimiter/string/comment balance is checked.
- The Rust-aware readability reflow was checked for token preservation relative to the same source after the intentional semantic/name edits. One final `attr_raw` helper was then manually expanded from a single method chain into the same Option chain with named closure variables for readability.
- Shell scripts are checked with `bash -n`.
- Product-facing stale executable/path/header names are searched repository-wide.
- `MANIFEST.sha256` is regenerated after the final archive contents are fixed.

## Required compiler validation on a Rust builder

Run the repository suite before deployment:

```sh
./scripts/test-all
```

For release CI, use:

```sh
STRICT=1 ./scripts/test-all
```

On a CUDA-capable builder with `nvcc`, the script also checks/tests `--features cuda`.

A release should not be considered compiler-validated until the above suite succeeds on the target Rust toolchain.
