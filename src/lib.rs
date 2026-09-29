// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Reusable Kagi core modules.
//!
//! The binaries keep their existing composition roots, while this library surface exposes
//! deterministic compute components to benchmark, fuzz, Miri, and sanitizer harnesses.

pub mod erasure;

pub mod wire;
