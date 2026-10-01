# Local dependency maintenance patch

Source: crates.io reed-solomon-erasure 6.0.0 (upstream MIT license retained).
The codec and persisted format are unchanged. Upgrade lru to >=0.18.2 for
RUSTSEC-2026-0253 and adapt its nonzero capacity argument; upgrade parking_lot
to 0.12 to remove the unmaintained instant dependency. Remove this patch when
an upstream release includes these dependency upgrades. Kagi codec round-trip,
reconstruction and exact-repair tests exercise the patched library.
