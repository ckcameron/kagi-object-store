<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->
# Runtime LRC v1

Set `cluster.erasure.scheme: lrc`. The persisted scheme, data-shard count `k` and
parity-shard count `m` fully specify the format. Old manifests still default to
Reed-Solomon; existing MSR/CLAY formats are unchanged.

LRC v1 contains `k` systematic data rows, `m-1` disjoint local XOR rows, and one
GF(256) global row. Data row `i` belongs to local group `i mod (m-1)`. The global
row uses coefficient `2^i` in Kagi's existing GF(256). Valid geometries require
`2 <= m <= k+1`, the existing total-shard bound, and no `repair_helpers` override.
The default `k=6,m=3` has local groups `{0,2,4}` and `{1,3,5}` plus global parity.

A single lost data or local-parity shard is repaired from its local group when
those helpers are available. Other repairs select an independent basis and apply
the decoded repair matrix. Reconstruction selects rows by rank, validates shard
sizes and recreates missing rows. LRC is not MDS: do not assume every set of `k`
survivors suffices. Writes require acknowledgement for every encoded LRC shard so
a successful initial write cannot silently leave an undecodable subset.

This reference CPU codec supports local helper reads through the existing exact
repair plan interface. Selecting a GPU does not count CPU LRC work as GPU
execution. Other existing accelerator paths retain their dispatch behavior.
Upgrade all readers before writing LRC objects. Changing the configured scheme
only affects new objects; reads use persisted layout metadata.

The topology planner supports a broader family of LRC geometries. Its output is
not automatically interchangeable with runtime LRC v1; verify geometry before
translating a planner recommendation. Tests enumerate all single and double
losses for 6+3, verify local helper selection, reject insufficient rank, persist
layout metadata, and exercise object read/repair/scrub after fragment loss.
