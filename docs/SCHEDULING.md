<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Explicit process scheduling

`kagi-run` launches any command, including `kagi-config`, with an explicitly
selected Linux scheduler. Normal scheduling is the default. Arguments following
`--` are passed directly to the executable, without shell interpretation.

```sh
kagi-run --policy normal -- kagi-config --resume simulation.save
kagi-run --policy round-robin --priority 10 --cpus 2,3,4 -- kagi-config --config topology.yaml
kagi-run --policy fifo --priority 10 -- kagi-cluster-host --config node.yaml serve
```

Real-time policies require priority 1–99 and permission through `RLIMIT_RTPRIO`
or `CAP_SYS_NICE`. Failure is explicit: the requested command does not start.
The launcher reads back the scheduler and priority before replacing itself with
the command. Apply scheduling before process startup so worker threads inherit
it; changing only an already-running main thread would miss existing workers.

In real-time mode the launcher excludes at least one logical CPU from its
allowed affinity. Without `--cpus`, it excludes the first allowed logical CPU.
It refuses real-time mode when the allowed set contains only one CPU. This keeps
that logical CPU free of this workload; it does not pin system services, reserve
an entire physical core, or guarantee a hard real-time deadline. Descendant
processes inherit scheduling unless they explicitly change it. Linux's existing
real-time throttling and limits remain unchanged. The launcher does not acquire
privileges or modify system policy.

Round-robin time-slices among equal-priority real-time threads. FIFO requires
threads to block, yield, or be preempted by higher-priority work. Both can delay
normal-priority work on their selected CPUs. Use normal scheduling for bulk
simulation unless measurements justify real-time scheduling.
