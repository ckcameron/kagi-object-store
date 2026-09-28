# Monte Carlo Planner, Quick Wizard, and Erasure-Geometry Optimizer

## Purpose

`kagi-config` turns physical failure domains into a deployable 64-bit Kagi placement plan. It models sites, racks, hosts, network paths, disk classes, repair behavior, correlated failures, and data-protection geometry. The generated YAML contains the selected placement salt, exact per-disk slot/key ranges, mount paths, failure estimates, and the best tested chunk geometry for every supported erasure-code family.

The planner is advisory: it evaluates placement and recoverability policy. The runtime data-plane codec remains the authoritative implementation boundary. The runtime implements Reed-Solomon, canonical product-matrix MSR (`d=2k-2`), and CLAY; LRC remains planner-only.

## Invocation modes

Configuration-file mode:

```sh
kagi-config --config topology.yaml --output kagi.generated.yaml
```

Interactive wizard:

```sh
kagi-config --wizard \
  --wizard-config-output topology.yaml \
  --output kagi.generated.yaml
```

The wizard begins with:

```text
Use quick defaults (sites/racks/hosts/disks only) (Y/n):
```

Answer `Y` for quick mode or `N` for the full topology questionnaire.

## Hard topology minimums

The planner rejects configurations with fewer than **6 servers total** or fewer than **6 disks on any server**. These limits are validated for wizard-generated and YAML-provided configurations.

Each policy must also request at least two simultaneous losses in each failure category when that is structurally possible. The minimum is computed as:

- 1 domain: tolerance 0
- 2 domains: tolerance 1
- 3 or more domains: tolerance 2

This rule applies independently to disks, hosts, racks, sites, and network domains. A higher user-configured tolerance is allowed.

## Quick-default mode

Quick mode asks only for:

1. number of sites;
2. racks per site;
3. hosts per rack; and
4. NVMe disks per host.

It enforces at least six total servers and at least six disks per host. All other values are synthesized from defaults:

- slot bits: `16`;
- mount root: `/var/lib/kagi/disks` unless `--mount-root` overrides it;
- disk class: `nvme`;
- disk capacity: `8,000,000,000,000` bytes (8 TB decimal) per disk;
- disk/class weight: `1.0`;
- fallback disk AFR: `0.01`;
- host annual failure probability: `0.002`;
- rack annual failure probability: `0.0005`;
- site annual failure probability: `0.0001`;
- network annual failure probability: `0.001`;
- disk/host/rack/site/network repair defaults are the same as the full wizard defaults;
- automatic EC geometry search is enabled.

Sites, racks, hosts, and disks receive deterministic names such as:

```text
site-01
site-01-rack-01
site-01-rack-01-host-01
site-01-rack-01-host-01-nvme-01
```

### Quick-mode networking

Quick mode allocates sequential `/24` networks from `10.0.0.0/8`:

```text
10.0.0.0/24
10.0.1.0/24
10.0.2.0/24
...
10.1.0.0/24
```

Addresses within each subnet are assigned serially from `.1` through `.254`. A rack with more than 254 hosts receives additional `/24` ranges automatically. Quick mode assigns one storage network path to each host; use the full wizard to model multi-homing.

## Full wizard

The full wizard asks for mount root, disk classes, media types, capacity, AFR and placement weight; site/rack names; site- and rack-level CIDRs; host nomenclature; single- or multi-homed host interfaces and addresses; per-host disk counts and optional `/dev/...` identities; protection-policy constraints; correlated failure events; repair behavior; and optimizer weights.

Every host must finish with at least six disks. The wizard refuses a completed topology containing fewer than six servers.

## Automatic mount generation

`topology.mount_root` is configurable. Disk mount names are deterministic:

```text
<host>-<disk-class>-<two-digit-ordinal>
```

Example:

```text
/var/lib/kagi/disks/site-01-rack-01-host-01-nvme-03
```

`device_path` identifies the underlying block device. `path` is the mounted directory used by Kagi.

## Erasure-code geometry search

The planner compares these families independently for every policy:

- Reed-Solomon / MDS (`k + m`);
- LRC (`k`, local groups, local parity, global parity);
- MSR (`k + m`, repair fan-in `d`);
- CLAY (`k + m`, repair fan-in `d`).

For each schema, the planner varies chunk geometry within the physically placeable limits of the configured disks and the policy's `max_fragments_per_host` / `max_fragments_per_disk`. The default automatic search ceiling is 32 total chunks and may be raised with `optimize.max_total_fragments`.

Each candidate is evaluated in isolation against the real topology failure model. Candidates are ordered first by simulated unreadable probability, then by the existing storage-overhead objective. The best candidates are subjected to deterministic tolerance validation across disk, host, rack, site, and network-domain losses. A geometry that cannot satisfy the requested tolerance is not considered feasible even if its sampled loss rate is low.

The planner alternates placement-salt selection and geometry optimization so chunk count is selected against the placement it will actually use rather than an arbitrary fixed salt.

Example policy enabling automatic geometry selection:

```yaml
policies:
  default:
    protection:
      type: reed_solomon
      k: 4
      m: 2
    locality:
      site: spread
      rack: spread
      max_fragments_per_host: 1
      max_fragments_per_disk: 1
    tolerate:
      disks: 2
      hosts: 2
      racks: 2
      sites: 2
      networks: 2
    optimize:
      auto_geometry: true
      max_total_fragments: 32
      min_data_fragments: 2
```

The initial `protection` is a valid seed geometry. When `auto_geometry` is true, the final selected protection is replaced with the lowest-loss feasible geometry found by the search. The output still reports the winning geometry for every EC family.

## Scheme optimization output

Each `policies.<name>.erasure_scheme_optimization` record includes:

- schema name;
- whether a deterministically valid geometry was found;
- selected protection parameters;
- data, parity, and total chunk counts;
- Monte Carlo unreadable probability used to rank candidates;
- trials used for geometry scoring;
- storage overhead;
- objective score;
- tolerance-validation result and counterexample if infeasible; and
- estimated repair window.

## Per-disk slot/keyspace output

The output contains both a global `keyspace.slot_assignment` list and per-disk `keyspace.disks[].slot_ranges`. Each range contains exact start/end slot numbers and inclusive 64-bit key bounds. Per-disk records include host, class, ordinal, generated mount name/path, device path, weight, target fraction, target slot count, actual slot count, and every contiguous range owned by that disk.

## Failure modeling

Disk failures use class-specific AFR when present and otherwise fall back to `failure_model.disk_annual_probability`. Host, rack, site, and network failures are modeled independently unless correlated events are configured. A multi-homed host is network-unreachable only when all of its configured network domains are failed.

The optimizer performs ordinary Monte Carlo, importance sampling, adaptive rare-event biasing, deterministic tolerance validation, and continuous-time failure/repair trajectories.

## Reproducibility

Preserve the generated YAML, input configuration, command line, and seed together. Changes to hardware topology, capacities, weights, failure probabilities, repair model, policy constraints, or optimizer bounds can change both the preferred chunk geometry and the placement salt.

## Live progress display

When stderr is attached to an interactive terminal, `kagi-config` renders a continuously refreshed status display while the optimizer runs. The display is written to **stderr** so generated YAML on stdout and in `--output` remains machine-readable.

The display contains:

- overall optimizer phase and percentage;
- current operation and its local progress bar;
- cumulative Monte Carlo simulations completed, simulations/second, and elapsed time;
- the lowest observed keyspace/placement-salt failure estimate so far; and
- the lowest observed erasure-code candidate so far, including policy, schema geometry, simulated loss probability, and objective score.

The instrumented phases include both placement-salt searches, both EC geometry searches, ordinary Monte Carlo, rare-event importance sampling, deterministic tolerance validation, adaptive importance sampling, and the continuous-time failure/repair simulation.

Use `--no-progress` to disable the display. The display is also disabled automatically when stderr is not a TTY. `--progress-interval-ms` controls refresh frequency and defaults to 150 ms (internally clamped to 50–2000 ms). Worker threads update lock-light counters while a single renderer thread owns terminal output, so progress rendering does not interleave output from Rayon simulation workers.

Example:

```bash
kagi-config --wizard --trials 100000 --rare-trials 100000 \
  --output kagi.generated.yaml
```

For unattended jobs:

```bash
kagi-config -c topology.yaml --no-progress -o kagi.generated.yaml \
  > keyspace.stdout.yaml
```

## Kagi CUDA Monte Carlo acceleration

Build with `cargo build --release --features cuda` and select `--mc-backend auto` (default) or `--mc-backend cuda`.

The GPU path intentionally accelerates the regular, massively parallel portion of EC geometry evaluation: Kagi generates topology-aware failure scenarios and placements on the CPU, batches the resulting fragment-survival vectors, and evaluates replication, Reed-Solomon/MSR/CLAY MDS readability and LRC local/global parity readability in CUDA. Placement generation, correlated-domain selection, deterministic tolerance validation, rare-event weighting and time-domain repair trajectories remain CPU/Rayon work. `auto` falls back to Rayon if CUDA is unavailable or a kernel call fails. `cuda` requires a CUDA-enabled build.

### Runtime presets

`--run-mode full` preserves the normal high-confidence workload. `quick30` and `quick60` reduce candidate count, ordinary/rare-event trials, deterministic validation keys, AIS rounds and time-domain trajectories. The generated optimizer section records both the run mode and a reduced-confidence warning. These names indicate approximate runtime classes on a well-provisioned modern multi-core system (and are especially useful with CUDA); they are not wall-clock guarantees.

Examples:

```sh
kagi-config --config topology.yaml --run-mode quick30 --mc-backend auto
kagi-config --config topology.yaml --run-mode quick60 --mc-backend cuda
```


## loss and durability presentation

Each ordinary/importance/adaptive estimate includes a `durability` record. The
continuous-time estimate uses `durability_within_horizon` because its probability
covers the configured horizon, not necessarily one year. The original numeric
fields remain for compatibility. Presentation uses `durability=1-p` and
`nines=-log10(p)` for finite `0<p<=1`; fractional nines are retained.

For `p=1e-20`, output is `1.00e-20`, 20 nines, and
`99.999999999999999999%`. Integer decimal arithmetic avoids f64 cancellation in
the percentage text, which uses three significant loss digits. This formatting
capability does not establish simulation accuracy at that scale. Zero estimated
loss reports unresolved durability with null nines, not 100% or infinity. Inspect
sample size, assumptions and confidence bounds; ordinary finite Monte Carlo cannot
resolve twenty-nines risk merely by observing zero losses. Existing importance
sampling confidence fields retain the prior estimator's limitations and should
not be read as proof of a 1e-20 bound.

## Periodic saves and resume

```sh
kagi-config --config topology.yaml --checkpoint simulation.save --checkpoint-seconds 60
kagi-config --resume simulation.save
```

The checkpoint stores the normalized input, effective run settings, seed,
admission key and checksummed completed trial batches. Writes use a same-directory
atomic rename and file/directory sync. A held lock prevents concurrent writers.
Files containing the admission key use owner-only permissions. Protect the
checkpoint directory like other key material.

Saves occur at completed batch boundaries after the requested interval, at phase
boundaries, or when the pending-record bound is reached. This is not a hard
wall-clock deadline: a long-running batch must finish first. `--checkpoint-batch-trials`
(default 1024) controls that work granularity. An interrupted run recomputes
uncommitted batches. Random streams retain their original trial indices and
batch results reduce in a fixed order, independent of worker scheduling.

Resume reuses saved settings and refuses conflicting simulation options or a
different Kagi version. Corrupt committed records stop the run. Completed batches
are reused while deterministic orchestration is replayed. Final outputs and the
admission key are also written atomically. Saved output paths are resolved to absolute paths, so resume does not depend on
the caller's working directory. The planner's binary
name is now `kagi-config`; older `kagi-montecarlo` commands must be updated.
