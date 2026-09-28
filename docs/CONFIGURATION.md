# Configuration Reference

## Monte Carlo topology

```yaml
slot_bits: 16

topology:
  mount_root: /var/lib/kagi/disks
  network_domains:
    - id: la-storage-a
      cidr: 10.20.0.0/24
      site: la
      rack: null
    - id: la-r01-storage-b
      cidr: 10.20.10.0/24
      site: la
      rack: la-r01

  disk_classes:
    - name: nvme
      media: nvme
      annual_failure_probability: 0.008
      default_capacity_bytes: 7681501126656
      default_weight: 1.0
    - name: sas-hdd
      media: sas_hdd
      annual_failure_probability: 0.02
      default_capacity_bytes: 18000000000000
      default_weight: 1.0

  hosts:
    - name: la-r01-host-01
      site: la
      rack: la-r01
      networks: [la-storage-a, la-r01-storage-b]
      addresses: [10.20.0.11, 10.20.10.11]

  disks:
    - id: la-r01-host-01-sas-hdd-01
      host: la-r01-host-01
      site: la
      rack: la-r01
      class: sas-hdd
      ordinal: 1
      mount_name: la-r01-host-01-sas-hdd-01
      path: /var/lib/kagi/disks/la-r01-host-01-sas-hdd-01
      device_path: /dev/disk/by-id/wwn-0x5000...
      capacity_bytes: 18000000000000
      weight: 1.0
```

Older configuration files containing only `topology.disks` continue to deserialize. Missing host records are inferred. Missing class/ordinal/mount-name fields are normalized before simulation.

## Failure model

```yaml
failure_model:
  disk_annual_probability: 0.01
  host_annual_probability: 0.002
  rack_annual_probability: 0.0005
  site_annual_probability: 0.0001
  network_annual_probability: 0.001
  importance_bias: 8.0
  correlated_events:
    - probability: 0.0001
      domain: rack
      count_min: 1
      count_max: 2
```

## Repair model

```yaml
repair_model:
  disk_mttr_hours: 24
  host_mttr_hours: 4
  rack_mttr_hours: 4
  site_mttr_hours: 24
  network_mttr_hours: 1
  repair_bandwidth_bytes_per_sec: 1000000000
```

## Policy example

```yaml
policies:
  bulk:
    protection:
      type: lrc
      k: 12
      local_groups: 3
      local_parity: 1
      global_parity: 3
    locality:
      site: spread
      rack: spread
      max_fragments_per_host: 1
      max_fragments_per_disk: 1
    tolerate:
      disks: 3
      hosts: 2
      racks: 1
      sites: 0
      networks: 1
```

## topology minimums

The planner requires at least six hosts and at least six disks on every host. Configuration-file inputs are checked with the same validator used for wizard output.

The minimum requested tolerance for each failure-domain category is derived from the number of independent members in that category: zero for one member, one for two members, and two for three or more members. Higher values may be configured.

## Automatic EC geometry search

Every policy receives a per-schema optimization report for Reed-Solomon, LRC, MSR and CLAY. Add `optimize.auto_geometry: true` when the optimizer should also replace the policy's seed `protection` with the lowest-loss feasible geometry.

```yaml
policies:
  bulk:
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
      # max_data_fragments may be supplied to narrow the search.
```

Supported planner `protection.type` values are `replication`, `reed_solomon`, `lrc`, `msr`, and `clay`. Runtime codecs exist for Reed-Solomon, canonical product-matrix MSR, and CLAY; LRC remains planning-only.

The automatic search is bounded by both the configured search ceiling and the actual number of fragments that can be placed under `max_fragments_per_host` and `max_fragments_per_disk`.

## Quick-wizard defaults

Quick mode uses:

```text
slot_bits: 16
mount_root: /var/lib/kagi/disks
media: nvme
capacity per disk: 8,000,000,000,000 bytes
weight: 1.0
network pool: sequential /24s from 10.0.0.0/8
disk annual failure probability: 0.01
host annual failure probability: 0.002
rack annual failure probability: 0.0005
site annual failure probability: 0.0001
network annual failure probability: 0.001
```

Use `--mount-root` to change the quick-mode mount root without entering the full wizard.


## Runtime erasure configuration

New EC configurations default to CLAY. The recommended baseline is:

```yaml
cluster:
  erasure:
    backend: auto
    scheme: clay
    data_shards: 6
    parity_shards: 3
    repair_helpers: 8
    gpu_threshold_bytes: 1048576
    max_gpu_inflight: 32
    max_matrix_cache_bytes: 268435456
```

`scheme` may be `clay`, `msr`, or `reed_solomon`. CLAY requires `k+1 <= d <= k+m-1`; omitted `repair_helpers` selects `d=k+m-1`. The product-matrix MSR backend currently requires `d=2k-2` and therefore `n>=2k-1`. Old manifests without `erasure_scheme` deserialize as Reed-Solomon.

## Monte Carlo display options

The live simulation display is controlled by CLI rather than YAML because it changes operator presentation, not placement semantics:

- `--no-progress` disables terminal rendering;
- `--progress-interval-ms N` changes refresh cadence (default 150 ms; clamped to 50–2000 ms).

The display is also disabled automatically when stderr is not a TTY. These options do not affect RNG seeds, failure models, placement results, or output YAML.

## Kagi web console

Node configuration supports:

```yaml
web_console:
  enabled: true
  userdb: /etc/kagi/users.yaml
  log_path: /var/log/kagi/kagi.log
  max_log_lines: 500
```

The user database is local to each node by design; operators can provision the same user set to all nodes or use distinct node-local credentials. Cluster data shown in the console is fetched node-to-node through signed internal Kagi requests, not by forwarding browser credentials.

Bucket records are replicated Raft metadata and contain `name`, `created_at_unix_ms`, `versioning`, `tags`, and `default_worm` (`mode`, `retain_until_unix_ms`, `legal_hold`).


## security and monitoring

See [security policy and monitoring](SECURITY-POLICY.md) for node YAML rules, the
optional BPF build, privileged metadata, authenticated REST/SSE endpoints, the
audit CLI and deployment boundaries.
