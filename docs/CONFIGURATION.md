<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Configuration Reference

## Runtime node configuration

`examples/node-v6.example.yaml` is the canonical, self-documenting 0.39 runtime
configuration. It intentionally includes every field currently deserialized by
`kagi-cluster-host`, including optional fields, accepted values, units, bounds,
security implications, and defaults. Copy it when creating a production node
configuration; do not copy secrets from another node.

A field described as **required** has no deserialization default. A section described
as optional may be omitted and its Rust `Default` implementation applies. The most
important defaults are:

| Parameter | Default | Meaning |
| --- | ---: | --- |
| `listen` | `0.0.0.0:7400` | TCP API/web listener |
| `cluster.replication` | 3 | replication copies |
| `cluster.write_quorum` | 2 | acknowledgements required |
| `cluster.chunk_replicas` | 1 | copies per encoded fragment |
| `cluster.transport.prefer_quic` | true | prefer QUIC when compiled/configured |
| `cluster.transport.quic_min_bytes` | 65,536 | QUIC selection threshold |
| `cluster.transport.max_frame_bytes` | 268,435,456 | framed body limit |
| `cluster.transport.prefer_rdma` | true | RDMA policy preference; 0.39 groundwork only |
| `cluster.transport.rdma_min_bytes` | 262,144 | intended RDMA threshold |
| `cluster.erasure.backend` | `auto` | runtime compute backend |
| `cluster.erasure.scheme` | `clay` | codec for new EC objects |
| `cluster.erasure.data_shards` | 6 | k |
| `cluster.erasure.parity_shards` | 3 | m |
| `cluster.erasure.gpu_threshold_bytes` | 1,048,576 | GPU dispatch threshold |
| `cluster.erasure.max_gpu_inflight` | 32 | GPU concurrency |
| `cluster.erasure.max_matrix_cache_bytes` | 268,435,456 | transform cache ceiling |
| `metadata.election_min_ms` | 1,500 | Raft election lower bound |
| `metadata.election_max_ms` | 3,000 | Raft election upper bound |
| `metadata.heartbeat_ms` | 400 | Raft heartbeat |
| `tls.allow_tls12` | false | TLS 1.3-only unless explicitly relaxed |
| `recovery.heartbeat_ms` | 2,000 | health probe cadence |
| `recovery.suspect_after_ms` | 6,000 | SUSPECT threshold |
| `recovery.down_after_ms` | 15,000 | DOWN threshold |
| `recovery.out_after_ms` | 120,000 | OUT threshold |
| `recovery.repair_interval_ms` | 10,000 | repair cadence |
| `recovery.max_parallel_repairs` | 4 | repair concurrency |
| `recovery.return_probe_successes` | 3 | healthy probes for return |
| `recovery.flap_window_ms` | 300,000 | flap observation window |
| `recovery.flap_transition_threshold` | 4 | quarantine threshold |
| `recovery.minimum_reinclude_uptime_ms` | 600,000 | automatic re-entry uptime |
| `garbage_collection.grace_period_ms` | 86,400,000 | physical deletion grace |
| `garbage_collection.interval_ms` | 30,000 | GC cadence |
| `garbage_collection.max_versions_per_cycle` | 32 | GC work cap |
| `snapshots.check_interval_ms` | 30,000 | snapshot evaluation cadence |
| `snapshots.archive_after_delta_bytes` | 10 GiB | materialization byte trigger |
| `snapshots.archive_after_delta_ratio` | 0.50 | materialization ratio trigger |
| `maintenance.timezone` | `UTC` | schedule timezone |
| `maintenance.scrub_interval_ms` | 300,000 | scrub scheduler cadence |
| `maintenance.quotas.network_mbps` | 100 | background network budget |
| `maintenance.quotas.cpu_percent` | 20 | background CPU budget |
| `maintenance.quotas.memory_mib` | 512 | background memory budget |
| `maintenance.quotas.max_concurrency` | 2 | background operation concurrency |
| `telemetry.enabled` | true | collect node telemetry |
| `telemetry.sample_interval_ms` | 1,000 | sample cadence; clamped 250–60,000 |
| `telemetry.retention_samples` | 3,600 | in-memory samples; clamped 60–86,400 |
| `web_console.enabled` | true | expose console routes |
| `web_console.userdb` | `/etc/kagi/users.yaml` | local console users |
| `web_console.log_path` | `/var/log/kagi/kagi.log` | console log source |
| `web_console.max_log_lines` | 500 | per-request log line ceiling |

The `security` section defaults to no additional kernel or logical-object rules.
When present, security configuration uses `deny_unknown_fields`: misspelled security
keys fail configuration parsing rather than being silently ignored.

### Transport caveats

QUIC requires the `quic` Cargo feature, a peer `quic_endpoint`, and TLS material.
QUIC is TLS 1.3-only and Kagi disables 0-RTT for mutation traffic. HTTPS remains the
fallback. The 0.39 `prefer_rdma`, `rdma_min_bytes`, and `rdma_endpoint` fields are
an explicit configuration boundary for RDMA work; they must not be interpreted as
evidence that the running build has a functional RDMA data path.

### Storage queue controls

Disk scheduler/cache changes are runtime administrator operations rather than static
node YAML. `QueueTuning` accepts `scheduler`, `write_cache_enabled`,
`read_cache_enabled`, and `read_ahead_kb`. Unset fields are left unchanged.
`read_ahead_kb` is capped at 1,048,576 KiB. The read-cache switch currently controls
Linux block read-ahead (zero when disabled, the current nonzero value or 128 KiB when
enabled); it is not a vendor drive-cache command. Unsupported sysfs writes fail visibly.


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
