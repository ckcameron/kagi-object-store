# Kagi security policy and monitoring (0.38)

The distributed `kagi-cluster-host` now owns kernel policy loading, logical-object
policy, side-action dispatch, event monitoring, and configuration/integrity audits.
Local cluster CLI put/get/repair/scrub commands also evaluate logical rules.
The existing Raft, placement, erasure, ACL, WORM and immutable-version architecture
remains in place. The smaller `kagi-host` is still a local development daemon; it
does not load these cluster security settings.

## Two identities, two enforcement boundaries

Kernel rules address `(superblock device, inode)`, using the supplied fileguard
LSM source in `security/kagi-guard-ebpf`. They synchronously allow or return
`-EACCES` from open, read/write/append, exec, getattr, create/mkdir, unlink/rmdir,
and rename hooks. Earlier LSM denials are preserved. An exact inode policy wins
before the nearest matching recursive ancestor; ancestry is limited to 32 parents
and does not cross mount roots. Hard links share identity. Create checks the
parent, delete checks the target, and rename checks the source and destination
parent, as in the uploaded implementation. Kernel rules do not mediate mmap.

Userspace translates the stat device encoding to kernel dev_t before loading the
map. Duplicate inode policies, including hardlink aliases, are rejected rather
than silently overwriting one another. Replacing a file changes its inode; restart
to refresh exact-file policies or use a recursive directory rule. Rules are loaded
once at startup. A successful load is not proof of arbitrary-kernel portability:
the generated BTF structure bindings must match the deployment kernel.

Logical rules address object keys because the kernel cannot associate distributed
fragment I/O with a client's object operation. These rules run before cluster HTTP
handlers, including ordinary/version/snapshot reads, writes/deletes, metadata,
namespace and explicit repair/scrub routes. They add restrictions to ACL/WORM;
`allow` never overrides an ACL or retention denial. All matching logical rules
are evaluated, and any deny wins. Recursive key matches stop at slash boundaries:
`secret` matches `secret/a`, not `secretary/a`. URL-encoded keys are decoded before
matching. Operators must deploy equivalent startup policy on every node.

Reserved resources `@api/v1/...` address non-object management APIs (for example,
`@api/v1/pq` or `@api/v1/volumes`). These resources are privileged. Existing trusted
internal RPCs, automatic repair, GC and Raft application are not logical client
operations; the logical gate does not disable those consistency mechanisms.
Kernel rules remain available for direct filesystem access by other processes.

The loader preserves fileguard's daemon-TGID bypass. Consequently the Kagi process
itself is exempt from its kernel rules; logical API checks are essential. Action
children are not exempt and may trigger further events. Do not configure recursive
actions that invoke themselves. Restrict who can edit node policy and executables.

## Configuration and build

Merge `examples/security.example.yaml` into the existing node YAML. All fields are
optional at the node level for backwards compatibility; kernel enforcement is off
until explicitly enabled. Unknown fields inside security policy are rejected.

```
cargo build --release --features ebpf --bin kagi-cluster-host
cd security
make bindings
make ebpf
```

The separate BPF workspace requires Linux BPF LSM, kernel BTF, `aya-tool`, nightly
Rust with rust-src, and `bpf-linker`. Build tooling is not run automatically by
normal Cargo builds. Set `security.kernel.object` to the resulting
`security/target/bpfel-unknown-none/release/kagi-guard-ebpf` file. `LOST_EVENTS` is
required, so use the bundled Kagi BPF source, not an old unmodified ELF.
If enabled, any missing feature, bad path, invalid rule, map error, verifier failure,
or attach failure aborts startup before the HTTP listener opens. There is no silent
fallback. When the daemon exits, its BPF links detach; use an appropriately
restricted service supervisor and file permissions as additional controls.

## Allow/deny plus side action

Both rule kinds support `decision: allow|deny` plus an optional named action:
`log`, `exec`, or (kernel events only) `signal`. A deny rejects the operation; it
does not terminate the process unless a separate signal action is configured.
Arbitrary commands run asynchronously in userspace. They cannot replace syscalls,
emulate results, roll back an allowed operation, or guarantee delivery.

Exec actions use an absolute executable path and argument vector, never a shell.
Argument placeholders are `{path}`, `{pid}`, `{tgid}`, `{uid}`, `{gid}`,
`{operation}`, `{decision}`, and `{comm}`. Substitution is single-pass: values
cannot inject additional placeholders. For recursive kernel rules `{path}` is the
configured rule root, not the descendant pathname. Logical events have zero process
IDs; signal actions are rejected for logical rules.

The action queue holds 256 items. One worker waits/reaps each child, with a
30-second execution timeout. Standard input/output/error are disconnected. Children
run as the service account. A timeout kills the direct child, not an arbitrary
process tree; configured programs must manage their own descendants. Queue overflow
and failures emit security errors. Kernel ring-buffer losses are counted and
reported once per second; a lost event means its action was not delivered, but
kernel denial still occurred. Signal delivery retains fileguard's asynchronous TGID
semantics, including the risk that a process exits or its PID is reused before
signal delivery. Prefer an alert action where delayed signals are inappropriate.

## Privileged object metadata

`FsMetadata.privileged` defaults to false when reading older versions. It is stored
with the encrypted/protected object metadata and Raft manifest. Existing flags
survive ordinary writes, ACL updates, repairs and archived snapshots. An admin may
supply `x-kagi-privileged: true|false` on PUT/mkdir; the gate authenticates the admin
through the console user database. Ordinary writes preserve the current flag.
Rules with `privileged_only: true` match marked objects. Historical reads consider
both the historical and current flag; snapshots also retain the source flag.
A flag by itself does not deny anything; configure a corresponding rule. Prefix
rules are recommended when a classification must persist after complete deletion
and later recreation of a key. Concurrent policy/classification administration
should be serialized operationally; classification is version metadata, not a
separate cluster-wide policy registry.

## Authenticated monitoring API

Create users with the existing `web-user-add` CLI. All monitoring endpoints require
HTTP Basic authentication against that Argon2id database (viewer or admin).
They expose node-wide operational data to trusted operators, not tenant-scoped
object access. Use HTTPS termination and a restricted backend listener; the
existing `tls` section configures internal clients and does not wrap axum::serve.
Never put passwords/tokens in monitoring URLs.

| Endpoint | Result |
| --- | --- |
| GET /v1/monitor/events | Bounded structured history with oldest/latest ID and gap indicator |
| GET /v1/monitor/stream | SSE replay then live events; `kagi` and `gap` event types |
| GET /v1/monitor/status | Enabled policy counts and delivery semantics |
| GET /v1/monitor/audit | Current findings and hardening recommendations |
| GET /v1/monitor/logs | Existing authenticated local/cluster Kagi system-log tail |

Events carry severity (`info`, `warning`, `error`), category (`system`, `security`,
`integrity`, `audit`), resource, timestamp, ID, and message. Requests/bodies/passwords
are not copied to events. Categories include HTTP outcomes, policy decisions,
action failures, scrub integrity failures, and changes to audit findings. The log
endpoint reads the configured Kagi log; arbitrary journald/kernel logs are not
implicitly exposed or ingested.

History and stream accept `after`, `category`, `severity`, and `resource_prefix`.
SSE also accepts `Last-Event-ID`, which takes precedence over `after`. Subscribe
before snapshotting history prevents missed events at the replay/live boundary;
live events already in replay are deduplicated. A lagging client receives a `gap`
event and should query history. The stream rechecks credentials at least every
30 seconds while it is being consumed. Node history is limited to 4,096 events,
not persisted, and IDs reset on restart; it is operational telemetry, not a durable
compliance ledger. Consumers should refresh state on reconnection/restart and keep
their own durable event store if needed. File-backed ordinary logs retain their
existing behavior.

The console's Security & Integrity tab displays findings and the last 100 live
events using text rendering. Existing authenticated log views remain available.

## Audits

`kagi-cluster-host --config node.yaml audit` reports configuration findings without
starting Raft, opening the server, or attaching BPF. The runtime repeats audits
once per minute and emits changed/resolved findings. Checks include exposed
plaintext listeners, missing mTLS/HTTPS or metadata encryption, security-file
permissions, disabled/empty kernel or logical policy, unsafe quorum, limited site
separation, disabled scrub, short GC grace, broad write ACLs and unprotected chunks.
Runtime output caps findings at approximately 1,024 to bound response growth.

The audit also calls out the inherited header-based ACL identity trust model:
put a trusted authenticating gateway in front of public object routes and strip
client-supplied identity headers. These findings are recommendations, not proof
of hardening or a replacement for a deployment threat model.
