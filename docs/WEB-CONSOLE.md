# Kagi Web Operations Console

The Kagi node daemon serves an embedded operations console at `/ui` on every node. The console is dark-themed with teal/electric-blue accents and is intentionally backed by live Raft/health/data-plane state rather than a separate monitoring database.

## Authentication

The initial authentication provider is a local YAML user database using Argon2id password hashes and `viewer` / `admin` roles. Configure:

```yaml
web_console:
  enabled: true
  userdb: /etc/kagi/users.yaml
  log_path: /var/log/kagi/kagi.log
  max_log_lines: 500
```

Create or replace a user without putting the password on the command line:

```sh
printf '%s\n' 'a-long-random-password' >/root/kagi-admin.pass
chmod 600 /root/kagi-admin.pass
kagi-cluster-host --config /etc/kagi/node.yaml web-user-add admin --role admin --password-file /root/kagi-admin.pass
rm /root/kagi-admin.pass
```

Browser authentication currently uses HTTP Basic against the Argon2id user database. Do not expose it over cleartext networks. Use the node behind TLS or a trusted TLS reverse proxy until native server-side TLS termination is enabled in the daemon.

## Views

- **Overview** — local/cluster object counts, logical bytes, fragment counts, resource-health totals, node role/leader information, Linux load, memory availability and uptime. It refreshes every two seconds.
- **Object explorer** — prefix search, immutable manifest metadata, EC family/geometry, every chunk replica, host/rack/site/disk locality, current resource health, checksum metadata, and known pending GC or snapshot-archive work.
- **Buckets & Lifecycle** — viewer inspection plus admin creation/update of Raft-replicated bucket metadata, versioning intent and default WORM mode/retain-until/legal-hold properties. Object PUTs inherit the bucket WORM default if no per-object retention header is supplied.
- **Logs** — local console-event tail or keyspace-wide aggregation. Inter-node aggregation uses the existing ML-DSA signed internal request protocol plus cluster admission key.

## Internal aggregation endpoints

`/internal/v1/ui/node` and `/internal/v1/ui/logs` are not user-authenticated web APIs. They require the same signed ML-DSA envelope and join-key admission used by other Kagi internal protocols. A node uses these endpoints to aggregate peer state for its locally authenticated browser session.

## Current pending-operation scope

Object detail currently reports durable operations that are explicitly represented in Raft metadata: fenced garbage-collection records and in-progress snapshot archive work. Proactive repair/rebalance loops are currently controller-driven rather than queued as per-object Raft records, so they are reflected in health/placement state but are not yet shown as a durable per-object queue item.


## security and monitoring

See [security policy and monitoring](SECURITY-POLICY.md) for node YAML rules, the
optional BPF build, privileged metadata, authenticated REST/SSE endpoints, the
audit CLI and deployment boundaries.
