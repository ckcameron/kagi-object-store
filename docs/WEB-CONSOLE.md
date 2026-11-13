<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Kagi Web Operations Console

`kagi-cluster-host` serves the operations console at `/ui` when enabled. The
console reads live Raft, health, and storage state.

## Authentication

The console uses a local YAML user database with Argon2id password hashes and
`viewer` and `admin` roles. The node configuration selects the database and log paths.

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

The browser uses HTTP Basic authentication against the local database. Serve
it over HTTPS. Setting the node's [`tls` configuration](CONFIGURATION.md#transport-caveats)
enables native TLS for the web and API listener. A trusted reverse proxy can
also terminate TLS with a private upstream connection to the daemon.

## Views

The console displays a persistent red danger banner when an acknowledged
two-site policy allows zero site failures. Losing a site can make objects
unavailable. The banner also reports configured sites whose loss can prevent a
Raft majority and any failure to validate quorum under the plan's concurrent
outage budget. The same protection information is available through
`/v1/monitor/status` and `kagi-cluster-host status`.

- **Overview** — local/cluster object counts, logical bytes, fragment counts, resource-health totals, node role/leader information, Linux load, memory availability and uptime. It refreshes every two seconds.
- **Object explorer** — prefix search, immutable manifest metadata, EC family/geometry, every chunk replica, host/rack/site/disk locality, current resource health, checksum metadata, and known pending GC or snapshot-archive work.
- **Buckets & Lifecycle** — viewer inspection plus admin creation/update of Raft-replicated bucket metadata, versioning intent and default WORM mode/retain-until/legal-hold properties. Object PUTs inherit the bucket WORM default if no per-object retention header is supplied.
- **Logs** — local console-event tail or keyspace-wide aggregation. Inter-node aggregation uses the existing ML-DSA signed internal request protocol plus cluster admission key.
- **Security & Integrity** — audit findings and recent live events, including policy decisions and action outcomes.

## Internal aggregation endpoints

`/internal/v1/ui/node`, `/internal/v1/ui/telemetry`, and `/internal/v1/ui/logs`
require the signed ML-DSA envelope and join-key admission used by other internal
protocols. A node uses these endpoints to aggregate peer state for its locally authenticated browser session.

## Current pending-operation scope

Object detail currently reports durable operations that are explicitly represented in Raft metadata: fenced garbage-collection records and in-progress snapshot archive work. Proactive repair/rebalance loops are currently controller-driven rather than queued as per-object Raft records, so they are reflected in health/placement state but are not yet shown as a durable per-object queue item.


## Security and monitoring

See [security policy and monitoring](SECURITY-POLICY.md) for node YAML rules, the
optional BPF build, privileged metadata, authenticated REST/SSE endpoints, the
audit CLI and deployment boundaries.
