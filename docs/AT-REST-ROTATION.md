<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->
# At-rest key generations

`cluster.active_key_id` selects a nonzero unsigned 64-bit generation for new
fragment and protected-metadata writes. `cluster.at_rest_keys` maps generations
to base64-encoded 32-byte random root keys. Generation IDs are permanent: never
assign different key material to an existing generation.

The fragment `KAGIFR3` envelope adds a fixed 16-byte magic/generation prefix to
the chunked AEAD envelope. Protected metadata records `key_id`. Domain-separated
key derivation binds the generation cryptographically, even if two generations
accidentally contain identical roots. Unknown, zero, malformed or missing keys
fail closed; readers never try another generation. Fragment identity, chunk
index, nonce and lengths retain their existing AEAD bindings. Authenticated
range reads seek past the prefix and read only the requested AEAD chunks.

Existing `KAGIFR2` fragments and metadata without `key_id` use
`cluster.metadata_key_b64`, irrespective of the active generation. Omitting
`active_key_id` continues writing the legacy format. This is a keyring scheme,
not wrapped per-object DEKs: retiring a generation requires rewriting data.

Roll out readers on every node before enabling a generation: old binaries
cannot read generation-tagged envelopes. Distribute the new keyring entry to all
nodes first, then activate its ID and restart nodes under the usual maintenance
procedure. Keep all historical keys, including the legacy key, available during
rotation. New writes and fragment repairs use the active generation; existing
ciphertext is not silently rewritten. Rewriting live objects alone does not
migrate snapshots, retained versions, archives, offline disks or backups. Do not
remove a key until every required copy has been migrated or expired and restore
has been tested. There is currently no automated key-retirement or inventory
command. Back up the complete keyring separately from stored ciphertext.

Example (replace placeholder values with independent random keys):

```yaml
cluster:
  metadata_key_b64: "LEGACY_BASE64_32_BYTE_KEY"
  active_key_id: 2
  at_rest_keys:
    1: "PREVIOUS_BASE64_32_BYTE_KEY"
    2: "ACTIVE_BASE64_32_BYTE_KEY"
```

Configuration changes take effect on process restart. The keyring is local
configuration, never replicated in Raft metadata or returned by the API.
