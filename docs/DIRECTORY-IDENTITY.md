<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->
# Directory-backed identity resolution

On Unix, Kagi calls `getpwnam_r` and `getgrouplist` through libc. This uses the host's
NSS configuration, including LDAP, SSSD and Samba/winbind providers. User lookup
returns a canonical name, UID and supplementary groups, always including the
primary group. NSS buffers and group counts are bounded. Blocking lookups run
outside the async executor with at most eight concurrent calls and a five-second
response deadline. Timed-out native calls retain their concurrency permit until
the host resolver returns.

When available, bounded-time `wbinfo --name-to-sid` and `--user-sids` lookups add
the AD user SID and group SIDs. Arguments are passed directly, with option=value
format, without a shell. SID parsing rejects malformed output. Hosts without
winbind still retain NSS-resolved UID/GID principals. Existing `ad:<sid>` and
`ad-group:<sid>` ACL behavior is unchanged.

The identity endpoint is `/v1/identity/:user`. An S3 credential can set
`directory_user` instead of a fixed `uid`; successful signature authentication is
followed by directory resolution and ACL evaluation. Directory failures deny
that request. Kagi does not trust a client-provided name as authentication.

LDAP binds, Kerberos ticket/password authentication, realm membership, TLS trust
for LDAP and principal-to-Unix-name mapping remain responsibilities of the host's
directory provider. Kagi does not implement its own LDAP schema, KDC or GSSAPI
login endpoint. Configure NSS/SSSD/winbind securely before enabling this mode.
The native lookup is unavailable on non-Unix systems; fixed S3 UID credentials
remain portable.

Local identity and malformed-input tests run in normal CI. The ignored
`directory_provider_matches_expected_user_and_groups` test requires a configured
directory runner and explicit `KAGI_DIRECTORY_TEST_USER`,
`KAGI_DIRECTORY_EXPECT_UID` and comma-separated `KAGI_DIRECTORY_EXPECT_GIDS`.
Optional expected user/group SID variables make AD assertions mandatory. An
unconfigured domain is not counted as a successful directory integration test.
