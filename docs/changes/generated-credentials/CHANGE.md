# Automatically generated startup credentials

Class D, user-authorized 2026-10-03: automatically create LDAP_ADMIN_PASSWORD and
SESSION_SECRET at initial startup and let the operator retrieve them. No production
credential rotations or shared deployment mutation authorized.

D40: explicit mounted files/environment values retain precedence. Otherwise generate
32 bytes from the OS CSPRNG once and persist in private files on durable volumes.
LDAP password is generated only for a fresh directory; a bootstrapped directory
without its original generated password fails closed instead of silently rotating.
Session secret reuses its private store and remains consistent across restarts.
Helm uses shared Kubernetes Secrets and lookup reuse, rather than per-pod generation.
Cost: retain/backup credential volumes; losing them requires deliberate recovery.
Escape hatch: use existingSecret/password env/file and explicit session secret.

D41: raw values are operator CLI/Kubernetes Secret reads only. HTTP exposes safe
session-secret source metadata, never values or file paths. Do not generate third-party
OAuth/S3/FTP credentials or overwrite LDAP identities/passwords through an API.

Files: entrypoint, UI config/startup CLI/runtime, compose, Helm admin Secret, credentials
lookup script, docs. No LDAP schema/ACL changes. Verification: helper/race tests,
actual fresh LDAP bind with generated credentials and recreation/restart, UI cookies
with persistent secret, empty/unsafe-store failures, env/file precedence, chart render
and real cluster lookup reuse when cluster available. API coverage inventory recorded.

D42 (2026-10-04, independent review follow-up): Helm never generates the admin
password in an offline render. When no `auth.adminPassword`/`existingSecret` is set and
the release Namespace is not visible to `lookup`, the chart fails with instructions
(`helm template`, ArgoCD, Flux and `--dry-run=client` cannot see the existing Secret and
would otherwise emit a new password on every render, locking out a retained data
volume). The generated Secret carries `helm.sh/resource-policy: keep`, so uninstall and
reinstall with the same release name reuse it. Cost: GitOps users must supply explicit
credentials or an existing Secret. Escape hatch: `existingSecret` / `adminPassword`.

D43: with `LDAP_REPLICATION_ENABLED` the entrypoint refuses to generate an admin
password. syncrepl binds as the admin DN, so every peer must share one explicit
`LDAP_ADMIN_PASSWORD(_FILE)`; an explicit `LDAP_REPLICATION_PASSWORD` alone is not
sufficient. Cost: replicated nodes need explicit credentials (as before generation
existed). Single-node generation is unchanged.

D44: `restore.sh` no longer deletes the target's generated credentials. They are moved
to `.credentials.pre-restore.<UTC timestamp>` (private) and a warning explains that the
restored directory uses the SOURCE password, which must be supplied explicitly. Backups
still never contain credentials. Cost: a leftover private file until the operator
removes it.

D45: generation checks every write step (`printf` exit status, non-empty, exactly 64
bytes) before publishing, so a full disk cannot leave an empty password file.
`get-credentials.sh --local` reports its source on stderr, fails when the container
cannot be read unless `--allow-env` is given, and prints bind examples that use `-y`
instead of `-w` so the password is not on a command line.

Not addressed here (follow-up): bootstrap still passes the password to `slappasswd -s`
and `ldapadd -w` (visible in `/proc/*/cmdline` during bootstrap, pre-existing);
`ui-secret.yaml` has the same offline-render behaviour for the session secret
(invalidates sessions, no lockout); no multi-process test for secret creation; the live
credentials E2E is not wired into CI.
