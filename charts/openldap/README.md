# openldap Helm chart

Deploys the `image/` OpenLDAP 2.6.14 server as a StatefulSet, with an optional
management UI (`ui/`). See the repo root [README.md](../../README.md) for why
this project exists, and [SESSION-HANDOFF.md](../../SESSION-HANDOFF.md) for
background on the replication design this chart implements (multi-provider,
peer list injected by this chart from `replicaCount`, admin-identity bind).

## Quick start

```bash
helm install ldap charts/openldap \
  --set image.repository=<your-registry>/openldap-suite-server \
  --set auth.adminPassword="$(openssl rand -base64 24)"
```

There is **no default admin password** — the chart refuses to render
(`helm template`/`install` fails with an explicit error) unless
`auth.adminPassword` or `auth.existingSecret` is set. This mirrors
`image/entrypoint.sh`, which refuses to start for the same reason.

### Two `helm` footguns, hit for real while operating this chart

- **`helm upgrade --reuse-values` does not pick up new chart defaults.**
  Upgrading to a chart version that adds a key (e.g. `backup.recordToDirectory`)
  with `--reuse-values` sends that key down as empty rather than as its new
  default — observed as `RECORD_TO_DIRECTORY=` on the container, which the
  backup CronJob's `[ "$RECORD_TO_DIRECTORY" = "true" ]` check silently
  evaluates to false. Nothing errors, nothing logs a warning; the feature is
  just off. When upgrading, pass `-f values.yaml` (your full values file) or
  set every value explicitly — don't rely on `--reuse-values` to carry
  forward a values file you didn't also pass.
- **`--set` treats a bare comma as a value separator**, including inside a
  DN. `--set ldap.rootDN=dc=example,dc=org` does not set `ldap.rootDN` to
  `dc=example,dc=org` — it sets `ldap.rootDN=dc=example` and then parses
  `dc=org` as a second, unrelated key=value pair (which usually fails to
  parse as a key at all, or silently sets a garbage key). Escape the comma
  (`--set ldap.rootDN=dc=example\,dc=org`) or, better, put DN-shaped values
  in a `-f values.yaml` file instead of `--set` — this was hit for real and
  put a bad value into a release.

## HA / replication

Set `replicaCount` > 1 to get a StatefulSet with N pods. Multi-provider
replication (every node accepts writes, CSN-based conflict resolution) is
enabled automatically whenever `replicaCount > 1` — set `replication.enabled`
explicitly to override that inference. The peer list
(`LDAP_REPLICATION_PEERS`) is generated from `replicaCount` and the headless
Service, and passed into the image; the image never has to guess K8s
topology. `PodDisruptionBudget` and `topologySpreadConstraints` are also only
rendered when `replicaCount > 1`.

## Values

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Server replica count. StatefulSet only. |
| `image.repository` | `ghcr.io/dasomel/openldap-suite-server` | Placeholder — override before real use. |
| `image.tag` | `""` (→ `.Chart.AppVersion`) | Server image tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride` / `fullnameOverride` | `""` | |
| `serviceAccount.create` | `true` | Also gates the UI ServiceAccount when `ui.enabled`. |
| `serviceAccount.name` | `""` | |
| `serviceAccount.annotations` | `{}` | |
| `podAnnotations` / `podLabels` | `{}` | Server pod only. |
| `ldap.rootDN` | `dc=example,dc=org` | → `LDAP_ROOT_DN`. Override for real installs. |
| `ldap.orgName` | `""` | → `LDAP_ORG_NAME` (image derives a default when unset). |
| `ldap.adminDN` | `""` | → `LDAP_ADMIN_DN` (image derives a default when unset). |
| `ldap.logLevel` | `stats` | → `LDAP_LOG_LEVEL`. |
| `auth.adminPassword` | `""` | → `LDAP_ADMIN_PASSWORD` via a chart-created Secret. Required unless `existingSecret` is set. |
| `auth.existingSecret` | `""` | Pre-existing Secret name to source the admin password from. |
| `auth.existingSecretKey` | `admin-password` | Key within the Secret. |
| `tls.enabled` | `false` | **Unverified path** — not exercised end-to-end. |
| `tls.existingSecret` | `""` | Secret (standard `tls.crt`/`tls.key`, optional `ca.crt`) mounted at `/etc/openldap/tls`. |
| `tls.certFile` / `tls.keyFile` / `tls.caFile` | see values.yaml | → `LDAP_TLS_CERT_FILE` / `LDAP_TLS_KEY_FILE` / `LDAP_TLS_CA_FILE`. |
| `replication.enabled` | unset (auto: `replicaCount > 1`) | Force replication on/off. |
| `replication.clusterDomain` | `cluster.local` | Used to build peer FQDNs and the UI's default `LDAP_URL`. |
| `replication.retry` | `5 10 30 +` | → `LDAP_REPLICATION_RETRY`. |
| `replication.interval` | `00:00:00:10` | → `LDAP_REPLICATION_INTERVAL`. |
| `replication.bindDN` | `""` | → `LDAP_REPLICATION_BIND_DN` (defaults to the admin DN in the image — see design contract D3). |
| `replication.existingSecret` / `existingSecretKey` | `""` / `replication-password` | Only needed if `bindDN` overrides the admin identity. |
| `seed.enabled` | `false` | Mount `seed.ldifs` as a ConfigMap at `LDAP_SEED_DIR`, applied on first boot only. This project ships no sample data by default. |
| `seed.ldifs` | `{}` | Map of filename → LDIF content. |
| `persistence.config.size` / `persistence.data.size` | `1Gi` / `2Gi` | PVC sizes for `slapd.d` and `mdb` data respectively. |
| `persistence.*.storageClassName` | `""` | |
| `persistence.*.accessModes` | `[ReadWriteOnce]` | |
| `resources` | requests only, conservative limit | LDAP is memory/mmap-bound; no default cpu limit. |
| `podSecurityContext.fsGroup` | `999` | Matches the image's uid (verified via `docker run ... id`). |
| `securityContext` | non-root, all caps dropped, read-only rootfs | See in-file comments for why `readOnlyRootFilesystem: true` is safe here (emptyDir at `/tmp` and the ldapi run dir). |
| `service.type` | `ClusterIP` | |
| `service.ldapPort` / `service.ldapsPort` | `389` / `636` | `ldaps` only exposed when `tls.enabled`. |
| `pdb.enabled` / `pdb.minAvailable` | `true` / `1` | Only rendered when `replicaCount > 1`. |
| `backup.enabled` | `false` | Renders a CronJob + PVC that dumps the directory via `ldapsearch` on a schedule. Replication is not backup — see in-file comment. |
| `backup.schedule` | `0 2 * * *` | Cron syntax, cluster local time. |
| `backup.retentionDays` | `7` | Backup files older than this are deleted at the end of each successful run. |
| `backup.concurrencyPolicy` | `Forbid` | The backup PVC has a single writer by design. |
| `backup.successfulJobsHistoryLimit` / `failedJobsHistoryLimit` | `3` / `3` | |
| `backup.backoffLimit` | `2` | Caps retries of a wedged/misconfigured run. |
| `backup.activeDeadlineSeconds` | `3600` | Kills a stuck run instead of blocking every future scheduled run under `Forbid`. |
| `backup.recordToDirectory` | `true` | Record each successful backup under `ou=operations` so the UI can show "last backup" via a plain LDAP read. See Backup / Restore below. |
| `backup.persistence.size` / `storageClassName` / `accessModes` | `5Gi` / `""` / `[ReadWriteOnce]` | Separate PVC from `persistence.data` — survives the server's own PVC being lost or recreated. |
| `backup.resources` | small requests + memory limit | |
| `backup.podSecurityContext` / `securityContext` | same shape/uid as the server | Non-root uid/gid 999, all caps dropped, read-only rootfs (writes go to the backup PVC and an `emptyDir` `/tmp`). |
| `topologySpreadConstraints` | `[]` | Sane hostname-spread default injected when empty and `replicaCount > 1`. |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | |
| `startupProbe` / `livenessProbe` / `readinessProbe` | see values.yaml | All exec `ldapwhoami` over the ldapi socket, matching the image's own `HEALTHCHECK`. |
| `ui.enabled` | `false` | |
| `ui.image.repository` / `ui.image.tag` | `ghcr.io/dasomel/openldap-suite-ui` / `""` | Placeholder — override before real use. |
| `ui.replicaCount` | `1` | |
| `ui.service.type` / `ui.service.port` | `ClusterIP` / `8080` | |
| `ui.ldap.url` | `""` (→ this release's server Service) | → `LDAP_URL`. |
| `ui.ldap.baseDN` | `""` (→ `ldap.rootDN`) | → `LDAP_BASE_DN`. |
| `ui.ldap.userSearchBase` / `groupSearchBase` / `userCreateBase` / `groupCreateBase` | `""` | → matching `LDAP_*_BASE` vars. |
| `ui.ldap.userSearchFilter` | `""` | → `LDAP_USER_SEARCH_FILTER`. Empty = DN-only login. |
| `ui.ldap.startTLS` | `false` | → `LDAP_START_TLS`. |
| `ui.ldap.tlsCACert` | `""` | → `LDAP_TLS_CA_CERT`. |
| `ui.ldap.tlsInsecureSkipVerify` | `false` | → `LDAP_TLS_INSECURE_SKIP_VERIFY`. |
| `ui.session.existingSecret` / `existingSecretKey` | `""` / `session-secret` | → `SESSION_SECRET`. Auto-generated (48 bytes) and reused across upgrades via `lookup` when unset. |
| `ui.session.ttl` | `30m` | → `SESSION_TTL`. |
| `ui.session.cookieSecure` | `true` | → `COOKIE_SECURE`. Disable only for local HTTP dev. |
| `ui.sso.enabled` | `false` | Enables Keycloak OIDC SSO and disables LDAP password login. |
| `ui.sso.issuerURL` | Beluga realm issuer | → `SSO_ISSUER_URL`. Required when SSO is enabled. |
| `ui.sso.clientID` | `""` | Confidential OIDC client ID. Required when SSO is enabled. |
| `ui.sso.adminRole` | `ldap-admin` | Required Keycloak realm role → `SSO_ADMIN_ROLE`. |
| `ui.sso.existingSecret` / `existingSecretKey` | `""` / `oidc-client-secret` | Existing Secret/key holding the confidential OIDC client secret. Required when SSO is enabled. |
| `ui.sso.callbackOrigins` | `[]` | Exact browser origins → `SSO_CALLBACK_ORIGINS`; required when SSO is enabled. |
| `ui.ldapServiceAccount.existingSecret` | `""` | Existing Secret holding the dedicated LDAP UI service account's DN and password. Required when SSO is enabled. |
| `ui.ldapServiceAccount.dnKey` / `passwordKey` | `ldap-service-account-dn` / `ldap-service-account-password` | Keys in `ui.ldapServiceAccount.existingSecret`. |
| `ui.ingress.enabled` | `false` | |
| `ui.ingress.className` / `annotations` / `hosts` / `tls` | see values.yaml | Standard `networking.k8s.io/v1` Ingress shape. |

## Keycloak SSO

`ui.sso.enabled=false` is the default and keeps the original LDAP password
form and per-user LDAP bind behavior. Enabling it makes the UI SSO-only:
`POST /api/login` rejects password logins, and every browser starts the
Keycloak authorization-code + PKCE flow.

The chart intentionally uses a **confidential** OIDC client, so
`ui.sso.existingSecret` is mandatory. It also requires a separate
`ui.ldapServiceAccount.existingSecret`; `auth.adminPassword` is never reused
as the UI service account. Rendering fails with an explicit message if any
required SSO value or secret reference is absent. The chart does not create
either Secret and never provisions the LDAP account.

Create a Keycloak client in the Beluga realm with:

- issuer: `https://sso.example.com/realms/example`;
- Standard Flow (authorization code) enabled, confidential client
  authentication enabled, and PKCE method `S256`;
- `openid` and `profile` scopes, so the ID token contains
  `preferred_username`;
- a realm role `ldap-admin` (or the configured `ui.sso.adminRole`);
- an ID-token role mapper providing either an array `roles` claim or
  Keycloak's standard `realm_access.roles`.

Register exact redirect URIs for every origin in `ui.sso.callbackOrigins`.
For forwarded local development, configure both:

```text
http://127.0.0.1:5173/api/sso/callback
http://127.0.0.1:8080/api/sso/callback
```

The backend derives its callback URI from the incoming/forwarded host and
scheme, but accepts it only when its origin exactly matches
`ui.sso.callbackOrigins`; do not configure wildcards.

An SSO user's `preferred_username` is looked up as LDAP `uid` using the
existing `ui.ldap.userSearchBase` and `ui.ldap.userSearchFilter`. The
filter is required in SSO mode, is RFC 4515 escaped by the backend, and
must resolve exactly one LDAP entry. A Keycloak account with no matching
LDAP uid is refused.

The dedicated LDAP account needs ACLs for the full UI feature set: DIT
read/write, user/group CRUD, user password reset, account unlock, and the
searches those views issue. The Keycloak role is the application gate;
LDAP ACLs still limit what the service identity can do. Provision and scope
that identity deliberately—this chart does **not** create it automatically.

Example values (the referenced Secrets must already exist and contain no
values in this file):

```yaml
ui:
  enabled: true
  ldap:
    userSearchBase: ou=people,dc=example,dc=org
    userSearchFilter: "(uid=%s)"
  sso:
    enabled: true
    issuerURL: https://sso.example.com/realms/example
    clientID: ldap-ui
    existingSecret: ldap-ui-oidc
    existingSecretKey: oidc-client-secret
    callbackOrigins:
      - http://127.0.0.1:5173
      - http://127.0.0.1:8080
  ldapServiceAccount:
    existingSecret: ldap-ui-service-account
    dnKey: ldap-service-account-dn
    passwordKey: ldap-service-account-password
```

`POST /api/logout` clears the local UI session and, when Keycloak advertises
an `end_session_endpoint`, uses the server-side ID-token hint for
RP-initiated logout. Register `<origin>/login` as a valid post-logout
redirect URI for every `ui.sso.callbackOrigins` entry. If Keycloak does not
advertise an end-session endpoint, logout remains local-only.

## Backup / Restore

`backup.enabled=true` renders a CronJob that dumps the directory over the
network with `ldapsearch` (both the data tree and `cn=config`), gzips it, and
writes timestamped files to a dedicated PVC. It does **not** touch the
server's own PVCs and does not need to — that's deliberate:

- `slapcat` needs local filesystem access to the `data` PVC, which is
  `ReadWriteOnce` and already held by the running server pod, so a second pod
  can't attach it to run `slapcat` itself.
- `ldapsearch -b <base> ... '*' '+'` gets the same information over the wire
  instead, including operational attributes (`entryUUID`, `entryCSN`,
  `creatorsName`, `modifyTimestamp`, ...) via `'+'`. Those matter: without
  them a restore mints fresh `entryUUID`/CSN values for every entry, which
  isn't a restore, it's a new directory with the same contents — and on a
  replicated deployment, CSN state is exactly what syncrepl uses to decide
  what's newer than what.
- The admin password is passed to `ldapsearch` via `-y <file>` (a file mount
  from the same admin Secret the server uses), never `-w` — `-w` puts the
  password on the command line, visible to any local user via `ps`.

Replication is **not** a substitute for this. Multi-provider syncrepl
propagates a bad delete to every replica within seconds; there is no "the
other node still has it" safety net for that.

### Status recorded in the directory

`backup.recordToDirectory=true` (the default) writes each successful backup's
status into the directory itself, under the data tree — not
Kubernetes-visible state — so `ui/`, which by design never gets a
ServiceAccount and only ever holds an ordinary bound LDAP connection, can
show "last backup" the same way it shows anything else: a plain LDAP read.
The write goes through the CronJob's ClusterIP Service connection like the
dumps do, never a specific pod, so on a replicated deployment it lands
wherever the Service happens to route and reaches every replica via normal
syncrepl.

When this is on, expect exactly two extra entries under `ldap.rootDN`,
created on the first successful run and updated in place after that:

```
dn: ou=operations,<rootDN>
objectClass: organizationalUnit
ou: operations

dn: cn=backup,ou=operations,<rootDN>
objectClass: applicationProcess
cn: backup
description: lastSuccessAt=<UTC ISO 8601 timestamp>
description: dataEntries=<entry count in the data dump>
description: dataFile=<data-<timestamp>.ldif.gz>
description: configFile=<config-<timestamp>.ldif.gz>
```

`applicationProcess` is a stock COSINE objectClass (always loaded — see
`image/ldifs/01-cn-config.ldif`), chosen over a custom attribute/schema
specifically to avoid touching the image, replication, or bootstrap LDIFs
for this. Its `description` is multi-valued and **unordered** — LDAP makes
no promise about the order values come back in — so the four values above
are `key=value` pairs a reader must parse by key, not by position. Any
client reading this (the UI included) needs to split on `=` and match the
key, not assume `description[0]` is `lastSuccessAt`.

This does not violate "no sample data": the two entries above are
operational status, not users, groups, or demo content — the same
distinction the password-policy container entries already make (see the
comment in `image/ldifs/03-base-structure.ldif`).

The write authenticates as `ldap.adminDN` (the directory's `rootDN`, which
bypasses ACLs entirely), so no ACL change was needed for the CronJob to
write it. The baseline ACL already grants any authenticated bind
(`by users read`) — not just admin — read access to everything but
`userPassword`, so a logged-in UI user's own bind can read it without any
new grant either.

A failure to write this status (LDAP unreachable, unexpected ACL, etc.)
never fails the backup Job — the dump having succeeded is what matters, the
directory record is informational on top of it. Set
`backup.recordToDirectory=false` to skip this entirely and keep the
directory free of anything but the data you put there yourself.

**After a restore** (see below), this status entry is part of the data tree
like anything else, so it gets restored along with it — meaning right after
a restore, "last backup" in the UI will show whatever backup was current
*at the time that restore's source dump was taken*, not "never". That's
expected, not a bug: the next scheduled run overwrites it with the truth.

### Restoring

Restore is offline, via `slapadd` — this preserves the operational
attributes captured above, which an online `ldapadd` would not (it would
regenerate them). Do this against a **fresh** volume (existing data would
either conflict or ldapadd is unable to merge conflicting entryUUIDs):

```bash
# 1. Scale the server down so nothing else is writing to the config/data PVCs.
kubectl -n <ns> scale statefulset <fullname> --replicas=0

# 2. Get the backup files onto a machine (or debug pod) that can mount the
#    server's config/data PVCs. One way: a throwaway pod with both PVCs and
#    the backup PVC attached, running the same server image.
kubectl -n <ns> run ldap-restore --rm -it --image=<image.repository>:<image.tag> \
  --overrides='{"spec":{"containers":[{"name":"ldap-restore","image":"<image.repository>:<image.tag>","command":["sleep","3600"],"volumeMounts":[{"name":"config","mountPath":"/etc/openldap/slapd.d"},{"name":"data","mountPath":"/var/lib/openldap/data"},{"name":"backup","mountPath":"/backup"}]}],"volumes":[{"name":"config","persistentVolumeClaim":{"claimName":"config-<fullname>-0"}},{"name":"data","persistentVolumeClaim":{"claimName":"data-<fullname>-0"}},{"name":"backup","persistentVolumeClaim":{"claimName":"<fullname>-backup"}}]}}' \
  -- sh

# Inside that pod:
gunzip -c /backup/config-<timestamp>.ldif.gz > /tmp/config.ldif
gunzip -c /backup/data-<timestamp>.ldif.gz   > /tmp/data.ldif

# 3. Wipe the target volumes — slapadd loads into an EMPTY database, it does
#    not merge. Only do this once you're sure you want to overwrite.
rm -rf /etc/openldap/slapd.d/* /var/lib/openldap/data/mdb
mkdir -p /var/lib/openldap/data/mdb && chmod 700 /var/lib/openldap/data/mdb

# 4. Load cn=config first, then the data tree (same order as bootstrap).
slapadd -n 0 -F /etc/openldap/slapd.d -l /tmp/config.ldif
slapadd -n 1 -F /etc/openldap/slapd.d -l /tmp/data.ldif

# 5. Re-create the bootstrap marker. entrypoint.sh treats a non-empty
#    slapd.d WITHOUT this file as unknown state and refuses to start:
#      "/etc/openldap/slapd.d is non-empty but unmarked — refusing to
#       bootstrap over unknown state"
#    Step 3's `rm -rf .../slapd.d/*` happens to leave it alone (a POSIX sh
#    glob does not match dotfiles), but do not rely on that — a shell with
#    dotglob set, or a slightly different wipe command, turns a successful
#    restore into a server that will not boot.
date -u +%FT%TZ > /etc/openldap/slapd.d/.bootstrapped

# 6. Fix ownership (this throwaway pod may have written as a different uid
#    than the server's fsGroup expects), exit, then scale the server back up.
chown -R 999:999 /etc/openldap/slapd.d /var/lib/openldap/data
exit

kubectl -n <ns> scale statefulset <fullname> --replicas=<original replicaCount>
```

### Restoring a replicated deployment

Restoring onto ordinal `-0` alone is **not enough**, and getting this wrong
quietly undoes the restore.

Multi-provider replication has no authority ranking: the surviving replicas
are peers, not followers. If the reason you are restoring is a bad delete,
that delete already reached every replica — so the moment you scale back up,
`-1` and `-2` replicate their (post-delete) state at `-0` and can undo what
you just restored. Which side wins is decided by CSN comparison, not by which
one you restored.

So wipe every replica's volumes, not just `-0`:

```bash
kubectl -n <ns> scale statefulset <fullname> --replicas=0

# Delete the PVCs of every ordinal EXCEPT -0 (which you are restoring into).
# The StatefulSet recreates them empty on scale-up.
kubectl -n <ns> delete pvc config-<fullname>-1 data-<fullname>-1 \
                          config-<fullname>-2 data-<fullname>-2

# ... run the restore procedure above against -0's PVCs ...

# Bring up ONLY -0 first and confirm the data is what you expect.
kubectl -n <ns> scale statefulset <fullname> --replicas=1
# ... verify with ldapsearch ...

# Then scale up. The other ordinals start with empty volumes and, because
# only serverID 1 (= ordinal 0) ever creates the base DIT, they populate
# themselves from -0 by syncrepl full refresh instead of minting their own.
kubectl -n <ns> scale statefulset <fullname> --replicas=<original>
```

Do not `slapadd` the same backup onto every replica independently — each
would mint its own view of "current" and they would conflict permanently.

## Known gaps

- TLS (`tls.enabled`) has not been exercised end-to-end — validate before
  relying on it.
- No `kubeconform`/schema-validation run was part of this chart's own
  verification (tool unavailable in the authoring environment); `kubectl
  apply --dry-run=client` was used instead.
- Not deployed to a real cluster as part of authoring this chart.
