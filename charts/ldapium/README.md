# ldapium Helm chart

Deploys the `image/` OpenLDAP 2.6.14 server as a StatefulSet, with an optional
management UI (`ui/`). See the repo root [README.md](../../README.md) for why
this project exists. The replication design this chart implements
(N-way multi-provider, peer list injected from `replicaCount`, admin-identity
bind) is described under Replication below.

## Quick start

```bash
helm install ldap charts/ldapium \
  --set image.repository=<your-registry>/ldapium \
  --set auth.adminPassword="$(openssl rand -base64 24)"
```

There is **no default admin password** — the chart refuses to render
(`helm template`/`install` fails with an explicit error) unless
`auth.adminPassword` or `auth.existingSecret` is set. This mirrors
`image/entrypoint.sh`, which refuses to start for the same reason.

### Three `helm` footguns, hit for real while operating this chart

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
- **`helm install --wait` hangs on a healthy release when `backup.enabled`
  is on.** `--wait` waits for PersistentVolumeClaims to reach `Bound`, and the
  backup PVC has no consumer until the CronJob first fires. On a storage class
  with `volumeBindingMode: WaitForFirstConsumer` — kind's default and most
  cloud defaults — that claim stays `Pending` by design, so `--wait` sits there
  until it times out while every pod is already running and ready. Wait on the
  workload instead: `kubectl -n <ns> rollout status statefulset/<fullname>`.

## HA / replication

Set `replicaCount` > 1 to get a StatefulSet with N pods. Multi-provider
replication (every node accepts writes, CSN-based conflict resolution) is
enabled automatically whenever `replicaCount > 1` — set `replication.enabled`
explicitly to override that inference. The peer list
(`LDAP_REPLICATION_PEERS`) is generated from `replicaCount` and the headless
Service, and passed into the image; the image never has to guess K8s
topology. `PodDisruptionBudget` and `topologySpreadConstraints` are also only
rendered when `replicaCount > 1`.

## Scale / Performance

"This holds up to N entries" is a claim; [docs/scale-benchmarks.md](../../docs/scale-benchmarks.md)
is the reproducible measurement behind it — offline `slapadd` load throughput,
search throughput/latency (with the p50/p95/p99 SLO thresholds to judge them
against), and write + multi-provider replication convergence, plus the local
reproduction scripts (`scripts/bench-*.sh`) to re-run all three against your
own hardware. `olcDbMaxSize` (`ldap.dbMaxSize` above) must be sized for your
target entry count before a load benchmark means anything — see that
document for why.

## TLS

`tls.enabled=true` mounts `tls.existingSecret` at `/etc/openldap/tls`, adds an
LDAPS listener on 636, and — on a replicated install — points every
`olcSyncrepl` provider at `ldaps://` instead of `ldap://`. The image sets
`LDAPTLS_REQCERT=demand` (OpenLDAP's own client default), so a certificate that
does not verify against the configured CA fails the connection rather than
quietly falling back to plaintext. `olcTLSProtocolMin: 3.3` (OpenLDAP's own
encoding for TLS 1.2 — not a version of this image) is also set unconditionally
whenever TLS is enabled: an explicit floor this project chose, rather than
whatever the linked OpenSSL build happens to default to. Not configurable —
nothing deploying in 2026 wants it lower.

The Secret is the standard Kubernetes TLS shape plus the CA:

| Key | Required | Used as |
|---|---|---|
| `tls.crt` | yes | `olcTLSCertificateFile` |
| `tls.key` | yes | `olcTLSCertificateKeyFile` |
| `ca.crt` | when `tls.caFile` is set | `olcTLSCACertificateFile` — also what clients and syncrepl verify peers against |

The certificate has to cover both names a peer may connect to: the Service,
`<release>-ldapium.<ns>.svc.<clusterDomain>`, and the per-pod headless name,
`*.<release>-ldapium-headless.<ns>.svc.<clusterDomain>`, which is the one
syncrepl uses.

### Renewing a certificate

`slapd` reads its key material once, at startup. Updating the Secret replaces
the files under `/etc/openldap/tls` but not what is being served, so a renewal
is two steps — update, then restart:

```bash
kubectl -n <ns> create secret generic <tls-secret> \
  --from-file=tls.crt=new.crt \
  --from-file=tls.key=new.key \
  --from-file=ca.crt=ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n <ns> rollout restart statefulset/<fullname>
kubectl -n <ns> rollout status statefulset/<fullname>
```

With `replicaCount > 1` that is a rolling restart behind the
`PodDisruptionBudget`: pods leave the Service's endpoints one at a time, so
LDAPS keeps answering throughout. A single-replica install has no second node
to answer, so it is unavailable for the length of one pod restart — schedule it
rather than discovering it.

Replacing the **CA** is two rotations, not one. Publish a `ca.crt` holding both
the old and the new CA and restart, so every pod trusts both; then issue leaf
certificates from the new CA and restart again; then drop the old CA. Done in a
single step it breaks replication, because a pod that has already restarted
presents a certificate the pods that have not restarted do not yet trust.

### What CI verifies

`.github/workflows/sssd-e2e.yml` installs the chart with the UI disabled,
seeds an RFC 2307 POSIX user and group, and runs a disposable client with a
real SSSD NSS daemon. It proves `getent` and `id` identity resolution only;
it does not claim PAM authentication or login-session coverage.

The `tls` job in `.github/workflows/e2e.yml` runs against a standalone and a
3-node install and uploads a `tls-evidence-<scenario>` artifact holding the
served certificate, the `cn=config` TLS attributes, and the rotation samples:

- authenticated LDAPS bind with strict verification
- an unknown CA, a name the certificate does not cover, and an expired
  certificate are each rejected
- the TLS 1.2 floor is actually enforced, not merely present in `cn=config`:
  raising `olcTLSProtocolMin` to TLS 1.3 stops a TLS 1.2 client that worked a
  moment earlier, while TLS 1.3 keeps working throughout
- the `olcTLSCipherSuite` baseline is actually enforced, not merely present
  in `cn=config`: a TLS 1.2 client offering only an ECDHE+AEAD cipher inside
  the configured baseline connects, while one offering only a static-RSA
  cipher outside it is refused
- `olcSyncrepl` uses `ldaps://` and never plaintext `ldap://`
- a write over LDAPS converges on every replica
- a certificate rotation, with LDAPS availability sampled every second from a
  pod outside the StatefulSet for the whole rolling restart, and the served
  serial asserted to have actually changed
- the "Replacing the CA is two rotations, not one" procedure above, in full:
  bundling old+new CA leaves the old-CA leaf certificate still trusted, a
  rolling leaf swap to the new CA is zero-downtime while both are still
  trusted, replication keeps converging throughout, and dropping the old CA
  afterward is verified by confirming a client that trusts *only* the
  retired CA is genuinely refused — not just that the new CA works

## Values

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Server replica count. StatefulSet only. |
| `image.repository` | `ghcr.io/dasomel/ldapium` | Placeholder — override before real use. |
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
| `ldap.anonymousReadBase` | `""` | → `LDAP_ANONYMOUS_READ_BASE`. Empty keeps today's DIT-wide anonymous read of `entry`/`uid`/`objectClass`; set to a DN under `ldap.rootDN` to narrow it to that subtree only (`image/README.md`, "Access control (ACL)"). DN-shaped, so it hits the `--set` comma footgun above — use `--set-string` with an escaped comma (`--set-string 'ldap.anonymousReadBase=ou=people\,dc=example\,dc=org'`) or a values file. |
| `ldap.logLevel` | `stats` | → `LDAP_LOG_LEVEL`. |
| `auth.adminPassword` | `""` | → `LDAP_ADMIN_PASSWORD` via a chart-created Secret. Required unless `existingSecret` is set. |
| `auth.existingSecret` | `""` | Pre-existing Secret name to source the admin password from. |
| `auth.existingSecretKey` | `admin-password` | Key within the Secret. |
| `tls.enabled` | `false` | Serves LDAPS on 636 and moves replication to `ldaps://`. See [TLS](#tls). |
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
| `ui.image.repository` / `ui.image.tag` | `ghcr.io/dasomel/ldapium-ui` / `""` | Placeholder — override before real use. |
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
| `ui.session.loginFailureLimit` | `10` | → `UI_LOGIN_FAILURE_LIMIT`. Failed `POST /api/login` attempts per client IP within the window before a `429`; `0` disables. Per pod, not cluster-wide — ppolicy lockout is the backstop across replicas. |
| `ui.session.loginFailureWindow` | `1m` | → `UI_LOGIN_FAILURE_WINDOW`. Sliding window the limit applies over. |
| `ui.trustedProxies` | `private` | → `UI_TRUSTED_PROXIES`. How the login limiter resolves a client IP: `private` trusts loopback/link-local/private-net hops (an in-cluster ingress); a comma-separated CIDR list trusts ONLY those listed hops (not a superset of `private`); `none` ignores `X-Forwarded-For` and keys on the raw TCP peer (only correct with no proxy in front). A multi-CIDR list hits the `--set` comma footgun above — use a `-f values.yaml` file or escape the commas (`\,`). |
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

## Verifying an install

```bash
helm test <release> --namespace <ns>
helm test <release> --logs        # print the report without kubectl
```

The hook runs `files/tests/directory-test.sh` in a pod built from the server
image — used only as an LDAP client, the same way the backup CronJob uses it.
Nothing test-related exists inside the image itself, so what is checked, and
whether the manifests exist at all (`tests.enabled`), is decided at install
time.

What it checks:

| Check | Catches |
|---|---|
| Anonymous root DSE search | Service/DNS wiring, server not listening |
| Admin bind | Wrong or unsynchronised admin Secret |
| Root DN exists | Bootstrap never completed |
| Create OU + user + group, then delete | Admin identity cannot write |
| `memberOf` appears on the test user | **The memberof overlay is not actually loaded** — slapd starts happily without it, so nothing else notices |
| Entry reaches every peer (replicated installs) | Replication configured but not converging |

The write checks create `ou=helm-test,<rootDN>` and remove it again, deleting
any leftovers from an interrupted earlier run first. On a replicated install
they go to one specific pod rather than through the Service: the `memberOf`
assertion has to read back from the node that performed the write, since a
Service read can land on a pod the entry has not reached yet. Propagation to
the other pods is what the replication check covers. Against a directory you
would rather nothing wrote to, `--set tests.write=false` leaves only the
read-only checks.

A failed test pod is deliberately **not** deleted — its log is the entire
report. `helm test` again removes it before creating the next one.

## Upgrades

### Which number is which

A git tag `vX.Y.Z` publishes the chart and both images together, so the chart
version and the image tag are always the same number. `appVersion` is a
different fact — the OpenLDAP release compiled into the server image — and
`scripts/check-versions.sh` fails when those drift apart, because a released
chart once reported OpenLDAP "0.1.0".

### What is known to upgrade in place

| Upgrade | Verdict | On what basis |
|---|---|---|
| OpenLDAP patch release inside 2.6.x | in place | tested on every run: the upgrade job installs the **previous** release, writes data with it, upgrades the image, and asserts the running version changed, the data survived, writes kept working and every replica converged |
| Chart version forward, same OpenLDAP | in place | same job |
| 2.5.x → 2.6.x, or any earlier major | **not tested here** | treat it as a restore, not an upgrade: dump with the old binary, load with the new one |
| Downgrading the server image | **not tested, do not assume** | a database written by a newer `slapd` is not guaranteed readable by an older one. Roll back by restoring a backup, not by pointing the tag backwards |
| Dropping an overlay or module that the live `cn=config` still references | **breaks** | `slapd` refuses to start when `cn=config` names a module the image does not contain, so the pod never becomes ready and the rollout stalls on it |

The chart itself uses only stable APIs — `apps/v1`, `batch/v1`, `policy/v1`,
`networking.k8s.io/v1`, plus `monitoring.coreos.com/v1` when the optional
ServiceMonitor/PrometheusRule are enabled — so there is no Kubernetes version
floor beyond what those require.

### Preflight

`.github/workflows/upgrade-e2e.yml` runs these as gates rather than as advice,
in this order. Do the same:

1. **Take a backup and verify it.** The job triggers the chart's own backup
   CronJob and refuses to continue unless the run reports that it checked both
   dumps against their manifest. This is the only step that helps if the
   rollback below is not enough.
2. **Render the upgrade before applying it** (`helm upgrade --dry-run=client`)
   and confirm the image you expect is in the output. `--reuse-values` does not
   pick up chart defaults added since the installed revision — see the helm
   footguns above.
3. **Check version consistency** (`scripts/check-versions.sh`).
4. **Know which revision you are rolling back to.** `helm rollback <release>`
   with no revision goes to the previous one, which is what you want after a
   failed upgrade. Naming a number gets stale.

### What a rolling upgrade costs

`replicaCount > 1` upgrades one pod at a time behind the PodDisruptionBudget,
so the Service keeps a writable endpoint throughout. The upgrade job measures
this rather than asserting it: a probe pod outside the StatefulSet adds and
deletes an entry once a second for the whole rollout, and the run fails if
writes are ever refused for more than five probes in a row — an isolated
rejection as an endpoint drains is expected, a run of them means no pod was
accepting writes. Across a 2.6.13 → 2.6.14 upgrade of three replicas the most
recent CI run accepted 36 of 38 writes with a longest failure run of 1; the
same test locally accepted 52 of 52 with a longest failure run of 0.

A single-replica install has no second endpoint, so it is unavailable for the
length of one pod restart. There is no rolling anything with one pod — schedule
the window.

## Audit

`audit.enabled=true` instantiates the `auditlog` overlay, which writes an LDIF
record for every write — add, modify, modrdn, delete — naming the bound
identity, the source address and the connection:

```
# modify 1787326667 dc=example,dc=org cn=admin,dc=example,dc=org IP=10.244.0.7:51220 conn=1001
dn: uid=alice,ou=people,dc=example,dc=org
changetype: modify
replace: sn
sn: Audited
```

The attribution is the point. A record that says a change happened without
saying who made it is a change log, not an audit log, and
`.github/workflows/security-e2e.yml` asserts the identity is in the record
rather than trusting that it is.

Off by default: every write costs a record, and a directory nobody audits
should not pay for it.

### Where the records go, and why

`olcAuditlogFile` defaults to `/dev/stdout`, so the records land in the
container log.

The overlay can only write to a file, and every on-disk destination available to
a StatefulSet pod is worse than that:

- the **data PVC** is `ReadWriteOnce`, so nothing else can attach to read the
  file while slapd holds it — the log is only reachable by exec'ing into the pod
  that produced it
- an **emptyDir** disappears with the pod, which is the wrong property for an
  audit trail
- **either one grows without bound**. There is no rotation in the overlay, so
  the log fills the volume and takes the directory down with it — an audit
  feature that eventually causes the outage it was meant to explain.

Sending it to stdout hands retention, rotation and shipping to whatever already
collects container logs, which is where those problems are solved properly.
`audit.file` overrides the destination if you have somewhere better and have
thought about rotation.

### Retention and export

Retention is your log stack's, and the number to configure is there rather than
here. What this chart guarantees is that the records reach it.

Extracting them:

```bash
# everything currently in the pod's buffer
kubectl -n <ns> logs <fullname>-0 -c openldap | \
  awk '/^# (add|modify|modrdn|delete) /,/^# end /'

# from a log store, filter on the same markers — the records are LDIF between
# a "# <op> <time> <suffix> <bound-dn> IP=<addr> conn=<n>" line and "# end <op>"
```

On a replicated install each provider audits the writes **it** received, so a
complete picture means collecting from every pod — replication carries the data,
not the audit records. That is also why the bound identity in the record is the
one that connected to *that* provider.

Two limits worth stating plainly:

- **Password changes put the stored password value in the log.** The overlay
  writes the whole modification as LDIF and has no notion of a sensitive
  attribute, so a `userPassword` change is recorded like any other:

  ```
  # modify 1787421351 dc=example,dc=org cn=admin,dc=example,dc=org IP=[::1]:45580 conn=1017
  dn: uid=alice,ou=people,dc=example,dc=org
  changetype: modify
  replace: userPassword
  userPassword:: e0FSR09OMn0kYXJnb24yaWQkdj0xOSRtPTcxNjgsdD01LHA9MSRWUHZ...
  ```

  It is the argon2 hash as stored, not the cleartext, and it arrives base64
  encoded (`::`) because that hash ends in a NUL byte. Adds carry it too, so
  creating a user writes that user's password hash into the log as well.

  Turning audit on therefore moves password hashes into your log pipeline, where
  they are readable by everyone with access to it and are no longer covered by
  the directory's own ACLs. Treat the audit stream at the same classification as
  the directory itself. `.github/workflows/security-e2e.yml` performs a password
  change and asserts the value is in the record, so this stays a checked
  statement rather than a remembered one.
- **The log is only as trustworthy as the pod.** Anyone who can exec into the
  container or edit `cn=config` can turn the overlay off. Ship the records off
  the node promptly if that matters.

### Reads and binds (`accesslog`)

`auditlog` above is a write-only overlay by design — it has nothing to say
about who read what, or who tried (and failed) to authenticate. `audit.
accessLog.enabled=true` instantiates the counterpart: a second `mdb`
database (`cn=accesslog`, its own files on the `data` PVC, its own
`olcRootDN` reusing the directory admin's password the same way
`cn=Monitor` already does) with the `accesslog` overlay on the main
database writing every search and bind into it. Off by default, same
reasoning as `auditlog`: real disk and log volume, and a directory nobody
reads the trail of should not pay for it.

Configured for reads and binds (`olcAccessLogOps: reads bind`) — a write
already lands in `auditlog`, and duplicating it into a second, externally-
bindable database would just be a second unaudited copy of whatever that
write contained, `userPassword` hashes included. Binds are logged
regardless of outcome (`olcAccessLogSuccess: FALSE`) — a rejected bind
attempt against a privileged DN is exactly the evidence this exists to
capture, and would be invisible if only successes were kept.
`.github/workflows/security-e2e.yml` asserts all of that: a search shows up
with its binder attributed, a failed bind shows up with `reqResult: 49`
(not silently dropped), and a write does **not** show up a second time.

```
$ ldapsearch -x -D cn=admin,cn=accesslog -w <password> -b cn=accesslog \
    "(objectClass=auditSearch)" reqStart reqAuthzID reqDN reqFilter reqResult
dn: reqStart=20260823155413.000004Z,cn=accesslog
reqStart: 20260823155413.000004Z
reqAuthzID: cn=admin,dc=example,dc=org
reqDN: dc=example,dc=org
reqFilter: (objectClass=*)
reqResult: 0

$ ldapsearch -x -D cn=admin,cn=accesslog -w <password> -b cn=accesslog \
    "(objectClass=auditBind)" reqStart reqDN reqResult
dn: reqStart=20260823155732.000004Z,cn=accesslog
reqStart: 20260823155732.000004Z
reqDN: cn=admin,dc=example,dc=org
reqResult: 49
```

Records purge themselves — `audit.accessLog.purgeDays` (default 30) —
because unlike `auditlog`'s stdout there is no external log pipeline doing
that for you here; this database lives on the same PVC as the directory
itself and would otherwise grow without bound the same way an unrotated
`auditlog` file would.

### Exporting both, unified

`scripts/export-audit-log.sh` reads `auditlog` writes and raw replication
diagnostics (container logs, every pod), plus `accesslog` reads/binds (an LDAP
bind, every pod, skipped with a warning on any pod where it is not enabled),
and prints one normalized identity-audit event per line — one feed for a
SIEM instead of separate manual procedures. The replication stream is
deliberately undeduplicated: its `CSN too old, ignoring` lines mix genuine
same-entry conflicts with harmless N-way relay duplicates, so no individual
line is confirmed data loss.

```bash
./scripts/export-audit-log.sh -n <namespace> -r <fullname>
{"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:57:32Z","actor":"cn=admin,dc=example,dc=org","target":"uid=alice,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:directory-ldapium-0:1787500652:uid=alice,ou=people,dc=example,dc=org:cn=admin,dc=example,dc=org","privileged":true,"raw":{"pod":"directory-ldapium-0","source":"auditlog","time":"1787500652","actor":"cn=admin,dc=example,dc=org","op":"modify","target":"dc=example,dc=org","entryDn":"uid=alice,ou=people,dc=example,dc=org","entryUUID":"","changedAttrs":["sn"]}}
{"schemaVersion":"1","source":"accesslog","seq":2,"time":"2026-08-23T15:57:32.000004Z","actor":"cn=admin,dc=example,dc=org","target":"dc=example,dc=org","op":"search","result":"success","objectId":null,"correlationId":"accesslog:directory-ldapium-0:118:20260823155732.000004Z","privileged":true,"raw":{"pod":"directory-ldapium-0","source":"accesslog","time":"20260823155732.000004Z","actor":"cn=admin,dc=example,dc=org","op":"search","target":"dc=example,dc=org","filter":"(objectClass=*)","result":"0","reqSession":"118"}}
```

Every record is wrapped in a common envelope — `schemaVersion`, `seq`,
`time` (RFC3339 UTC, normalized from each source's own native format),
`actor`, `target`, `op`, `result`, `objectId`, `correlationId`, and
`privileged` — with the original per-source fields preserved (with search
filters and changed-attribute lists redacted/sanitized where sensitive)
under `raw`. Full field semantics, derivations, and their documented limits
live in [`docs/audit-event-schema.md`](../../docs/audit-event-schema.md);
`--legacy` reproduces the pre-envelope flat shape for scripts that want it,
but is not a byte-for-byte compatibility guarantee — see that document
before relying on it.

On a replicated install this iterates every pod for the same reason the
extraction procedure above does: each provider only has the events it
personally handled.

### Detecting cn=config drift

`cn=config` is rendered once by each pod's own `entrypoint.sh` at bootstrap and
never touched again unless an operator hand-edits it with `ldapmodify` against
`cn=config` directly — nothing else in this project changes it after that.
`scripts/detect-config-drift.sh` snapshots every pod's `cn=config` and diffs a
later snapshot against a saved baseline, so that kind of out-of-band edit
doesn't go unnoticed:

```bash
./scripts/detect-config-drift.sh -n <namespace> -r <fullname> --baseline > baseline.ldif
# ... later, on a cron or before a maintenance window ...
./scripts/detect-config-drift.sh -n <namespace> -r <fullname> --check baseline.ldif
```

Exit code from `--check` is the actual signal (0 = no drift, 1 = drift found
or a pod unreachable) — suitable as a CI/cron gate; the diff itself goes to
stdout for a human to read. It strips `entryUUID`/`entryCSN`/`creatorsName`/
`createTimestamp`/`modifiersName`/`modifyTimestamp` — bootstrap bookkeeping
that differs on every independent bootstrap even when the logical config is
identical — plus `olcRootPW`, which entrypoint.sh re-hashes with a fresh
Argon2 salt every bootstrap regardless of whether the admin password
actually changed (confirmed live: two containers started with the
byte-identical password produced two different `olcRootPW` values). Without
stripping all seven, redeploying onto a fresh PVC with unchanged Helm values
— an ordinary disaster-recovery event, not a config change — would report as
full drift. `olcSyncrepl`'s `credentials="..."` (the cleartext replication
bind password) is masked to a fixed placeholder rather than compared, so it
never reaches the baseline file or a diff line, same principle as the
`userPassword` denylist above.

## Observability

`metrics.enabled=true` adds an exporter sidecar on port 9330. With Prometheus
Operator installed, `metrics.serviceMonitor.enabled` creates the ServiceMonitor,
`metrics.prometheusRule.enabled` the alert rules, and
`metrics.grafanaDashboard.enabled` a dashboard ConfigMap.
`charts/ldapium/examples/metrics-values.yaml` is a working profile.

### What is exposed

| Metric | Meaning |
|---|---|
| `up{service=<fullname>-metrics}` | the exporter answered a scrape |
| `openldap_monitor_counter_object{dn="cn=Current,cn=Connections,cn=Monitor"}` | connections open right now |
| `openldap_monitor_counter_object{dn="cn=Max File Descriptors,cn=Connections,cn=Monitor"}` | the ceiling those connections run into |
| `openldap_replication_delta{replica=...}` | contextCSN distance from this provider to that peer, in seconds |
| `openldap_pages_used` / `openldap_pages_max` | mdb pages consumed against the map size |
| `kube_job_status_failed` / `kube_job_status_completion_time` | backup Job outcome and age — from kube-state-metrics, not from this chart |

The last row matters when reading the backup alerts: they are the only rules
here whose input comes from somewhere else, so they silently never fire in a
cluster without kube-state-metrics.

### Alerts, and what to do when one fires

Every rule the chart renders by default is exercised by
`tests/prometheus/alerts_test.yaml`, which feeds it the series a real failure
would produce and asserts it fires — and, for several, feeds it a healthy
series and asserts it does not. The rules under test are rendered from this
chart, so the tests cannot drift away from what ships.

The one exception is `LDAPiumTLSCertificateExpiringSoon`, which is not rendered
unless `tlsCertificateExpirationExpr` is set and so cannot be tested from the
default profile. If you set that expression, you are supplying the rule's input
and nothing here has verified it — check it against your own metric.

| Alert | Fires when | First thing to check |
|---|---|---|
| `LDAPiumExporterDown` | no scrape for 5m | Is the pod up at all? The exporter shares the pod, so this is often "the server is gone", not "metrics are gone". `kubectl get pods`, then the container's logs. |
| `LDAPiumReplicationLag` | a peer is more than `replicationLagThreshold` seconds behind for `replicationLagFor` | Compare `contextCSN` on each provider (`ldapsearch -b <rootDN> -s base contextCSN`). A peer that is behind and catching up is different from one that has stopped: check its syncrepl errors in the log. |
| `LDAPiumConnectionSaturation` | connections exceed `connectionSaturationPercent` of the file-descriptor ceiling for 10m | Who is connecting: `cn=Connections,cn=Monitor`. The ceiling comes from the container's open-file limit (`LDAP_MAX_OPEN_FILES`, `ldap.maxOpenFiles`); raise it only after ruling out a client that never closes connections, which is the more common cause. |
| `LDAPiumBackupFailed` | a backup Job reports failure for `backupFailureFor` | `kubectl logs job/<fullname>-backup-<id>`. The run either could not reach the directory or could not write the PVC; both are in the log. |
| `LDAPiumBackupStale` | the newest completed backup is older than `backupMaxAgeSeconds`, for 10m | The CronJob may be suspended, unschedulable, or failing before it completes. Note this fires on *age*, so it also catches a CronJob that silently stopped being created at all. |
| `LDAPiumTLSCertificateExpiringSoon` | the expiry metric is inside `tlsExpiryWarningSeconds` | Renew and restart — see the TLS section. **Only rendered when `tlsCertificateExpirationExpr` is set**; there is no built-in certificate metric, so leaving it empty means no expiry alerting at all. |
| `LDAPiumMDBUsageHigh` | mdb pages exceed 80% of the map for 15m | `ldap.dbMaxSize` is the map size, and it cannot be grown while slapd is running. Plan the restart before the directory hits the ceiling, because hitting it fails writes outright. |

### Offline use

Everything here travels as files in the repository: the rules come from the
chart, the dashboard from `metrics.grafanaDashboard.enabled` as a ConfigMap,
and this table is the runbook. Nothing needs to be fetched from a hosted
dashboard library at install time. `docs/air-gap.md` covers keeping
vulnerability data current, which is the one part of observability that does
not travel as a file.

### Web console health view

The admin UI's "Health" page reads the same `cn=Monitor` subtree the metrics
exporter above does — connection counts, per-operation-type counters, thread
pool status, and the primary database's LMDB page usage. That is the entire
scope: **the UI backend talks to the directory only over LDAP, with no
Kubernetes ServiceAccount**, so pod resource usage (CPU/memory) and the
server's actual log stream are not reachable from it at all — those need
`kubectl top`/`kubectl logs` directly, the same as any other pod. This page
does not attempt to substitute for them; it exists for what LDAP itself can
answer.

**cn=Monitor grants nothing by default — not even to the directory admin.**
Its ACL (`image/ldifs/01-cn-config.ldif`) is `to * by
dn.exact="cn=monitoring,cn=Monitor" read by * none`: only the metrics
exporter's own dedicated bind identity can read it out of the box.
Confirmed against a running container: binding as `cn=admin,<rootDN>` itself
and searching `cn=Monitor` returns `32 No such object`, not "insufficient
access" — an ACL with no disclose right hides the entry's existence rather
than admitting it exists and denying the read, which is standard LDAP
behavior (RFC 4511), not a bug. The health page treats that response as "not
available to this account" rather than a real 404, but the practical effect
is the same: **the page shows nothing until an operator explicitly grants
read access.**

To grant it to your own admin DN (LDAP-password mode) or the SSO service
account (the DN in `ui.ldapServiceAccount`'s secret — see "Keycloak SSO"
above), add a
`by dn.exact=...read` clause to the monitor database's ACL, online, via
`ldapmodify`:

```bash
cat <<'EOF' | ldapmodify -x -D "cn=admin,cn=config" -w "$LDAP_ADMIN_PASSWORD"
dn: olcDatabase={2}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact="cn=monitoring,cn=Monitor" read by dn.exact="<your DN>" read by * none
EOF
```

The monitor database's numeric index (`{2}` above) is whatever this
deployment actually assigned it — confirm with `ldapsearch -x -D
"cn=admin,cn=config" -w "$LDAP_ADMIN_PASSWORD" -b cn=config
"(olcDatabase=monitor)" dn` before modifying, rather than assuming `{2}`.
Widening this ACL to `by users read` instead of naming a specific DN would
let every authenticated directory user see connection and replication
internals — a real security-scope decision, not something this chart makes
for you by default.

**Logs**, in the sense of an audit trail, are reachable a different way:
`cn=accesslog` (when `audit.accessLog.enabled` is set — see "Audit" above)
records reads and binds as ordinary LDAP entries under its own suffix, with
the identical "own dedicated bind identity, `by * none`" ACL shape as
`cn=Monitor`. `scripts/export-audit-log.sh` already reads it this way for
export. slapd's actual write/error log stream, by contrast, goes to
**container stdout only** — `kubectl logs` is the only way to reach that,
today and for the foreseeable future given the no-ServiceAccount design; the
web console does not and will not show it.

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

### RPO and RTO

**RPO is the backup interval, and nothing shortens it but a shorter interval.**
The CronJob takes a point-in-time dump; everything written since the last
successful run is gone after a restore. At the default
`backup.schedule: "0 2 * * *"` that is up to 24 hours. Replication does not
help here — it copies the mistake, it does not keep an older copy.

The actual exposure is observable rather than assumed: every successful run
stamps `lastSuccessAt` on `cn=backup,ou=operations,<rootDN>` (below), and with
`metrics.prometheusRule` enabled, `LDAPiumBackupStale` fires once the newest
completed backup Job is older than
`metrics.prometheusRule.backupMaxAgeSeconds`, `LDAPiumBackupFailed` on a run
that failed outright.

**RTO is dominated by `slapadd`, not by Kubernetes.** The recovery sequence —
scale to 0, wipe the other ordinals, restore into `-0`, scale back up — is
timed end to end by the `3-node backup → bad delete → restore → resync` job in
`.github/workflows/backup-restore.yml`, which publishes `rto.txt` in its
`dr-3node-evidence` artifact. On a kind cluster holding a handful of entries it
measures **46 seconds**, all three replicas serving the restored entry again.

Read that as a floor, not a promise. It leaves out the time to notice and
decide, image pull on a cold node, and the term that actually grows: `slapadd`
of a real directory, which scales with entry and index count. Measure it
against your own data before writing a number into an SLA.

### Encryption at rest

The backup `CronJob` now connects over `ldaps://` whenever `tls.enabled` is
set — previously it connected over plain `ldap://` regardless, sending the
admin bind and every entry (`userPassword` hashes included) unencrypted even
when TLS was on for every other client. Both the data/config PVCs and the
backup PVC delegate encryption at rest to their `StorageClass`; there is no
chart-level encryption of the volumes or the `.ldif.gz` archives themselves.
See [docs/encryption-at-rest.md](../../docs/encryption-at-rest.md) for the
full boundary — what this chart does and does not do, how to verify a
`StorageClass` actually encrypts, and what the built TLS/password-hashing
crypto does and does not certify against.

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

Rendered chart manifests are schema-validated by
[`scripts/verify-chart-schema.sh`](../../scripts/verify-chart-schema.sh), which
CI runs for the default, replicated, TLS, and UI profiles.

## Known gaps

- Not deployed to a real cluster as part of authoring this chart.
