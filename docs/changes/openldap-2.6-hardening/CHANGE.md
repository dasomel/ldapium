# Change: Adopt OpenLDAP 2.6 recommended hardening in the server image

- Change class: `D` (security boundary; image side only)
- Owner: image lane (chart/ui handled separately)
- Related issue: none
- Status: `Implementing`
- Accepted by / date: pending

## Problem

The image ships slapd with compiled-in resource limits (no idle/write timeout, large pending queues, unbounded filter depth), no lastbind record, no failure-count aging in the default ppolicy, and no way to require TLS or refuse anonymous access.

## Intent

Explicit resource limits (Group A: idle/write timeouts and filter depth are new caps; `olcConnMaxPending*` and `olcSockbufMaxIncoming*` pin slapd's compiled defaults explicitly rather than newly capping), opt-in lastbind, optional modules (Group C), plus opt-in transport/authentication requirements (Group B) that change nothing when unset.

## Scope

- In scope: `image/entrypoint.sh`, `image/ldifs/01-cn-config.ldif`, `image/Dockerfile` (HEALTHCHECK, `--enable-nestgroup=mod`, ppm build), `image/README.md`; chart-side guards/probes/NetworkPolicy/helm test and UI filter were done in the chart lane.
- Affected: every deployment of the image. Chart/UI wiring is owned by another lane.
- Also in this working tree, separate and small: the `ui/` change (`ServerVersion` reads the Root DSE, then falls back to `monitoredInfo` on `cn=Monitor`). It is a related but independent change. The fallback works only if the bound identity may read `cn=Monitor`; otherwise the version is reported as unavailable.

## Non-goals

- DH parameter file; changing `pwdMinLength` defaults; chart/ui changes.

## Requirements

- `REQ-001` Group A env vars (names/defaults in README) map to `olcIdleTimeout`, `olcWriteTimeout`, `olcConnMaxPending(Auth)`, `olcSockbufMaxIncoming(Auth)`, `olcMaxFilterDepth`, `olcTLSECName` (TLS only, default empty).
- `REQ-002` Opt-in (`LDAP_LASTBIND_ENABLED`, default false) `olcLastBind`/`olcLastBindPrecision` on the main mdb database; records `pwdLastSuccess`. Multi-provider behavior UNVERIFIED.
- `REQ-003` New indexes `uidNumber`, `gidNumber`, `memberUid`, `uniqueMember` (all defined by the loaded `nis`/`core` schemas).
- `REQ-004` Default ppolicy gets `pwdFailureCountInterval` from `LDAP_PASSWORD_FAILURE_INTERVAL` (900).
- `REQ-005` Group B (`LDAP_REQUIRE_TLS`, `LDAP_DISALLOW_ANON_BIND`, `LDAP_REQUIRE_AUTHC`) default off, no behavior change when unset; `LDAP_REQUIRE_TLS` keeps `ldapi://` and the HEALTHCHECK working. `LDAP_REQUIRE_TLS` with a non-`ldaps://` replication peer also fails fast.
- `REQ-007` Group C (`LDAP_PPM_*`, `LDAP_DEREF_ENABLED`, `LDAP_CONSTRAINT_*`, `LDAP_NESTGROUP_*`, `LDAP_DYNLIST_*`, `LDAP_SSSVLV_MAIN_*`, `LDAP_OTP_ENABLED`) reconciled every start; ppm/deref/constraint default on, the rest off.
- `REQ-006` `LDAP_DISALLOW_ANON_BIND` / `LDAP_REQUIRE_AUTHC` together with `LDAP_ANONYMOUS_READ_BASE` fail fast.

## Acceptance scenarios

### `AC-001` — defaults applied
- Covers: `REQ-001`..`REQ-004`
- Given a fresh container with only required env
- When cn=config and the mdb database entry are read as `cn=admin,cn=config`
- Then every Group A attribute holds its default, Group B attributes are absent, and the container is healthy. (`pwdLastSuccess` appears after a user bind only with `LDAP_LASTBIND_ENABLED=true`.)

### `AC-002` — hardening on
- Covers: `REQ-005`
- Given all three Group B variables true
- Then anonymous bind returns 48, plaintext simple bind returns 13, `ldapi://` (EXTERNAL and simple) works, container stays healthy across a restart.

### `AC-003` — contradiction
- Covers: `REQ-006`
- Then startup exits with a message naming both variables.

### `AC-004` — restart reconciles
- Given an existing volume restarted with changed env
- Then changed values are applied and turned-off opt-ins are removed.

## Architecture and decisions

- ADR threshold result: `not required` — configuration of existing slapd features, no new component.
- `D1` Reconcile on every start via offline `slapmodify -n 0` (new section 3b), not bootstrap-only. Reason: existing volumes must pick up hardening on image upgrade and env changes; cost: one sub-second slapmodify per start. Escape hatch: values are plain `olc*` attributes, editable via `ldapmodify`. Indexes and the ppolicy entry stay bootstrap-only (index changes need `slapindex`; the policy is directory data).
- `D2` `olcSecurity: ssf=128` only, not `ssf=128 tls=128`. Verified live: `tls=` counts only the TLS layer, which `ldapi://` never has, so it refuses the HEALTHCHECK and the entrypoint's own ldapi calls even with `olcLocalSSF: 128` (err=13). `ssf=128` still rejects plaintext TCP.
- `D3` HEALTHCHECK and the entrypoint's temp-slapd readiness probe switch from anonymous `ldapwhoami -x` to `ldapwhoami -Y EXTERNAL`. Reason: an anonymous simple bind is exactly what `bind_anon`/`authc` refuse, and the setting persists in cn=config so it would break the probe on the next restart. Downstream: the chart's start/liveness/readiness probes currently use `-x` over ldapi and must move to `-Y EXTERNAL` before Group B is enabled there.
- `D4` Lastbind vs multi-provider: `olcLastBind` is a per-database option, independent of `olcMultiProvider`/`olcSyncrepl`, so the replication section (which only touches `olcServerID`, `olcSyncrepl`, `olcMultiProvider`, syncprov) is unaffected. `pwdLastSuccess` is an ordinary modify that replicates and refreshes `entryCSN` of the user entry, so a concurrent edit of the same entry on another node can lose last-write-wins to a bind; `LDAP_LASTBIND_PRECISION=3600` bounds this to one write per user per hour, and `LDAP_LASTBIND_ENABLED=false` opts out. **Superseded by D6:** lastbind is opt-in. Observed live 2026-09-29 (2 nodes, `LDAP_LASTBIND_ENABLED=true`, precision 3600): a successful bind of a fresh user on node A wrote `pwdLastSuccess` on A, it appeared on node B, and the user entry's `entryCSN` changed on both nodes (new CSN at bind time, writer's serverID) — i.e. the bind is an ordinary replicated write that competes last-write-wins with real edits. Only a single-writer case was tried; concurrent edit vs bind and the chaos E2E were not run. **Later finding (another worker, one run, not repeated):** in a 2-node multi-provider setup with `LDAP_LASTBIND_ENABLED=true`, a partition sequence silently REVERTED an admin password change: node B admin-changed X's password to NEW; node A (partitioned) accepted a bind with OLD, and its `pwdLastSuccess` write got a newer `entryCSN` (13:41:40 vs B's 13:41:34); after reconnect last-write-wins made A's state win, so NEW failed (err=49) and OLD succeeded on BOTH nodes. Ordinary concurrent (non-partition) writes converged (20 iterations, identical entryCSN). Consequence: keep lastbind off on multi-provider deployments; the chart refuses it with replication unless `ldap.lastBind.allowWithReplication=true`.
- `D5` `olcTLSECName` set only when TLS is enabled; no DH params (ECDHE-only cipher baseline).
- `D6` `LDAP_LASTBIND_ENABLED` defaults to `false`. Reason: whether `pwdLastSuccess` writes replicate cleanly under multi-provider (entryCSN churn, last-write-wins against real edits) is UNVERIFIED. Cost: no last-login data by default. Escape hatch/condition: run the replication-chaos E2E with lastbind on; only then may the default flip. Any earlier claim that lastbind is default-on or replication-verified is void.
- `D7` `LDAP_TLS_EC_NAME` defaults to empty (attribute not emitted, OpenSSL negotiates). When set it is validated (`[A-Za-z0-9_-]+` and `openssl ecparam -list_curves`) because a bad curve lands verbatim in cn=config and stops slapd on the next boot. Reconcile removes the attribute when empty or TLS off.
- `D8` `dynlist` and `nestgroup` `member-values`/`memberof-values` are refused with `LDAP_REPLICATION_ENABLED`: they rewrite entries as returned, and a syncrepl consumer search takes the same path, so computed values would enter the stream. Reasoned, NOT verified; lifting the guard needs a 2-node test. `member-filter`/`memberof-filter` stay allowed.
- `D9` ppm is built from `contrib/slapd-modules/ppm` of the already SHA-verified 2.6.15 tarball (no new source fetched), `CRACK=no` (no dictionary/libcrack in the runtime image), installed as `/usr/lib/openldap/ppm.so` and loaded by path through `olcPPolicyCheckModule`. Defaults: `LDAP_PPM_ENABLED=true`, `LDAP_PPM_MIN_CLASSES=1` (near-permissive). ppm arguments are written to `cn=default,ou=policies` only when they differ.
- `D10` (H1 resolution) The first-boot peer check for an existing base DIT binds with the replication DN/password (0600 temp file), not anonymously, so peers with `LDAP_DISALLOW_ANON_BIND`/`LDAP_REQUIRE_AUTHC` are not mistaken for "no base DIT". Any failure still counts as "not found" (#203/#204 semantics unchanged). Exercised 2026-09-29 with two nodes (both anon-bind-disallowed): the wiped node logged `peer already has the base DIT` and both nodes share the base entry's entryUUID. See the wipe finding under Review record.
- `D12` Ownership rule for reconcile. Group A limits and switched-ON opt-ins are env-owned and overwritten each start. A switched-OFF opt-in is removed only if its current value equals what the entrypoint writes (`olcSecurity ssf=128`, `olcLocalSSF 128`, `olcDisallows bind_anon`, `olcRequires authc`, `olcLastBind TRUE` + precision, ppm module path, `pwdUseCheckModule TRUE`); other values are operator-set and kept, with a log line. `olcTLSECName` stays env-driven. Verified live: custom `olcSecurity: simple_bind=0` and `olcDisallows: tls_2_anon` survived restarts with flags off; flags on applied `bind_anon`/`authc` (operator `olcSecurity` untouched); on->off removed ours.
- `D13` ppm policy attributes on `cn=default,ou=policies` are written when the wiring is missing and re-applied only when `LDAP_PPM_MIN_CLASSES` is explicitly set (unset leaves operator `ldapmodify` tuning alone); removal when `LDAP_PPM_ENABLED=false` stays. They are offline slapmodify writes without `-S`/`-w`: sid 000 CSN, no contextCSN update, NOT replicated, applied per node. The chart always sets the env var, so with the chart the value is re-applied every start. ppm counts ASCII character classes only: a Hangul-only passphrase is rejected when `LDAP_PPM_MIN_CLASSES` > 1.
- `D11` Modules and overlays (section 3c): module loads first (own slapmodify), then overlays added/modified in place/deleted. Disabling removes the overlay but leaves `olcModuleLoad` and the `dyngroup` schema in cn=config. Overlays are modified in place to keep `{N}` order stable.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | New env vars; HEALTHCHECK command changed |
| Dependencies / lockfiles | N/A — none |
| Runtime / toolchain | SASL EXTERNAL over ldapi (present in image, verified) |
| CI / CD | shellcheck on entrypoint.sh |
| Release / packaging | Image behavior change (Group A defaults): idle/write timeouts and PDU limits now apply |
| Generated output | N/A |
| Security / supply chain | Reduces DoS surface; opt-in TLS/auth requirements |
| Offline / air-gap | N/A |
| Documentation / operations | image/README.md env table + reconcile note |
| Portfolio / downstream repositories | Chart probes and values (other lane) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | ldapsearch as cn=admin,cn=config + bind | local Colima container | attribute dump |
| `AC-002` | ldapwhoami variants + restart | local container | error codes 48/13, healthy |
| `AC-003` | docker run with contradiction | local | error line |
| `AC-004` | recreate on same volumes with changed env | local | changed attrs |

## Rollout, rollback and recovery

- Rollout: new image over existing volumes applies Group A on first start.
- Rollback: an older image does NOT ignore the extra attributes. With ppm default-on, an upgraded volume holds `olcPPolicyCheckModule: /usr/lib/openldap/ppm.so` (plus `nestgroup.la` if enabled) and an image without `ppm.so` fails at config load (`lt_dlopen(...ppm.so) failed: file not found`), so slapd crash-loops. Downgrade procedure: restart once on the NEW image with `LDAP_PPM_ENABLED=false` (and any opt-in modules false) so the reconcile removes the wiring, then roll back; or restore from backup. Verified live 2026-09-29 (T-028): after that restart `olcPPolicyCheckModule` was gone from the ppolicy overlay and `pwdUseCheckModule`/`pwdCheckModuleArg` from the default policy, and the older image (HEAD build) started healthy on the same volume; without the step it exited with the lt_dlopen error above.
- Compatibility: clients holding idle connections >10 min are dropped; bulk loads exceeding 4 MiB PDUs are refused; raise the variables if needed.

## Evidence and durable synchronization

- Evidence: this session's local container output (see TASKS.md); no CI job added.
- Docs updated: `image/README.md`.

## Review record

- Open questions: live replication with lastbind (replication-chaos E2E), and the D8 guards are not verified. Out of scope: self-service `userPassword` replace without the old password was observed once (likely admin-bound, unconfirmed, not investigated; separate issue); chart README-ko summary table drift (separate issue).
- Reviewer findings and resolution (authoritative wording; an earlier docs pass had to guess L6-L8 and the chart-side resolutions):
  - `H1` anonymous peer check misread as "no base DIT" -> D10 (image).
  - `H2` lastbind default-on with unverified multi-provider behavior -> default now false (D6).
  - `M3` chart guard missed the UI anonymous uid->DN lookup case -> chart now fails when `ui.enabled` and `userSearchFilter` are set together with `disallowAnonBind`/`requireAuthc`.
  - `M4` `helm test` readiness used an anonymous rootDSE search -> now admin-authenticated.
  - `M5` `networkPolicy.ingressFrom: []` rendered allow-all -> render now fails on an empty list.
  - `L6` chart README claimed Group A applies only at first bootstrap, that upgrades change nothing, and named the attribute `authTimestamp`; the code reconciles every start, upgrades DO change behavior, and the attribute is `pwdLastSuccess` -> fixed in the chart and image READMEs.
  - `L7` `LDAP_REQUIRE_TLS=true` with plain `ldap://` replication peers silently stopped replication -> now fails fast in the entrypoint.
  - `L8` `olcTLSECName` default `secp384r1` restricted key exchange to one curve -> default now empty, validated when set (D7).
  - Chart-side items are recorded from the chart lane's report, not re-verified here.
- Real-certificate TLS end-to-end verified 2026-09-29 (T-026): ldaps/StartTLS/verification, TLS 1.1 refused, `LDAP_REQUIRE_TLS` 13 + healthcheck, `LDAP_TLS_EC_NAME` accept/refuse behavior.
- Verification 2026-09-29 (Colima, image rebuilt from the current tree): shellcheck clean; Group B recheck pass (T-022); `test-bootstrap-seed.sh` 13/13 (T-024); 2-node peer check pass (T-023); lastbind replication facts in D4.
- OPEN FINDING (data loss, not caused by this diff; structure exists at HEAD): in the 2-node test, after wiping node 1's (serverID 1) volumes, entries written after the initial sync (`uid=bob`, `uid=eve`) disappeared from both nodes. The wiped node creates `cn=default,ou=policies` locally (entrypoint "creating password policy" runs before the peer check, at HEAD as well) and stamps it with a fresh serverID-1 CSN newer than the peer's cookie for sid 1, so the peer appears to treat the wiped node as ahead and its present-phase refresh removes entries the wiped node lacks. Cause is inferred from the syncrepl log, not isolated by a controlled test. Needs its own issue; not fixed here (replication design change).
