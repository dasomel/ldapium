# Keycloak LDAP federation: hypotheses, live results, recommended server settings

Class A/B evidence record (no image/chart change is made here). Reproduce with
`scripts/test/test-keycloak-federation-local.sh <image> all` (about 7 minutes,
docker only); a developer helper lives in `scripts/dev/keycloak-local.sh`.

Run details: image built from the tree carrying the OpenLDAP 2.6.15 hardening
plus the Keycloak server settings (`LDAP_LIMITS_DNS`, `LDAP_REFINT_NOTHING`,
`LDAP_IDLE_TIMEOUT=600` default), Keycloak `quay.io/keycloak/keycloak:26.0.7`
(the version `.github/workflows/keycloak-federation-e2e.yml` pins), `start-dev`,
2026-09-30, colima. Final run: `DONE: 0 failure(s), 388 s, 48 PASS, 1 XFAIL (H3 default policy)`. `XFAIL`
lines are findings kept visible on purpose; they do not fail the run. The
harness was first written against an image without the new settings, where H1
and H7 were XFAIL; they are real PASS checks now.

## Results

| H | Claim | Verdict | Evidence |
|---|---|---|---|
| H1 | More than `olcSizeLimit` users truncates a paged full sync unless the bind DN gets `size.prtotal=unlimited` | **CONFIRMED, fixed by `LDAP_LIMITS_DNS`** (PASS) | 12002 users, default `olcSizeLimit: 10000`. Control run without `LDAP_LIMITS_DNS`: paged search (`pr=1000`) 10000 entries then `Size limit exceeded (4)`; Keycloak full sync **reports nothing wrong** and imports `10000 of 12002`. Run with `LDAP_LIMITS_DNS=cn=keycloak-svc,<root>`: paged search 12002, Keycloak 12002 (full sync 16 s), and a non-paged search by the same DN still stops at 10000 (soft/hard pinned by the image). |
| H2 | `olcIdleTimeout` leaves Keycloak's pooled connection dead after idle | **REFUTED** (PASS) | `LDAP_IDLE_TIMEOUT=20` (test speed; image default is 600), 35 s idle, slapd logged 3 `closed (idletimeout)`. First LDAP-backed lookup afterwards succeeded in 1-2 s in all three variants (default pooling, `-Dcom.sun.jndi.ldap.connect.pool.timeout=10000`, `connectionPooling=false`); slapd accepted a fresh connection each time. The JDK drops a pooled connection when the server closes it. No mitigation needed. |
| H3 | WRITABLE password reset as a non-root bind DN is refused by ppolicy `pwdSafeModify` | **CONFIRMED** (default policy: XFAIL, intentional; recipe: PASS) | Read-only DN: refused (ACL). Writer DN with a `userPassword`-scoped write ACL: `ldappasswd` -> `Insufficient access (50) Must supply old password to be changed as well as new one`; Keycloak's passwordless set is refused with `usePasswordModifyExtendedOp=true` (the XFAIL line) and `=false`. Recipe below (per-user `pwdPolicySubentry` -> `pwdSafeModify: FALSE` policy): exop reset works, LDAP bind with the new password 0, Keycloak login 200, old password 401; a user left on the default policy stays protected. |
| H4 | `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` works with the read-only bind DN | **CONFIRMED** (PASS) | Stock ACL lets `cn=keycloak-svc` read `memberOf`. Switching the mapper in place: alice `["developers","marketing"]`, bob `["developers"]`. Caveat: Keycloak's user cache kept bob's old claim after an LDAP-side removal (`memberOf` was already gone server-side) until `clear-user-cache`; the script logs this as INFO, not a directory issue. Same latency applies to any revocation via groups. |
| H5 | `triggerChangedUsersSync` works via createTimestamp/modifyTimestamp | **CONFIRMED** (PASS) | New user imported, modified `sn` updated. Deletions are not seen by a changed sync (bob stayed); a full sync removed him. |
| H6 | LDAPS with strict hostname check, throwaway CA, Keycloak truststore | **CONFIRMED** (PASS) | With the CA in `conf/truststores` plus `KC_TRUSTSTORE_PATHS`: sync, login and groups claim OK. Without the CA: `SSLHandshakeFailed`, 0 users. Same cert via a name not in the SAN: `SSLHandshakeFailed`, 0 users. |
| H7 | Removing the last member of a groupOfNames stays consistent | **CONFIRMED fixed by default `LDAP_REFINT_NOTHING`** (PASS) | Deleting the sole member user (dave) leaves `member: cn=empty-membership-placeholder,dc=example,dc=org` (`olcRefintNothing` shown in `cn=config`), no dangling DN. Directly emptying a group is still `Object class violation (65)`. Keycloak's own placeholder on leave-group is `member: cn=empty-membership-placeholder` (no base DN): it differs from the server default, the two coexist as member values of one group, a real member can join again, and Keycloak lists only the real member. |

## Recommended server-side settings

1. **Large directories (H1).** Set `LDAP_LIMITS_DNS` (chart
   `ldap.limits.pagedUnlimitedDNs`) to the federation bind DN, `;` separated
   for several. Only paged-search limits are lifted; non-paged searches stay
   bounded. Without it an undersized limit makes Keycloak sync silently
   partial (control run above).
2. **Idle timeout (H2).** Keep `LDAP_IDLE_TIMEOUT=600`; no change. JNDI
   clients recover from server-side idle closes.
3. **WRITABLE mode (H3).** The stock ACL gives a service DN no write on
   `userPassword`, so an explicit, narrow grant is needed, and the default
   policy's `pwdSafeModify: TRUE` still blocks a reset without the old
   password. Tested recipe (the test follows it exactly): a second policy with
   `pwdSafeModify: FALSE` attached only to Keycloak-managed users through
   `pwdPolicySubentry`; other users keep the strict default. Do **not** flip
   the default policy.
   ```
   dn: cn=kc-managed,ou=policies,<root>
   objectClass: device
   objectClass: pwdPolicy
   cn: kc-managed
   pwdAttribute: userPassword
   pwdMinLength: 8
   pwdSafeModify: FALSE
   pwdAllowUserChange: TRUE

   dn: uid=<user>,ou=people,<root>
   changetype: modify
   replace: pwdPolicySubentry
   pwdPolicySubentry: cn=kc-managed,ou=policies,<root>
   ```
   ACL, scoped to the password attributes (not whole-base write), ahead of the
   stock rules:
   ```
   olcAccess: {0}to dn.subtree="ou=people,<root>" attrs=userPassword,shadowLastChange by dn.exact="<writer DN>" write by * break
   ```
   Profile-attribute or group writes (Keycloak WRITABLE beyond passwords) need
   further grants; the placeholder scenario in the script uses a broad
   whole-base writer grant for that reason, in a throwaway container only.
4. **Group placeholders (H7).** Nothing to set: the image default
   `LDAP_REFINT_NOTHING=cn=empty-membership-placeholder,<root>` covers it.
   A `member` placeholder (either DN) must be filtered from member listings in
   the UI/API.
5. **TLS (H6).** No server change; Keycloak needs the CA in its truststore and
   a name from the certificate's SAN in `connectionUrl`.

## Scope and limits

Only local docker (colima) evidence; nothing was run in GitHub Actions. The
two workflow steps added to `keycloak-federation-e2e.yml` (changed-sync,
memberOf) mirror the script's groups but were only lint-checked
(`actionlint`, YAML parse) here. `scale`, `idle` and `tls` are deliberately
not in the workflow (12000-user bulk load, 35 s wait, extra images).
