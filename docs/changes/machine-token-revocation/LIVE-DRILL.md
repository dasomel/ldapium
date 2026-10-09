# Live revocation enforcement evidence

Related to #286; partial acceptance until the source multi-provider evidence,
independent review, whole CI and close-out documentation are complete.

Plan: execute the production bearer path on two unchanged UI containers against
real Keycloak and LDAP, using the operator tool. Extend the existing release-critical
job without changing its name or trigger. No production identities, ACLs or data are used.

Observed command:

```sh
LDAPIUM_IMAGE=ldapium:revocation-integration \
LDAPIUM_UI_IMAGE=ldapium-ui:revocation-integration \
LDAPIUM_REVOCATION_TOOL=/tmp/ldapium-revocation-tool/scripts/machine-revocation.sh \
python3 scripts/test/test-machine-live-revocation.py
```

Fresh server and UI images were built from the tested worktrees. The latest complete
run passed 16 checks in 93 seconds; logs: `/tmp/ldapium-live-revocation-drill.log`.
The script prints relative time, status and convergence duration without token identifiers.

| Trigger | Both UI replicas | Evidence |
| --- | --- | --- |
| Missing sentinel, valid JWT | 503 | initial fail closed; invalid JWT still 401 |
| Initialize sentinel | 200 | no UI restart; human login/read/logout unchanged |
| Add actual Keycloak JTI | 401 | observed about 1 second; container IDs unchanged |
| Remove JTI | 200 | both recover |
| Add client cutoff | old JWT 401; newer JWT 200 | actual server createTimestamp compared with both iat values; skew 0 |
| Malformed device entry | 503 after stale budget | delete + heartbeat recovers |
| LDAP ACL hides revocation rows | 503 after stale budget | restoring ACL + heartbeat recovers |
| Lower sentinel generation | 503 after stale budget | monotonic heartbeat recovers |
| Stop LDAP | 503 after stale budget | restart + heartbeat recovers |
| Offline-aged JTI fixtures | old matching JTI stays 401; newer JWT 200 | heartbeat prunes ret+30s marker without downtime; near-TTL matching JTI retained after prune |
| Active entries exceed cap | 503 | cleanup + heartbeat recovers |
| Stop heartbeat | 503 after sentinel age + stale | new heartbeat recovers |
| Other client outside allowlist | 401 | allowed newer JWT still 200; individually revoked JWT 401 |

All container logs passed the token/credential scan. Temporary containers and networks
were cleaned. The age fixture uses slapmodify while the disposable server is stopped,
then reads actual createTimestamp values back. This is not natural 4440-second aging;
exact equality is covered by the pure snapshot tests. This drill uses one LDAP node;
actual peer partition/lag and L4 alternation are separate source evidence.

Mutation: a separately built UI image with only the post-verification revocation hook
removed failed this same drill at its first valid-JWT/missing-sentinel check: timed out
waiting for both replicas to return 503. `/tmp/ldapium-live-revocation-mutation.log`.
The production implementation was untouched by the mutation.

ACL denial is injected and restored with offline `slapmodify` on the disposable
LDAP volume. CI run 37929754840 stalled in a live `olcAccess` replacement with
active snapshot readers; the fixture now bounds the stop/configuration commands
and avoids that concurrent configuration path. Both UI container IDs remain
unchanged. A real machine-identity search must return LDAP success and zero
entries under the denial before the HTTP fail-closed assertion; this is not an
outage-only substitute. This fixture does not prove concurrent runtime ACL
reconfiguration reliability.
