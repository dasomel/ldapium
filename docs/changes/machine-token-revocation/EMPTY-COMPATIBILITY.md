# Enabled empty-snapshot compatibility

Related to #286 T-018; full CI and independent review are still pending.

Run each existing real-server machine contract through
`scripts/test/test-machine-empty-revocation-compat.py <original-script>`.
The original scripts and their HTTP assertions are unchanged. The test-only
runner initializes an empty revocation sentinel and enables revocation for
machine-enabled fixture containers, with refresh 60 s, max-stale 180 s and
sentinel age 1 h. Machine-disabled containers still exercise the existing
feature-off rollback behavior.

The source adds background binds. Request-bind assertions therefore count real
LDAP accesslog bind sessions, excluding only sessions with an observed search
on the revocation base. They do not claim the raw total bind count is unchanged.
Missing bind session identifiers or accesslog errors fail the test. Source
results, HTTP responses and tokens are never fabricated.

Observed with real Keycloak `26.7.4`, freshly built
`ldapium:revocation-integration` and `ldapium-ui:revocation-integration`:

| Existing contract | Observed result | Local artifact |
| --- | --- | --- |
| Machine auth, both UI modes | 71 checks, 127 s, exit 0 | `/tmp/ldapium-revocation-empty-main.log` |
| Keycloak client settings | 35 checks, 47 s, exit 0 | `/tmp/ldapium-revocation-empty-settings.log` |
| Emergency rollout and feature-off rollback | 18 checks, 44 s, exit 0 | `/tmp/ldapium-revocation-empty-drill.log` |
| JWKS rotation/outages | 34 checks, 246 s, exit 0 | `/tmp/ldapium-revocation-empty-jwks.log` |

All completed scripts passed their container-log secret scans and cleaned up.
The initial main run hit a disposable Docker host-port allocation collision;
the retry above completed successfully. Feature-off contracts continue to run
directly in the same release-critical job before these enabled runs. Independent
review and complete CI remain required before checking T-018.
