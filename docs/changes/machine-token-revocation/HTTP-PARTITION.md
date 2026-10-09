# Actual HTTP enforcement under LDAP replication partition

Related to #286 (not closing yet). This test uses actual two-provider slapd replication and real Keycloak tokens. Two unchanged UI containers point to different LDAP providers. The providers share a replication-only bridge with peer aliases; UI connections keep a separate client bridge. Disconnecting one provider from the replication bridge leaves its LDAP service reachable while preventing peer synchronization. No LDAP replies or clocks are fabricated.

Observed behavior: after a real JTI write on the healthy node, its HTTP endpoint returns 401. The isolated node temporarily returns 200 from its previously valid directory snapshot, then returns 503 after real sentinel aging and the local stale budget. The test verifies the isolated LDAP server still answers administrator queries. Reconnection and ordinary heartbeat updates cause both unchanged UI containers to return 401. Raw container logs must contain no credentials or tokens.

Configuration: refresh 1s, max-stale 6s, sentinel max-age 30s. The observational bound is 42s (30s age + 6s stale + one 5s query budget + 1s scheduling margin); the script prints actual elapsed time. Failure throttling is raised only in the fixture so repeated revoked-token polling does not obscure the revocation outcome. Heartbeats continue during recovery so recovery does not depend on a second sentinel expiration. This is a two-node HTTP partition check; transparent L4 alternation and source connection pinning are covered by the separate source fixture.

Run:

```sh
LDAPIUM_IMAGE=ldapium:revocation-integration \
LDAPIUM_UI_IMAGE=ldapium-ui:revocation-integration \
python3 scripts/test/test-machine-http-partition.py
```

The release-critical machine Keycloak workflow runs this fixture against freshly built images and treats leftover objects under its owned prefix as failures. Full compatibility and issue close-out remain separate acceptance work.

Observed final run: all four checks passed in 76s; isolated HTTP became 503 after 33.65s from the JTI write (`/tmp/ldapium-http-partition-final.log`). Initial runs established partition/stale behavior but recovery polling was obscured by fixture throttling and heartbeat expiration; the final fixture explicitly maintains heartbeat during recovery and raises only its test throttle. Python compilation and diff hygiene passed.
