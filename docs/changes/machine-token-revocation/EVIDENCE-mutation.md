# T-017 / T-020 evidence: live cutoff boundary, heartbeat stop, AC-008 and mutation proof

Related to #286 (not closing yet). For the orchestrator to merge into EVIDENCE.md.

## Drills run (images `ldapium:l286a2`, `ldapium-ui:l286a2` built from this worktree)

- `scripts/test/test-machine-cutoff-boundary.py` (new, wired into `machine-keycloak-e2e.yml`): T is the
  server-stamped `createTimestamp` of the cutoff entry, skew 5 s. Tokens are real Keycloak claims re-signed
  with an imported realm key, differing only in `iat`/`exp`/`jti`. The verdict is read from the audit
  `reason`, not only from the status. 9 checks in 19 s.

  | iat | status | audit reason |
  | --- | --- | --- |
  | T-1, T, T+skew-1 | 401 | revoked |
  | T+skew | 401 | revoked |
  | T+skew+1, T+skew+2 | 200 | ok |
  | other client at T, T+skew | 200 | ok |

- `scripts/test/test-machine-live-revocation.py` (extended): 17 checks in 102 s.
  - Heartbeat stopped: both replicas stay 200 until SENTINEL_MAX_AGE (30 s) and are both 503 after 35.7 s
    (30 s + MAX_STALE 6 s); the assertions bound it between 29 s and 43 s. 503 persists, then the next
    heartbeat restores 200.
  - AC-008: after the aged JTI rows are pruned, 4 heartbeat-only cycles with 32 requests per token gave
    32x200 (newer token) and 32x401 (retained near-TTL JTI), zero 503, and sentinel generation 13 -> 17
    with `entries=1`.

## Mutation proof (scratch copy of `ui/`, source restored and diffed identical after each)

| # | Mutation | Unit result | Live drill result |
| --- | --- | --- | --- |
| M1 | revocation hook disabled (`machine.go`, `if m.revocation != nil && false`) | `TestMachineRevocationHook` FAIL | cutoff-boundary FAIL (`iat=T-1` not revoked); live-revocation FAIL (no 503 before the sentinel exists) |
| M2 | digest comparison skipped (`machineauth/revocation.go`) | `TestBuildSnapshot_SwappedEntryDigest` FAIL | both drills PASS: not detected live |
| M3 | stale snapshot returns OK (`Check` ignores MaxStale) | `TestMachineRevocationHook`, `TestRevocationRefreshRetainsSnapshotAndExpires`, `TestCheck_Staleness`, `TestCheck_StalenessMeasuredFromQueryStart` FAIL | live-revocation FAIL (timed out waiting for 503); cutoff-boundary PASS (does not exercise staleness) |
| M4 | cutoff off by one (`!iat.After(T+skew)` -> `iat.Before(T+skew)`) | `TestCheck_CutoffBoundary` FAIL | cutoff-boundary FAIL at `iat=T+skew` (not revoked); live-revocation PASS (zero skew, not at boundary) |

M4's first cutoff-boundary run hit a Docker port-programming error at container start (infrastructure, not a
mutation verdict). It was rerun alone and failed on the assertion above.

## Not exercisable live

- M2 (digest) is not caught by the Keycloak drills. The same-count-replacement case is covered by the
  Go `-tags live` test `TestRevocationReaderLive*` and the unit test above, not by these drills.
- AC-008 with natural aging cannot be waited for live: the tool refuses `--retention` below 4440 s
  (`MIN_RETENTION`), and there is no test override. The aged rows are produced by an offline
  `createTimestamp` fixture (existing), and the N-pinned-to-ts rule is unit-tested
  (`TestBuildSnapshot_CountPinnedToSentinelTS`).
