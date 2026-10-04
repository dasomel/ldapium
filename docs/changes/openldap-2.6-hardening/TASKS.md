# Tasks: OpenLDAP 2.6 hardening (image)

Link this checklist to the related Change Package. Every implementation task SHOULD name the requirement or acceptance scenario it advances.

## Implement

- [x] `T-010` (`REQ-001`,`REQ-002`,`REQ-005`,`REQ-006`) entrypoint.sh env contract, validation, section 3b reconcile, probe change.
- [x] `T-011` (`REQ-003`) 01-cn-config.ldif indexes.
- [x] `T-012` (`REQ-004`) ppolicy `pwdFailureCountInterval`.
- [x] `T-013` Dockerfile HEALTHCHECK to SASL EXTERNAL.
- [x] `T-014` (`REQ-007`) Group C: nestgroup build flag, ppm build (D9), section 3c overlay reconcile, replication guards (D8).
- [x] `T-015` D6 lastbind opt-in, D7 TLS EC default empty + validation, D10 peer check binds with replication DN.
- [x] `T-016` Reviewer findings H1-L8 addressed (see CHANGE.md Review record); chart-side items done in the chart lane.

## Verify

- [x] `T-020` shellcheck -s sh image/entrypoint.sh (re-run 2026-09-29 on the current tree, image rebuilt as ldapium:e2e: exit 0, no findings).
- [x] `T-021` (`AC-001`..`AC-004`) local container runs (Group A/B, earlier session).
- [x] `T-022` Group B container recheck on the current image (2026-09-29): healthy, and healthy again after `docker restart`; anonymous bind -> 48 "anonymous bind disallowed"; plaintext simple bind -> 13 "confidentiality required"; `ldapwhoami -Y EXTERNAL -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi` works (the bare `ldapi:///` default path is not the image's socket).
- [x] `T-023` 2-node test of the D10 H1 peer check (2026-09-29, both nodes `LDAP_DISALLOW_ANON_BIND=true LDAP_REQUIRE_AUTHC=true`, TLS off): node 1 (ols-0) wiped and restarted logged `peer already has the base DIT: ldap://ols-1:389 — skipping local slapadd -n 1`; base entry entryUUID identical on both nodes afterwards. FINDING (unresolved, pre-existing structure, see CHANGE.md Review record): entries added after the initial sync (uid=bob, uid=eve) were gone from BOTH nodes after the wipe.
- [x] `T-024` `scripts/test/test-bootstrap-seed.sh ldapium:e2e` on the current image (2026-09-29): 13/13 PASS, "all bootstrap seed tests passed".
- [ ] `T-025` replication-chaos E2E with `LDAP_LASTBIND_ENABLED=true` (required before D6 default can change). Chaos E2E NOT run; a manual 2-node observation was made (see D4): pwdLastSuccess replicates and bumps the user entry's entryCSN. A partition run (single, unrepeated) showed lastbind silently reverting an admin password change via last-write-wins on entryCSN (details in D4); the chart now refuses lastBind with replication unless `allowWithReplication=true`.
- [x] `T-026` real-certificate TLS end-to-end (2026-09-29, throwaway CA + RSA server cert, SAN localhost + container name, certs baked into a derived image per AGENTS.md; image rebuilt from the current tree). TLS on: healthy; `ldaps://` and `-ZZ` binds succeed with `LDAPTLS_CACERT`; a client without the CA fails "certificate verify failed"; `olcTLSProtocolMin: 3.3` and the ECDHE-only `olcTLSCipherSuite` present, `olcTLSECName` absent by default; server refuses TLS 1.1 ("alert protocol version") and a non-ECDHE cipher ("handshake failure"); TLS 1.2/1.3 handshakes succeed. `LDAP_REQUIRE_TLS=true` + `LDAP_TLS_EC_NAME=secp384r1`: plaintext simple bind -> 13, ldaps and -ZZ OK, HEALTHCHECK command (`-Y EXTERNAL` over ldapi) OK, healthy after `docker restart`; `olcSecurity: ssf=128`, `olcLocalSSF: 128`, `olcTLSECName: secp384r1`; `s_client -curves secp384r1` succeeds (1.2 and 1.3), `-curves prime256v1` is refused (handshake failure) - the documented compat risk is real. Note: a libldap client canonicalizes `ldaps://localhost` to the container hostname and fails hostname checks against a SAN of `localhost` - client-side, not a server fault. Not covered: mutual TLS, ECDSA certificate, replication over ldaps.
- [ ] `T-027` CI coverage for Group B flags.
- [x] `T-028` Group C live check (2026-09-29, image `ldapium:hv6`, fresh volume and a volume upgraded in place from the HEAD image): `LDAP_DEREF_ENABLED`/`LDAP_CONSTRAINT_ENABLED` true->false->true->false->true across restarts on both: healthy every time, RestartCount 0, overlays `{0}memberof {1}refint {2}ppolicy {3}unique` stay stable with `{4}deref {5}constraint` added/removed/re-added at the same indices. ppm via `ldappasswd` as the user (admin bypasses ppolicy): `LDAP_PPM_MIN_CLASSES=3` rejects `qwertyui` ("does not pass quality", 19) and accepts `Qwerty1x`; `=1` accepts `asdfghjk`. Operator-tuned `minQuality 2` survived a restart with the variable unset. `LDAP_PPM_ENABLED=false` removed `olcPPolicyCheckModule` and `pwdUseCheckModule`/`pwdCheckModuleArg`, after which the HEAD image started healthy on that volume (without that step it exits: `lt_dlopen(/usr/lib/openldap/ppm.so) failed: file not found`). Ownership rule (D12) verified. D8 guards (dynlist/nestgroup with replication) remain reasoned only; the chart-side dynlist guard was checked with `helm template` only. Not covered: nestgroup/dynlist/sssvlv/otp overlays live.

## Synchronize durable truth

- [x] `T-030` image/README.md (env table, reconcile section, module table, HEALTHCHECK).

## Out of scope / separate issue

- Self-service `userPassword` replace without the old password was observed once (likely admin-bound; unconfirmed).
- Chart `README-ko.md` summary table drift.
