# ADR: verified-TLS read-only replication identity (D50–D67)

- Status: `Accepted (design only; implementation acceptance conditions remain open)`.
  This records the design already accepted by dasomel on 2026-10-06 in
  [CHANGE.md](CHANGE.md). It does not grant a new implementation acceptance.
- Owner: dasomel (maintainer).
- Issue: [#229](https://github.com/dasomel/ldapium/issues/229), still open.
- Evidence and outstanding work: [EVIDENCE.md](EVIDENCE.md), [TASKS.md](TASKS.md).
- ADR threshold: required, because credentials, privileged identities and
  replication/recovery behavior cross the directory trust boundary.

## Context

The administrator password originally remained in slapd's inherited environment.
The entrypoint now clears credentials before starting slapd, with an actual
`/proc/1/environ` regression. Simple-bind syncrepl still persists its credential
in cleartext in cn=config by protocol/configuration design. Binding replication
as the rootDN makes that persisted credential administrator-capable. The chosen
change reduces its privilege instead of claiming the cleartext disappears.

## Decisions

| ID | Decision | Cost and escape hatch |
|---|---|---|
| D50, D58 | Keep `admin` as the compatible default. Opt-in `prepare` installs controls while retaining administrator replication; `dedicated` selects the reserved `cn=replicator,<root>` and its credential together. | Existing defaults remain unchanged. Return to admin only after the nonempty/synchronized-node and administrator credential rollback gates. |
| D51, D51a | An explicit first ACL permits identity reads only with `ssf=128`; an explicit first limits rule allows complete replication reads. Keep it ahead of machine principal rules. | RootDN still bypasses ACLs; do not make the reserved identity a rootDN. Inspect configuration and data, rather than relying on contextCSN alone. |
| D52, D53 | Create the identity and explicit non-expiring/non-locking password policy only through an administrator operator command. Entrypoint startup does not create them. | The identity lacks online password-guessing lockout; use verified TLS, network restrictions and a CSPRNG credential. Retire is an explicitly destructive operator operation. |
| D54, D60, D61, D64, D65 | Dedicated mode is verified LDAPS/simple-bind only. Every node, including sid 1, is consumer-only and creates no base DIT. Refuse unsafe TLS/SASL/proxy-authorization mappings and reserved rootDN collisions. | mTLS/SASL EXTERNAL coexistence is outside this design. Fail closed with fixed diagnostics, never administrator fallback. |
| D55 | Rotation adds the new password before changing consumers; remove prior values only after every consumer configuration fingerprint matches the new credential. Derive resumable state from directory/configuration. | Rollback retains/re-adds the old credential. Current operator rotation/fingerprint orchestration is not yet fully implemented/accepted. Existing sessions can retain old credentials even when configuration is new. |
| D56 | Relax the shared administrator password constraint only in dedicated mode, after the recovery/security CI gates pass. | The relaxation is optional and remains disabled; admin/prepare retain D43. |
| D59, D59b | Inspect explicit data attributes with stable entryCSN sampling, configuration predicates, consumer fingerprints and cross-node/canary gates. Periodic checks are default-off jobs with explicit administrator credential access. | Enumerated attributes miss unlisted ACL defects, root-view losses, discarded LWW writes and gaps between checks. Complete cross-node/periodic checks remain outstanding. |
| D63, D67 | After total loss, restore one node offline; keep peers stopped, start dedicated with the current credential, reconcile the restored identity, verify configuration/data, then refill peers. | A backup restores old hashes. Successful credential bind is only one primitive, not a complete recovery gate. Source-only restore/refill evidence does not complete the full rotation/recovery matrix. |
| D66 | Mode selects DN and credential atomically in the image/chart; refuse incompatible dedicated Secret combinations. | Secret changes require controlled rollout. Directly starting an empty sid 1 in admin mode bypasses the operator rollback gate and can mint a new DIT. |

## Alternatives and residual risk

Administrator binding is retained for compatibility, but carries broad credential
risk. Credential files/SASL references cannot be claimed as a replacement for
stored simple-bind credentials without separate implementation evidence. SASL
EXTERNAL and a dedicated-by-default fresh cluster require separate designs.

cn=config and backups still contain cleartext replication credentials. Clearing
process environment and masking diagnostics do not erase old disk blocks. Limit
volume/backup access, encrypt storage, and rotate administrator credentials after
migration when appropriate. This ADR makes no deployment, rollout, release or
production acceptance claim; the Change Package acceptance table remains binding.
