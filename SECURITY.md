# Security policy

## Reporting a vulnerability

Please report privately, not in a public issue:

- GitHub [private vulnerability reporting](https://github.com/dasomel/openldap-suite/security/advisories/new)
  (Security → Report a vulnerability) — preferred, it keeps the discussion and
  the eventual advisory in one place.

Please include the version or image digest, what an attacker gains, and the
smallest reproduction you have. Expect an initial reply within a week. This is
a small project without a paid security team; that is the honest turnaround,
not a target anyone is on the hook for.

## Scope

In scope: this repository — the server image (`image/`), the management UI
(`ui/`), the Helm chart (`charts/`), the shipped scripts, and their default
configuration.

Not in scope: vulnerabilities in OpenLDAP itself. Report those to
[the OpenLDAP project](https://bugs.openldap.org/); this repo compiles
unmodified upstream source and carries no patches of its own. Once a fix is
released upstream, bumping the pinned version here is an ordinary issue, not a
security report.

## Supported versions

Only the latest release. This project is at 0.x: there are no backports, and a
fix ships in the next release rather than as a patch to an older one.

Both images are also rebuilt weekly (`.github/workflows/weekly-rebuild.yml`)
so base-image security updates reach the `:main` tag without waiting for a
release. Released tags are immutable and are not rebuilt in place.

## What this project already assumes about deployment

Worth knowing before reporting, because these are deliberate:

- **No default credentials exist.** The image, chart and compose file each
  refuse to start without an explicitly supplied admin password. A report that
  a default password is weak will not apply.
- **The UI holds no service account.** Every request binds as the logged-in
  user, so the directory's own ACLs — not UI code — decide what a session can
  read or write. The single exception is SSO, where an OIDC token carries no
  password to bind with; that path is documented in `ui/README.md`.
- **`cn=config` is not reachable from the UI** under any session it can
  create. This is a design constraint, not an oversight.
- **TLS is off by default** and is expected to be terminated by the platform
  (Ingress/service mesh) or enabled explicitly via `tls.enabled`. Plaintext
  LDAP on a cluster-internal Service is the documented default, not an
  accident — but do report anything that leaks credentials outside that
  boundary.
