# Client compatibility

What "this LDAP client works against ldapium" actually means varies by
client — a browser doing OIDC login through the UI, `sssd` resolving a Linux
login, a Windows box that expects an entirely different protocol family, a
`kubectl` binding a Kubernetes `Group` to an RBAC role. This is the boundary
for each, backed by what was actually checked against a running server rather
than assumed from the client's own documentation.

## SASL mechanisms

Checked against a running container, not inferred from the build flags:

```
$ docker run -d --name t -e LDAP_ADMIN_PASSWORD=x -e LDAP_ROOT_DN=dc=example,dc=org ldapium:<tag>
$ docker exec t ldapsearch -x -LLL -H ldap://localhost -b "" -s base "(objectClass=*)" supportedSASLMechanisms
dn:
```

**Zero SASL mechanisms are advertised**, on a fresh container with no other
configuration. `slapd` is built `--with-cyrus-sasl` (`image/Dockerfile`), so
the library is present, but a compiled-in library is not a configured
mechanism — nothing in `image/ldifs/*.ldif` or `image/entrypoint.sh` sets
`olcSaslSecProps`, `olcSaslHost`, `olcSaslRealm`, `olcAuthzRegexp`, or
`TLSVerifyClient` by default. The optional mTLS configuration described below
adds the latter two only when an operator enables it.

What that means per mechanism, concretely:

- **`SIMPLE` (bind with a DN and password)** is what this project actually
  supports and is verified continuously by `security-e2e.yml`. Every example
  in this repo's docs uses it.
- **`EXTERNAL` (TLS client-certificate authentication)** is available when
  the image is bootstrapped with `LDAP_TLS_MUTUAL_AUTH=true`, TLS and
  `LDAP_TLS_CA_FILE`, plus the operator's `LDAP_TLS_AUTHZ_REGEXP` /
  `LDAP_TLS_AUTHZ_DN` subject-to-DN mapping. It deliberately sets
  `olcTLSVerifyClient: try`, not `demand`: a client certificate is requested
  and verified when supplied, but it is not required for the TLS handshake.
  Existing TLS clients using password/SIMPLE bind without a client certificate
  therefore continue to work unchanged. The image's default mapping is a
  documented example only; operators should override it for their CA subject
  shape and directory layout.

  **Verified live, and load-bearing for anyone enabling this**: a certificate
  signed by the configured CA whose subject does **not** match
  `LDAP_TLS_AUTHZ_REGEXP` does not fail the bind. OpenLDAP falls back to
  binding as the raw, unmapped certificate-subject string (confirmed with
  both a static-DN `olcAuthzRegexp` replacement and the `ldap:///…??sub?(…)`
  search-URI form — neither rejects an unresolved identity; RFC 4513's
  identity-mapping fallback applies regardless). That bind still counts as
  "authenticated" for ACL purposes, and this repo's own `by users read`
  fallback ACL (see `image/entrypoint.sh`'s primary-database ACL, audited
  live in #76) grants **any** authenticated identity broad read access
  across the DIT — verified by binding with a certificate for an entirely
  unrelated, non-matching subject and successfully reading another user's
  `description` attribute with it.

  The practical consequence: **`LDAP_TLS_CA_FILE` under mutual auth must be
  a CA dedicated solely to issuing this directory's client certificates.**
  If the same CA also signs certificates for any other purpose (service
  mesh mTLS, unrelated internal services, monitoring agents), every one of
  those certificates gains this directory's baseline authenticated-read
  access too, regardless of what `LDAP_TLS_AUTHZ_REGEXP` was written to
  match. There is currently no ACL-only mitigation for this with the ACL
  model in place today — see #76 for the "authenticated users get broad
  read" question this makes more urgent, not less.
- **`DIGEST-MD5` / `CRAM-MD5` / `PLAIN`** need `saslauthd` or a SASL password
  database slapd can check against; this image ships neither. `PLAIN` over a
  TLS-protected channel is materially equivalent to `SIMPLE` over `ldaps://`
  for the purposes this directory is built for, which is why `SIMPLE` was
  the one built rather than `PLAIN`.

If a client's SASL requirement is a hard constraint, treat this as a "not yet"
rather than a "maybe" — nothing here half-supports a mechanism.

## Linux clients (SSSD / PAM / nsswitch)

The bootstrap schema (`image/ldifs/01-cn-config.ldif`) loads `core`,
`cosine`, `inetorgperson`, and **`nis`** — the last one is what defines
`posixAccount` / `posixGroup` and their `uidNumber` / `gidNumber` /
`homeDirectory` / `loginShell` attributes. The schema supports POSIX identity
resolution; whether any given entry actually carries `posixAccount` and those
attributes is a seeding decision (`LDAP_SEED_DIR` — see `image/README.md`),
not something this chart supplies by default. Nothing this chart creates by
default carries `posixAccount`: the bootstrap admin entry
(`image/ldifs/03-base-structure.ldif`) is `organizationalRole` +
`simpleSecurityObject`, and every user the management UI creates
(`ui/backend/internal/ldapclient/users.go`) is `inetOrgPerson`. `id <user>`
on an SSSD-joined host will not resolve either until an entry — or an
equivalent one — exists with POSIX attributes.

The initial DN lookup SSSD can make is already what this directory's ACL is
shaped for: anonymous or an authenticated identity can read `entry`, `uid`,
`objectClass` to resolve a bare `uid` to a DN. This cannot be turned off
outright without breaking that resolution flow for every anonymously-binding
client, but as of
`LDAP_ANONYMOUS_READ_BASE` (`image/README.md`) it can be **narrowed**: set it
to the subtree that actually holds your user entries (e.g.
`ou=people,dc=example,dc=org`) and a root-base anonymous `uid` search — the
`ldap_search_base = <rootDN>` shown below — keeps working unchanged, because
slapd still needs (and keeps) `search` access to traverse the root and
intermediate OUs on the way to that subtree. What stops is enumeration
outside the base: an anonymous bind can no longer list or read `entry`/`uid`/
`objectClass` on entries in, say, `ou=groups` or `ou=policies`, and a filter
against those trees returns nothing rather than the DIT-wide visibility this
directory has always granted anonymous by default. A standard `sssd.conf`
`[domain]` section against this directory:

```ini
[domain/ldapium]
id_provider = ldap
ldap_uri = ldaps://<fullname>.<namespace>.svc.<clusterDomain>:636
ldap_search_base = <rootDN>
ldap_tls_cacert = /etc/openldap/tls/ca.crt
ldap_id_use_start_tls = false
```

using `ldaps://` on 636 once `tls.enabled` is set — this chart's documented,
tested TLS path (`charts/ldapium/README.md`, "TLS"). Checked directly: a
container with no TLS configured at all does not advertise the StartTLS
extended-operation OID (`1.3.6.1.4.1.1466.20037`) in its root DSE
`supportedExtension` list, and once `tls.enabled` is set, StartTLS on port
389 does work — OpenLDAP enables it automatically as soon as
`olcTLSCertificateFile`/`olcTLSCertificateKeyFile` are configured, which this
chart always sets together. Verified live: `ldapwhoami -x -ZZ -H
ldap://<host>:389 -D <bindDN> -w <password>` with `LDAPTLS_REQCERT=demand
LDAPTLS_CACERT=/etc/openldap/tls/ca.crt` succeeds and returns the bound DN,
and the same command fails closed (does not fall back to plaintext) against
an unverifiable CA — see the "Verify StartTLS on port 389" step in
`.github/workflows/e2e.yml`'s `tls` job. `ldaps://` on 636 remains the path
this project documents as the primary TLS integration (a separate
TLS-from-the-first-byte connection rather than a protocol upgrade
mid-connection), but StartTLS on 389 is a supported alternative, not an
open question. Add `ldap_default_bind_dn`/`ldap_default_authtok` for the
search identity if anonymous read is not enough for your deployment's ACL.
In fact, ldapium's default anonymous ACL deliberately exposes only `entry`,
`uid`, and `objectClass`; SSSD needs `uidNumber`, `gidNumber`,
`homeDirectory`, and other POSIX attributes as well. The live CI therefore
uses an authenticated search bind and leaves `ldap.anonymousReadBase` unset:
that preserves the default DIT-wide DN-discovery behavior while avoiding a
broader anonymous attribute grant.

**Live-tested for NSS identity resolution, not PAM authentication.**
`.github/workflows/sssd-e2e.yml` starts a real SSSD daemon with
`services = nss`, `passwd: sss files`, and `group: sss files` in a disposable
client, then proves `getent passwd posixuser` and `id posixuser` against a
seeded RFC 2307 user and group. It deliberately makes no claim about PAM
login, password verification, session setup, or host enrollment.

## Windows / Active Directory

**This is not an Active Directory replacement, and nothing here makes it
one.** AD is a specific protocol family — Kerberos for authentication, its own
schema and multi-master replication model, SMB/CIFS for file services, Group
Policy — layered on top of LDAP as one piece among several. This project
implements LDAPv3 and nothing else in that stack:

| AD component | Here |
|---|---|
| LDAPv3 directory protocol | Yes — the actual surface this project targets |
| Kerberos (domain auth, SSO) | No |
| SPNEGO / Windows Negotiate (integrated LDAP authentication) | No — the image configures no GSSAPI/SASL mechanism; use LDAPv3 `SIMPLE` bind or an external IdP instead |
| Group Policy | No |
| SMB/CIFS, DFS | No |
| AD's replication model / trusts / forests | No — this project's own multi-provider replication (`charts/ldapium/README.md`, "HA / replication") is unrelated and not AD-compatible |
| A Windows box joining this directory as its domain | Not supported — Windows domain join requires Kerberos and AD-specific schema extensions this project does not provide |

Where this genuinely interoperates with a Windows-adjacent workflow:

- **A Windows machine as an LDAP client**, not a domain member — an application
  that performs basic LDAPv3 `SIMPLE` bind and search is within the protocol
  boundary. In `ldp.exe`, explicitly select Simple bind rather than an
  Integrated/SSPI bind, and configure the TLS trust store when using LDAPS or
  StartTLS. This project does not yet have a Windows-specific live test, so
  validate the intended client and its TLS settings before treating that
  compatibility as verified.
- **Migrating identities *from* AD** — exporting AD's LDIF and re-importing
  it here needs schema reconciliation (AD's `objectClass`/attribute set
  differs from what is loaded — see the schema list above) and is a
  migration project, not a compatibility mode. Not covered here; would be its
  own issue if wanted.

Anyone evaluating this project as "the LDAP server for a Windows shop" should
read this table as the boundary, not as a to-do list — several of these
(Kerberos, Group Policy) are entire subsystems, not configuration flags.

## Kubernetes RBAC group mapping

This chart does not, and architecturally cannot on its own, become a
Kubernetes `Group` subject — that mapping happens in the Kubernetes API
server's own auth configuration, outside anything this repository controls.
The integration pattern, for the record:

1. **An OIDC provider sits between Kubernetes and this directory.** This
   project's own UI already authenticates through one
   (`ui/backend/internal/httpapi/sso.go`, `charts/ldapium/README.md`'s
   "Keycloak SSO" section) — the same provider
   (Keycloak or equivalent) can be configured with an LDAP user federation
   pointing at this directory, and to include LDAP group membership in its
   issued tokens' `groups` claim.
2. **The Kubernetes API server is started with `--oidc-issuer-url`,
   `--oidc-client-id`, and `--oidc-groups-claim=groups`** pointing at that
   same provider. This is a control-plane flag on the API server itself —
   not something a chart running workloads inside the cluster can set.
3. **RBAC binds to the `Group` subject Kubernetes now recognizes** —
   `RoleBinding`/`ClusterRoleBinding` with `kind: Group`,
   `name: <the LDAP group's name as it appears in the groups claim>`.

This chart's part of that chain stops at step 1: being an LDAP directory a
provider can federate against, with groups a client can read (subject to the
ACL — group entries fall under the "every other attribute" row in
`image/README.md`'s matrix, readable by any authenticated bind). Steps 2 and
3 are cluster-operator configuration outside this project's scope, documented
here so the integration is describable rather than left as a gap with no
shape.

## TLS cipher suite baseline

`olcTLSCipherSuite` is fixed to the Mozilla "Intermediate" profile's TLS 1.2
list — AEAD ciphers with ECDHE forward secrecy only:

```
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
```

This excludes CBC+SHA-1 ciphers, static-RSA key exchange (no forward
secrecy), and 3DES/RC4/export/NULL ciphers — all still technically
negotiable on a bare TLS 1.2 connection unless a server explicitly narrows
its list, which `olcTLSProtocolMin: 3.3` alone does not do. Practical impact:
a client stuck on TLS 1.2 that only offers one of the excluded ciphers now
fails the handshake instead of falling back to it. Every client this project
has verified against (`ldapsearch`, this project's own `go-ldap` UI backend,
any TLS 1.3-capable client) already prefers ECDHE+AEAD and is unaffected.
Only a legacy client hard-coded to a static-RSA or CBC-only cipher list
(pre-2014-era Java/.NET LDAP clients are the realistic case) would need an
update — the same clients that a TLS 1.2 floor already pushes toward
modernizing.

This directive has **no effect on TLS 1.3**: OpenSSL negotiates TLS 1.3's
fixed AEAD ciphersuite list (`TLS_AES_128_GCM_SHA256` and friends)
separately, and OpenLDAP does not expose a directive to further restrict it.
A TLS 1.3 client sees no behavior change from this baseline at all.

## General compatibility matrix

| Client / tool | Status | Notes |
|---|---|---|
| `ldapsearch` / `ldapadd` / `ldapmodify` / `ldapdelete` (OpenLDAP CLI) | Supported, continuously verified | Used throughout this project's own E2E suites |
| Go `go-ldap` client (this project's own UI backend) | Supported, continuously verified | `ui/backend/internal/ldapclient` |
| LDAPv3 client using `SIMPLE` bind for basic bind/search | Protocol-level compatibility; not client-specific verified | OpenLDAP CLI and this project's Go client are continuously verified. Third-party controls/extensions, referrals, and TLS version/cipher requirements are unverified; validate the intended client before relying on it. |
| SSSD / nsswitch (Linux) | NSS identity resolution continuously live-tested | `getent passwd` / `id`; no PAM claim — see above |
| SASL `EXTERNAL` (mTLS) | Opt-in image configuration | `LDAP_TLS_MUTUAL_AUTH=true` with CA and operator-configured subject-to-DN mapping; uses `try`, so password binds remain compatible |
| SASL `DIGEST-MD5` / `CRAM-MD5` / `PLAIN` | Not supported | No `saslauthd`/SASL password backend shipped |
| Windows as an LDAPv3 client | Protocol-level compatibility; not Windows-specific verified | Not a domain join — see above |
| Windows/AD domain member, Kerberos, Group Policy | Not supported | Different protocol family, out of scope |
| Kubernetes RBAC via OIDC groups claim | Supported via external OIDC provider | This chart provides the directory; the OIDC provider and API server config are the operator's |
