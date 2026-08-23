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
`TLSVerifyClient`, and grepping those files confirms it: none of them appear
anywhere in this image.

What that means per mechanism, concretely:

- **`SIMPLE` (bind with a DN and password)** is what this project actually
  supports and is verified continuously by `security-e2e.yml`. Every example
  in this repo's docs uses it.
- **`EXTERNAL` (TLS client-certificate authentication)** needs, at minimum,
  `TLSVerifyClient: demand` and an `olcAuthzRegexp` mapping a certificate
  subject to a bind DN — neither is set here. `EXTERNAL` is the SASL
  mechanism most operators actually want (mutual TLS instead of a shared
  password), and it is architecturally reachable — TLS support already exists
  (`tls.enabled` in the chart) — but wiring it is not done and is not claimed.
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

The bind-then-search pattern SSSD needs is already what this directory's ACL
is shaped for (`image/README.md`, "Access control (ACL)"): anonymous or an
authenticated identity can read `entry`, `uid`, `objectClass` to resolve a
bare `uid` to a DN, then bind as that DN to verify a password — the same flow
the management UI's own login uses. A standard `sssd.conf` `[domain]` section
against this directory:

```ini
[domain/ldapium]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldaps://<fullname>.<namespace>.svc.<clusterDomain>:636
ldap_search_base = <rootDN>
ldap_tls_cacert = /etc/openldap/tls/ca.crt
ldap_id_use_start_tls = false
```

using `ldaps://` on 636 once `tls.enabled` is set — this chart's documented,
tested TLS path (`charts/ldapium/README.md`, "TLS"). Checked directly: a
container with no TLS configured at all does not advertise the StartTLS
extended-operation OID (`1.3.6.1.4.1.1466.20037`) in its root DSE
`supportedExtension` list. Whether StartTLS on port 389 also becomes
available once `tls.enabled` is set was not checked directly — OpenLDAP
typically enables it automatically once `olcTLSCertificateFile`/
`olcTLSCertificateKeyFile` are configured, which this chart does set, so it
may work, but `ldaps://` is the path this project actually tests and
documents; treat StartTLS as unverified rather than assume it from this
sentence. Add `ldap_default_bind_dn`/`ldap_default_authtok` for the search
identity if anonymous read is not enough for your deployment's ACL.

**Not live-tested against a real `sssd`/`nsswitch` client** — this is the
standard integration procedure for an RFC 2307 (`nis`-schema) directory,
cross-checked against this repo's actual ACL and schema configuration rather
than written from memory alone, but it has not been run through an actual
`getent passwd` / `id` / PAM login on a joined host. Flagged rather than
claimed as verified.

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
| Group Policy | No |
| SMB/CIFS, DFS | No |
| AD's replication model / trusts / forests | No — this project's own multi-provider replication (`charts/ldapium/README.md`, "HA / replication") is unrelated and not AD-compatible |
| A Windows box joining this directory as its domain | Not supported — Windows domain join requires Kerberos and AD-specific schema extensions this project does not provide |

Where this genuinely interoperates with a Windows-adjacent workflow:

- **A Windows machine as an LDAP client**, not a domain member — anything on
  Windows that speaks LDAPv3 directly (e.g. `ldp.exe` for inspection, an
  application configured with an explicit LDAP connection string) binds and
  searches like any other `SIMPLE`-auth client. This works today and needs
  nothing special.
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

## General compatibility matrix

| Client / tool | Status | Notes |
|---|---|---|
| `ldapsearch` / `ldapadd` / `ldapmodify` / `ldapdelete` (OpenLDAP CLI) | Supported, continuously verified | Used throughout this project's own E2E suites |
| Go `go-ldap` client (this project's own UI backend) | Supported, continuously verified | `ui/backend/internal/ldapclient` |
| Any LDAPv3 client using `SIMPLE` bind | Supported | The verified path |
| SSSD / PAM / nsswitch (Linux) | Supported in principle, not live-tested | See above |
| SASL `EXTERNAL` (mTLS) | Not configured | Architecturally reachable, not wired |
| SASL `DIGEST-MD5` / `CRAM-MD5` / `PLAIN` | Not supported | No `saslauthd`/SASL password backend shipped |
| Windows as an LDAPv3 client | Supported (LDAP only) | Not a domain join — see above |
| Windows/AD domain member, Kerberos, Group Policy | Not supported | Different protocol family, out of scope |
| Kubernetes RBAC via OIDC groups claim | Supported via external OIDC provider | This chart provides the directory; the OIDC provider and API server config are the operator's |
