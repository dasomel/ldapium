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
  StartTLS.
- **Migrating identities *from* AD** — exporting AD's LDIF and re-importing
  it here needs schema reconciliation (AD's `objectClass`/attribute set
  differs from what is loaded — see the schema list above) and is a
  migration project, not a compatibility mode. Not covered here; would be its
  own issue if wanted.

### Active Directory coexistence and "where applicable" boundary

Where requirements or RFPs specify "Active Directory coexistence and integration
where applicable" (e.g. #16), what "where applicable" concretely means for
ldapium is strictly protocol-level:

- **Applicable (protocol-level interoperability)**: Standard LDAPv3 clients
  running on Windows (such as `ldp.exe`, PowerShell LDAP cmdlets, or Windows-hosted
  enterprise applications) connecting to ldapium over standard LDAPv3 using `SIMPLE`
  bind, over plaintext (port 389), StartTLS (port 389), or LDAPS (port 636).
- **Out of scope (domain-level integration)**: Native Active Directory domain
  features — Kerberos realm trusts, cross-forest trusts, Active Directory
  replication (DRS-RPC / MS-DRSR), Active Directory Lightweight Directory Services
  (AD LDS) schema synchronization, Group Policy Objects (GPO), SID history, and
  SMB/CIFS/DFS file services. ldapium is an LDAPv3 directory, not an Active Directory
  domain controller or multi-directory sync engine.

**Active Directory coexistence has no live test in this repository.** CI workflows
execute entirely within containerized Linux environments (`.github/workflows/*.yml`)
and verify OpenLDAP CLI tools, Go `go-ldap`, and Linux SSSD/NSS. Coexistence where
an organization maintains both Active Directory and ldapium requires treating them
as separate directory realms or brokering authentication and synchronization via
an external Identity Provider (such as Keycloak user federation) or dedicated
integration tooling; ldapium contains no built-in AD connector or synchronization
agent (see [docs/product-boundary.md](docs/product-boundary.md)).

Anyone evaluating this project as "the LDAP server for a Windows shop" should
read this table as the boundary, not as a to-do list — several of these
(Kerberos, Group Policy) are entire subsystems, not configuration flags.

## Identity classes and trust boundaries

ldapium is a single LDAPv3 directory: upstream OpenLDAP packaged for
Kubernetes plus a thin management UI. It deliberately does not ship, and will
not grow: a multi-directory federation/sync engine, a Source-of-Authority
matching/merge engine, a SCIM server or client, an IGA connector framework (SPI,
retry/dead-letter, reconciliation engine), a PAM/JIT/JEA request workflow or
credential vault, a SPIFFE/SPIRE integration, or a ChatOps/AI remediation
executor (see [docs/product-boundary.md](docs/product-boundary.md)). The
integration boundary for each of those capabilities is an external IdP / IGA /
PAM / observability product (e.g. Keycloak, an enterprise IGA suite, a PAM
vault, a SIEM) that talks to ldapium over standard LDAPv3
(`bind`/`search`/`modify`/`modrdn`) and consumes ldapium's audit NDJSON export.

Integrating ldapium into Kubernetes and SSO environments establishes distinct
trust boundaries across four identity classes.

### Identity classes

1. **Human user (`inetOrgPerson`)**:
   Standard directory users residing in the DIT under `LDAP_USER_SEARCH_BASE`
   (e.g. `ou=people,dc=example,dc=org`). These entries use the `inetOrgPerson`
   structural objectClass (defined in `image/ldifs/01-cn-config.ldif` via
   `file:///etc/openldap/schema/inetorgperson.ldif`), carrying standard naming
   and profile attributes (`uid`, `cn`, `sn`, `mail`, `userPassword`). Human users
   authenticate either directly via LDAPv3 `SIMPLE` bind (when UI SSO is disabled)
   or federate through Keycloak via browser-based OIDC.
2. **Directory administrator (`rootdn`)**:
   The administrative superuser identity (`cn=admin,$LDAP_ROOT_DN` or
   `cn=admin,cn=config`), represented as `organizationalRole` with
   `simpleSecurityObject` (`image/ldifs/03-base-structure.ldif`). This identity
   bypasses OpenLDAP directory ACLs entirely. It is strictly reserved for
   offline container bootstrap, seeding (`LDAP_SEED_DIR`), disaster recovery,
   and administrative batch jobs (`scripts/backup.sh`). It must never be exposed
   to browser sessions or used as an application service account.
3. **UI service account (`LDAP_SERVICE_ACCOUNT_DN`)**:
   When Keycloak SSO is enabled (`SSO_ENABLED=true`), human users do not provide
   LDAP passwords to the UI backend. Instead, the UI backend authenticates
   against LDAP using a dedicated service account identity configured via
   `LDAP_SERVICE_ACCOUNT_DN` and `LDAP_SERVICE_ACCOUNT_PASSWORD`
   (`ui/backend/internal/httpapi/sso.go` lines 146–150). This identity executes
   search, user/group CRUD, password reset, and account unlock operations on
   behalf of authenticated administrators. It is governed by explicit,
   operator-defined LDAP ACLs and must never reuse the `rootdn` credentials
   (`charts/ldapium/README.md`, "Keycloak SSO").
4. **Kubernetes ServiceAccount (workload identity)**:
   A Kubernetes ServiceAccount (`system:serviceaccount:<namespace>:<name>`) is
   issued and verified exclusively by the Kubernetes control plane or an
   associated workload identity framework (e.g. SPIFFE/SPIRE). **A Kubernetes
   ServiceAccount is NEVER an ldapium identity and must not be mapped to or
   treated as a human directory user.** Workload identities operate within the
   Kubernetes execution boundary; ldapium contains no workload identity code,
   issues no SPIFFE SVIDs, and accepts no Kubernetes service account tokens
   directly.

### LDAP group and attribute mapping contract (Keycloak)

When Keycloak integrates with ldapium using LDAP user federation, it connects as
an authenticated LDAPv3 client. The contract relies on schemas explicitly loaded
by ldapium's bootstrap configuration (`image/ldifs/01-cn-config.ldif`):

- **User attribute resolution**:
  - `uid` -> Keycloak username and `preferred_username` claim.
  - `mail` -> Keycloak email address claim.
  - `cn` / `givenName` / `sn` -> user first name, last name, and full name.
  These attributes are provided by the `core.ldif`, `cosine.ldif`, and
  `inetorgperson.ldif` schemas loaded into `cn=schema,cn=config` and indexed in
  `olcDatabase={1}mdb` (`olcDbIndex: uid eq`, `cn pres,eq,sub`, `mail eq`, `sn pres,eq,sub`, `givenName eq`).
- **Group membership resolution**:
  - Keycloak's `group-ldap-mapper` reads `groupOfNames` entries (from `core.ldif`),
    evaluating user DNs listed in the `member` attribute (`olcDbIndex: member eq`).
  - Alternatively, Keycloak can read the user's `memberOf` operational attribute,
    which is dynamically generated and maintained by OpenLDAP's `slapo-memberof`
    overlay (`olcOverlay=memberof,olcDatabase={1}mdb,cn=config`, `01-cn-config.ldif:104–109`).
    Referential integrity is guaranteed by `slapo-refint` (`01-cn-config.ldif:110–117`),
    which automatically purges stale member references on user deletion or rename.
- **Claim emission**:
  Keycloak maps resolved LDAP groups and roles into token claims:
  - For the ldapium UI: Keycloak maps the required administrator entitlement into
    the `roles` claim array or `realm_access.roles` (configured by `SSO_ADMIN_ROLE`,
    default `ldap-admin`).
  - For Kubernetes API access: Keycloak maps LDAP groups into a designated `groups`
    claim array in the issued ID/access tokens.

### Keycloak to Kubernetes issuer and audience validation

ldapium does not validate Kubernetes API tokens, nor does it interact with the
Kubernetes API server's authentication pipeline. The mapping of LDAP-derived
identities to Kubernetes RBAC occurs strictly between Keycloak and the Kubernetes
API server:

1. **An OIDC provider sits between Kubernetes and this directory**: Keycloak
   federates users and groups from ldapium, issuing cryptographically signed JWT
   tokens containing the user identity and group memberships.
2. **The Kubernetes API server verifies tokens directly**: The cluster operator
   configures `kube-apiserver` with OIDC control-plane flags:
   - `--oidc-issuer-url`: The exact issuer URL of the Keycloak realm (e.g.
     `https://sso.example.com/realms/example`). `kube-apiserver` verifies the
     `iss` claim and discovers Keycloak's public signing keys via JWKS
     (`/.well-known/openid-configuration`).
   - `--oidc-client-id`: The expected audience (`aud` claim) matching the client ID
     registered in Keycloak for cluster authentication.
   - `--oidc-username-claim`: The claim mapped to the Kubernetes user identity
     (e.g. `preferred_username` or `sub`).
   - `--oidc-groups-claim`: The claim mapped to Kubernetes RBAC groups (e.g. `groups`).
   - `--oidc-ca-file`: CA certificate bundle validating Keycloak's TLS certificate.
3. **RBAC binds to the resulting `Group` subjects**: Kubernetes RBAC
   `RoleBinding` or `ClusterRoleBinding` manifests bind roles to `kind: Group`
   subjects (`name: <ldap-group-name>`), corresponding to the group names emitted
   in the `groups` claim.

This chart's role stops at step 1: operating as an LDAPv3 directory that Keycloak
can federate against. Steps 2 and 3 are Kubernetes cluster control-plane configurations
outside this project's scope.

This half of the chain — LDAP `member` -> Keycloak group -> token `groups`
claim, including a live LDAP membership change propagating through a
re-sync — is no longer just described here: it's live-verified end to
end by `.github/workflows/keycloak-federation-e2e.yml`, with the exact
provider settings in `charts/ldapium/README.md`'s "Keycloak LDAP user
federation".

### UI OIDC login validation contract (`sso.go`)

When SSO is enabled (`SSO_ENABLED=true`), the ldapium management UI backend
(`ui/backend/internal/httpapi/sso.go`) acts as an OIDC Relying Party. It
implements strict cryptographic, session, and role verification at each step:

- **Provider Discovery & Verifier Construction**: `newOIDCAuthenticator`
  initializes the OIDC client via `oidc.NewProvider` (`sso.go:42`), discovering
  provider endpoints and JWKS keys. It initializes an `oidc.IDTokenVerifier`
  enforcing `ClientID: cfg.ClientID` (`sso.go:67`).
- **Scope Minimization**: The client scopes are strictly restricted to
  `openid` and `profile` (`sso.go:72`).
- **State, PKCE, and Nonce Generation**: On `POST /api/sso/start`, `states.Create`
  generates high-entropy cryptographic random values: a 32-byte `state`, a
  64-byte PKCE `code_verifier` (encoding to 86 base64url characters, RFC 7636), a
  32-byte `nonce`, and a 32-byte browser `binding` cookie (`sso.go:90–95`,
  `353–370`).
- **Authorization Request**: The browser is redirected to Keycloak with the PKCE
  `S256` challenge (`oauth2.S256ChallengeOption(login.verifier)`) and the `nonce`
  (`oidc.Nonce(login.nonce)`) (`sso.go:99–103`).
- **Callback State & Browser Binding Verification**: On `/api/sso/callback`, the
  backend checks that the request origin matches allowlisted `SSO_CALLBACK_ORIGINS`
  (`sso.go:125–128`, `222–231`). It consumes the state from the single-use in-memory
  cache (`sso.go:121`, `421–438`) and compares the stored binding against the
  `ldapium_sso_login` cookie using constant-time comparison
  (`subtle.ConstantTimeCompare`, `sso.go:431`), defeating login CSRF (RFC 6749 §10.12).
- **Code Exchange with PKCE Verifier**: The backend exchanges the authorization
  code using the stored PKCE `verifier` (`sso.go:188`).
- **Cryptographic ID Token Validation**: `a.verifier.Verify(ctx, rawIDToken)`
  (`sso.go:196–199`) cryptographically validates the token against Keycloak's
  published JWKS keys, ensuring the signature is valid, `iss` matches `SSO_ISSUER_URL`,
  `aud` matches `SSO_CLIENT_ID`, and the token is not expired.
- **Nonce Verification**: The backend compares the token's `nonce` claim to the
  session's expected nonce in constant time (`sso.go:200–202`), rejecting replayed
  tokens.
- **Administrative Role Enforcement**: Decodes token claims (`sso.go:204–207`) and
  asserts that the user possesses `SSO_ADMIN_ROLE` (default `ldap-admin`) in either
  the custom `roles` array or Keycloak's standard `realm_access.roles`
  (`sso.go:208–210`, `303–315`). Users without this role are redirected with
  `not_authorized` (`sso.go:140–142`).
- **LDAP Account Resolution**: The backend extracts `preferred_username`
  (`sso.go:211–214`), binds to LDAP as `LDAP_SERVICE_ACCOUNT_DN` (`sso.go:146–153`),
  and resolves the username to exactly one LDAP entry DN via `ResolveUID`
  (`sso.go:154–161`). If no matching LDAP entry exists, login is refused with
  `directory_account_not_found`.

### Claim and attribute minimization policy

To minimize identity exposure across trust boundaries:
- **OIDC scopes**: The UI requests only `openid` and `profile` (`sso.go:72`).
  Scopes such as `email`, `phone`, `address`, or broad user profile data are not
  requested.
- **Token claims**: Downstream consumers inspect only minimal required claims:
  the UI extracts only `preferred_username` and role claims (`roles` /
  `realm_access.roles`); Kubernetes `kube-apiserver` extracts only the username
  claim and `groups`.
- **Directory attribute exposure**: Keycloak's LDAP user federation mapper should
  read only attributes required for authentication and access control (`uid`,
  `mail`, `cn`, `sn`, `givenName`, `memberOf`/`member`). `userPassword` and
  `shadowLastChange` are restricted by OpenLDAP ACLs
  (`image/ldifs/01-cn-config.ldif:86–89`); `userPassword` specifically is also
  held back from every UI API response via a hardcoded denylist regardless of
  what those ACLs would otherwise permit (`entryRedactedAttrs` in
  `ui/backend/internal/ldapclient/tree.go`) — the root/admin bind the UI uses
  bypasses ACLs entirely, so that denylist is the only thing stopping it from
  returning a raw `userPassword` value.

### Hop-by-hop invalid token rejection

Invalid tokens and unauthorized credentials fail closed and are rejected at each
component boundary:
1. **At the UI backend**: Tokens with invalid signatures, expired timestamps,
   mismatched issuers, incorrect audience (`ClientID`), mismatched nonces, or
   missing administrative roles are rejected immediately
   (`sso.go:134–144`). No UI session is created, and no LDAP operation is
   performed.
2. **At the Kubernetes API server**: Bearer tokens with invalid cryptographic
   signatures, unknown issuers, mismatched audiences, or expired timestamps are
   rejected with HTTP 401 Unauthorized by `kube-apiserver` prior to RBAC
   evaluation.
3. **At ldapium**: ldapium does not consume, validate, or trust JWTs. All
   requests from Keycloak or the UI service account arrive as standard LDAPv3 wire
   operations (`BIND`, `SEARCH`, `MODIFY`). Operations with invalid credentials,
   unregistered identities, or insufficient ACL permissions are rejected directly
   by OpenLDAP with standard LDAP result codes (e.g. `invalidCredentials` [49],
   `insufficientAccessRights` [50]).

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
| Windows as an LDAPv3 client | Protocol-level compatibility; not Windows-specific verified | Standard LDAPv3 `SIMPLE` bind over plaintext, LDAPS, or StartTLS; not a domain join. No live test in this repository — see above |
| Windows/AD domain member, Kerberos, Group Policy | Not supported | Different protocol family, out of scope |
| Microsoft Entra ID | Not supported directly | Not a supported direct federation peer; integration is supported only through an external IdP (such as Keycloak identity brokering). ldapium does not implement Entra sync, SCIM, or graph connectors. |
| PAM / JIT / JEA products | Protocol-level compatibility; unverified | Any PAM product that uses standard LDAPv3 (`bind`/`modify`/`search`) is protocol-level compatible. ldapium provides no credential vault integration, JIT/JEA request/elevation workflows, or session recording; no specific PAM product combination has been verified in CI. |
| Keycloak LDAP user federation (LDAP -> Keycloak group -> token `groups` claim) | Supported, continuously live-verified | `.github/workflows/keycloak-federation-e2e.yml`; settings in `charts/ldapium/README.md`'s "Keycloak LDAP user federation" — was previously described but untested |
| Kubernetes API server OIDC via Keycloak | Supported via external IdP | `kube-apiserver` validates OIDC tokens issued by Keycloak; ldapium serves as the backing LDAP user/group directory. |
| Kubernetes RBAC via OIDC groups claim | Supported via external OIDC provider | This chart provides the directory; the OIDC provider and API server config are the operator's |
| SPIFFE / SPIRE | Not supported | Out of scope; ldapium contains no workload-identity code, SVID issuance, or attestation endpoints. |
| Multi-directory federation / directory connectors | Not applicable | ldapium is a single LDAPv3 directory and will not ship a multi-directory sync or conflict-resolution engine; see [docs/product-boundary.md](docs/product-boundary.md). |
| SCIM (RFC 7643 / RFC 7644) | Not applicable | ldapium does not implement a SCIM server or client; see [docs/product-boundary.md](docs/product-boundary.md). |
