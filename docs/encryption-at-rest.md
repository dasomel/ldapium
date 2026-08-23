# Encryption at rest

The question this answers is not "is the data encrypted" — it is **who is
responsible for it**: this product, or the platform it runs on. Getting that
boundary wrong in either direction is a real failure mode. Claiming this
product encrypts data it does not touch is a compliance finding waiting to
happen; assuming the platform covers something it was never asked to is a
breach waiting to happen. This document draws the line and says how to check
which side of it you are on.

## What this product does not do

OpenLDAP's `mdb` backend — what this chart uses, and the only backend it
supports — is a memory-mapped B+tree (LMDB) with no pluggable encryption
layer. There is no `back_mdb` encryption module in stock OpenLDAP, no
transparent-data-encryption equivalent, nothing to turn on. The bytes in
`data-<n>.mdb` on the `data` PVC are exactly the directory's contents, and the
same is true of the `config` PVC's `cn=config` state.

This is not a gap in this chart specifically — it is the backend's own
architecture, upstream, and no chart-level setting changes it.

## What it delegates, and how to verify the delegation

Encryption at rest for both PVCs (`persistence.data`, `persistence.config` —
`charts/ldapium/values.yaml`) is the storage layer's responsibility. Every
volume this chart creates has an independently settable `storageClassName`
(empty string uses the cluster default), so the supported path is: point it at
a `StorageClass` backed by encrypted storage — LUKS-encrypted block devices,
an encrypting CSI driver, or a cloud provider's disk encryption (EBS, Persistent
Disk, Azure Disk, and equivalents all support encryption-at-rest options at the
`StorageClass` or disk level).

There is no generic way for this chart to verify that delegation succeeded —
whether a `StorageClass` actually encrypts is provisioner-specific, and stock
`kubectl` cannot answer it from the `StorageClass` object alone in general.
What you can check:

```bash
kubectl get storageclass <name> -o yaml
```

and read the `parameters` block against your provisioner's own documentation
(AWS EBS CSI: `encrypted: "true"` and optionally `kmsKeyId`; GCP PD CSI:
`disk-encryption-kms-key`; Azure Disk CSI: `diskEncryptionSetID`; a
LUKS-backed local/CSI setup: verified at the node/volume level, outside
Kubernetes' own object model entirely). If your provisioner's parameters don't
show an encryption setting, treat the volume as unencrypted until you have
confirmed otherwise directly with whoever operates the underlying storage.

## Backup artifacts

`*.ldif.gz` written by the backup `CronJob` (`persistence` under `backup:` in
values) sits on its own PVC, with its own independently settable
`storageClassName` — the same delegation, and the same verification
procedure, apply to it as to the data and config volumes. There is
deliberately no separate encryption mechanism for the archive files
themselves (e.g. GPG-encrypting each `.ldif.gz`): it would be a second key to
manage, rotate, and lose, covering exactly the same threat the storage layer
already covers for the volume the files live on. If backups are copied off
that PVC — to object storage, to another cluster, to a laptop — that copy step
is outside this chart's control, and encrypting the copy (or the destination)
is the operator's decision at that point, not a default this chart can supply.

**Related, separate findings, fixed alongside this document:** two of this
chart's own in-cluster clients connected over plain `ldap://` regardless of
whether `tls.enabled` was set — the backup `CronJob` and the `helm test` Pod
(`charts/ldapium/templates/tests/directory-test.yaml`), including that Pod's
per-replica peer checks. Both are data-in-transit gaps, not data-at-rest ones,
but they were found while writing this document and are fixed in the same
change: both now follow the `ldaps://`-when-`tls.enabled` rule the UI backend
already applied (`charts/ldapium/templates/ui-deployment.yaml`), mounting the
same TLS secret the server itself uses. Verified on a kind cluster: a
triggered backup Job against a TLS-enabled release logs `dumping data (...)
from ldaps://<fullname>.<ns>.svc.<domain>:636` and completes; the same trigger
against a non-TLS release logs the `ldap://` form and also completes — so
enabling TLS does not regress backups that were relying on the plain form.
`helm template` confirms the same pattern for the test Pod, including the
per-replica `REPLICA_URLS` list in a replicated release.

## Public-sector crypto module review

What is actually built, read from the image rather than assumed:

```
$ docker run --rm <image> openssl version -a
OpenSSL 3.5.6 ...
$ docker run --rm <image> openssl list -providers
Providers:
  default
    name: OpenSSL Default Provider
    status: active
```

- **TLS** (`--with-tls=openssl`, `image/Dockerfile`) uses Debian trixie's
  packaged OpenSSL 3.5.6 — a current, maintained release, but only the
  **default** provider is loaded. No FIPS provider is built or configured.
  This build has **not** been validated against FIPS 140-2/140-3, and nothing
  here claims otherwise. Getting there is a build-level decision (OpenSSL's
  `fips` provider, built and used with a validated module, is a separate
  artifact from the default provider this image ships) and a separate
  certification exercise — not a runtime flag.
- **Password hashing** (`--with-argon2=libargon2`) uses Argon2id
  (`m=7168,t=5,p=1` — `image/entrypoint.sh`), OWASP's current recommended
  memory-hard KDF. This is a defensible modern choice on its own merits;
  it is not a certified module and is not offered as one.
- **SASL** (`--with-cyrus-sasl`) — Cyrus SASL is built in; which mechanisms
  are actually usable is tracked separately (#43), not duplicated here.

If a specific certification (KISA cryptographic module validation, FIPS
140-3, or similar) is a hard requirement for a deployment, that requirement
should be checked against this list *before* the deployment is planned, not
discovered during it — the honest answer today is that this build does not
carry one, and adding one is a build change, not a configuration one.
