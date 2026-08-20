# Air-gapped install

Everything ldapium needs at runtime can travel as one directory. This describes
how that directory is produced, what has to be true of it before you trust it,
how to install and upgrade from it with no network at all, and the one thing
that does keep needing a connected machine: vulnerability data.

## The bundle

`scripts/offline-bundle.sh VERSION OUTPUT_DIR` assembles it on a connected
machine:

```
bundle/
  chart/ldapium-<version>.tgz            packaged chart
  images/ldapium-{amd64,arm64}.tar.gz    server image, one archive per platform
  images/ldapium-ui-{amd64,arm64}.tar.gz management UI
  sbom/*.spdx.json                       SPDX SBOM per image
  metadata/*-manifest.json               the images' registry manifests
  metadata/bundle-manifest.json          release, digests, chart version, provenance
  SHA256SUMS                             every file above
```

The image archives carry the images under their **release names**
(`ghcr.io/<owner>/ldapium:<version>`), so nothing downstream needs to be told
it is looking at a bundle rather than a registry — the chart's own
`image.repository` default already matches.

`--from-local-images` builds the same layout from images already in the local
daemon and the chart in the working tree. That is what CI uses to test this
path on a pull request, where nothing is published yet. Such a bundle records
`"source": "local-build"` and no signed attestations; do not promote one.

## Before you trust it

```bash
scripts/offline-install.sh --bundle ./bundle --verify-only
```

This is a gate, not a formality. It fails when:

- any file no longer matches `SHA256SUMS`, or has gone missing since assembly
- the bundle has no packaged chart, no image archive, or no SBOM — which
  checksums alone would not catch, because a bundler that skipped SBOMs
  produces a perfectly self-consistent `SHA256SUMS`
- `bundle-manifest.json` does not name the release, both images, and the chart
  version

CI proves all three refusals on every pull request, against a bundle it just
built, before it installs anything.

## Install

```bash
scripts/offline-install.sh \
  --bundle ./bundle \
  --release directory \
  --namespace directory \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set replicaCount=3
```

It verifies, `docker load`s each archive, and installs the packaged chart with
`imagePullPolicy=Never` for both images. That last part is the whole point: it
turns "we did not happen to need the network" into "the network was never an
option". If an archive failed to load, the pod fails to start instead of
quietly pulling from a registry that an air-gapped cluster should not be able
to reach in the first place.

For clusters whose nodes do not share the local daemon, load the archives with
whatever your runtime uses — `ctr -n k8s.io images import`, `crictl`, or a
local registry seeded from the archives. `--kind-cluster NAME` covers kind,
which is what CI uses.

## Upgrade and rollback

Same bundle, same script:

```bash
scripts/offline-install.sh --bundle ./bundle-<newer> --release directory \
  --namespace directory --upgrade  ...
helm rollback directory --namespace directory      # if it goes wrong
```

Take a backup first — `charts/ldapium/README.md` has the preflight and the
reason it is a gate rather than a suggestion. Rollback returns the release to
the previous revision, whose images are already on the node from the bundle
that installed it; it does not need the network either.

## Vulnerability data

This is the one thing a bundle cannot freeze, because the answer changes while
the artifacts do not. An image that was clean when it was bundled is not clean
forever, and an air-gapped scanner with a six-month-old database will report
that it is.

Trivy — what this project's CI uses — keeps two OCI artifacts, both fetchable
on a connected machine and transferable:

```bash
# On a connected machine, once per refresh:
trivy image --download-db-only --cache-dir ./trivy-cache
trivy image --download-java-db-only --cache-dir ./trivy-cache   # only if scanning JVM images
tar czf trivy-cache.tar.gz trivy-cache

# On the air-gapped machine:
tar xzf trivy-cache.tar.gz
trivy image --cache-dir ./trivy-cache --skip-db-update --skip-java-db-update \
  --input ./bundle/images/ldapium-amd64.tar.gz
```

`--skip-db-update` matters: without it Trivy tries to refresh and fails closed
on a host that cannot reach the internet, which reads like a broken scanner
rather than a stale database.

If the environment has an internal registry, the more durable arrangement is to
mirror the DB artifacts into it and point scanners at that with
`--db-repository`, so refreshing is a registry sync rather than a file transfer
someone has to remember to repeat.

Whichever way it moves, **record when the database was last refreshed** and
treat that date as part of the scan result. A scan is a statement about a
database version as much as about an image, and in an air-gapped environment
the database version is the part that silently goes wrong.
