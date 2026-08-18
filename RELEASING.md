# Releasing

One git tag publishes everything. `v0.1.0` produces:

| Artifact | Where |
|---|---|
| Server image | `ghcr.io/dasomel/openldap-suite:0.1.0`, `:0.1`, `:latest`, `:sha-<sha>` |
| UI image | `ghcr.io/dasomel/openldap-suite-ui:` (same tags) |
| Helm chart | `oci://ghcr.io/dasomel/charts/openldap` version `0.1.0` |
| GitHub Release | Notes from `CHANGELOG.md`, with the chart tarball and four SBOMs attached |
| Attestations | Build provenance and SBOM, signed and pushed to the registry alongside each image |

## Cutting a release

1. **Decide the version.** 0.x, so a minor bump is allowed to break things —
   say so in the changelog when it does.

2. **Update the version in the four places that carry it**, then let the
   script confirm you found them all:

   ```sh
   # charts/openldap/Chart.yaml   version:
   # docker-compose.yml           OPENLDAP_IMAGE / UI_IMAGE default tags
   # ui/frontend/package.json     version
   # README.md                    install examples
   ./scripts/check-versions.sh
   ```

   `appVersion` is **not** one of them — that is the OpenLDAP release the
   image compiles, and it only changes when `image/Dockerfile`'s
   `OPENLDAP_VERSION` and its sha256 change.

3. **Write the changelog entry.** `## [X.Y.Z] — YYYY-MM-DD`, with a matching
   link at the bottom. The release workflow extracts this section verbatim and
   **fails if it is missing**, so the release cannot ship without it.

4. **Run the full check** — the same things CI runs:

   ```sh
   make check
   ```

5. **Merge to `main` and wait for CI to be green.** Tag from a commit that has
   already passed, not from one you hope will.

6. **Tag and push:**

   ```sh
   git tag -a v0.1.0 -m "openldap-suite 0.1.0"
   git push origin v0.1.0
   ```

   Never put `[skip ci]` in a tag annotation — the tag push is what triggers
   the release.

7. **Verify what was published**, rather than assuming the green check means
   it worked:

   ```sh
   helm pull oci://ghcr.io/dasomel/charts/openldap --version 0.1.0
   docker buildx imagetools inspect ghcr.io/dasomel/openldap-suite:0.1.0
   gh attestation verify oci://ghcr.io/dasomel/openldap-suite:0.1.0 \
     --repo dasomel/openldap-suite
   ```

   The `imagetools inspect` output must list both `linux/amd64` and
   `linux/arm64`.

## Going public (once)

Things no file in this repo can set. Do them before, or immediately after,
flipping the repository to public:

- [ ] **Repository → Settings → Actions → Workflow permissions:** read-only by
      default. Each workflow already requests exactly what it needs.
- [ ] **Code security:** enable secret scanning **and push protection**, and
      private vulnerability reporting (SECURITY.md links to the latter, so it
      404s until it is on).
- [ ] **Branch protection on `main`:** require the CI checks and a review.
      Scorecard grades this, so it also shows up in the badge.
- [ ] **Make the GHCR packages public.** They are private by default, and the
      first release will publish images nobody can pull. Under
      `github.com/users/dasomel/packages`, set `openldap-suite`,
      `openldap-suite-ui` and `charts/openldap` to public, and link each to
      this repository so the provenance attestation is discoverable.
- [ ] **Verify a clean pull from a machine that has never authenticated:**
      `docker pull ghcr.io/dasomel/openldap-suite:0.1.0` and
      `helm pull oci://ghcr.io/dasomel/charts/openldap --version 0.1.0`.
      This is the only check that catches package visibility being wrong.
- [ ] Add topics (`openldap`, `ldap`, `kubernetes`, `helm-chart`, `directory`)
      and a description so the repo is findable.

## Bumping OpenLDAP

Separate from a release of this project, though it usually triggers one:

1. Fetch the new tarball and its sha256 directly from openldap.org — take the
   digest from the file you downloaded, not from a mirror's listing.
2. Update `OPENLDAP_VERSION` and `OPENLDAP_SHA256` in `image/Dockerfile` and
   `appVersion` in `charts/openldap/Chart.yaml`. `./scripts/check-versions.sh`
   asserts those two agree.
3. Build the image and **boot it**, then check the overlays are still loaded
   and replication still converges on a 3-node install. A configure flag being
   renamed upstream shows up at runtime, not at build time.

## What is not automated

- **Nothing is signed by a human key.** Provenance and SBOM attestations are
  signed by GitHub's OIDC identity for this repository, which is what
  `gh attestation verify` checks. There is no separate maintainer GPG key.
- **No backports.** A fix ships in the next release; see SECURITY.md.
- **`:main` is not a release.** It is the weekly rebuild of the current source,
  published so base-image security updates are available between releases.
