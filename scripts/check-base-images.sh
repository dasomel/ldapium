#!/usr/bin/env bash
# Fails when a pinned base image cannot serve every architecture we publish.
#
# Pinning by digest trades away one thing that floating tags gave us for free:
# a tag like `debian:trixie-slim` always resolves to a manifest list, but a
# digest can name either the list or a single-architecture image inside it.
# `docker inspect` on a pulled image hands you the latter, so that mistake is
# one copy-paste away. Pin the inner one and the amd64 build keeps working while
# the arm64 build fails — in build-multiarch.yml, which runs on push and release
# rather than on pull requests, so the PR that introduced it goes green.
#
# So: every FROM must carry a digest, and every digest must resolve to a
# manifest list covering the platforms we publish. This is the check a
# Dependabot digest bump has to pass, not just the one a human bump does.
set -eu

cd "$(dirname "$0")/.."

# Kept in step with the `platforms:` line in build-multiarch.yml. Compared
# against os/architecture only: registries record arm64 as arm64/v8, and the
# variant is not something we have an opinion about.
required_platforms="linux/amd64 linux/arm64"

fail=0
note() {
	printf '  %s\n' "$1"
	fail=1
}

dockerfiles=(image/Dockerfile ui/Dockerfile)

# `FROM <repo>:<tag>@sha256:<hex>` — the tag stays for humans, the digest is
# what docker actually resolves.
pins=$(grep -hE '^FROM ' "${dockerfiles[@]}" | awk '{print $2}' | sort -u)

if [ -z "$pins" ]; then
	echo "no FROM lines found; check the parsing in this script" >&2
	exit 2
fi

for ref in $pins; do
	case "$ref" in
	*@sha256:*) ;;
	*)
		note "$ref is not pinned by digest"
		continue
		;;
	esac

	# --raw returns the manifest itself. The rendered output is for reading and
	# has shifted between buildx releases; this has not.
	if ! raw=$(docker buildx imagetools inspect --raw "$ref" 2>&1); then
		note "$ref could not be inspected: $(printf '%s' "$raw" | head -1)"
		continue
	fi

	# Attestation manifests ride along as unknown/unknown; ignore them.
	available=$(printf '%s' "$raw" | jq -r '
		[.manifests // [] | .[] | .platform
		 | select(.os != "unknown")
		 | "\(.os)/\(.architecture)"] | unique | join(" ")')

	if [ -z "$available" ]; then
		note "$ref is a single-architecture image, not a manifest list"
		continue
	fi

	printf '%s\n  %s\n' "$ref" "$available"

	for platform in $required_platforms; do
		case " $available " in
		*" $platform "*) ;;
		*) note "$ref does not provide $platform" ;;
		esac
	done
done

if [ "$fail" -ne 0 ]; then
	echo "base image pins are not release-safe" >&2
	exit 1
fi

echo "every base image is pinned by digest and covers: $required_platforms"
