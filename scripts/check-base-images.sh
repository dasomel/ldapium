#!/usr/bin/env bash
# Fails when a pinned base image cannot serve every architecture we publish.
#
# Pinning by digest trades away one thing that floating tags gave us for free:
# a tag like `debian:trixie-slim` always resolves to a manifest list, but a
# digest can name either the list or a single-architecture image inside it.
# Pin the inner one and the amd64 build keeps working while the arm64 build
# fails — and it fails in build-multiarch.yml, which only runs on push and
# release, long after the PR that introduced it went green.
#
# So: every FROM must carry a digest, and every digest must resolve to a
# manifest list covering the platforms release.yml publishes. This is the check
# a Dependabot digest bump has to pass, not just the one a human bump does.
set -eu

cd "$(dirname "$0")/.."

# Kept in step with the `platforms:` line in build-multiarch.yml.
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

	printf 'checking %s\n' "$ref"
	if ! inspect=$(docker buildx imagetools inspect "$ref" 2>&1); then
		note "$ref could not be inspected: $(printf '%s' "$inspect" | head -1)"
		continue
	fi

	for platform in $required_platforms; do
		if ! printf '%s' "$inspect" | grep -q "Platform: *$platform\$"; then
			note "$ref does not provide $platform"
		fi
	done
done

if [ "$fail" -ne 0 ]; then
	echo "base image pins are not release-safe" >&2
	exit 1
fi

echo "every base image is pinned by digest and covers: $required_platforms"
