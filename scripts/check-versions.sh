#!/bin/sh
# Fails when the version numbers that have to agree across this repo have
# drifted apart. Three of them are copies of the same fact and one is a
# different fact that is easy to confuse with the others:
#
#   release version  — charts/openldap Chart.yaml `version`. A git tag vX.Y.Z
#                      publishes the chart AND both images under X.Y.Z (see
#                      .github/workflows/release.yml), so the chart's default
#                      image tag and docker-compose.yml's default images must
#                      all say the same thing.
#   OpenLDAP version — Chart.yaml `appVersion` and image/Dockerfile's
#                      OPENLDAP_VERSION arg. This is what gets compiled and
#                      what the UI reports; it is never an image tag.
#
# A released chart once reported OpenLDAP "0.1.0" because the release
# workflow overwrote appVersion with the chart version. Nothing caught it,
# so this script exists.
set -eu

cd "$(dirname "$0")/.."

fail=0
note() {
	printf '  %s\n' "$1"
	fail=1
}

chart_version=$(awk '/^version:/ { print $2; exit }' charts/openldap/Chart.yaml)
app_version=$(awk '/^appVersion:/ { gsub(/"/, "", $2); print $2; exit }' charts/openldap/Chart.yaml)
dockerfile_version=$(awk -F= '/^ARG OPENLDAP_VERSION=/ { print $2; exit }' image/Dockerfile)

printf 'release version (Chart.yaml version): %s\n' "$chart_version"
printf 'OpenLDAP version (appVersion):        %s\n' "$app_version"

if [ -z "$chart_version" ] || [ -z "$app_version" ] || [ -z "$dockerfile_version" ]; then
	echo "could not read one of the versions; check the parsing in this script" >&2
	exit 2
fi

# The OpenLDAP the chart claims to run must be the one the image builds.
if [ "$app_version" != "$dockerfile_version" ]; then
	note "Chart.yaml appVersion ($app_version) != image/Dockerfile OPENLDAP_VERSION ($dockerfile_version)"
fi

# appVersion is an OpenLDAP release, so it must not be the chart's own
# version. Equal values are how the confusion above starts.
if [ "$app_version" = "$chart_version" ]; then
	note "Chart.yaml appVersion equals version ($app_version); appVersion is the OpenLDAP release, not the chart release"
fi

# docker-compose.yml pins published images by tag for people who never touch
# Kubernetes; those tags are cut by the same release.
for var in OPENLDAP_IMAGE UI_IMAGE; do
	tag=$(sed -n "s/.*\${$var:-[^:]*:\([^}]*\)}.*/\1/p" docker-compose.yml)
	if [ -z "$tag" ]; then
		note "docker-compose.yml has no default tag for \$$var"
	elif [ "$tag" != "$chart_version" ]; then
		note "docker-compose.yml \$$var default tag ($tag) != release version ($chart_version)"
	fi
done

# The frontend package is never published to npm, but its version shows up in
# lockfiles and SBOMs, so it is one more copy of the same number.
npm_version=$(awk -F'"' '/^  "version":/ { print $4; exit }' ui/frontend/package.json)
if [ "$npm_version" != "$chart_version" ]; then
	note "ui/frontend/package.json version ($npm_version) != release version ($chart_version)"
fi

# README.md's install examples are what people copy; a stale version there
# sends them to a tag that may not exist yet.
readme_tags=$(grep -oE 'openldap-suite(-ui)?:[0-9]+\.[0-9]+\.[0-9]+' README.md | sed 's/.*://' | sort -u)
readme_chart=$(grep -oE -- '--version [0-9]+\.[0-9]+\.[0-9]+' README.md | awk '{ print $2 }' | sort -u)
for v in $readme_tags $readme_chart; do
	if [ "$v" != "$chart_version" ]; then
		note "README.md refers to version $v, expected $chart_version"
	fi
done

# The chart's own rendering is the thing users actually pull, so assert on
# the rendered output rather than on the template that produces it.
if command -v helm >/dev/null 2>&1; then
	rendered=$(helm template versioncheck charts/openldap \
		--set auth.adminPassword=render-only-not-a-secret \
		--set ui.enabled=true |
		sed -n 's/^[[:space:]]*image:[[:space:]]*//p' | sort -u)
	for ref in $rendered; do
		case "$ref" in
		*":$chart_version") ;;
		*) note "chart renders image $ref, expected tag $chart_version" ;;
		esac
	done
else
	echo "helm not found; skipped the rendered-image check"
fi

if [ "$fail" -ne 0 ]; then
	echo
	echo "version drift detected — see the comment at the top of $0" >&2
	exit 1
fi

echo "versions agree"
