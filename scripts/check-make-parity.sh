#!/usr/bin/env bash
# Fails when `make check` stops being what it says it is.
#
# CONTRIBUTING.md and the target's own help text both promise that `make check`
# runs everything CI runs. That promise decays silently: someone adds a step to
# ci.yml, CI goes green, and the local command quietly covers less than it
# claims. It had already decayed twice by the time this script was written.
#
# The comparison is limited to scripts/*.sh invocations, which is the part that
# can be compared honestly — a job's inline shell and its Action steps have no
# Makefile equivalent by construction. A CI script that genuinely cannot run on
# a developer's machine belongs in ci_only below, with the reason written down.
set -eu

cd "$(dirname "$0")/.."

# Scripts CI runs that `make check` deliberately does not.
#
#   check-base-images.sh    queries a container registry for each pinned digest,
#                           so it needs network and credentials that an air-gapped
#                           checkout will not have. CI has both.
#
#   verify-chart-schema.sh  needs the kubeconform binary. CI downloads it as its
#                           own step right before this script runs; `make check`
#                           deliberately does not require installing it locally.
ci_only="./scripts/check-base-images.sh ./scripts/verify-chart-schema.sh"

# A comment that mentions a script is not a step that runs one, and counting it
# would demand the Makefile run something CI only talks about.
uncommented() {
	sed -e 's/^[[:space:]]*#.*$//' -e 's/[[:space:]]#[[:space:]].*$//' "$1"
}

# `./scripts/<name>.sh` plus any --flags, so `licenses.sh --check` is not
# mistaken for a bare `licenses.sh`.
invocations() {
	grep -oE '\./scripts/[a-z-]+\.sh( --[a-z-]+)*' | sort -u
}

ci=$(uncommented .github/workflows/ci.yml | invocations)
# The range ends at the next target, whatever it is called; anchoring on a
# lowercase name would run past an uppercase or .PHONY one into other targets.
mk=$(uncommented Makefile | sed -n '/^check:/,/^[A-Za-z._-][A-Za-z._-]*:/p' | invocations)

if [ -z "$ci" ] || [ -z "$mk" ]; then
	echo "could not read the script lists; check the parsing in this script" >&2
	exit 2
fi

printf 'ci.yml runs:    %s\n' "$(echo "$ci" | tr '\n' ' ')"
printf 'make check runs: %s\n' "$(echo "$mk" | tr '\n' ' ')"

fail=0

# Everything below compares what ci.yml runs. If this script stops being one of
# those things, it goes on comparing an ever-shorter list and reports success.
if ! printf '%s\n' "$ci" | grep -qxF ./scripts/check-make-parity.sh; then
	echo "  ci.yml no longer runs this script, so nothing would notice the next drift" >&2
	exit 1
fi

while read -r step; do
	[ -z "$step" ] && continue
	case " $ci_only " in
	*" ${step%% *} "*) continue ;;
	esac
	if ! printf '%s\n' "$mk" | grep -qxF "$step"; then
		printf '  ci.yml runs %s but the check target does not\n' "$step"
		fail=1
	fi
done <<EOF
$ci
EOF

if [ "$fail" -ne 0 ]; then
	echo "add it to the check target, or to ci_only in this script with a reason" >&2
	exit 1
fi

echo "the check target covers every scripts/*.sh that CI runs"
