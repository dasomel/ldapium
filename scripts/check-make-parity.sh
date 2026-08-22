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
#   check-base-images.sh  queries a container registry for each pinned digest,
#                         so it needs network and credentials that an air-gapped
#                         checkout will not have. CI has both.
ci_only="check-base-images.sh"

invocations() {
	# `./scripts/<name>.sh` plus any --flags, so `licenses.sh --check` is not
	# mistaken for a bare `licenses.sh`.
	grep -oE '\./scripts/[a-z-]+\.sh( --[a-z-]+)*' "$1" | sort -u
}

ci=$(invocations .github/workflows/ci.yml)
mk=$(sed -n '/^check:/,/^[a-z]/p' Makefile | grep -oE '\./scripts/[a-z-]+\.sh( --[a-z-]+)*' | sort -u)

if [ -z "$ci" ] || [ -z "$mk" ]; then
	echo "could not read the script lists; check the parsing in this script" >&2
	exit 2
fi

printf 'ci.yml runs:    %s\n' "$(echo "$ci" | tr '\n' ' ')"
printf 'make check runs: %s\n' "$(echo "$mk" | tr '\n' ' ')"

fail=0
while read -r step; do
	[ -z "$step" ] && continue
	name=${step##*/}
	name=${name%% *}
	case " $ci_only " in
	*" $name "*) continue ;;
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
