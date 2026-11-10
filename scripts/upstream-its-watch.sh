#!/usr/bin/env bash
# Weekly upstream watch for #471. *_FILE overrides are offline fixture inputs:
# ITS_FILE, MASTER_FILE, REL26_FILE, TAGS_FILE, COMMENTS_FILE (missing = unavailable).
set -euo pipefail

ITS_ID=${ITS_ID:-10664}
TRACK_ISSUE=${TRACK_ISSUE:-471}
GH_REPO=${GH_REPO:-dasomel/ldapium}

fetch() {
	local override=$1 url=$2 destination=$3
	if [[ -n ${!override+x} ]]; then
		cat -- "${!override}" >"$destination"
	else
		curl --fail --max-time 30 --retry 2 -sS -L "$url" -o "$destination"
	fi
}

parse_its() {
	python3 - "$1" <<'PY'
import sys
import xml.etree.ElementTree as ET
from urllib.parse import quote
bug = ET.parse(sys.argv[1]).find(".//bug")
if bug is None or bug.get("error"):
    raise ValueError("missing bug or Bugzilla error")
def field(name, required=False):
    value = (bug.findtext(name) or "").strip()
    if required and not value:
        raise ValueError("missing " + name)
    return quote(value or "---", safe="-_.:")
print(f'{field("bug_status", True)}/{field("resolution")}'
      f'/milestone={field("target_milestone")}/comments={len(bug.findall("long_desc"))}'
      f'/delta={field("delta_ts", True)}')
PY
}

parse_code() {
	python3 - "$1" <<'PY'
import hashlib
import re
import sys
from pathlib import Path
raw = Path(sys.argv[1]).read_bytes()
code = raw.decode("utf-8")
region = re.search(r"^\s*retry_diff:\s*$([\s\S]*?)\bgoto\s+retry_diff\b", code, re.M)
if not region:
    raise ValueError("retry_diff region missing")
hint = any(marker in region.group(1) for marker in
           ("slap_entry2mods", "diff_done", "SLAP_ATTR_IXADD"))
print(hashlib.sha256(raw).hexdigest()[:12] + "/fixhint=" + ("yes" if hint else "no"))
PY
}

parse_tags() {
	python3 - "$1" <<'PY'
import json
import re
import sys
with open(sys.argv[1]) as source:
    tags = json.load(source)
versions = []
for tag in tags:
    match = re.fullmatch(r"OPENLDAP_REL_ENG_2_6_(\d+)", tag["name"])
    if match:
        versions.append((2, 6, int(match.group(1))))
print(".".join(map(str, max(versions))))
PY
}

previous_state() {
	python3 - "$1" "${MARKER_AUTHOR:-github-actions[bot]}" <<'PY'
import json
import re
import sys
with open(sys.argv[1]) as source:
    pages = json.load(source)
# gh --slurp wraps paginated arrays; fixtures may also be a single array.
comments = [comment for page in pages for comment in (page if isinstance(page, list) else [page])]
# #471 is a public issue: anyone can post a marker. Trust only the workflow's
# own comments, and only a marker whose every field has the expected shape.
field = r"(?:its|master|rel26|latest26)=[A-Za-z0-9%._:/=+-]+"
shape = re.compile(rf"{field}(?: {field})*")
for comment in sorted(comments, key=lambda c: c["id"], reverse=True):
    if (comment.get("user") or {}).get("login") != sys.argv[2]:
        continue
    match = re.search(r"<!-- upstream-its-watch state: (.*?) -->", comment.get("body") or "")
    if match and shape.fullmatch(match.group(1)):
        print(match.group(1))
        break
PY
}

main() (
	local work source value previous state body label old changed=0 reachable=0
	local -a prev_fields=()
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	local -a sources=(its master rel26 latest26) values=() changes=()
	local -a overrides=(ITS_FILE MASTER_FILE REL26_FILE TAGS_FILE)
	local -a parsers=(parse_its parse_code parse_code parse_tags)
	local -a urls=(
		"https://bugs.openldap.org/show_bug.cgi?ctype=xml&id=$ITS_ID"
		'https://git.openldap.org/openldap/openldap/-/raw/master/servers/slapd/syncrepl.c'
		'https://git.openldap.org/openldap/openldap/-/raw/OPENLDAP_REL_ENG_2_6/servers/slapd/syncrepl.c'
		'https://git.openldap.org/api/v4/projects/openldap%2Fopenldap/repository/tags?search=%5EOPENLDAP_REL_ENG_2_6_&per_page=100'
	)
	for source in 0 1 2 3; do
		if fetch "${overrides[$source]}" "${urls[$source]}" "$work/source" &&
			value=$("${parsers[$source]}" "$work/source" 2>"$work/parse-error"); then
			values[source]=$value
			reachable=$((reachable + 1))
		else
			values[source]=unreachable
			printf 'warning: %s unreachable (fetch or parse failed)\n' "${sources[$source]}" >&2
			# A partly blind watcher still exits 0; surface it on the run page too.
			if [[ ${GITHUB_ACTIONS:-} == true ]]; then
				printf '::warning::upstream-its-watch: %s unreachable\n' "${sources[$source]}"
			fi
		fi
	done
	if [[ $reachable == 0 ]]; then
		echo 'all sources unreachable' >&2
		return 1
	fi

	# D1: Fail closed if history cannot be read; otherwise an API outage could
	# duplicate comments. This costs one read/run; retry the workflow to recover.
	if [[ -n ${COMMENTS_FILE+x} ]]; then
		cp -- "$COMMENTS_FILE" "$work/comments"
	else
		gh api "repos/$GH_REPO/issues/$TRACK_ISSUE/comments" --paginate --slurp >"$work/comments"
	fi
	previous=$(previous_state "$work/comments")
	[[ -n $previous ]] || changed=1
	state=''
	for source in 0 1 2 3; do
		label=${sources[$source]}
		old=''
		read -ra prev_fields <<<"$previous"
		# ${a[@]+...}: an empty array under set -u is "unbound" in bash < 4.4 (macOS).
		for value in ${prev_fields[@]+"${prev_fields[@]}"}; do
			if [[ $value == "$label="* ]]; then old=${value#*=}; fi
		done
		value=${values[$source]}
		# D2: Retain unavailable sources' last observation so outages do not
		# notify. Recovery is compared on the next run; no separate state store.
		if [[ $value == unreachable ]]; then
			value=${old:-unreachable}
		elif [[ $value != "$old" ]]; then
			changed=1
			case $label in
			its) label='ITS status' ;;
			master) label='master code' ;;
			rel26) label='2.6 branch code' ;;
			latest26) label='latest 2.6 release' ;;
			esac
			changes+=("- $label: ${old:-not previously observed} -> $value")
		fi
		state+="${state:+ }${sources[$source]}=$value"
	done
	if [[ $changed == 0 ]]; then
		echo 'no change'
		return 0
	fi
	body=$(printf 'OpenLDAP ITS#%s upstream watch: changes detected.\n\n' "$ITS_ID"
		printf '%s\n' "${changes[@]}"
		printf '\nFix hints are heuristic; review upstream before removing the local retry_diff patch.\n'
		printf '\n<!-- upstream-its-watch state: %s -->\n' "$state")
	if [[ ${DRY_RUN:-0} == 1 ]]; then
		printf 'would comment on %s#%s:\n%s\n' "$GH_REPO" "$TRACK_ISSUE" "$body"
	else
		gh issue comment "$TRACK_ISSUE" --repo "$GH_REPO" --body "$body"
	fi
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
fi
