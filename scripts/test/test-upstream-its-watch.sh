#!/usr/bin/env bash
# Offline behavior checks; block curl/gh to catch accidental external calls.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0
check() {
	local description=$1
	shift
	if "$@"; then
		printf 'PASS: %s\n' "$description"
	else
		printf 'FAIL: %s\n' "$description" >&2
		fail=1
	fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixtures=$PWD/scripts/test/fixtures/upstream-its-watch
mkdir "$work/bin"
for command in curl gh; do
	printf '#!/bin/sh\necho "unexpected external call" >&2\nexit 99\n' >"$work/bin/$command"
	chmod +x "$work/bin/$command"
done
export PATH="$work/bin:$PATH"
export ITS_FILE=$fixtures/its.xml MASTER_FILE=$fixtures/syncrepl-before.c
export REL26_FILE=$fixtures/syncrepl-before.c TAGS_FILE=$fixtures/tags.json
export COMMENTS_FILE=$fixtures/comments-empty.json DRY_RUN=1
export ITS_ID=10664 TRACK_ISSUE=471 GH_REPO=dasomel/ldapium
watch() { ./scripts/upstream-its-watch.sh; }

out=$(watch)
check 'first run would comment' grep -qF 'would comment on dasomel/ldapium#471' <<<"$out"
check 'numeric release sorting excludes RC tags' grep -qF 'latest26=2.6.16 -->' <<<"$out"
check 'markers outside retry region are ignored' grep -qF '/fixhint=no' <<<"$out"
check 'first run posts one state marker' test "$(grep -c '<!-- upstream-its-watch state:' <<<"$out")" = 1

export COMMENTS_FILE=$fixtures/comments-previous.json
out=$(watch)
check 'same state: newest valid bot marker across pages, spoofed and malformed markers ignored' test "$out" = 'no change'

sed 's/UNCONFIRMED/RESOLVED/; s|<resolution></resolution>|<resolution>FIXED</resolution>|' \
	"$fixtures/its.xml" >"$work/changed.xml"
out=$(ITS_FILE=$work/changed.xml watch)
check 'ITS status change would comment' grep -qF 'would comment' <<<"$out"
check 'ITS status change is named' grep -qE 'ITS status: .* -> RESOLVED/FIXED/' <<<"$out"

out=$(MASTER_FILE=$fixtures/syncrepl-fixed.c watch)
check 'fix hint flip would comment' grep -qE 'master code: .*/fixhint=no -> .*/fixhint=yes' <<<"$out"

out=$(ITS_FILE=$work/missing watch 2>"$work/warnings")
check 'one unreachable source causes no false change' test "$out" = 'no change'
check 'unreachable source warns' grep -qF 'warning: its unreachable' "$work/warnings"
out=$(ITS_FILE=$work/missing MASTER_FILE=$fixtures/syncrepl-fixed.c watch 2>"$work/warnings")
check 'other changes retain unreachable source previous value' grep -qF 'its=UNCONFIRMED/---/milestone=---/comments=1/' <<<"$out"

status=0
ITS_FILE=$work/missing MASTER_FILE=$work/missing REL26_FILE=$work/missing TAGS_FILE=$work/missing \
	watch >"$work/all-out" 2>"$work/all-errors" || status=$?
check 'all unreachable exits 1' test "$status" = 1
check 'all unreachable never comments' test ! -s "$work/all-out"

printf '<html>invalid upstream response</html>\n' >"$work/invalid"
out=$(ITS_FILE=$work/invalid watch 2>"$work/warnings")
check 'invalid response is treated as unavailable' test "$out" = 'no change'
status=0
COMMENTS_FILE=$work/missing watch >"$work/history-out" 2>"$work/history-errors" || status=$?
check 'unreadable history fails closed' test "$status" != 0
check 'unreadable history never comments' test ! -s "$work/history-out"
exit "$fail"
