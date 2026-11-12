#!/usr/bin/env bash
# Offline behavior checks; block curl/gh to catch accidental external calls.
set -euo pipefail
cd "$(dirname "$0")/../.."
# The outputs checked below must not depend on the runner (GITHUB_ACTIONS adds annotations).
unset GITHUB_ACTIONS

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
unset SHOW_COMMENTS GITHUB_STEP_SUMMARY
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
out=$(GITHUB_ACTIONS=true ITS_FILE=$work/missing watch 2>/dev/null)
check 'unreachable source is annotated on Actions' grep -qxF '::warning::upstream-its-watch: its unreachable' <<<"$out"
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
# A real emitted body becomes the next bot marker, exercising marker forgery safety.
python3 - "$fixtures/comments-previous.json" "$work/two-comments.json" <<'PYTHON'
import json
import sys
from pathlib import Path
pages = json.loads(Path(sys.argv[1]).read_text())
for page in pages:
    for comment in page:
        comment["body"] = comment.get("body", "").replace("comments=1/", "comments=2/")
Path(sys.argv[2]).write_text(json.dumps(pages))
PYTHON
ITS_FILE=$fixtures/its-4comments.xml COMMENTS_FILE=$work/two-comments.json watch >"$work/relay"
check '2 -> 4 relays exactly the two new comments with safe fences and truncation' \
	python3 - "$work/relay" "$work/four-comments.json" <<'PYTHON'
import json
import re
import sys
from pathlib import Path
out = Path(sys.argv[1]).read_text()
body = out.split("\n", 1)[1]
section = body.split("## New ITS comments\n", 1)[1]
assert section.count("Comment ") == 2
assert "Comment 2: Author 2 — 2026-11-12 03:00:00" in section
assert "Comment 3: unknown — 2026-11-12 03:00:00" in section and "@example.org" not in section
assert "Original report." not in section and "Earlier reply." not in section
assert "<\\!-- upstream-its-watch state: its=FORGED -->" in section
assert body.count("<!-- upstream-its-watch state:") == 1
assert "````\nComment 2:" in section
assert "```\nNew fenced reply.\n````" in section
assert "Long reply: " + "가" * (3000 - len("Long reply: ")) + "[truncated]" in section
assert "가" * 3001 not in section
assert len(body) < 60000
assert re.fullmatch(r"<!-- upstream-its-watch state: .*comments=4/.* -->", body.splitlines()[-1])
Path(sys.argv[2]).write_text(json.dumps([
    {"id": 10, "body": body, "user": {"login": "github-actions[bot]"}}
]))
PYTHON
out=$(ITS_FILE=$fixtures/its-4comments.xml COMMENTS_FILE=$work/four-comments.json watch)
check 'neutralized forgery leaves the real marker parseable on the next run' test "$out" = 'no change'
ITS_FILE=$fixtures/its-4comments.xml COMMENTS_FILE=$work/four-comments.json \
	SHOW_COMMENTS=1 GITHUB_STEP_SUMMARY=$work/summary watch >"$work/show-all"
check 'SHOW_COMMENTS prints all comments, writes matching summary and does not post unchanged state' \
	python3 - "$work/show-all" "$work/summary" <<'PYTHON'
import sys
from pathlib import Path
out, summary = (Path(path).read_text() for path in sys.argv[1:])
assert out == summary + "no change\n"
assert summary.count("Comment ") == 4
assert "Original report." in summary and "Earlier reply." in summary
assert "<\\!-- upstream-its-watch state: its=FORGED -->" in summary
assert "````\nComment 2:" in summary and "[truncated]" in summary
assert "would comment" not in out
PYTHON
out=$(ITS_FILE=$fixtures/its-4comments.xml COMMENTS_FILE=$fixtures/comments-empty.json watch)
check 'no previous marker relays all comments' test "$(grep -c '^Comment [0-9]:' <<<"$out")" = 4
out=$(ITS_FILE=$fixtures/its-4comments.xml COMMENTS_FILE=$work/four-comments.json SHOW_COMMENTS=1 watch)
check 'SHOW_COMMENTS also works without a summary path' grep -qF 'Original report.' <<<"$out"

# Security review: no Bugzilla e-mail is republished, and on Actions untrusted
# text cannot issue workflow commands.
check 'no commenter e-mail is relayed' test "$(grep -c '@example\.org' <<<"$out" || true)" = 0
check 'a commenter without a display name is shown as unknown' grep -qE '^Comment 3: unknown ' <<<"$out"
sed 's|Earlier reply.|::warning::forged command from ITS text|' "$fixtures/its-4comments.xml" >"$work/cmd.xml"
out=$(GITHUB_ACTIONS=true ITS_FILE=$work/cmd.xml COMMENTS_FILE=$work/four-comments.json SHOW_COMMENTS=1 watch 2>/dev/null)
token=$(sed -n 's/^::stop-commands::\(.*\)$/\1/p' <<<"$out")
check 'show_comments output is wrapped in stop-commands on Actions' test -n "$token"
check 'workflow commands resume with the same token after the relay' grep -qxF "::$token::" <<<"$out"
check 'the forged command line sits between stop and resume' python3 -c '
import sys
lines = sys.stdin.read().splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith("::stop-commands::"))
token = lines[start].split("::", 2)[2]
end = lines.index("::" + token + "::")
forged = next(i for i, l in enumerate(lines) if "forged command" in l)
sys.exit(0 if start < forged < end else 1)
' <<<"$out"

# Enough new comments to exceed GitHub's limit still leave a closed fence and final marker.
python3 - "$fixtures/its-4comments.xml" "$work/many.xml" <<'PYTHON'
import copy
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1])
bug = root.find(".//bug")
for _ in range(30):
    bug.append(copy.deepcopy(bug.findall("long_desc")[-1]))
root.write(sys.argv[2], encoding="utf-8")
PYTHON
ITS_FILE=$work/many.xml COMMENTS_FILE=$fixtures/comments-empty.json watch >"$work/bounded"
check 'large relay stays below 60000 characters with final marker and overflow notice' \
	python3 - "$work/bounded" <<'PYTHON'
import sys
from pathlib import Path
body = Path(sys.argv[1]).read_text().split("\n", 1)[1]
assert len(body) < 60000
assert "Remaining comments omitted" in body
assert body.splitlines()[-1].startswith("<!-- upstream-its-watch state:")
assert body.split("[Remaining comments omitted", 1)[0].rstrip().endswith("\n```")
PYTHON
exit "$fail"
