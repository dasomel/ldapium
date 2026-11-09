#!/usr/bin/env bash
# Runs govulncheck on ui/backend and gates on reachable ("called") findings,
# minus the explicit per-ID exclusions in ui/backend/govulncheck-exclude.txt.
#
# D460-1: govulncheck has no per-ID ignore flag, and call-graph reachability
# still flags advisories in imported packages when package init or a shared
# helper is reached while the vulnerable middleware itself is unused and has no
# upstream fix yet (#460). Cost: jq parses `-format json` instead of raw text
# output. Escape hatch: stale exclusions fail the gate so each entry must be
# removed in the PR that bumps to a fixed release; drop this wrapper once the
# exclusion file is empty and native filtering exists.
set -euo pipefail

cd "$(dirname "$0")/.."

exclude_file="ui/backend/govulncheck-exclude.txt"

for cmd in go jq; do
	command -v "$cmd" >/dev/null 2>&1 || {
		echo "$cmd is required" >&2
		exit 2
	}
done

if [ ! -f "$exclude_file" ]; then
	echo "$exclude_file not found" >&2
	exit 2
fi

excluded_ids=""
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
	line="${raw_line%%#*}"
	line="${line#"${line%%[![:space:]]*}"}"
	line="${line%"${line##*[![:space:]]}"}"
	if [ -z "$line" ]; then
		continue
	fi
	if [[ ! "$line" =~ ^GO-[0-9]{4}-[0-9]{4,}$ ]]; then
		echo "invalid exclusion entry in $exclude_file: $line" >&2
		exit 2
	fi
	case " $excluded_ids " in
	*" $line "*)
		echo "duplicate exclusion in $exclude_file: $line" >&2
		exit 2
		;;
	esac
	excluded_ids="${excluded_ids:+$excluded_ids }$line"
done <"$exclude_file"

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
raw_json="$tmp_dir/govulncheck.json"
raw_err="$tmp_dir/govulncheck.err"
called_tsv="$tmp_dir/called.tsv"

# Pinned, not @latest: `go run tool@latest` downloads and executes whatever was
# published most recently at scan time. Keep bumped by hand.
# Note: with `-format json`, govulncheck exits 0 even when findings exist; a
# non-zero exit or missing `config` header means the scanner itself failed.
if ! (cd ui/backend && go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -format json ./...) >"$raw_json" 2>"$raw_err"; then
	cat "$raw_err" >&2
	exit 2
fi

if ! jq -se 'any(.[]; .config != null)' "$raw_json" >/dev/null 2>&1; then
	echo "govulncheck output is missing the config object" >&2
	cat "$raw_err" >&2
	exit 2
fi

jq -sr '
	(reduce (.[] | select(.osv != null) | .osv) as $o ({}; .[$o.id] = $o.summary)) as $summaries |
	(reduce (.[] | select(.finding != null and ((.finding.trace[0].function // "") != "")) | .finding) as $f (
		{order: [], seen: {}};
		if .seen[$f.osv] then . else
			.seen[$f.osv] = $f | .order += [$f.osv]
		end
	)) as $called |
	($called.order | sort)[] as $id |
	$called.seen[$id] as $f |
	$f.trace[0] as $t |
	(if ($t.package // "") != "" then "\($t.package).\($t.function)" else $t.function end) as $fn |
	((if ($summaries[$id] // "") != "" then $summaries[$id] else "(no summary)" end) | gsub("[\t\r\n]+"; " ")) as $sum |
	"\($id)\t\($fn)\t\($sum)"
' "$raw_json" >"$called_tsv"

fail=0
called_ids=""

while IFS=$'\t' read -r id fn summary; do
	if [ -z "$id" ]; then
		continue
	fi
	called_ids="${called_ids:+$called_ids }$id"
	case " $excluded_ids " in
	*" $id "*)
		printf 'excluded (see %s): %s %s\n' "$exclude_file" "$id" "$summary"
		;;
	*)
		printf 'unexcluded reachable vulnerability: %s — %s (called: %s)\n' "$id" "$summary" "$fn"
		fail=1
		;;
	esac
done <"$called_tsv"

for ex_id in $excluded_ids; do
	case " $called_ids " in
	*" $ex_id "*) ;;
	*)
		printf 'stale exclusion: %s, remove it from %s\n' "$ex_id" "$exclude_file"
		fail=1
		;;
	esac
done

if [ "$fail" -ne 0 ]; then
	exit 1
fi

echo "govulncheck: no unexcluded reachable vulnerabilities"
