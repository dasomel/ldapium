# Parses one pod's container log into flat replication-conflict-raw
# extraction records. Invoked as:
#   grep -E 'do_syncrep2: rid=[0-9]+ CSN too old, ignoring [^ ]+ \(.*\)$' \
#     | awk -v pod="$pod" -f parse-replication-conflict.awk
#
# `CSN too old, ignoring` also marks ordinary relay duplicates, so this
# leaves that undeduplicated evidence intact rather than guessing which
# records lost data — see export-audit-log.sh's own header comment.
#
# Kept as its own file (rather than inline in export-audit-log.sh) so
# scripts/test/test-export-audit-log.sh can run this exact code path against
# fixture input without a live cluster.
function esc(s) {
  gsub(/\\/,"\\\\",s)
  gsub(/"/,"\\\"",s)
  return s
}
{
  record=$0
  sub(/^.*do_syncrep2: rid=/, "", record)
  rid=record
  sub(/ CSN too old, ignoring .*/, "", rid)
  csn=record
  sub(/^[0-9]+ CSN too old, ignoring /, "", csn)
  entry=csn
  sub(/^.* \(/, "", entry)
  sub(/\)$/, "", entry)
  sub(/ \(.*/, "", csn)
  time=csn
  sub(/#.*/, "", time)
  printf "{\"pod\":\"%s\",\"source\":\"replication-conflict-raw\",\"time\":\"%s\",\"entry\":\"%s\",\"discardedCSN\":\"%s\",\"rid\":\"%s\"}\n", \
    esc(pod), esc(time), esc(entry), esc(csn), esc(rid)
}
