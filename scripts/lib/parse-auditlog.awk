# Parses one pod's container log into flat auditlog extraction records.
#
# Invoked as: awk -v pod="$pod" -f parse-auditlog.awk
#
# auditlog's own format: "# <op> <unixtime> <suffix> <bindDN> IP=... conn=..."
# opening each record, ended by the next such line or EOF, followed by the
# LDIF body of what changed. This reads that body too — not to capture full
# attribute values (still left for a SIEM's own "show me the raw event"
# drill-down, and doing so would risk logging userPassword's value) but to
# pull two cheap, high-value fields out of it: the entry's real DN (the
# LDIF's own "dn:" line — the header's $4 is the database suffix, not the
# entry) and which attribute NAMES changed (docs/audit-event-schema.md's
# redaction guarantee: names only, never values, which is what keeps a
# password out of this export without needing to know every password-like
# attribute name in advance).
#
# changedAttrs enforcement (not just a name-token grab): add_changed() below
# truncates at the first whitespace and validates what remains against a
# strict attribute-name shape before accepting it, so a malformed or
# adversarial line like "replace: userPassword <value>" on one line (real
# LDIF never does this — a modify's changed value is always its own
# following line) cannot smuggle a value past the "names only" guarantee.
# scripts/lib/audit-normalize.py applies the same check again downstream as
# a second, independent layer.
#
# Kept as its own file (rather than inline in export-audit-log.sh) so
# scripts/test/test-export-audit-log.sh can run this exact code path against
# fixture input without a live cluster.
function esc(s) {
  gsub(/\\/, "\\\\", s)
  gsub(/"/, "\\\"", s)
  gsub(/\r/, "\\r", s)
  gsub(/\n/, "\\n", s)
  gsub(/\t/, "\\t", s)
  return s
}
function b64dec(enc,    cmd, decoded) {
  cmd = "printf %s '" enc "' | base64 -d 2>/dev/null"
  decoded = ""
  cmd | getline decoded
  close(cmd)
  return decoded
}
# Attribute descriptions look like "cn" or "userPassword;lang-en" — a
# leading letter, then letters/digits/hyphens, optionally followed by one or
# more ";"-separated options with the same shape. Nothing else is a valid
# bare attribute name, which is exactly the property this guarantee needs.
function valid_attr_name(name) {
  return name ~ /^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$/
}
function add_changed(name) {
  sub(/[ \t].*/, "", name)
  if (!valid_attr_name(name)) {
    if (name != "")
      print "parse-auditlog.awk: dropping malformed changedAttrs entry: " name > "/dev/stderr"
    return
  }
  if (index("\037" changed "\037", "\037" name "\037") == 0) changed = changed "\037" name
}
function flush(    n, i, attrs_json) {
  if (op == "") return
  attrs_json = "["
  n = split(changed, arr, "\037")
  for (i = 1; i <= n; i++) {
    if (arr[i] == "") continue
    if (attrs_json != "[") attrs_json = attrs_json ","
    attrs_json = attrs_json "\"" esc(arr[i]) "\""
  }
  attrs_json = attrs_json "]"
  printf "{\"pod\":\"%s\",\"source\":\"auditlog\",\"time\":\"%s\",\"actor\":\"%s\",\"op\":\"%s\",\"target\":\"%s\",\"entryDn\":\"%s\",\"entryUUID\":\"%s\",\"changedAttrs\":%s}\n", \
    esc(pod), esc(t), esc(actor), esc(op), esc(target), esc(entrydn), esc(entryuuid), attrs_json
}
/^# (add|modify|modrdn|delete) / {
  flush()
  op = $2; t = $3; target = $4; actor = $5
  entrydn = ""; entryuuid = ""; changed = ""
  next
}
op == "" { next }
entrydn == "" && /^dn: / { entrydn = substr($0, 5); next }
entrydn == "" && /^dn:: / { entrydn = b64dec(substr($0, 6)); next }
/^entryUUID: / { entryuuid = substr($0, 12); next }
op == "modify" && /^(add|delete|replace): / {
  name = $0
  sub(/^(add|delete|replace): /, "", name)
  add_changed(name)
  next
}
op == "add" && /^[A-Za-z][A-Za-z0-9;-]*:: ?/ {
  name = $0; sub(/::.*/, "", name)
  if (name != "dn") add_changed(name)
  next
}
op == "add" && /^[A-Za-z][A-Za-z0-9;-]*: / {
  name = $0; sub(/:.*/, "", name)
  if (name != "dn" && name != "changetype") add_changed(name)
  next
}
END { flush() }
