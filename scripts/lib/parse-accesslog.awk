# Parses one pod's cn=accesslog ldapsearch LDIF output into flat accesslog
# extraction records. Invoked as:
#   ldapsearch ... objectClass reqStart reqSession reqAuthzID reqDN reqFilter reqResult \
#     | awk -v pod="$pod" -f parse-accesslog.awk
#
# reqSession: slapo-accesslog's own per-connection counter, captured solely
# to build correlationId (docs/audit-event-schema.md) — it is the closest
# thing this overlay has to a request/session id, though it resets across a
# slapd restart so it is not cross-restart-unique on its own (the
# correlationId derivation pairs it with reqStart).
#
# Kept as its own file (rather than inline in export-audit-log.sh) so
# scripts/test/test-export-audit-log.sh can run this exact code path against
# fixture input without a live cluster.
BEGIN { t=""; session=""; actor=""; dn=""; filt=""; result=""; is_bind=0 }
/^dn: reqStart=/ { if (t != "") print_record(); t=""; session=""; actor=""; dn=""; filt=""; result=""; is_bind=0 }
/^objectClass: auditBind$/ { is_bind=1 }
/^reqStart: / { t=substr($0,11) }
/^reqSession: / { session=substr($0,13) }
/^reqAuthzID: / { actor=substr($0,13) }
/^reqAuthzID:: / { actor=b64dec(substr($0,14)) }
/^reqDN: / { dn=substr($0,8) }
/^reqDN:: / { dn=b64dec(substr($0,9)) }
/^reqFilter: / { filt=substr($0,12) }
/^reqFilter:: / { filt=b64dec(substr($0,13)) }
/^reqResult: / { result=substr($0,12) }
# LDIF uses "attr:: <base64>" instead of "attr: <value>" whenever the value
# itself would be unsafe as plain text — a leading space or colon, a
# trailing space, or a non-UTF8 byte. A DN or filter with such a character
# is unusual but not impossible, and an audit export silently dropping a
# field on exactly the kind of value someone might be trying to hide is the
# wrong failure mode.
# Known residual limit: `cmd | getline` reads exactly one line, so a decoded
# value containing an embedded newline of its own only yields that value up
# to its first line — the rest is discarded when the pipe is closed below.
# Covers the realistic case (a DN or filter needing base64 for a stray byte,
# not for holding multiple lines of content) without the complexity of a
# full multi-line read for a shape reqDN/reqFilter are not expected to take.
function b64dec(enc,    cmd, decoded) {
  cmd = "printf %s '" enc "' | base64 -d 2>/dev/null"
  decoded = ""
  cmd | getline decoded
  close(cmd)
  return decoded
}
# Order matters: backslash first, or the backslashes this function itself
# inserts for \n/\t below would get escaped a second time. \n/\t/\r matter
# specifically because a base64-decoded value (the one case a raw control
# character can actually reach this function) can legitimately contain one —
# that is the reason LDIF encoded it in the first place, and an un-escaped
# one here would split a single JSON record across two lines of output.
function esc(s) {
  gsub(/\\/,"\\\\",s)
  gsub(/"/,"\\\"",s)
  gsub(/\r/,"\\r",s)
  gsub(/\n/,"\\n",s)
  gsub(/\t/,"\\t",s)
  return s
}
# A bind record has an empty reqAuthzID (there is no authorization identity
# until the bind itself succeeds) — reqDN, the identity the client attempted
# to bind as, is the only "who" a bind record has, so it stands in for actor
# here rather than being left blank.
function print_record(    op, who) {
  op = is_bind ? "bind" : "search"
  who = is_bind ? dn : actor
  printf "{\"pod\":\"%s\",\"source\":\"accesslog\",\"time\":\"%s\",\"actor\":\"%s\",\"op\":\"%s\",\"target\":\"%s\",\"filter\":\"%s\",\"result\":\"%s\",\"reqSession\":\"%s\"}\n", \
    pod, esc(t), esc(who), op, esc(dn), esc(filt), esc(result), esc(session)
}
END { if (t != "") print_record() }
