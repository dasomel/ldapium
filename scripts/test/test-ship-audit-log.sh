#!/usr/bin/env bash
# Integration test for scripts/ship-audit-log.sh and scripts/lib/audit-ship.py.
#
# Tests against a local HTTP server fixture:
# 1. Plaintext http:// forbidden without --allow-insecure-http (D5).
# 2. CLI argument validation (batch-size >= 1) (D7).
# 3. HTTP redirect refused without following or credential leak (D5).
# 4. Successful batch delivery with Bearer token and X-Ldapium-Batch-Id (D3).
# 5. Cursor idempotency: re-running on the same input produces 0 duplicates.
# 6. Bounded exponential backoff: transient 5xx errors succeed on retry.
# 7. Dead-letter queue creation when retries are exhausted.
# 8. Dead-letter replay on subsequent run before shipping new records (D7 streaming).
# 9. Overall delivery order and strict sequence.
# 10. Cursor across invocations when seq restarts at 1 (D4 time+hash cursor).
# 11. Fatal non-zero exit on cursor persistence failure with read-only state dir (D6).
# 12. Float argument validation: non-finite values (nan, inf) rejected with exit 2 (D7).
# 13. Per-(source, pod) cursor: late pod not shadowed by newer events from another pod (D4).
# 14. Dead-letter file lock: concurrent invocations fail fast or serialize with no lost lines (D6).
#
# Run: ./scripts/test/test-ship-audit-log.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
top="${here}/../.."
work="$(mktemp -d)"
server_log="${work}/server.log"
server_received="${work}/received.ndjson"
server_ctl="${work}/server-ctl.txt"
server_port_file="${work}/port.txt"
server_ready="${work}/ready"

server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  # Ensure any read-only test directories are writable before cleanup
  chmod -R 0755 "$work" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# Start the mock HTTP sink server
python3 - "$server_port_file" "$server_ctl" "$server_received" "$server_ready" <<'PYEOF' > "$server_log" 2>&1 &
import json
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

port_file = sys.argv[1]
ctl_file = sys.argv[2]
received_file = sys.argv[3]
ready_file = sys.argv[4]

class MockSinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")

        auth = self.headers.get("Authorization", "")
        batch_id = self.headers.get("X-Ldapium-Batch-Id", "")

        status_to_return = 200
        fail_remaining = 0
        delay_sec = 0.0
        try:
            with open(ctl_file, "r") as f:
                for line in f.read().splitlines():
                    line = line.strip()
                    if line.startswith("fail:"):
                        fail_remaining = int(line.split(":", 1)[1])
                    elif line.startswith("delay:"):
                        delay_sec = float(line.split(":", 1)[1])
                    elif line.isdigit():
                        status_to_return = int(line)
        except Exception:
            pass

        if delay_sec > 0:
            time.sleep(delay_sec)

        if fail_remaining > 0:
            fail_remaining -= 1
            with open(ctl_file, "w") as f:
                f.write(f"fail:{fail_remaining}\n")
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Service Unavailable (mock)\n")
            return

        if status_to_return in (301, 302, 303, 307, 308):
            self.send_response(status_to_return)
            self.send_header("Location", "http://127.0.0.1:9999/redirected")
            self.end_headers()
            return

        if status_to_return != 200:
            self.send_response(status_to_return)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Error (mock)\n")
            return

        # Record received records along with batch metadata
        with open(received_file, "a") as f:
            for line in body.splitlines():
                line = line.strip()
                if line:
                    entry = {"auth": auth, "batchId": batch_id, "record": json.loads(line)}
                    f.write(json.dumps(entry) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"accepted"}\n')

    def log_message(self, format, *args):
        pass

server = HTTPServer(("127.0.0.1", 0), MockSinkHandler)
port = server.server_port
with open(port_file, "w") as f:
    f.write(str(port))
with open(ready_file, "w") as f:
    f.write("ready")
server.serve_forever()
PYEOF
server_pid=$!

# Wait for server to become ready
for _ in $(seq 1 30); do
  [ -f "$server_ready" ] && break
  sleep 0.1
done
[ -f "$server_ready" ] || { echo "mock server failed to start" >&2; exit 1; }

port=$(cat "$server_port_file")
sink_url="http://127.0.0.1:${port}/siem/ingest"

# Create token file
token_file="${work}/bearer-token.txt"
printf 'secret-bearer-token-12345\n' > "$token_file"

cursor_file="${work}/cursor.json"
dead_letter_file="${work}/dead-letter.ndjson"

# Create test input events (seq 1, 2, 3)
input_part1="${work}/events-part1.ndjson"
cat <<'EOF' > "$input_part1"
{"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:00:00Z","actor":"cn=admin,dc=example,dc=org","target":"uid=alice,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:1:uid=alice:cn=admin","privileged":true,"raw":{}}
{"schemaVersion":"1","source":"auditlog","seq":2,"time":"2026-08-23T15:00:01Z","actor":"cn=admin,dc=example,dc=org","target":"uid=bob,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:2:uid=bob:cn=admin","privileged":true,"raw":{}}
{"schemaVersion":"1","source":"accesslog","seq":1,"time":"2026-08-23T15:00:02Z","actor":"uid=bob,ou=people,dc=example,dc=org","target":"uid=bob,ou=people,dc=example,dc=org","op":"bind","result":"success","objectId":null,"correlationId":"accesslog:pod-0:1:20260823150002.000000Z","privileged":false,"raw":{}}
EOF

# 1. Plaintext http:// rejected without --allow-insecure-http (D5)
if "${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --token-file "$token_file"   --file "$input_part1" > "${work}/insecure-refused.stdout" 2>"${work}/insecure-refused.stderr"; then
  bad "shipper allowed insecure http:// without --allow-insecure-http"
else
  if grep -q "plaintext http:// sink URL is forbidden" "${work}/insecure-refused.stderr"; then
    ok "shipper rejects plaintext http:// sink URL without --allow-insecure-http"
  else
    bad "shipper rejected http:// but without expected error message"
    cat "${work}/insecure-refused.stderr" >&2
  fi
fi

# 2. CLI argument validation: batch-size 0 rejected (D7)
if "${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --batch-size 0   --file "$input_part1" > "${work}/batch-zero.stdout" 2>"${work}/batch-zero.stderr"; then
  bad "shipper accepted --batch-size 0"
else
  if grep -q "must be an integer >= 1" "${work}/batch-zero.stderr"; then
    ok "shipper rejects --batch-size 0 with argparse validation error"
  else
    bad "shipper rejected --batch-size 0 but without expected error message"
    cat "${work}/batch-zero.stderr" >&2
  fi
fi

# 3. HTTP redirect refused without following (D5)
printf '302\n' > "$server_ctl"
if "${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "${work}/cursor-redirect.json"   --dead-letter-file "${work}/dead-letter-redirect.ndjson"   --file "$input_part1"   --max-retries 1   --initial-backoff 0.05   --max-backoff 0.1 > "${work}/ship-redirect.stdout" 2>"${work}/ship-redirect.stderr"; then
  bad "shipper unexpectedly succeeded on HTTP 302 redirect"
else
  if grep -q "redirect.*refused" "${work}/ship-redirect.stderr" || grep -q "HTTP redirect (302)" "${work}/ship-redirect.stderr"; then
    ok "shipper refuses HTTP redirects without following or leaking credentials"
  else
    bad "shipper failed on redirect but without expected refused message"
    cat "${work}/ship-redirect.stderr" >&2
  fi
fi

# 4. Initial delivery: all 3 records shipped with bearer token and X-Ldapium-Batch-Id header
printf '200\n' > "$server_ctl"
"${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$cursor_file"   --dead-letter-file "$dead_letter_file"   --file "$input_part1"   --batch-size 2 > "${work}/ship1.stdout" 2>"${work}/ship1.stderr"

if [ "$(wc -l < "$server_received" | tr -d ' ')" = "3" ]; then
  ok "initial batch delivery sent 3 records"
else
  bad "expected 3 received records after initial delivery"
fi

if grep -q '"auth": "Bearer secret-bearer-token-12345"' "$server_received" || grep -q '"auth":"Bearer secret-bearer-token-12345"' "$server_received"; then
  ok "bearer token from token-file was sent in Authorization header"
else
  bad "bearer token was not correctly sent in Authorization header"
fi

if python3 -c '
import json, sys
for line in open(sys.argv[1]):
    bid = json.loads(line).get("batchId", "")
    if not (bid and len(bid) == 64 and all(c in "0123456789abcdefABCDEF" for c in bid)):
        sys.exit(1)
' "$server_received"; then
  ok "X-Ldapium-Batch-Id header sent on every batch with valid 64-char SHA-256 digest (D3)"
else
  bad "X-Ldapium-Batch-Id header missing or malformed"
fi

if [ -f "$cursor_file" ] && grep -q '"auditlog"' "$cursor_file" && grep -q '"accesslog"' "$cursor_file"; then
  ok "cursor state file recorded delivery status for both sources"
else
  bad "cursor state file missing or incomplete"
fi

# 5. Idempotency test: re-run on the exact same input produces 0 additional deliveries
"${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$cursor_file"   --dead-letter-file "$dead_letter_file"   --file "$input_part1" > "${work}/ship-rerun.stdout" 2>"${work}/ship-rerun.stderr"

if [ "$(wc -l < "$server_received" | tr -d ' ')" = "3" ]; then
  ok "re-running on identical input skipped all records (idempotent cursor, 0 duplicates)"
else
  bad "re-running on identical input resulted in duplicate delivery"
fi

# 6. Retry with bounded exponential backoff: server fails first 2 requests, succeeds on 3rd
input_part2="${work}/events-part2.ndjson"
cat <<'EOF' > "$input_part2"
{"schemaVersion":"1","source":"auditlog","seq":3,"time":"2026-08-23T15:00:03Z","actor":"cn=admin,dc=example,dc=org","target":"uid=carol,ou=people,dc=example,dc=org","op":"add","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:3:uid=carol:cn=admin","privileged":true,"raw":{}}
EOF

printf 'fail:2\n' > "$server_ctl"
"${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$cursor_file"   --dead-letter-file "$dead_letter_file"   --file "$input_part2"   --max-retries 3   --initial-backoff 0.1   --max-backoff 0.5 > "${work}/ship-retry.stdout" 2>"${work}/ship-retry.stderr"

if [ "$(wc -l < "$server_received" | tr -d ' ')" = "4" ]; then
  ok "transient 5xx errors succeeded after bounded exponential retries"
else
  bad "transient 5xx retry did not deliver record"
fi

# 7. Dead-letter queue creation: server fails permanently (500)
input_part3="${work}/events-part3.ndjson"
cat <<'EOF' > "$input_part3"
{"schemaVersion":"1","source":"auditlog","seq":4,"time":"2026-08-23T15:00:04Z","actor":"cn=admin,dc=example,dc=org","target":"uid=dave,ou=people,dc=example,dc=org","op":"delete","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:4:uid=dave:cn=admin","privileged":true,"raw":{}}
{"schemaVersion":"1","source":"auditlog","seq":5,"time":"2026-08-23T15:00:05Z","actor":"cn=admin,dc=example,dc=org","target":"uid=eve,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:5:uid=eve:cn=admin","privileged":true,"raw":{}}
EOF

printf '500\n' > "$server_ctl"
if "${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$cursor_file"   --dead-letter-file "$dead_letter_file"   --file "$input_part3"   --max-retries 1   --initial-backoff 0.05   --max-backoff 0.1 > "${work}/ship-fail.stdout" 2>"${work}/ship-fail.stderr"; then
  bad "shipper should have exited non-zero when delivery failed"
else
  ok "shipper exited non-zero when delivery failed after retry exhaustion"
fi

if [ -f "$dead_letter_file" ] && [ "$(wc -l < "$dead_letter_file" | tr -d ' ')" = "2" ]; then
  ok "failed records written to dead-letter queue NDJSON file"
else
  bad "dead-letter file missing or unexpected line count"
fi

if grep -q '"error":"HTTP 500: Internal Server Error"' "$dead_letter_file"; then
  ok "dead-letter records record the failure reason"
else
  bad "dead-letter records do not contain failure reason"
fi

# 8. Dead-letter replay: server restored (200), next run replays dead-letter FIRST
printf '200\n' > "$server_ctl"
input_part4="${work}/events-part4.ndjson"
cat <<'EOF' > "$input_part4"
{"schemaVersion":"1","source":"auditlog","seq":6,"time":"2026-08-23T15:00:06Z","actor":"cn=admin,dc=example,dc=org","target":"uid=frank,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:6:uid=frank:cn=admin","privileged":true,"raw":{}}
EOF

"${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$cursor_file"   --dead-letter-file "$dead_letter_file"   --file "$input_part4"   --batch-size 10 > "${work}/ship-replay.stdout" 2>"${work}/ship-replay.stderr"

if [ ! -f "$dead_letter_file" ]; then
  ok "dead-letter queue was cleared after successful replay"
else
  bad "dead-letter file still exists after successful replay"
fi

# Check total received count: 4 (from steps 4 and 6) + 2 (replayed seq 4, 5) + 1 (new seq 6) = 7
total_received=$(wc -l < "$server_received" | tr -d ' ')
if [ "$total_received" = "7" ]; then
  ok "total records delivered matches expected count (7 records)"
else
  bad "expected 7 total delivered records, got ${total_received}"
fi

# 9. Delivery order verification:
# Server must have received seq 1, 2, 3, 4, 5, 6 for auditlog in that exact order
python3 - "$server_received" <<'PYEOF'
import json
import sys

received_path = sys.argv[1]
audit_seqs = []
with open(received_path) as f:
    for line in f:
        item = json.loads(line)
        rec = item["record"]
        if rec.get("source") == "auditlog":
            audit_seqs.append(rec["seq"])

if audit_seqs != [1, 2, 3, 4, 5, 6]:
    sys.exit(f"auditlog delivery sequence out of order or incomplete: {audit_seqs}")
print(f"PASS: auditlog delivery sequence verified in strict order: {audit_seqs}")
PYEOF

# 10. Cursor across two invocations where the second export restarts seq at 1 (D4)
# In an independent second export, seq restarts at 1. The cursor must recognize
# time 15:00:07Z > 15:00:06Z and deliver the record instead of skipping it.
input_part5="${work}/events-part5.ndjson"
cat <<'EOF' > "$input_part5"
{"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:00:07Z","actor":"cn=admin,dc=example,dc=org","target":"uid=grace,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:1:uid=grace:cn=admin","privileged":true,"raw":{}}
EOF

before_count=$(wc -l < "$server_received" | tr -d ' ')
"${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$cursor_file"   --dead-letter-file "$dead_letter_file"   --file "$input_part5" > "${work}/ship-restart-seq.stdout" 2>"${work}/ship-restart-seq.stderr"

after_count=$(wc -l < "$server_received" | tr -d ' ')
if [ "$after_count" -gt "$before_count" ] && grep -q 'uid=grace,ou=people,dc=example,dc=org' "$server_received"; then
  ok "cursor across invocations delivered record where seq restarted at 1 (D4 time+hash cursor)"
else
  bad "shipper incorrectly skipped record when seq restarted at 1"
  cat "${work}/ship-restart-seq.stderr" >&2
fi

# 11. Cursor persistence failure path: state directory made read-only (D6)
# When the cursor cannot be saved after an acknowledged batch, the shipper
# must exit non-zero with a fatal error and halt immediately.
ro_dir="${work}/ro-state"
mkdir -p "$ro_dir"
ro_cursor="${ro_dir}/cursor.json"
ro_dl="${ro_dir}/dead-letter.ndjson"
input_ro="${work}/events-ro.ndjson"
cat <<'EOF' > "$input_ro"
{"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:00:08Z","actor":"cn=admin,dc=example,dc=org","target":"uid=heidi,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:1:uid=heidi:cn=admin","privileged":true,"raw":{}}
EOF

chmod 0555 "$ro_dir"
if "${top}/scripts/ship-audit-log.sh"   --sink-url "$sink_url"   --allow-insecure-http   --token-file "$token_file"   --cursor-file "$ro_cursor"   --dead-letter-file "$ro_dl"   --file "$input_ro" > "${work}/ship-ro.stdout" 2>"${work}/ship-ro.stderr"; then
  bad "shipper unexpectedly succeeded when state dir was read-only"
else
  if grep -q "fatal error: failed to persist cursor" "${work}/ship-ro.stderr"; then
    ok "shipper exits non-zero with fatal error when cursor cannot be persisted (D6)"
  else
    bad "shipper failed on read-only state dir but without expected fatal cursor error"
    cat "${work}/ship-ro.stderr" >&2
  fi
fi
chmod 0755 "$ro_dir"

# 12. CLI argument validation: reject non-finite floats (nan, inf) with exit 2 (D7)
status_nan=0
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --allow-insecure-http \
  --max-backoff nan > "${work}/nan.stdout" 2> "${work}/nan.stderr" || status_nan=$?

if [ "$status_nan" -eq 2 ] && grep -q "must be a finite float" "${work}/nan.stderr"; then
  ok "shipper rejects --max-backoff nan with exit 2"
else
  bad "shipper failed to reject --max-backoff nan with exit 2 (got ${status_nan})"
  cat "${work}/nan.stderr" >&2
fi

status_inf=0
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --allow-insecure-http \
  --backoff inf > "${work}/inf.stdout" 2> "${work}/inf.stderr" || status_inf=$?

if [ "$status_inf" -eq 2 ] && grep -q "must be a finite float" "${work}/inf.stderr"; then
  ok "shipper rejects --backoff inf with exit 2"
else
  bad "shipper failed to reject --backoff inf with exit 2 (got ${status_inf})"
  cat "${work}/inf.stderr" >&2
fi

# 13. Per-(source, pod) cursor: late pod not shadowed by newer events of another pod (D4)
# Export 1 has pod-0 events at 15:00 only.
# Export 2 adds pod-1 events at 14:00 (older time) alongside already-delivered pod-0 events at 15:00.
# Because the cursor is keyed per (source, pod), pod-1 events must be delivered.
pod_cursor_file="${work}/cursor-pod.json"
pod_dl_file="${work}/dead-letter-pod.ndjson"
input_pod_exp1="${work}/events-pod-exp1.ndjson"
cat <<'EOF' > "$input_pod_exp1"
{"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:00:00Z","actor":"cn=admin,dc=example,dc=org","target":"uid=pod0-user,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:1:uid=pod0-user:cn=admin","privileged":true,"raw":{"pod":"pod-0"}}
EOF

before_pod_count=$(wc -l < "$server_received" | tr -d ' ')
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --allow-insecure-http \
  --token-file "$token_file" \
  --cursor-file "$pod_cursor_file" \
  --dead-letter-file "$pod_dl_file" \
  --file "$input_pod_exp1" > "${work}/ship-pod1.stdout" 2> "${work}/ship-pod1.stderr"

mid_pod_count=$(wc -l < "$server_received" | tr -d ' ')
if [ "$mid_pod_count" -eq "$((before_pod_count + 1))" ]; then
  ok "export 1 delivered pod-0 event at 15:00"
else
  bad "export 1 failed to deliver pod-0 event"
fi

input_pod_exp2="${work}/events-pod-exp2.ndjson"
cat <<'EOF' > "$input_pod_exp2"
{"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:00:00Z","actor":"cn=admin,dc=example,dc=org","target":"uid=pod0-user,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:1:uid=pod0-user:cn=admin","privileged":true,"raw":{"pod":"pod-0"}}
{"schemaVersion":"1","source":"auditlog","seq":2,"time":"2026-08-23T14:00:00Z","actor":"cn=admin,dc=example,dc=org","target":"uid=pod1-user,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-1:1:uid=pod1-user:cn=admin","privileged":true,"raw":{"pod":"pod-1"}}
EOF

"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --allow-insecure-http \
  --token-file "$token_file" \
  --cursor-file "$pod_cursor_file" \
  --dead-letter-file "$pod_dl_file" \
  --file "$input_pod_exp2" > "${work}/ship-pod2.stdout" 2> "${work}/ship-pod2.stderr"

after_pod_count=$(wc -l < "$server_received" | tr -d ' ')
if [ "$after_pod_count" -eq "$((mid_pod_count + 1))" ] && grep -q "uid=pod1-user" "$server_received"; then
  ok "export 2 delivered late pod-1 event at 14:00 without being shadowed by pod-0 event at 15:00 (D4)"
else
  bad "export 2 failed to deliver late pod-1 event at 14:00"
  cat "${work}/ship-pod2.stderr" >&2
fi

# 14. Dead-letter locking: concurrent invocations sharing dead-letter file fail fast or serialize without lost lines (D6)
shared_dl="${work}/shared-dead-letter.ndjson"
dir_conc_a="${work}/state-conc-a"
dir_conc_b="${work}/state-conc-b"
mkdir -p "$dir_conc_a" "$dir_conc_b"

# Pre-populate shared dead-letter queue with records to replay
cat <<'EOF' > "$shared_dl"
{"error":"HTTP 500","failedAt":"2026-08-23T15:10:00Z","record":{"schemaVersion":"1","source":"auditlog","seq":10,"time":"2026-08-23T15:10:00Z","actor":"cn=admin,dc=example,dc=org","target":"uid=dl-user1,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:10:uid=dl-user1:cn=admin","privileged":true,"raw":{"pod":"pod-0"}}}
{"error":"HTTP 500","failedAt":"2026-08-23T15:10:01Z","record":{"schemaVersion":"1","source":"auditlog","seq":11,"time":"2026-08-23T15:10:01Z","actor":"cn=admin,dc=example,dc=org","target":"uid=dl-user2,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:11:uid=dl-user2:cn=admin","privileged":true,"raw":{"pod":"pod-0"}}}
{"error":"HTTP 500","failedAt":"2026-08-23T15:10:02Z","record":{"schemaVersion":"1","source":"auditlog","seq":12,"time":"2026-08-23T15:10:02Z","actor":"cn=admin,dc=example,dc=org","target":"uid=dl-user3,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:12:uid=dl-user3:cn=admin","privileged":true,"raw":{"pod":"pod-0"}}}
{"error":"HTTP 500","failedAt":"2026-08-23T15:10:03Z","record":{"schemaVersion":"1","source":"auditlog","seq":13,"time":"2026-08-23T15:10:03Z","actor":"cn=admin,dc=example,dc=org","target":"uid=dl-user4,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:13:uid=dl-user4:cn=admin","privileged":true,"raw":{"pod":"pod-0"}}}
EOF

# Instruct mock server to delay responses slightly (0.3s) so invocation A holds the lock during replay
printf 'delay:0.3\n200\n' > "$server_ctl"

empty_input="${work}/empty.ndjson"
touch "$empty_input"

"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --allow-insecure-http \
  --token-file "$token_file" \
  --cursor-file "${dir_conc_a}/cursor.json" \
  --dead-letter-file "$shared_dl" \
  --batch-size 2 \
  --file "$empty_input" > "${work}/conc-a.stdout" 2> "${work}/conc-a.stderr" &
pid_conc_a=$!

# Brief pause to let invocation A acquire the dead-letter lock and begin replay
sleep 0.05

status_conc_b=0
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --allow-insecure-http \
  --token-file "$token_file" \
  --cursor-file "${dir_conc_b}/cursor.json" \
  --dead-letter-file "$shared_dl" \
  --batch-size 2 \
  --file "$empty_input" > "${work}/conc-b.stdout" 2> "${work}/conc-b.stderr" || status_conc_b=$?

status_conc_a=0
wait "$pid_conc_a" || status_conc_a=$?

# Reset server_ctl back to standard 200 with no delay
printf '200\n' > "$server_ctl"

if [ "$status_conc_a" -eq 0 ] && [ "$status_conc_b" -ne 0 ]; then
  if grep -q "dead-letter.*locked by another running shipper process (fail fast)" "${work}/conc-b.stderr" || grep -q "dead-letter lock.*is held by another running shipper process (fail fast)" "${work}/conc-b.stderr"; then
    ok "concurrent shipper on shared dead-letter failed fast with lock error"
  else
    bad "concurrent shipper failed but without expected dead-letter lock message"
    cat "${work}/conc-b.stderr" >&2
  fi
elif [ "$status_conc_a" -eq 0 ] && [ "$status_conc_b" -eq 0 ]; then
  ok "concurrent shippers serialized successfully on shared dead-letter file"
else
  bad "unexpected failure in concurrent shipper run (status A: ${status_conc_a}, status B: ${status_conc_b})"
  cat "${work}/conc-a.stderr" >&2
  cat "${work}/conc-b.stderr" >&2
fi

# Verify that all 4 dead-letter records were delivered to the server with no lost lines
if grep -q "uid=dl-user1" "$server_received" && \
   grep -q "uid=dl-user2" "$server_received" && \
   grep -q "uid=dl-user3" "$server_received" && \
   grep -q "uid=dl-user4" "$server_received"; then
  ok "all records from shared dead-letter queue delivered with zero lost lines (D6)"
else
  bad "one or more records lost during concurrent dead-letter access"
fi

if [ "$fail" != 0 ]; then
  echo "one or more audit shipper tests FAILED" >&2
  exit 1
fi
echo "all audit shipper tests passed"
