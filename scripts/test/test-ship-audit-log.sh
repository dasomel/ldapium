#!/usr/bin/env bash
# Integration test for scripts/ship-audit-log.sh and scripts/lib/audit-ship.py.
#
# Tests against a local HTTP server fixture:
# 1. Successful batch delivery with Bearer token authentication from file.
# 2. Cursor idempotency: re-running on the same input produces 0 duplicates.
# 3. Bounded exponential backoff: transient 5xx errors succeed on retry.
# 4. Dead-letter queue creation when retries are exhausted.
# 5. Dead-letter replay on subsequent run before shipping new records.
# 6. Overall delivery order and strict deduplication.
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
        # Read control instruction: "fail:<N>" to fail next N requests with 503, or "200"
        status_to_return = 200
        fail_remaining = 0
        try:
            with open(ctl_file, "r") as f:
                line = f.read().strip()
                if line.startswith("fail:"):
                    fail_remaining = int(line.split(":", 1)[1])
                elif line.isdigit():
                    status_to_return = int(line)
        except Exception:
            pass

        if fail_remaining > 0:
            fail_remaining -= 1
            with open(ctl_file, "w") as f:
                f.write(f"fail:{fail_remaining}\n")
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Service Unavailable (mock)\n")
            return

        if status_to_return != 200:
            self.send_response(status_to_return)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Error (mock)\n")
            return

        # Record received records
        with open(received_file, "a") as f:
            for line in body.splitlines():
                line = line.strip()
                if line:
                    entry = {"auth": auth, "record": json.loads(line)}
                    f.write(json.dumps(entry) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"accepted"}\n')

    def log_message(self, format, *args):
        # Silence default stderr logging
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

# 1. Initial delivery: all 3 records shipped with bearer token
printf '200\n' > "$server_ctl"
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --token-file "$token_file" \
  --cursor-file "$cursor_file" \
  --dead-letter-file "$dead_letter_file" \
  --file "$input_part1" \
  --batch-size 2 > "${work}/ship1.stdout" 2>"${work}/ship1.stderr"

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

if [ -f "$cursor_file" ] && grep -q '"auditlog"' "$cursor_file" && grep -q '"accesslog"' "$cursor_file"; then
  ok "cursor state file recorded delivery status for both sources"
else
  bad "cursor state file missing or incomplete"
fi

# 2. Idempotency test: re-run on the exact same input produces 0 additional requests
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --token-file "$token_file" \
  --cursor-file "$cursor_file" \
  --dead-letter-file "$dead_letter_file" \
  --file "$input_part1" > "${work}/ship-rerun.stdout" 2>"${work}/ship-rerun.stderr"

if [ "$(wc -l < "$server_received" | tr -d ' ')" = "3" ]; then
  ok "re-running on identical input skipped all records (idempotent, 0 duplicates)"
else
  bad "re-running on identical input resulted in duplicate delivery"
fi

# 3. Retry with bounded exponential backoff: server fails first 2 requests, succeeds on 3rd
input_part2="${work}/events-part2.ndjson"
cat <<'EOF' > "$input_part2"
{"schemaVersion":"1","source":"auditlog","seq":3,"time":"2026-08-23T15:00:03Z","actor":"cn=admin,dc=example,dc=org","target":"uid=carol,ou=people,dc=example,dc=org","op":"add","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:3:uid=carol:cn=admin","privileged":true,"raw":{}}
EOF

printf 'fail:2\n' > "$server_ctl"
"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --token-file "$token_file" \
  --cursor-file "$cursor_file" \
  --dead-letter-file "$dead_letter_file" \
  --file "$input_part2" \
  --max-retries 3 \
  --initial-backoff 0.1 \
  --max-backoff 0.5 > "${work}/ship-retry.stdout" 2>"${work}/ship-retry.stderr"

if [ "$(wc -l < "$server_received" | tr -d ' ')" = "4" ]; then
  ok "transient 5xx errors succeeded after bounded exponential retries"
else
  bad "transient 5xx retry did not deliver record"
fi

# 4. Dead-letter queue creation: server fails permanently (500)
input_part3="${work}/events-part3.ndjson"
cat <<'EOF' > "$input_part3"
{"schemaVersion":"1","source":"auditlog","seq":4,"time":"2026-08-23T15:00:04Z","actor":"cn=admin,dc=example,dc=org","target":"uid=dave,ou=people,dc=example,dc=org","op":"delete","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:4:uid=dave:cn=admin","privileged":true,"raw":{}}
{"schemaVersion":"1","source":"auditlog","seq":5,"time":"2026-08-23T15:00:05Z","actor":"cn=admin,dc=example,dc=org","target":"uid=eve,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:5:uid=eve:cn=admin","privileged":true,"raw":{}}
EOF

printf '500\n' > "$server_ctl"
if "${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --token-file "$token_file" \
  --cursor-file "$cursor_file" \
  --dead-letter-file "$dead_letter_file" \
  --file "$input_part3" \
  --max-retries 1 \
  --initial-backoff 0.05 \
  --max-backoff 0.1 > "${work}/ship-fail.stdout" 2>"${work}/ship-fail.stderr"; then
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

# 5. Dead-letter replay: server restored (200), next run replays dead-letter FIRST
printf '200\n' > "$server_ctl"
input_part4="${work}/events-part4.ndjson"
cat <<'EOF' > "$input_part4"
{"schemaVersion":"1","source":"auditlog","seq":6,"time":"2026-08-23T15:00:06Z","actor":"cn=admin,dc=example,dc=org","target":"uid=frank,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:pod-0:6:uid=frank:cn=admin","privileged":true,"raw":{}}
EOF

"${top}/scripts/ship-audit-log.sh" \
  --sink-url "$sink_url" \
  --token-file "$token_file" \
  --cursor-file "$cursor_file" \
  --dead-letter-file "$dead_letter_file" \
  --file "$input_part4" \
  --batch-size 10 > "${work}/ship-replay.stdout" 2>"${work}/ship-replay.stderr"

if [ ! -f "$dead_letter_file" ]; then
  ok "dead-letter queue was cleared after successful replay"
else
  bad "dead-letter file still exists after successful replay"
fi

# Check total received count: 4 (from steps 1 and 3) + 2 (replayed seq 4, 5) + 1 (new seq 6) = 7
total_received=$(wc -l < "$server_received" | tr -d ' ')
if [ "$total_received" = "7" ]; then
  ok "total records delivered matches expected count (7 records)"
else
  bad "expected 7 total delivered records, got ${total_received}"
fi

# 6. Delivery order verification:
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

if [ "$fail" != 0 ]; then
  echo "one or more audit shipper tests FAILED" >&2
  exit 1
fi
echo "all audit shipper tests passed"
