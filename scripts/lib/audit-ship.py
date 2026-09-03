#!/usr/bin/env python3
"""Push shipper with retry and dead-letter queue for normalized identity-audit NDJSON.

Reads normalized NDJSON events (from stdin or a file), batches them, and POSTs
them to a generic HTTP/HTTPS sink URL (the SIEM adapter boundary).

Key guarantees (issue #126, ACs from #24):
- Cursor state file keeps the last delivered correlationId + seq per source so
  re-runs are idempotent and produce no duplicate deliveries.
- Generic HTTP sink boundary: plain NDJSON (application/x-ndjson) over HTTP/HTTPS.
- Bearer token is strictly loaded from a file (--token-file), never a CLI argument.
- Transient errors (HTTP 5xx, connection/timeout errors, 429) trigger bounded
  exponential backoff retries.
- Undeliverable batches after retry exhaustion are written to a dead-letter
  NDJSON file alongside the error and timestamp.
- On subsequent runs, dead-letter records are replayed first before new records.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_token(token_file: str | None) -> str | None:
    if not token_file:
        return None
    try:
        with open(token_file, "r", encoding="utf-8") as f:
            token = f.read().strip()
            if not token:
                raise ValueError(f"token file {token_file} is empty")
            return token
    except OSError as exc:
        sys.exit(f"audit-ship.py: failed to read token file: {exc}")


def load_cursor(cursor_file: str) -> dict:
    if os.path.isfile(cursor_file):
        try:
            with open(cursor_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    data.setdefault("sources", {})
                    return data
        except Exception as exc:
            print(f"audit-ship.py: warning: could not read cursor file {cursor_file}: {exc}", file=sys.stderr)
    return {"sources": {}}


def save_cursor(cursor_file: str, cursor: dict) -> None:
    tmp_path = f"{cursor_file}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cursor, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp_path, cursor_file)
    except Exception as exc:
        print(f"audit-ship.py: error: could not write cursor file {cursor_file}: {exc}", file=sys.stderr)
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def is_already_delivered(rec: dict, cursor: dict) -> bool:
    source = rec.get("source")
    if not source:
        return False
    source_cursor = cursor.get("sources", {}).get(source)
    if not source_cursor:
        return False

    last_seq = source_cursor.get("seq")
    last_cid = source_cursor.get("correlationId")
    curr_seq = rec.get("seq")
    curr_cid = rec.get("correlationId")

    if curr_seq is not None and last_seq is not None:
        if curr_seq < last_seq:
            return True
        if curr_seq == last_seq:
            return curr_cid == last_cid
    elif curr_cid and last_cid:
        return curr_cid == last_cid

    return False


def update_cursor_for_batch(cursor: dict, batch: list[dict]) -> None:
    sources = cursor.setdefault("sources", {})
    for rec in batch:
        source = rec.get("source")
        if not source:
            continue
        curr_seq = rec.get("seq")
        curr_cid = rec.get("correlationId")
        existing = sources.get(source)
        if existing:
            last_seq = existing.get("seq")
            if curr_seq is not None and last_seq is not None:
                if curr_seq >= last_seq:
                    sources[source] = {"seq": curr_seq, "correlationId": curr_cid}
            else:
                sources[source] = {"seq": curr_seq, "correlationId": curr_cid}
        else:
            sources[source] = {"seq": curr_seq, "correlationId": curr_cid}


def send_batch_http(
    records: list[dict],
    sink_url: str,
    bearer_token: str | None,
    max_retries: int,
    initial_backoff: float,
    max_backoff: float,
    backoff_factor: float,
) -> tuple[bool, str | None]:
    lines = [json.dumps(r, separators=(",", ":")) for r in records]
    body = ("\n".join(lines) + "\n").encode("utf-8")

    headers = {
        "Content-Type": "application/x-ndjson",
        "User-Agent": "ldapium-audit-shipper/1.0",
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    last_err = None
    for attempt in range(max_retries + 1):
        req = urllib.request.Request(sink_url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if 200 <= resp.status < 300:
                    return True, None
                last_err = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            last_err = f"HTTP {exc.code}: {exc.reason}"
            # 5xx and 429 are retryable; 4xx (client error) is not
            if not (500 <= exc.code < 600 or exc.code == 429):
                return False, last_err
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = f"Connection error: {exc}"

        if attempt < max_retries:
            delay = min(max_backoff, initial_backoff * (backoff_factor ** attempt))
            time.sleep(delay)

    return False, last_err


def append_dead_letter(dead_letter_file: str, records: list[dict], error_msg: str) -> None:
    now = now_rfc3339()
    with open(dead_letter_file, "a", encoding="utf-8") as f:
        for rec in records:
            dl_entry = {
                "error": error_msg,
                "failedAt": now,
                "record": rec,
            }
            f.write(json.dumps(dl_entry, separators=(",", ":")) + "\n")


def replay_dead_letter(
    dead_letter_file: str,
    cursor_file: str,
    cursor: dict,
    sink_url: str,
    bearer_token: str | None,
    batch_size: int,
    max_retries: int,
    initial_backoff: float,
    max_backoff: float,
    backoff_factor: float,
) -> bool:
    if not os.path.isfile(dead_letter_file) or os.path.getsize(dead_letter_file) == 0:
        return True

    try:
        with open(dead_letter_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except OSError as exc:
        print(f"audit-ship.py: error reading dead-letter file {dead_letter_file}: {exc}", file=sys.stderr)
        return False

    if not lines:
        return True

    dl_items = []
    for line in lines:
        try:
            item = json.loads(line)
            record = item.get("record") if (isinstance(item, dict) and "record" in item) else item
            dl_items.append((item, record))
        except json.JSONDecodeError:
            continue

    if not dl_items:
        return True

    print(f"audit-ship.py: replaying {len(dl_items)} record(s) from dead-letter queue...", file=sys.stderr)

    remaining_items = []
    replayed_count = 0

    for i in range(0, len(dl_items), batch_size):
        chunk = dl_items[i : i + batch_size]
        chunk_records = [r for _, r in chunk]

        ok, err = send_batch_http(
            chunk_records,
            sink_url,
            bearer_token,
            max_retries,
            initial_backoff,
            max_backoff,
            backoff_factor,
        )

        if ok:
            replayed_count += len(chunk_records)
            update_cursor_for_batch(cursor, chunk_records)
            save_cursor(cursor_file, cursor)
        else:
            print(f"audit-ship.py: dead-letter replay failed ({err})", file=sys.stderr)
            remaining_items.extend(dl_items[i:])
            break

    if remaining_items:
        tmp_path = f"{dead_letter_file}.tmp.{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for item, _ in remaining_items:
                f.write(json.dumps(item, separators=(",", ":")) + "\n")
        os.replace(tmp_path, dead_letter_file)
        return False
    else:
        # All dead-letter records replayed successfully
        try:
            os.remove(dead_letter_file)
        except OSError:
            pass
        print(f"audit-ship.py: successfully replayed {replayed_count} dead-letter record(s)", file=sys.stderr)
        return True


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sink-url",
        "-u",
        default=os.environ.get("SIEM_SINK_URL") or os.environ.get("AUDIT_SINK_URL", ""),
        help="Generic HTTP/HTTPS sink URL (SIEM ingestion endpoint)",
    )
    parser.add_argument(
        "--token-file",
        default=os.environ.get("BEARER_TOKEN_FILE", ""),
        help="Path to file containing bearer authentication token (never pass credentials as CLI args)",
    )
    parser.add_argument(
        "--cursor-file",
        default=".audit-ship-cursor.json",
        help="Cursor state file path tracking last delivered seq + correlationId per source (default: .audit-ship-cursor.json)",
    )
    parser.add_argument(
        "--dead-letter-file",
        default=".audit-dead-letter.ndjson",
        help="Dead-letter file path for undeliverable batches (default: .audit-dead-letter.ndjson)",
    )
    parser.add_argument(
        "--file",
        "-f",
        default=None,
        help="Input NDJSON file to read from (default: stdin)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Maximum records per POST batch (default: 50)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts on 5xx or connection failures (default: 3)",
    )
    parser.add_argument(
        "--initial-backoff",
        type=float,
        default=0.5,
        help="Initial exponential backoff delay in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--max-backoff",
        type=float,
        default=10.0,
        help="Maximum backoff delay in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--backoff-factor",
        type=float,
        default=2.0,
        help="Exponential backoff factor (default: 2.0)",
    )
    args = parser.parse_args(argv)

    if not args.sink_url:
        sys.exit("audit-ship.py: error: --sink-url (or SIEM_SINK_URL / AUDIT_SINK_URL env) is required")

    bearer_token = load_token(args.token_file)
    cursor = load_cursor(args.cursor_file)

    # 1. Replay dead-letter first
    dl_ok = replay_dead_letter(
        args.dead_letter_file,
        args.cursor_file,
        cursor,
        args.sink_url,
        bearer_token,
        args.batch_size,
        args.max_retries,
        args.initial_backoff,
        args.max_backoff,
        args.backoff_factor,
    )
    if not dl_ok:
        sys.exit("audit-ship.py: stopping because dead-letter replay could not complete")

    # 2. Read input records
    if args.file and args.file != "-":
        try:
            input_file = open(args.file, "r", encoding="utf-8")
        except OSError as exc:
            sys.exit(f"audit-ship.py: error opening input file {args.file}: {exc}")
    else:
        input_file = sys.stdin

    records_to_ship = []
    skipped_count = 0

    try:
        for lineno, line in enumerate(input_file, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"audit-ship.py: warning: skipping invalid JSON on line {lineno}: {exc}", file=sys.stderr)
                continue

            if is_already_delivered(rec, cursor):
                skipped_count += 1
                continue

            records_to_ship.append(rec)
    finally:
        if input_file is not sys.stdin:
            input_file.close()

    if not records_to_ship:
        print(f"audit-ship.py: all {skipped_count} record(s) already delivered according to cursor state; 0 to ship")
        return 0

    # 3. Ship batches
    shipped_count = 0
    batches = [records_to_ship[i : i + args.batch_size] for i in range(0, len(records_to_ship), args.batch_size)]

    for idx, batch in enumerate(batches):
        ok, err = send_batch_http(
            batch,
            args.sink_url,
            bearer_token,
            args.max_retries,
            args.initial_backoff,
            args.max_backoff,
            args.backoff_factor,
        )

        if ok:
            shipped_count += len(batch)
            update_cursor_for_batch(cursor, batch)
            save_cursor(args.cursor_file, cursor)
        else:
            # Batch failed after retries: write to dead-letter queue along with any subsequent batches
            print(f"audit-ship.py: delivery failed for batch {idx + 1}/{len(batches)} ({err}); writing to dead-letter", file=sys.stderr)
            remaining_batches = batches[idx:]
            for r_batch in remaining_batches:
                append_dead_letter(args.dead_letter_file, r_batch, err or "Delivery failed")
            return 1

    print(f"audit-ship.py: shipped {shipped_count} record(s) across {len(batches)} batch(es) (skipped {skipped_count} already delivered)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
