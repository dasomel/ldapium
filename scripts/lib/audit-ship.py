#!/usr/bin/env python3
"""Push shipper with retry and dead-letter queue for normalized identity-audit NDJSON.

Reads normalized NDJSON events (from stdin or a file) line-by-line, batches them,
and POSTs them to a generic HTTP/HTTPS sink URL (the SIEM adapter boundary).

Key guarantees (issue #126, ACs from #24, critic review fixes):
- Delivery semantics: At-least-once delivery. If network connectivity drops after
  the sink receives a batch but before acknowledgment reaches the shipper, the batch
  will be retransmitted. Batches carry an idempotency header:
    X-Ldapium-Batch-Id = sha256(canonical NDJSON of batch)
  plus per-record 'hash' when --chain was used during export. The downstream sink
  deduplicates using these keys.
- Cursor: Tracks (time, hashes) per (source, pod). 'seq' is strictly invocation-scoped
  and resets on each export run, so seq CANNOT be used as a persistent cursor.
  A record is already delivered if its timestamp is older than the cursor timestamp,
  or equal and its canonical hash is in the set of hashes seen at that timestamp.
  Keyed per (source, pod) so that an event from a pod whose fetch failed in one export
  (|| true in export-audit-log.sh) and appears later with an older time is not shadowed
  by another pod's newer events. Limitation: within a single pod, records are assumed
  to be fetched in time order; a pod whose fetch fails is simply not advanced.
- Transport: HTTPS only by default. Plaintext http:// is rejected unless
  --allow-insecure-http is explicitly passed (for CI/local testing fixtures).
  Redirects are strictly forbidden via a custom urllib opener to prevent credential leakage.
  TLS certificate verification is never disabled.
- Process locking: Takes an exclusive flock on the state directory for the run (fail fast
  if locked), plus a second exclusive flock on <dead-letter-file>.lock for every
  dead-letter read/append/rewrite operation (fail fast if held).
- Persistence failure: Cursor persistence failure after an acknowledged batch is fatal.
  The shipper exits non-zero immediately with a clear error; it does not continue.
  Cursor file writes use a tmpfile + os.replace for atomicity.
- Streaming: Reads stdin or input file line-by-line and dead-letter line-by-line
  without buffering whole files in memory.
- CLI argument validation: batch_size >= 1, max_retries >= 0, finite backoff values >= 0.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def positive_int(val: str) -> int:
    try:
        ival = int(val)
        if ival < 1:
            raise ValueError()
        return ival
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be an integer >= 1, got '{val}'")


def non_negative_int(val: str) -> int:
    try:
        ival = int(val)
        if ival < 0:
            raise ValueError()
        return ival
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be an integer >= 0, got '{val}'")


def non_negative_float(val: str) -> float:
    try:
        fval = float(val)
        if not math.isfinite(fval) or fval < 0.0:
            raise ValueError()
        return fval
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a finite float >= 0.0, got '{val}'")


def extract_pod(rec: dict) -> str:
    """Extract pod name from record (same field normalizer uses: raw.pod or correlationId)."""
    raw = rec.get("raw")
    if isinstance(raw, dict) and raw.get("pod"):
        return str(raw["pod"])
    cid = rec.get("correlationId")
    if isinstance(cid, str):
        parts = cid.split(":")
        if len(parts) >= 2 and parts[1]:
            return parts[1]
    if rec.get("pod"):
        return str(rec["pod"])
    return ""


def canonical_record_json(rec: dict) -> str:
    """Canonical JSON string of a record (sorted keys, compact separators)."""
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


def canonical_record_hash(rec: dict) -> str:
    """SHA-256 hash of the record's canonical JSON representation."""
    return hashlib.sha256(canonical_record_json(rec).encode("utf-8")).hexdigest()


def compute_batch_id(batch: list[dict]) -> str:
    """Canonical batch ID: sha256 of the batch's canonical NDJSON.

    Used as the X-Ldapium-Batch-Id idempotency key so sinks can deduplicate
    retried batches under at-least-once delivery semantics (D3).
    """
    canonical_lines = [canonical_record_json(r) for r in batch]
    batch_ndjson = "\n".join(canonical_lines) + "\n"
    return hashlib.sha256(batch_ndjson.encode("utf-8")).hexdigest()


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


def acquire_state_lock(state_dir: str) -> int:
    """Acquire an exclusive non-blocking flock on the state directory for the run (D6)."""
    os.makedirs(state_dir, exist_ok=True)
    try:
        lock_fd = os.open(state_dir, os.O_RDONLY)
    except OSError as exc:
        sys.exit(f"audit-ship.py: error: cannot open state directory {state_dir} for locking: {exc}")

    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError) as exc:
        sys.exit(
            f"audit-ship.py: error: state directory {state_dir} is locked by another running shipper process (fail fast): {exc}"
        )
    return lock_fd


_DEAD_LETTER_LOCKS: dict[str, tuple[int, int]] = {}


@contextlib.contextmanager
def dead_letter_lock(dead_letter_file: str):
    """Acquire exclusive non-blocking flock on <dead-letter-file>.lock for read/append/rewrite (D6).

    Fails fast if held by another shipper process. Re-entrant within the same process.
    """
    lock_path = os.path.abspath(f"{dead_letter_file}.lock")
    if lock_path in _DEAD_LETTER_LOCKS:
        fd, depth = _DEAD_LETTER_LOCKS[lock_path]
        _DEAD_LETTER_LOCKS[lock_path] = (fd, depth + 1)
        try:
            yield
        finally:
            fd, depth = _DEAD_LETTER_LOCKS[lock_path]
            if depth > 1:
                _DEAD_LETTER_LOCKS[lock_path] = (fd, depth - 1)
            else:
                del _DEAD_LETTER_LOCKS[lock_path]
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(fd)
                except OSError:
                    pass
        return

    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError as exc:
        sys.exit(f"audit-ship.py: error: cannot open dead-letter lock file {lock_path}: {exc}")

    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError) as exc:
        try:
            os.close(lock_fd)
        except OSError:
            pass
        sys.exit(
            f"audit-ship.py: error: dead-letter lock {lock_path} is held by another running shipper process (fail fast): {exc}"
        )

    _DEAD_LETTER_LOCKS[lock_path] = (lock_fd, 1)
    try:
        yield
    finally:
        if lock_path in _DEAD_LETTER_LOCKS:
            fd, depth = _DEAD_LETTER_LOCKS[lock_path]
            if depth > 1:
                _DEAD_LETTER_LOCKS[lock_path] = (fd, depth - 1)
            else:
                del _DEAD_LETTER_LOCKS[lock_path]
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(fd)
                except OSError:
                    pass


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
    """Persist cursor atomically via tmpfile + os.replace (D6).

    Failure after an acknowledged batch is fatal: exit non-zero immediately.
    """
    tmp_path = f"{cursor_file}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cursor, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp_path, cursor_file)
    except Exception as exc:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        sys.exit(f"audit-ship.py: fatal error: failed to persist cursor to {cursor_file}: {exc}")


def is_already_delivered(rec: dict, cursor: dict) -> bool:
    """Check if record is already delivered using per-(source, pod) (time, canonical_record_hash) (D4).

    'seq' is invocation-scoped (resets to 1 each export run) and is NOT used as a cursor.
    Keyed per (source, pod) so that an event from a pod whose fetch failed in one export
    (|| true in export-audit-log.sh) and appears later with an older time is not skipped.

    Limitation: within a single pod, records are assumed to be fetched in time order;
    a pod whose fetch fails is simply not advanced.
    """
    source = rec.get("source")
    if not source:
        return False
    source_entry = cursor.get("sources", {}).get(source)
    if not source_entry or not isinstance(source_entry, dict):
        return False

    pod = extract_pod(rec)
    pod_cursor = source_entry.get(pod)
    # Backward-compatible check if cursor file was saved in legacy flat format
    if pod_cursor is None and "time" in source_entry and "hashes" in source_entry:
        pod_cursor = source_entry

    if not pod_cursor or not isinstance(pod_cursor, dict):
        return False

    cursor_time = pod_cursor.get("time")
    cursor_hashes = set(pod_cursor.get("hashes", []))

    rec_time = rec.get("time")
    rec_hash = canonical_record_hash(rec)

    if rec_time and cursor_time:
        if rec_time < cursor_time:
            return True
        if rec_time == cursor_time:
            return rec_hash in cursor_hashes
        return False

    if rec_time is None and cursor_time is None:
        return rec_hash in cursor_hashes

    return False


def update_cursor_for_batch(cursor: dict, batch: list[dict]) -> None:
    """Update cursor state per (source, pod) with the latest (time, hashes) (D4).

    Limitation: within a single pod, records are assumed to be fetched in time order;
    a pod whose fetch fails is simply not advanced.
    """
    sources = cursor.setdefault("sources", {})
    for rec in batch:
        source = rec.get("source")
        if not source:
            continue
        pod = extract_pod(rec)
        rec_time = rec.get("time")
        rec_hash = canonical_record_hash(rec)

        source_entry = sources.setdefault(source, {})
        # If existing source_entry was saved in legacy flat format, migrate to dict of pods
        if "time" in source_entry and "hashes" in source_entry:
            old_time = source_entry.pop("time")
            old_hashes = source_entry.pop("hashes")
            source_entry[""] = {"time": old_time, "hashes": old_hashes}

        existing = source_entry.get(pod)
        if not existing:
            source_entry[pod] = {
                "time": rec_time,
                "hashes": [rec_hash],
            }
            continue

        curr_time = existing.get("time")
        curr_hashes = list(existing.get("hashes", []))

        if rec_time and curr_time:
            if rec_time > curr_time:
                source_entry[pod] = {
                    "time": rec_time,
                    "hashes": [rec_hash],
                }
            elif rec_time == curr_time:
                if rec_hash not in curr_hashes:
                    curr_hashes.append(rec_hash)
                source_entry[pod]["hashes"] = curr_hashes
            # Older timestamp within batch for this pod: do not regress cursor
        elif rec_time and not curr_time:
            source_entry[pod] = {
                "time": rec_time,
                "hashes": [rec_hash],
            }
        else:
            if curr_time is None:
                if rec_hash not in curr_hashes:
                    curr_hashes.append(rec_hash)
                source_entry[pod]["hashes"] = curr_hashes


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom redirect handler that refuses all HTTP redirects (D5).

    Prevents leaking credentials (e.g. Authorization: Bearer ...) across origins
    or following unintended redirects.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_301(self, req, fp, code, msg, headers):
        loc = headers.get("Location", "")
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect ({code}) to {loc} refused", headers, fp)

    def http_error_302(self, req, fp, code, msg, headers):
        loc = headers.get("Location", "")
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect ({code}) to {loc} refused", headers, fp)

    def http_error_303(self, req, fp, code, msg, headers):
        loc = headers.get("Location", "")
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect ({code}) to {loc} refused", headers, fp)

    def http_error_307(self, req, fp, code, msg, headers):
        loc = headers.get("Location", "")
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect ({code}) to {loc} refused", headers, fp)

    def http_error_308(self, req, fp, code, msg, headers):
        loc = headers.get("Location", "")
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect ({code}) to {loc} refused", headers, fp)


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

    batch_id = compute_batch_id(records)
    headers = {
        "Content-Type": "application/x-ndjson",
        "User-Agent": "ldapium-audit-shipper/1.0",
        "X-Ldapium-Batch-Id": batch_id,
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    opener = urllib.request.build_opener(NoRedirectHandler())

    last_err = None
    for attempt in range(max_retries + 1):
        req = urllib.request.Request(sink_url, data=body, headers=headers, method="POST")
        try:
            with opener.open(req, timeout=15) as resp:
                if 200 <= resp.status < 300:
                    return True, None
                last_err = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            last_err = f"HTTP {exc.code}: {exc.reason}"
            # 5xx and 429 are retryable; 3xx and 4xx are client/config errors and not retryable
            if not (500 <= exc.code < 600 or exc.code == 429):
                return False, last_err
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = f"Connection error: {exc}"

        if attempt < max_retries:
            delay = min(max_backoff, initial_backoff * (backoff_factor ** attempt))
            time.sleep(delay)

    return False, last_err


def append_dead_letter(dead_letter_file: str, records: list[dict], error_msg: str) -> None:
    with dead_letter_lock(dead_letter_file):
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
    """Stream replay of dead-letter records batch-by-batch without loading entire file into memory (D7)."""
    if not os.path.isfile(dead_letter_file) or os.path.getsize(dead_letter_file) == 0:
        return True

    with dead_letter_lock(dead_letter_file):
        if not os.path.isfile(dead_letter_file) or os.path.getsize(dead_letter_file) == 0:
            return True

        try:
            dl_f = open(dead_letter_file, "r", encoding="utf-8")
        except OSError as exc:
            print(f"audit-ship.py: error opening dead-letter file {dead_letter_file}: {exc}", file=sys.stderr)
            return False

        print("audit-ship.py: replaying records from dead-letter queue...", file=sys.stderr)

        replayed_count = 0
        current_entries: list[dict] = []
        current_records: list[dict] = []
        replay_failed = False
        fail_err = None

        try:
            for line in dl_f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    item = json.loads(line_str)
                    record = item.get("record") if (isinstance(item, dict) and "record" in item) else item
                    current_entries.append(item)
                    current_records.append(record)
                except json.JSONDecodeError:
                    continue

                if len(current_records) >= batch_size:
                    ok, err = send_batch_http(
                        current_records,
                        sink_url,
                        bearer_token,
                        max_retries,
                        initial_backoff,
                        max_backoff,
                        backoff_factor,
                    )
                    if ok:
                        replayed_count += len(current_records)
                        update_cursor_for_batch(cursor, current_records)
                        save_cursor(cursor_file, cursor)
                        current_entries = []
                        current_records = []
                    else:
                        replay_failed = True
                        fail_err = err
                        break

            if not replay_failed and current_records:
                ok, err = send_batch_http(
                    current_records,
                    sink_url,
                    bearer_token,
                    max_retries,
                    initial_backoff,
                    max_backoff,
                    backoff_factor,
                )
                if ok:
                    replayed_count += len(current_records)
                    update_cursor_for_batch(cursor, current_records)
                    save_cursor(cursor_file, cursor)
                    current_entries = []
                    current_records = []
                else:
                    replay_failed = True
                    fail_err = err

            if replay_failed:
                print(f"audit-ship.py: dead-letter replay failed ({fail_err})", file=sys.stderr)
                tmp_path = f"{dead_letter_file}.tmp.{os.getpid()}"
                with open(tmp_path, "w", encoding="utf-8") as out_f:
                    for item in current_entries:
                        out_f.write(json.dumps(item, separators=(",", ":")) + "\n")
                    for rest_line in dl_f:
                        rest_stripped = rest_line.strip()
                        if rest_stripped:
                            out_f.write(rest_stripped + "\n")
                os.replace(tmp_path, dead_letter_file)
                return False
            else:
                try:
                    os.remove(dead_letter_file)
                except OSError:
                    pass
                print(f"audit-ship.py: successfully replayed {replayed_count} dead-letter record(s)", file=sys.stderr)
                return True
        finally:
            dl_f.close()


def spill_to_dead_letter(input_file, cursor: dict, dead_letter_file: str, error_msg: str) -> None:
    """Stream remaining un-delivered input records directly into dead-letter file without buffering in memory."""
    with dead_letter_lock(dead_letter_file):
        now = now_rfc3339()
        with open(dead_letter_file, "a", encoding="utf-8") as f:
            for line in input_file:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if is_already_delivered(rec, cursor):
                    continue
                dl_entry = {
                    "error": error_msg,
                    "failedAt": now,
                    "record": rec,
                }
                f.write(json.dumps(dl_entry, separators=(",", ":")) + "\n")


def ship_stream(
    input_file,
    sink_url: str,
    bearer_token: str | None,
    cursor_file: str,
    cursor: dict,
    dead_letter_file: str,
    batch_size: int,
    max_retries: int,
    initial_backoff: float,
    max_backoff: float,
    backoff_factor: float,
) -> tuple[int, int, int, bool]:
    """Stream records from input_file line-by-line, shipping in batches (D7).

    Returns (shipped_count, skipped_count, batch_count, success_bool).
    """
    shipped_count = 0
    skipped_count = 0
    batch_count = 0
    current_batch: list[dict] = []

    def flush_batch(batch: list[dict]) -> tuple[bool, str | None]:
        nonlocal shipped_count, batch_count
        batch_count += 1
        ok, err = send_batch_http(
            batch,
            sink_url,
            bearer_token,
            max_retries,
            initial_backoff,
            max_backoff,
            backoff_factor,
        )
        if ok:
            shipped_count += len(batch)
            update_cursor_for_batch(cursor, batch)
            save_cursor(cursor_file, cursor)
            return True, None
        return False, err

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

        current_batch.append(rec)
        if len(current_batch) >= batch_size:
            ok, err = flush_batch(current_batch)
            if not ok:
                print(
                    f"audit-ship.py: delivery failed for batch {batch_count} ({err}); writing to dead-letter",
                    file=sys.stderr,
                )
                with dead_letter_lock(dead_letter_file):
                    append_dead_letter(dead_letter_file, current_batch, err or "Delivery failed")
                    spill_to_dead_letter(input_file, cursor, dead_letter_file, err or "Delivery failed (spilled after prior failure)")
                return shipped_count, skipped_count, batch_count, False
            current_batch = []

    if current_batch:
        ok, err = flush_batch(current_batch)
        if not ok:
            print(
                f"audit-ship.py: delivery failed for batch {batch_count} ({err}); writing to dead-letter",
                file=sys.stderr,
            )
            with dead_letter_lock(dead_letter_file):
                append_dead_letter(dead_letter_file, current_batch, err or "Delivery failed")
            return shipped_count, skipped_count, batch_count, False

    return shipped_count, skipped_count, batch_count, True


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
        help="Cursor state file path tracking last delivered (time, hash) per (source, pod) (default: .audit-ship-cursor.json)",
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
        type=positive_int,
        default=50,
        help="Maximum records per POST batch (>= 1, default: 50)",
    )
    parser.add_argument(
        "--max-retries",
        type=non_negative_int,
        default=3,
        help="Maximum retry attempts on 5xx or connection failures (>= 0, default: 3)",
    )
    parser.add_argument(
        "--initial-backoff",
        type=non_negative_float,
        default=0.5,
        help="Initial exponential backoff delay in seconds (>= 0, default: 0.5)",
    )
    parser.add_argument(
        "--max-backoff",
        type=non_negative_float,
        default=10.0,
        help="Maximum backoff delay in seconds (>= 0, default: 10.0)",
    )
    parser.add_argument(
        "--backoff-factor",
        "--backoff",
        type=non_negative_float,
        default=2.0,
        help="Exponential backoff factor (>= 0, default: 2.0)",
    )
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        default=False,
        help="Allow plaintext http:// sink URL (strictly for CI/local test fixtures; never in production)",
    )
    args = parser.parse_args(argv)

    if not args.sink_url:
        sys.exit("audit-ship.py: error: --sink-url (or SIEM_SINK_URL / AUDIT_SINK_URL env) is required")

    # D5: Validate transport scheme: HTTPS only unless --allow-insecure-http is explicitly given
    parsed_url = urllib.parse.urlparse(args.sink_url)
    if parsed_url.scheme == "http":
        if not args.allow_insecure_http:
            sys.exit(
                "audit-ship.py: error: plaintext http:// sink URL is forbidden to protect credentials; "
                "use https:// or pass --allow-insecure-http for local testing"
            )
    elif parsed_url.scheme != "https":
        sys.exit(
            f"audit-ship.py: error: unsupported sink URL scheme '{parsed_url.scheme}', must be https:// "
            "(or http:// with --allow-insecure-http)"
        )

    # D6: Take exclusive flock on state directory for the run (fail fast if locked)
    state_dir = os.path.dirname(os.path.abspath(args.cursor_file))
    lock_fd = acquire_state_lock(state_dir)

    bearer_token = load_token(args.token_file)
    cursor = load_cursor(args.cursor_file)

    # 1. Replay dead-letter first (streaming)
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

    # 2. Read and ship input records (streaming line-by-line)
    if args.file and args.file != "-":
        try:
            input_file = open(args.file, "r", encoding="utf-8")
        except OSError as exc:
            sys.exit(f"audit-ship.py: error opening input file {args.file}: {exc}")
    else:
        input_file = sys.stdin

    try:
        shipped, skipped, batches, ok = ship_stream(
            input_file,
            args.sink_url,
            bearer_token,
            args.cursor_file,
            cursor,
            args.dead_letter_file,
            args.batch_size,
            args.max_retries,
            args.initial_backoff,
            args.max_backoff,
            args.backoff_factor,
        )
    finally:
        if input_file is not sys.stdin:
            input_file.close()

    if not ok:
        return 1

    if shipped == 0 and skipped > 0:
        print(f"audit-ship.py: all {skipped} record(s) already delivered according to cursor state; 0 to ship")
        return 0

    print(f"audit-ship.py: shipped {shipped} record(s) across {batches} batch(es) (skipped {skipped} already delivered)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
