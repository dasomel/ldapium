#!/usr/bin/env python3
"""Verify the cryptographic SHA-256 hash chain of an NDJSON audit log file.

Each record in a chained audit log must contain 'prevHash' and 'hash'.
- For the genesis (first) record, prevHash must equal sha256(manifest_line).
- For subsequent records, prevHash must equal the previous record's hash.
- The record's hash must equal sha256 of the record's canonical JSON excluding
  the 'hash' field.

Security guarantee and limitation (D10):
- A valid chain proves forward continuity from the genesis record: any alteration
  of record content, interior deletion of records, or reordering breaks the chain
  and is detected.
- TAIL TRUNCATION LIMITATION: Without an out-of-band anchor (--expected-head),
  deleting the tail (the most recent records from the end) leaves a valid prefix
  chain that still starts from genesis and passes verification. Tail truncation
  is detectable ONLY when the expected head hash has been recorded externally
  (e.g., in a signed backup manifest or external SIEM) and asserted via --expected-head.

Exits 0 if the chain is intact and valid; exits non-zero on any break, interior
deletion, reordering, content mutation, malformed JSON, or head mismatch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys


def canonical_json(record: dict) -> str:
    # Sorted keys and compact separators match audit-normalize.py's canonicalization
    return json.dumps(
        {k: v for k, v in record.items() if k != "hash"},
        sort_keys=True,
        separators=(",", ":"),
    )


def verify_stream(
    stream,
    manifest_line: str,
    expected_head: str | None = None,
) -> tuple[bool, str, str | None]:
    genesis_prev_hash = hashlib.sha256(manifest_line.encode("utf-8")).hexdigest()
    expected_prev = genesis_prev_hash
    count = 0
    last_hash = None

    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, f"line {lineno}: invalid JSON: {exc}", None

        if not isinstance(rec, dict):
            return False, f"line {lineno}: record is not a JSON object", None

        if "prevHash" not in rec or "hash" not in rec:
            return False, f"line {lineno}: missing 'prevHash' or 'hash' field", None

        prev_hash = rec["prevHash"]
        curr_hash = rec["hash"]

        if prev_hash != expected_prev:
            if count == 0:
                return (
                    False,
                    f"line {lineno}: genesis prevHash mismatch (expected {expected_prev}, got {prev_hash})",
                    None,
                )
            return (
                False,
                f"line {lineno} (seq {rec.get('seq')}): broken chain: prevHash mismatch (expected {expected_prev}, got {prev_hash})",
                None,
            )

        canonical = canonical_json(rec)
        computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if curr_hash != computed_hash:
            return (
                False,
                f"line {lineno} (seq {rec.get('seq')}): record hash mismatch / tampered content (expected {computed_hash}, got {curr_hash})",
                None,
            )

        expected_prev = curr_hash
        last_hash = curr_hash
        count += 1

    if count == 0:
        return False, "empty audit log: no records found to verify", None

    if expected_head and last_hash != expected_head:
        return (
            False,
            f"chain head hash mismatch (expected {expected_head}, got {last_hash})",
            None,
        )

    return True, f"audit chain verified: {count} records, head: {last_hash}", last_hash


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "file",
        nargs="?",
        default="-",
        help="Path to NDJSON audit log file to verify (default: stdin)",
    )
    parser.add_argument(
        "--manifest-line",
        default="export-audit-log:v1",
        help="Genesis export manifest line used for the initial prevHash (default: 'export-audit-log:v1')",
    )
    parser.add_argument(
        "--expected-head",
        default=None,
        help="Optional expected head hash to assert against the final record's hash",
    )
    args = parser.parse_args(argv)

    if args.file == "-":
        ok, msg, _ = verify_stream(sys.stdin, args.manifest_line, args.expected_head)
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                ok, msg, _ = verify_stream(f, args.manifest_line, args.expected_head)
        except OSError as exc:
            print(f"verify-audit-chain.py: cannot open {args.file}: {exc}", file=sys.stderr)
            return 1

    if not ok:
        print(f"verify-audit-chain.py: FAIL: {msg}", file=sys.stderr)
        return 1

    print(f"verify-audit-chain.py: PASS: {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
