#!/usr/bin/env python3
"""Normalize export-audit-log.sh's per-source extraction records into the
identity audit event envelope described in docs/audit-event-schema.md
(issue #24).

Input (stdin): one JSON object per line, in the exact emission order
export-audit-log.sh already produces them in. Each object carries the
source-specific fields that script's awk/sed stages have always emitted
(pod/source/time/actor/op/target/...), plus a small number of additive
fields introduced alongside this normalizer (entryUUID, changedAttrs,
entryDn, reqSession) — see the "raw" field notes in the schema doc for
which source carries which.

Output (stdout): one JSON object per line, same order, each wrapped in the
common envelope. The entire, unmodified input object is preserved verbatim
under "raw" so no field any existing consumer reads is lost — only moved.

This script does no I/O of its own (no kubectl, no network): it is a pure
stream transform, which is what makes it possible to unit-test with fixture
input/output files instead of a live cluster (scripts/test/fixtures/).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "1"

# Same convention as ui/backend/internal/ldapclient/tree.go's
# entryRedactedAttrs: userPassword is the one attribute this codebase treats
# as sensitive everywhere. changedAttrs (built by export-audit-log.sh's
# auditlog block parser) only ever carries attribute NAMES, never values, so
# this list is a belt-and-suspenders sanity check on that invariant rather
# than the primary control.
PASSWORD_LIKE_ATTRS = {"userpassword"}

_GENERALIZED_TIME_RE = re.compile(
    r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$"
)


def dn_key(dn: str) -> str:
    """Normalize a DN for comparison, matching entrypoint.sh's own technique
    (strip spaces after commas, lowercase) for the LDAP_ADMIN_DN/LDAP_ROOT_DN
    comparisons it does at bootstrap. Not a full LDAP DN-equality algorithm
    (no attribute-type OID folding, no escaped-comma handling) — good enough
    for comparing against a single known rootdn, same scope entrypoint.sh
    itself accepts there.
    """
    return re.sub(r",\s*", ",", dn.strip()).lower()


def iso_from_epoch(raw: str) -> str | None:
    """auditlog's header line gives a raw Unix epoch (seconds, occasionally
    with stray non-digit noise never observed in practice but not assumed
    away). Returns None rather than raising so one malformed record cannot
    take down the whole export.
    """
    try:
        epoch = int(str(raw).split(".", 1)[0])
    except (TypeError, ValueError):
        return None
    try:
        return (
            datetime.fromtimestamp(epoch, tz=timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    except (OverflowError, OSError, ValueError):
        return None


def iso_from_generalized_time(raw: str) -> str | None:
    """accesslog/replication-conflict-raw give LDAP GeneralizedTime
    (20260823155413.000004Z) — already UTC ('Z'), so this is pure string
    reformatting, not a timezone conversion, and needs no `date` binary
    (the GNU-vs-BSD portability risk export-audit-log.sh's own comments
    already flag for epoch conversion does not apply here).
    """
    m = _GENERALIZED_TIME_RE.match(str(raw))
    if not m:
        return None
    year, month, day, hour, minute, second, frac = m.groups()
    if frac:
        return f"{year}-{month}-{day}T{hour}:{minute}:{second}{frac}Z"
    return f"{year}-{month}-{day}T{hour}:{minute}:{second}Z"


def normalize_result(source: str, rec: dict) -> str:
    # Only accesslog carries a real LDAP result code (reqResult). auditlog's
    # header line and the replication "CSN too old" diagnostic carry no
    # success/failure signal at all — reporting anything but "unknown" for
    # them would be a claim this data cannot back up.
    if source != "accesslog":
        return "unknown"
    result = rec.get("result")
    if result is None or result == "":
        return "unknown"
    return "success" if result == "0" else "failure"


def correlation_id(source: str, rec: dict) -> str:
    if source == "auditlog":
        # No cross-system ID exists here: this is the modify timestamp (raw
        # epoch, not the normalized RFC3339 — the epoch is what the server
        # actually recorded) + the real entry DN + the bind identity. Two
        # writes to the same entry by the same actor in the same second
        # collide; auditlog's one-line-per-record format has nothing finer
        # grained to key on.
        target = rec.get("entryDn") or rec.get("target") or ""
        actor = rec.get("actor") or ""
        return f"auditlog:{rec.get('time', '')}:{target}:{actor}"
    if source == "accesslog":
        # reqSession is slapo-accesslog's own per-connection counter — the
        # closest thing this overlay has to a request/session id. Combined
        # with reqStart (raw GeneralizedTime) it identifies one request; it
        # is NOT a cross-restart-unique id (reqSession resets when slapd
        # restarts), so correlating across a restart needs reqStart too,
        # which is why both are in the key rather than reqSession alone.
        return f"accesslog:{rec.get('reqSession', '')}:{rec.get('time', '')}"
    if source == "replication-conflict-raw":
        # discardedCSN already encodes a server-assigned, globally unique
        # timestamp+counter+server-id+mod-count — genuinely unique on its
        # own — but rid (which consumer discarded it) is included too since
        # two consumers can independently discard the same delivered CSN and
        # that is two distinct discard events, not one.
        return f"replication-conflict-raw:{rec.get('rid', '')}:{rec.get('discardedCSN', '')}"
    return f"{source}:{rec.get('time', '')}"


def check_changed_attrs_are_names_only(changed_attrs, warn) -> None:
    """Defense in depth, not the primary control: changedAttrs is built by
    export-audit-log.sh's auditlog block parser to hold attribute NAMES only,
    never values, which is what actually keeps a password value out of this
    export. This just flags — to stderr, without failing the run — anything
    that does not look like a bare attribute name, in case that invariant is
    ever broken by a future change to the extraction side.
    """
    for attr in changed_attrs or []:
        if not isinstance(attr, str) or " " in attr or "::" in attr or len(attr) > 64:
            warn(f"changedAttrs entry does not look like a bare attribute name: {attr!r}")


def normalize_record(rec: dict, seq: int, admin_dn_key: str | None, warn) -> dict:
    source = rec.get("source", "")

    if source == "auditlog":
        raw_time = rec.get("time")
        time_iso = iso_from_epoch(raw_time)
        actor = rec.get("actor") or "anonymous"
        target = rec.get("entryDn") or rec.get("target")
        object_id = rec.get("entryUUID") or None
        check_changed_attrs_are_names_only(rec.get("changedAttrs"), warn)
    elif source == "accesslog":
        raw_time = rec.get("time")
        time_iso = iso_from_generalized_time(raw_time)
        actor = rec.get("actor") or "anonymous"
        target = rec.get("target") or None
        # accesslog's own log line carries no entryUUID — reqEntryUUID does
        # not exist as a slapo-accesslog attribute; the overlay logs what
        # was requested (reqDN/reqFilter), not a resolved object identity.
        object_id = None
    elif source == "replication-conflict-raw":
        raw_time = rec.get("time")
        time_iso = iso_from_generalized_time(raw_time)
        # This is a server-side sync-consumer event, not a bind identity's
        # action — "anonymous" would misstate it as an anonymous LDAP bind,
        # which it is not. "system" says plainly that no directory identity
        # is attached to this event.
        actor = "system"
        target = rec.get("entry") or None
        # slapd's "CSN too old, ignoring" diagnostic carries only the entry
        # DN, never entryUUID — documented limitation, not an omission.
        object_id = None
    else:
        raw_time = rec.get("time")
        time_iso = None
        actor = rec.get("actor") or "anonymous"
        target = rec.get("target")
        object_id = None

    privileged = False
    if admin_dn_key and isinstance(actor, str) and actor not in ("anonymous", "system"):
        try:
            privileged = dn_key(actor) == admin_dn_key
        except re.error:
            privileged = False

    envelope = {
        "schemaVersion": SCHEMA_VERSION,
        "source": source,
        "seq": seq,
        "time": time_iso,
        "actor": actor,
        "target": target,
        "op": rec.get("op") or ("replication-conflict" if source == "replication-conflict-raw" else None),
        "result": normalize_result(source, rec),
        "objectId": object_id,
        "correlationId": correlation_id(source, rec),
        "privileged": privileged,
        "raw": rec,
    }
    return envelope


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--admin-dn",
        default="",
        help="Rootdn/admin bind DN (LDAP_ADMIN_DN) used to classify privileged "
        "actors. Without it every record is privileged:false and a warning "
        "is printed once to stderr.",
    )
    args = parser.parse_args(argv)

    admin_dn_key = dn_key(args.admin_dn) if args.admin_dn else None
    if admin_dn_key is None:
        print(
            "audit-normalize.py: no --admin-dn given — every record will be "
            "privileged:false (rootdn could not be identified)",
            file=sys.stderr,
        )

    warned = set()

    def warn(msg: str) -> None:
        if msg not in warned:
            warned.add(msg)
            print(f"audit-normalize.py: {msg}", file=sys.stderr)

    seq = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            warn(f"skipping unparseable input line: {exc}")
            continue
        seq += 1
        envelope = normalize_record(rec, seq, admin_dn_key, warn)
        # Compact separators to match the rest of this export's NDJSON style
        # (no spaces) — also keeps a line's byte size down for a SIEM feed
        # that may be charged per byte ingested.
        sys.stdout.write(json.dumps(envelope, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
