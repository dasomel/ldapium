#!/usr/bin/env python3
"""Normalize export-audit-log.sh's per-source extraction records into the
identity audit event envelope described in docs/audit-event-schema.md
(issue #24).

Input (stdin): one JSON object per line, in the order export-audit-log.sh's
awk extraction stages happen to produce them in (NOT assumed to be a
meaningful order — see "Determinism" below). Each object carries the
source-specific fields that script's awk/sed stages have always emitted
(pod/source/time/actor/op/target/...), plus a small number of additive
fields introduced alongside this normalizer (entryUUID, changedAttrs,
entryDn, reqSession) — see the "raw" field notes in the schema doc for
which source carries which.

Output (stdout):

  Default (envelope) mode: one JSON object per line, each wrapped in the
  common envelope, sorted into a deterministic order (see "Determinism"
  below) before `seq` is assigned. The complete extraction record — with
  `filter` (accesslog) redacted and `changedAttrs` (auditlog) sanitized, see
  "Redaction and sanitization" — is preserved under "raw" so no field any
  existing consumer reads is lost, only moved (and, for these two fields,
  cleaned).

  --legacy mode: the flat, pre-#24 per-source shape (no envelope, no
  additive keys), in ORIGINAL input order, with the same `filter`
  redaction applied — see "Legacy mode" below for why this one guarantee
  is not optional even in --legacy.

This script does no I/O of its own (no kubectl, no network): it is a pure
stream transform, which is what makes it possible to unit-test with fixture
input/output files instead of a live cluster (scripts/test/fixtures/).

Determinism: `export-audit-log.sh`'s own retrieval order is NOT guaranteed
stable across runs (accesslog's ldapsearch in particular has no ORDER BY
equivalent). This script sorts records itself — by time, then pod, then
correlationId, then a stable hash of the raw record — before assigning
`seq`, so two runs over the same underlying data produce byte-identical
output regardless of what order the data happened to arrive in. See
scripts/test/test-export-audit-log.sh's shuffle test.

Redaction and sanitization (defense in depth, TWO independent layers):
  - accesslog's `filter` (an LDAP search filter, e.g. "(userPassword=x)")
    has any password/secret/credential/token/pwd-like assertion VALUE
    replaced with "<redacted>", attribute name preserved. The primary
    control; there is no earlier layer for this field.
  - auditlog's `changedAttrs` is enforced (not just checked) to contain
    bare attribute names only — scripts/lib/parse-auditlog.awk is the
    primary control (it never captures a value into this field to begin
    with); this script re-validates and drops anything that still doesn't
    look like a bare name, as a second, independent layer.

Malformed input handling: a stdin line that fails to parse as JSON is
counted and dropped, never silently. Default mode appends one final
"exporter" summary record naming the drop/emit counts (visible in the NDJSON
stream itself, so a consumer reading only the stream — not checking exit
status — still sees it) and still exits 0. --legacy mode has no summary
record shape that fits the flat structure without adding a key, so it
instead exits non-zero when anything was dropped — one behavior for each
mode, chosen so neither one can succeed unnoticed. See
docs/audit-event-schema.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "1"

# Same convention as ui/backend/internal/ldapclient/tree.go's
# entryRedactedAttrs: userPassword is the one attribute this codebase names
# explicitly elsewhere, but an LDAP search filter can target any
# password/secret/credential/token-shaped attribute a deployment happens to
# use (custom schema), so the filter-redaction check below is a substring
# match against this pattern, not a fixed attribute allowlist.
SENSITIVE_ATTR_RE = re.compile(r"password|secret|credential|token|pwd", re.IGNORECASE)

# "cn" or "userPassword;lang-en" — a leading letter, letters/digits/hyphens,
# optionally followed by ";"-separated options of the same shape. Nothing
# else is a valid bare LDAP attribute description.
ATTR_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$")

# (attr<op>value) — value runs up to the next unescaped "(" or ")", which is
# good enough for the simple, non-nested-value filters an audit correlation
# search actually uses; LDAP filter escaping (\28/\29 for literal parens
# inside a value) and extensible-match (":=") filters are out of scope, same
# boundary the rest of this export already draws around filter parsing.
_FILTER_ASSERTION_RE = re.compile(r"\(([A-Za-z][A-Za-z0-9;_-]*)(=|>=|<=|~=)([^()]*)\)")

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


def redact_filter(filt) -> str:
    """Redact password/secret/credential/token/pwd-like assertion VALUES in
    an LDAP search filter, keeping the attribute name and operator. Applied
    unconditionally in both output modes — this is the one place a
    plaintext-in-a-search-filter secret (e.g. an authentication attempt
    logged via "(userPassword=hunter2)", or a bearer token filtered on
    directly) could otherwise reach this export untouched.
    """
    if not isinstance(filt, str) or not filt:
        return filt

    def _redact_one(m: re.Match) -> str:
        name, op, _value = m.group(1), m.group(2), m.group(3)
        if SENSITIVE_ATTR_RE.search(name):
            return f"({name}{op}<redacted>)"
        return m.group(0)

    return _FILTER_ASSERTION_RE.sub(_redact_one, filt)


def sanitize_changed_attrs(changed_attrs, warn) -> list[str]:
    """Enforce (not just check) that changedAttrs holds bare attribute
    names only. scripts/lib/parse-auditlog.awk is the primary control — it
    never captures a value into this field — so this is a second,
    independent layer: anything that still doesn't look like a bare
    attribute name (per ATTR_NAME_RE) after truncating at the first
    whitespace is dropped, not merely flagged, and a stderr warning names
    what was dropped.
    """
    cleaned: list[str] = []
    for attr in changed_attrs or []:
        if not isinstance(attr, str):
            warn(f"dropping non-string changedAttrs entry: {attr!r}")
            continue
        candidate = attr.split()[0] if attr.split() else attr
        if not ATTR_NAME_RE.match(candidate):
            warn(f"dropping malformed changedAttrs entry: {attr!r}")
            continue
        if candidate not in cleaned:
            cleaned.append(candidate)
    return cleaned


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
    (20260823155413.000004Z) — already UTC ('Z'), so turning it into RFC3339
    is pure string reformatting, not a timezone conversion, and needs no
    `date` binary. Calendar validity IS checked (via datetime construction)
    so an impossible date (month 13, February 30, hour 25, ...) is rejected
    rather than reformatted into an equally-impossible RFC3339 string — the
    regex alone only checks digit *shape*, not that the digits name a real
    date, and shape-only was a real gap (an actual bug found in review).
    """
    m = _GENERALIZED_TIME_RE.match(str(raw))
    if not m:
        return None
    year, month, day, hour, minute, second, frac = m.groups()
    try:
        datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc)
    except ValueError:
        return None
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
    # The pod is included for every source: two different pods can
    # legitimately produce the same rid/CSN pair, the same
    # actor+target+timestamp-second write (multi-provider replication
    # commonly does exactly this — the same write lands on more than one
    # provider's own auditlog), or, in principle, the same reqSession value
    # after independent slapd restarts. Without the pod these collide and
    # look like the same event; a real cross-pod correlation still has to
    # go through `objectId`/`target`, not this id (see the schema doc).
    pod = rec.get("pod", "")
    if source == "auditlog":
        # No cross-system ID exists here: this is the modify timestamp (raw
        # epoch, not the normalized RFC3339 — the epoch is what the server
        # actually recorded) + the real entry DN + the bind identity. Two
        # writes to the same entry by the same actor on the same pod in the
        # same second collide; auditlog's one-line-per-record format has
        # nothing finer grained to key on.
        target = rec.get("entryDn") or rec.get("target") or ""
        actor = rec.get("actor") or ""
        return f"auditlog:{pod}:{rec.get('time', '')}:{target}:{actor}"
    if source == "accesslog":
        # reqSession is slapo-accesslog's own per-connection counter — the
        # closest thing this overlay has to a request/session id. Combined
        # with reqStart (raw GeneralizedTime) it identifies one request; it
        # is NOT a cross-restart-unique id (reqSession resets when slapd
        # restarts), so correlating across a restart needs reqStart too,
        # which is why both are in the key rather than reqSession alone.
        return f"accesslog:{pod}:{rec.get('reqSession', '')}:{rec.get('time', '')}"
    if source == "replication-conflict-raw":
        # discardedCSN already encodes a server-assigned, effectively-unique
        # timestamp+counter+server-id+mod-count on its own, but rid (which
        # consumer discarded it) and pod (which pod's log this came from)
        # are included too since two different consumers — on two different
        # pods — can each independently discard the same delivered CSN, and
        # that is two distinct discard events, not one.
        return f"replication-conflict-raw:{pod}:{rec.get('rid', '')}:{rec.get('discardedCSN', '')}"
    return f"{source}:{pod}:{rec.get('time', '')}"


def raw_hash(raw: dict) -> str:
    """Stable tiebreaker for the sort key below — deterministic regardless
    of dict key insertion order (sort_keys=True), used only when time, pod,
    and correlationId all tie (e.g. two genuinely identical records).
    """
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def build_envelope(rec: dict, admin_dn_key: str | None, warn) -> dict:
    """Build the full envelope for one record, EXCEPT `seq` (left as a
    placeholder so its dict-insertion position — and therefore JSON key
    order — is fixed before the final sort decides its value). Mutates
    `rec` in place to apply redaction/sanitization, since `rec` becomes this
    envelope's own "raw" field: the sanitized version is what "raw" means
    from here on, not a separate cleaned copy sitting next to a dirty one.
    """
    source = rec.get("source", "")

    if source == "auditlog":
        raw_time = rec.get("time")
        time_iso = iso_from_epoch(raw_time)
        actor = rec.get("actor") or "anonymous"
        target = rec.get("entryDn") or rec.get("target")
        object_id = rec.get("entryUUID") or None
        rec["changedAttrs"] = sanitize_changed_attrs(rec.get("changedAttrs"), warn)
    elif source == "accesslog":
        raw_time = rec.get("time")
        time_iso = iso_from_generalized_time(raw_time)
        actor = rec.get("actor") or "anonymous"
        target = rec.get("target") or None
        # accesslog's own log line carries no entryUUID — reqEntryUUID does
        # not exist as a slapo-accesslog attribute; the overlay logs what
        # was requested (reqDN/reqFilter), not a resolved object identity.
        object_id = None
        rec["filter"] = redact_filter(rec.get("filter"))
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
        # DN; entryUUID is resolved at export time (or via stub map in tests)
        # when available.
        object_id = rec.get("entryUUID") or rec.get("objectId") or None
    else:
        raw_time = rec.get("time")
        time_iso = None
        actor = rec.get("actor") or "anonymous"
        target = rec.get("target")
        object_id = None

    if raw_time not in (None, "") and time_iso is None:
        warn(f"could not parse time value {raw_time!r} for source {source!r}; time will be null")

    privileged = False
    if admin_dn_key and isinstance(actor, str) and actor not in ("anonymous", "system"):
        try:
            privileged = dn_key(actor) == admin_dn_key
        except re.error:
            privileged = False

    return {
        "schemaVersion": SCHEMA_VERSION,
        "source": source,
        "seq": None,  # placeholder — overwritten after sorting, see main()
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


def sort_key(envelope: dict):
    time_iso = envelope["time"]
    pod = envelope["raw"].get("pod", "")
    return (
        time_iso is None,  # valid times sort first
        time_iso or "",
        pod,
        envelope["correlationId"],
        raw_hash(envelope["raw"]),
    )


def summary_record(dropped: int, emitted: int, seq: int) -> dict:
    """Appended once, as the last line, when any input line failed to parse
    as JSON — see the module docstring's "Malformed input handling". `time`
    is deliberately null (this record describes the run's own integrity,
    not a directory event with a timestamp) so its presence never breaks
    deterministic replay: dropped/emitted counts are a function of the
    input data, not of when the normalizer happened to run.
    """
    return {
        "schemaVersion": SCHEMA_VERSION,
        "source": "exporter",
        "seq": seq,
        "time": None,
        "actor": "exporter",
        "target": None,
        "op": "summary",
        "result": "unknown",
        "objectId": None,
        "correlationId": f"exporter:summary:{dropped}:{emitted}",
        "privileged": False,
        "raw": {"dropped": dropped, "emitted": emitted},
    }


LEGACY_FIELDS = {
    "auditlog": ("pod", "source", "time", "actor", "op", "target"),
    "accesslog": ("pod", "source", "time", "actor", "op", "target", "filter", "result"),
    "replication-conflict-raw": ("pod", "source", "time", "entry", "discardedCSN", "rid"),
}


def project_legacy(rec: dict) -> dict:
    """The pre-#24 flat shape for one record: exactly the field set that
    shape had (no entryDn/entryUUID/changedAttrs/reqSession — those are
    additive fields this normalizer's default mode introduced), with
    `filter` redaction still applied — see the module docstring's "Legacy
    mode" note on why that one guarantee is not skippable even here.
    """
    source = rec.get("source", "")
    fields = LEGACY_FIELDS.get(source)
    if fields is None:
        return dict(rec)
    projected = {k: rec.get(k) for k in fields}
    if source == "accesslog":
        projected["filter"] = redact_filter(projected.get("filter"))
    return projected


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--admin-dn",
        default="",
        help="Rootdn/admin bind DN (LDAP_ADMIN_DN) used to classify privileged "
        "actors. Without it every record is privileged:false and a warning "
        "is printed once to stderr. Ignored with --legacy (privileged is not "
        "part of the legacy shape).",
    )
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Emit the flat pre-#24 per-source shape instead of the envelope "
        "— see docs/audit-event-schema.md's '--legacy is not a compatibility "
        "guarantee' section.",
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help="Add cryptographic SHA-256 hash chaining (prevHash, hash) across "
        "records for tamper-evidence (docs/audit-event-schema.md, issue #126).",
    )
    parser.add_argument(
        "--manifest-line",
        default="export-audit-log:v1",
        help="Genesis export manifest line used for the initial prevHash "
        "(default: 'export-audit-log:v1').",
    )
    args = parser.parse_args(argv)

    if args.legacy and args.chain:
        print(
            "audit-normalize.py: --chain cannot be used with --legacy "
            "(the legacy flat shape does not support envelope hash chaining)",
            file=sys.stderr,
        )
        return 2

    admin_dn_key = dn_key(args.admin_dn) if (args.admin_dn and not args.legacy) else None
    if admin_dn_key is None and not args.legacy:
        print(
            "audit-normalize.py: no --admin-dn given — every record will be "
            "privileged:false (rootdn could not be identified)",
            file=sys.stderr,
        )

    warned: set[str] = set()

    def warn(msg: str) -> None:
        if msg not in warned:
            warned.add(msg)
            print(f"audit-normalize.py: {msg}", file=sys.stderr)

    records: list[dict] = []
    dropped = 0
    for lineno, line in enumerate(sys.stdin, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            dropped += 1
            warn(f"line {lineno}: skipping unparseable input: {exc}")
            continue
        records.append(rec)
    emitted = len(records)

    if args.legacy:
        for rec in records:
            projected = project_legacy(rec)
            sys.stdout.write(json.dumps(projected, separators=(",", ":")) + "\n")
        if dropped:
            print(
                f"audit-normalize.py: --legacy: {dropped} input line(s) could not be "
                "parsed and were dropped; the flat shape has no field to carry this "
                "count in-stream, so this run exits non-zero instead — see "
                "docs/audit-event-schema.md",
                file=sys.stderr,
            )
            return 1
        return 0

    envelopes = [build_envelope(rec, admin_dn_key, warn) for rec in records]
    envelopes.sort(key=sort_key)
    for i, envelope in enumerate(envelopes, start=1):
        envelope["seq"] = i
    if dropped:
        envelopes.append(summary_record(dropped, emitted, len(envelopes) + 1))

    if args.chain:
        genesis_line = args.manifest_line or "export-audit-log:v1"
        prev_h = hashlib.sha256(genesis_line.encode("utf-8")).hexdigest()
        for envelope in envelopes:
            envelope["prevHash"] = prev_h
            canonical = json.dumps(
                {k: v for k, v in envelope.items() if k != "hash"},
                sort_keys=True,
                separators=(",", ":"),
            )
            curr_h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            envelope["hash"] = curr_h
            prev_h = curr_h

    for envelope in envelopes:
        # Compact separators to match the rest of this export's NDJSON style
        # (no spaces) — also keeps a line's byte size down for a SIEM feed
        # that may be charged per byte ingested.
        sys.stdout.write(json.dumps(envelope, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
