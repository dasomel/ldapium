#!/usr/bin/env python3
"""Canonicalize LDIF records for entry-data drift detection.

Input: raw LDIF from ldapsearch -LLL or a file/stdin.
Transformations:
  1. Unfold RFC 2849 continuation lines (a physical newline followed by a
     single SPACE). Only the fold marker itself -- that one leading space --
     is removed; everything else in the value, including further leading or
     trailing whitespace that is part of the data, is preserved verbatim.
  2. Strip comment lines (starting with '#') and the record-separator blank
     lines between entries.
  3. Strip operational attributes: entryCSN, entryUUID, modifyTimestamp,
     modifiersName, createTimestamp, creatorsName, contextCSN,
     structuralObjectClass.
  4. Redact userPassword values to a fixed placeholder: 'userpassword: <redacted>'.
  5. Lowercase attribute names (LDAP attribute *types* are case-insensitive,
     so "CN" and "cn" from two different dumps of the same entry must not
     read as drift). Attribute *values* are never case-folded here: value
     case sensitivity depends on the attribute's syntax, which this script
     has no schema access to determine, so it is conservative and leaves
     values exactly as given.
  6. Decode base64 (`::`) values and, independently of how the source
     encoded them, re-encode deterministically based on RFC 2849 safety:
     values that are safe as a plain SAFE-STRING are emitted as
     "attr: value"; values that are not (leading space/colon/'<', any
     control byte, or any non-ASCII byte) are emitted as "attr:: <base64>".
     This makes two dumps of the *same* underlying value canonicalize
     identically even if one happened to base64-encode it (e.g. different
     wrapping/padding) and the other emitted it as plain text.
  7. Sort attributes within each entry (with 'dn:' line preserved first).
  8. Normalize DN case per RDN *attribute type* only (e.g. "UID=" ->
     "uid="), leaving each RDN's *value* untouched for the same
     case-sensitivity reason as point 5.
  9. Sort entries across the LDIF by normalized DN.
Output: deterministic, canonical LDIF to stdout or a specified file.
"""

import base64
import sys

STRIP_ATTRS = {
    "entrycsn",
    "entryuuid",
    "modifytimestamp",
    "modifiersname",
    "createtimestamp",
    "creatorsname",
    "contextcsn",
    "structuralobjectclass",
}


def unfold_ldif(lines):
    """Unfold RFC 2849 continuation lines.

    Only the terminating "\\r\\n"/"\\n" is stripped from each physical line;
    a continuation line's single leading SPACE (the fold marker) is removed
    by slicing off exactly one character, and the remainder -- including any
    further leading whitespace that is part of the value -- is appended
    as-is. No other whitespace in the line is touched.
    """
    unfolded = []
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    return unfolded


def _split_unescaped(s, seps):
    """Split s on any character in seps, except where escaped by a
    backslash. A backslash always protects the character that follows it
    (the pair is kept intact) so an escaped separator is never treated as a
    split point."""
    parts = []
    current = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            current.append(c)
            current.append(s[i + 1])
            i += 2
            continue
        if c in seps:
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    parts.append("".join(current))
    return parts


def normalize_dn_case(dn):
    """Lowercase each RDN's attribute type, leaving values untouched.

    LDAP attribute types are always case-insensitive, so "UID=alice" and
    "uid=alice" name the same RDN and must canonicalize identically.
    Attribute *values*, however, are not uniformly case-insensitive --
    that depends on the attribute's matching rule/syntax, which this
    script has no schema access to check -- so this function never
    modifies the value half of an attributeTypeAndValue, only the type.
    """
    if not dn:
        return dn
    rdns = _split_unescaped(dn, {","})
    norm_rdns = []
    for rdn in rdns:
        avas = _split_unescaped(rdn, {"+"})
        norm_avas = []
        for ava in avas:
            eq_parts = _split_unescaped(ava, {"="})
            if len(eq_parts) >= 2:
                attr_type = eq_parts[0]
                value = "=".join(eq_parts[1:])
                norm_avas.append(f"{attr_type.lower()}={value}")
            else:
                norm_avas.append(ava)
        norm_rdns.append("+".join(norm_avas))
    return ",".join(norm_rdns)


def parse_dn(line):
    """Extract and normalize a DN from a 'dn:' or 'dn::' line.

    Returns (display_dn, sort_key): display_dn is what gets printed as the
    canonical entry's own "dn:" line (RDN types lowercased per
    normalize_dn_case, values untouched); sort_key is display_dn further
    lowercased in full, used only to order entries deterministically and
    never shown in output, so fully case-folding it for that purpose alone
    does not conflict with preserving value case in the visible output.
    """
    rest = line[3:]  # line[:3] == "dn:", verified by the caller
    is_b64 = rest.startswith(":")
    if is_b64:
        rest = rest[1:]
    if rest.startswith(" "):
        rest = rest[1:]
    if is_b64:
        try:
            val = base64.b64decode(rest).decode("utf-8", errors="replace")
        except Exception:
            val = rest
    else:
        val = rest
    display_dn = normalize_dn_case(val)
    return display_dn, display_dn.lower()


def _is_ldif_safe(raw_bytes):
    """True if raw_bytes may be represented as a plain (non-base64) LDIF
    value per RFC 2849's SAFE-STRING grammar: no NUL/LF/CR byte anywhere,
    no byte above US-ASCII (which also rules out multi-byte UTF-8), and the
    first byte is not SPACE, ':', or '<' (LDIF reserves those at that
    position for insignificant leading space, base64, and URL values)."""
    if not raw_bytes:
        return True
    for b in raw_bytes:
        if b in (0x00, 0x0A, 0x0D) or b > 0x7F:
            return False
    if raw_bytes[0] in (0x20, 0x3A, 0x3C):
        return False
    return True


def _format_value(raw_bytes):
    """Render raw_bytes as the canonical ": value" or ":: <base64>" suffix
    for an attribute line, deciding purely from the decoded bytes so the
    same underlying value always canonicalizes the same way regardless of
    how the source LDIF happened to encode it."""
    if _is_ldif_safe(raw_bytes):
        return ": " + raw_bytes.decode("ascii")
    return ":: " + base64.b64encode(raw_bytes).decode("ascii")


def canonicalize_entry(record_lines):
    """Process a single record's lines into (sort_key, canonical_lines)."""
    dn_display = None
    norm_dn = None
    attr_lines = []

    for line in record_lines:
        if line == "" or line.startswith("#"):
            continue

        lower_line = line.lower()
        if lower_line.startswith("dn:"):
            dn_display, norm_dn = parse_dn(line)
            continue

        if ":" not in line:
            continue

        attr_name, _, rest = line.partition(":")
        attr_name_lower = attr_name.lower()

        if attr_name_lower in STRIP_ATTRS:
            continue

        is_b64 = rest.startswith(":")
        if is_b64:
            rest = rest[1:]
        if rest.startswith(" "):
            rest = rest[1:]

        if attr_name_lower == "userpassword":
            attr_lines.append("userpassword: <redacted>")
            continue

        if is_b64:
            try:
                raw = base64.b64decode(rest)
            except Exception:
                # Malformed base64: fall back to the literal bytes rather
                # than crashing, so a corrupt dump still produces *some*
                # deterministic (if not meaningful) canonical output.
                raw = rest.encode("utf-8", errors="surrogateescape")
        else:
            raw = rest.encode("utf-8", errors="surrogateescape")

        attr_lines.append(f"{attr_name_lower}{_format_value(raw)}")

    if not dn_display:
        return None

    # Sort attributes alphabetically by (name, line); names are already
    # lowercased above so this sorts purely on name then full line content.
    attr_lines.sort(key=lambda s: (s.split(":", 1)[0], s))

    # Entry always begins with 'dn: <dn_display>'
    canonical_lines = [f"dn: {dn_display}"] + attr_lines
    return norm_dn, canonical_lines


def process_ldif(input_stream):
    """Parse LDIF stream and return canonicalized string."""
    unfolded = unfold_ldif(input_stream)
    records = []
    current = []

    for line in unfolded:
        if line == "":
            if current:
                records.append(current)
                current = []
        else:
            current.append(line)
    if current:
        records.append(current)

    entries = []
    for rec in records:
        entry = canonicalize_entry(rec)
        if entry is not None:
            entries.append(entry)

    # Sort entries by normalized DN
    entries.sort(key=lambda e: e[0])

    if not entries:
        return ""

    blocks = ["\n".join(lines) for _, lines in entries]
    return "\n\n".join(blocks) + "\n"


def main():
    source = sys.stdin
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        try:
            source = open(sys.argv[1], "r", encoding="utf-8", errors="replace")
        except OSError as e:
            sys.stderr.write(f"canonicalize-ldif: could not read {sys.argv[1]}: {e}\n")
            sys.exit(2)

    try:
        output = process_ldif(source)
    finally:
        if source is not sys.stdin:
            source.close()

    sys.stdout.write(output)


if __name__ == "__main__":
    main()
