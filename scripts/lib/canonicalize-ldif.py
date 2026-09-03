#!/usr/bin/env python3
"""Canonicalize LDIF records for entry-data drift detection.

Input: raw LDIF from ldapsearch -LLL or a file/stdin.
Transformations:
  1. Unfold RFC 2849 continuation lines (starting with a single space).
  2. Strip comment lines (starting with '#').
  3. Strip operational attributes: entryCSN, entryUUID, modifyTimestamp,
     modifiersName, createTimestamp, creatorsName, contextCSN,
     structuralObjectClass.
  4. Redact userPassword values to a fixed placeholder: 'userPassword: <redacted>'.
  5. Sort attributes within each entry (with 'dn:' line preserved first).
  6. Sort entries across the LDIF by normalized DN.
Output: deterministic, canonical LDIF to stdout or a specified file.
"""

import base64
import re
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
    """Unfold RFC 2849 continuation lines."""
    unfolded = []
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    return unfolded


def parse_dn(line):
    """Extract decoded and normalized DN from a 'dn:' or 'dn::' line."""
    if line.startswith("dn:: "):
        encoded = line[5:].strip()
        try:
            val = base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            val = encoded
    elif line.startswith("dn: "):
        val = line[4:].strip()
    else:
        val = line.strip()

    # Normalize DN for deterministic sorting key:
    # lowercased, comma-separated components without extra whitespace
    norm_key = re.sub(r"\s*,\s*", ",", val.strip().lower())
    return val, norm_key


def canonicalize_entry(record_lines):
    """Process a single record's lines into (norm_dn, canonical_lines)."""
    dn_display = None
    norm_dn = None
    attr_lines = []

    for line in record_lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue

        lower_line = line_clean.lower()
        if lower_line.startswith("dn:") or lower_line.startswith("dn::"):
            dn_display, norm_dn = parse_dn(line_clean)
            continue

        # Split into attribute name and rest
        if ":" not in line_clean:
            continue

        attr_name, sep, attr_val = line_clean.partition(":")
        attr_name = attr_name.strip()
        attr_name_lower = attr_name.lower()

        if attr_name_lower in STRIP_ATTRS:
            continue

        if attr_name_lower == "userpassword":
            attr_lines.append("userPassword: <redacted>")
            continue

        # Keep original attribute casing and formatting
        if attr_val.startswith(":"):
            # Base64 attribute
            attr_lines.append(f"{attr_name}::{attr_val[1:]}")
        else:
            attr_lines.append(f"{attr_name}: {attr_val.strip()}")

    if not dn_display:
        return None

    # Sort attributes alphabetically by (name.lower(), line)
    attr_lines.sort(key=lambda s: (s.split(":", 1)[0].lower(), s))

    # Entry always begins with 'dn: <dn_display>'
    canonical_lines = [f"dn: {dn_display}"] + attr_lines
    return norm_dn, canonical_lines


def process_ldif(input_stream):
    """Parse LDIF stream and return canonicalized string."""
    unfolded = unfold_ldif(input_stream)
    records = []
    current = []

    for line in unfolded:
        if not line.strip():
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
