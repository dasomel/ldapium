#!/usr/bin/env python3
"""
scripts/lib/migration-report.py — deterministic LDIF schema/data reconciliation report.

Analyzes an external LDIF export against ldapium's OpenLDAP schema and overlay
configuration, producing a deterministic JSON reconciliation report.
Can run standalone offline for fixture validation or consume slapadd -u logs
from a throwaway container execution.

Report structure:
- entry_count_by_objectclass: entry count for each objectClass
- unknown_object_classes: unrecognized objectClasses and occurrence counts
- unknown_attributes: unrecognized attributes and occurrence counts
- entries_outside_base_dn: entries outside --base-dn
- duplicate_collisions: unique overlay constraint collisions for uid and mail
- entries_with_no_structural_object_class: entries without any structural objectClass
- errors: per-entry error list (dn + message)

Exit codes:
  0: Clean (no schema or data findings)
  1: Findings detected
  2: Execution or parsing error
"""

import argparse
import base64
import json
import os
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

# Standard schemas loaded by ldapium (image/ldifs/01-cn-config.ldif):
# core.ldif, cosine.ldif, inetorgperson.ldif, nis.ldif
# plus OpenLDAP internal operational/overlay attributes.

KNOWN_OBJECT_CLASSES: Dict[str, str] = {
    # Name (lowercase) -> ObjectClass type: 'STRUCTURAL', 'AUXILIARY', 'ABSTRACT'
    # RFC 4512 / core
    "top": "ABSTRACT",
    "system": "STRUCTURAL",
    "domain": "STRUCTURAL",
    "dcobject": "AUXILIARY",
    "country": "STRUCTURAL",
    "locality": "STRUCTURAL",
    "organization": "STRUCTURAL",
    "organizationalunit": "STRUCTURAL",
    "person": "STRUCTURAL",
    "organizationalperson": "STRUCTURAL",
    "organizationalrole": "STRUCTURAL",
    "groupofnames": "STRUCTURAL",
    "residentialperson": "STRUCTURAL",
    "applicationprocess": "STRUCTURAL",
    "applicationentity": "STRUCTURAL",
    "dsa": "STRUCTURAL",
    "device": "STRUCTURAL",
    "strongauthenticationuser": "AUXILIARY",
    "certificateauthority": "AUXILIARY",
    "certificationauthority": "STRUCTURAL",
    "certificationauthority-v2": "STRUCTURAL",
    "crldistributionpoint": "STRUCTURAL",
    "dmd": "STRUCTURAL",
    "labeleduriobject": "AUXILIARY",
    "simplesecurityobject": "AUXILIARY",
    "uidobject": "AUXILIARY",
    "subentry": "STRUCTURAL",
    "subschema": "STRUCTURAL",
    # cosine
    "pilotobject": "AUXILIARY",
    "newpilotperson": "STRUCTURAL",
    "account": "STRUCTURAL",
    "document": "STRUCTURAL",
    "room": "STRUCTURAL",
    "documentseries": "STRUCTURAL",
    "domainrelatedobject": "AUXILIARY",
    "friendlycountry": "STRUCTURAL",
    # inetOrgPerson
    "inetorgperson": "STRUCTURAL",
    # nis
    "posixaccount": "AUXILIARY",
    "shadowaccount": "AUXILIARY",
    "posixgroup": "STRUCTURAL",
    "ipservice": "STRUCTURAL",
    "ipprotocol": "STRUCTURAL",
    "oncrpc": "STRUCTURAL",
    "iphost": "STRUCTURAL",
    "ipnetwork": "STRUCTURAL",
    "nisnetgroup": "STRUCTURAL",
    "nismap": "STRUCTURAL",
    "nisobject": "STRUCTURAL",
    "bootabledevice": "AUXILIARY",
    # overlays & system
    "pwdpolicy": "AUXILIARY",
    "pwdpolicychecker": "AUXILIARY",
    "olcoverlayconfig": "STRUCTURAL",
    "olcuniqueconfig": "AUXILIARY",
    "olcmemberofconfig": "AUXILIARY",
    "olcrefintconfig": "AUXILIARY",
    "olcppolicyconfig": "AUXILIARY",
    "olcauditlogconfig": "AUXILIARY",
    "olcaccesslogconfig": "AUXILIARY",
    "olcglobal": "STRUCTURAL",
    "olcschemaconfig": "STRUCTURAL",
    "olcdatabaseconfig": "STRUCTURAL",
    "olcmdbconfig": "AUXILIARY",
    "olcfrontendconfig": "AUXILIARY",
    "olcmodulelist": "STRUCTURAL",
    "olcmonitorconfig": "AUXILIARY",
}

KNOWN_ATTRIBUTES: Set[str] = {
    # Lowercase attribute names
    # core
    "objectclass", "structuralobjectclass", "entryuuid", "entrycsn", "createtimestamp",
    "modifytimestamp", "creatorsname", "modifiersname", "subschemasubentry",
    "hassubordinates", "numsubordinates", "contextcsn", "entrydn",
    "cn", "commonname", "sn", "surname", "c", "countryname", "l", "localityname",
    "st", "stateorprovincename", "street", "streetaddress", "o", "organizationname",
    "ou", "organizationalunitname", "title", "description", "searchguide",
    "businesscategory", "postaladdress", "postalcode", "postofficebox",
    "physicaldeliveryofficename", "telephonenumber", "telexnumber",
    "teletexterminalidentifier", "facsimiletelephonenumber", "x121address",
    "internationalisdnnumber", "registeredaddress", "destinationindicator",
    "preferreddeliverymethod", "presentationaddress", "supportedapplicationcontext",
    "member", "owner", "roleoccupant", "seealso", "userpassword", "usercertificate",
    "cacertificate", "authorityrevocationlist", "certificaterevocationlist",
    "crosscertificatepair", "name", "knowledgeinformation", "dc", "domaincomponent",
    "uid", "userid", "mail", "rfc822mailbox", "associateddomain", "email",
    "emailaddress", "labeleduri",
    # cosine
    "textencodedoraddress", "info", "drink", "favouritedrink", "roomnumber",
    "photo", "userclass", "host", "manager", "documentidentifier", "documenttitle",
    "documentversion", "documentauthor", "documentlocation", "hometelephonenumber",
    "secretary", "uniqueidentifier", "co", "associatedname", "homepostaladdress",
    "personaltitle", "mobile", "mobiletelephonenumber", "pager", "pagertelephonenumber",
    "friendlycountryname", "uniquemember", "organizationalstatus", "janetmailbox",
    "mailpreferenceoption", "buildingname", "dsaquality", "singlelevelquality",
    "subtreeminimumquality", "subtreemaximumquality", "personalsignature", "ditredirect",
    "audio", "documentpublisher",
    # inetorgperson
    "carlicense", "departmentnumber", "displayname", "employeenumber", "employeetype",
    "generationqualifier", "givenname", "initials", "jpegphoto", "preferredlanguage",
    "usersmimecertificate", "userpkcs12",
    # nis
    "uidnumber", "gidnumber", "gecos", "homedirectory", "loginshell", "shadowlastchange",
    "shadowmin", "shadowmax", "shadowwarning", "shadowinactive", "shadowexpire",
    "shadowflag", "memberuid", "membernisnetgroup", "nisnetgrouptriple", "ipserviceport",
    "ipserviceprotocol", "ipprotocolnumber", "oncrpcnumber", "iphostnumber",
    "ipnetworknumber", "ipnetmasknumber", "macaddress", "bootparameter", "bootfile",
    "nismapname", "nismapentry",
    # ppolicy & overlays
    "pwdpolicysubentry", "pwdaccountlockedtime", "pwdchangedtime", "pwdfailuretime",
    "pwdhistory", "pwdgraceusetime", "pwdreset", "pwdstarttime", "pwdendtime",
    "pwdattribute", "pwdminlength", "pwdmaxfailure", "pwdlockout", "pwdlockoutduration",
    "pwdmaxage", "pwdexpirewarning", "pwdgraceauthnlimit", "pwdsafemodify",
    "pwdcheckquality", "pwdinhistory", "pwdmustchange", "pwdallowuserchange",
    "memberof",
    # accesslog / auditlog
    "reqdn", "reqtype", "reqresult", "reqstart", "reqend", "reqmod", "reqsession",
    "reqauthzid", "reqcontrols", "reqrespcontrols", "reqmethod", "reqassertion",
    # general / SASL
    "authzto", "authzfrom", "vendorname", "vendorversion"
}

REDACTED_PASSWORD = "***REDACTED***"


class LDIFParseError(Exception):
    def __init__(self, errors: List[Dict[str, str]]):
        super().__init__("Unparseable LDIF")
        self.errors = errors


class LDIFEntry:
    def __init__(self, start_line: int, end_line: int):
        self.start_line = start_line
        self.end_line = end_line
        self.dn: str = ""
        self.raw_dn: str = ""
        # attr_name (lowercase) -> list of original values
        self.attributes: Dict[str, List[str]] = {}
        # original attribute casing map (lowercase -> original first seen)
        self.attr_casing: Dict[str, str] = {}
        # objectClasses original values
        self.object_classes: List[str] = []

    def add_attribute(self, name: str, value: str):
        low_name = name.lower()
        if low_name == "dn":
            self.raw_dn = value
            self.dn = value.strip()
            return

        if low_name == "userpassword":
            value = REDACTED_PASSWORD

        if low_name not in self.attributes:
            self.attributes[low_name] = []
            self.attr_casing[low_name] = name
        self.attributes[low_name].append(value)

        if low_name == "objectclass":
            self.object_classes.append(value)


def parse_ldif(path: str) -> List[LDIFEntry]:
    """Parse LDIF file into LDIFEntry objects, handling RFC 2849 line continuations and validating syntax."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"LDIF file not found: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()

    parse_errors: List[Dict[str, str]] = []
    logical_lines: List[Tuple[int, str]] = []

    # Unfold lines per RFC 2849
    for idx, line in enumerate(raw_lines, 1):
        line_stripped = line.rstrip("\r\n")
        if not line_stripped:
            logical_lines.append((idx, ""))
            continue
        if line_stripped.startswith(" ") or line_stripped.startswith("\t"):
            if logical_lines and logical_lines[-1][1]:
                orig_idx, prev_content = logical_lines[-1]
                logical_lines[-1] = (orig_idx, prev_content + line_stripped[1:])
            else:
                parse_errors.append({
                    "dn": "unknown",
                    "message": f'line {idx}: leading space continuation without preceding attribute line'
                })
        else:
            logical_lines.append((idx, line_stripped))

    entries: List[LDIFEntry] = []
    current_entry: Optional[LDIFEntry] = None
    in_entry = False

    for line_num, line in logical_lines:
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            if in_entry and current_entry:
                if current_entry.dn:
                    current_entry.end_line = line_num - 1
                    entries.append(current_entry)
                else:
                    parse_errors.append({
                        "dn": "unknown",
                        "message": f'entry starting at line {current_entry.start_line} lacks a "dn:" record'
                    })
                current_entry = None
                in_entry = False
            continue

        if not in_entry:
            in_entry = True
            current_entry = LDIFEntry(line_num, line_num)

        # Attribute name per RFC 2849: starts with letter, contains letters/digits/hyphens/semicolons
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9\-_;]*)\s*(::?|<)\s*(.*)$", line)
        if not m:
            parse_errors.append({
                "dn": current_entry.dn if current_entry and current_entry.dn else "unknown",
                "message": f'unparseable LDIF line {line_num}: "{line}"'
            })
            continue

        attr = m.group(1)
        sep = m.group(2)
        rest = m.group(3)
        val = ""
        if sep == "::":
            # base64
            b64_str = rest.strip()
            try:
                val = base64.b64decode(b64_str).decode("utf-8", errors="replace")
            except Exception:
                val = b64_str
        elif sep == "<":
            val = rest.strip()
        else:
            val = rest.strip()

        if current_entry:
            current_entry.add_attribute(attr, val)

    if in_entry and current_entry:
        if current_entry.dn:
            current_entry.end_line = len(raw_lines)
            entries.append(current_entry)
        else:
            parse_errors.append({
                "dn": "unknown",
                "message": f'entry starting at line {current_entry.start_line} lacks a "dn:" record'
            })

    if not entries:
        parse_errors.append({
            "dn": "unknown",
            "message": 'unparseable LDIF: no valid "dn:" records found'
        })

    if parse_errors:
        raise LDIFParseError(parse_errors)

    return entries


def load_schema(schema_ldif_path: Optional[str]) -> Tuple[Dict[str, str], Set[str], str]:
    """Load schema objectClasses and attributeTypes from a slapcat dump or return static fallback."""
    if not schema_ldif_path or not os.path.exists(schema_ldif_path) or os.path.getsize(schema_ldif_path) == 0:
        return dict(KNOWN_OBJECT_CLASSES), set(KNOWN_ATTRIBUTES), "static-fallback"

    try:
        with open(schema_ldif_path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()

        lines: List[str] = []
        for line in raw_lines:
            line_str = line.rstrip("\r\n")
            if line_str.startswith(" ") or line_str.startswith("\t"):
                if lines:
                    lines[-1] += line_str[1:]
                else:
                    lines.append(line_str.lstrip())
            else:
                lines.append(line_str)

        loaded_ocs: Dict[str, str] = {}
        loaded_attrs: Set[str] = set()

        for line in lines:
            trimmed = line.strip()
            # Match olcObjectClasses or objectClasses
            m_oc = re.match(r"^(?:olcObjectClasses|objectClasses):\s*\((.*)\)\s*$", trimmed, re.IGNORECASE | re.DOTALL)
            if m_oc:
                body = m_oc.group(1)
                m_names = re.search(r"\bNAME\s+(\([^)]+\)|'[^']+'|\"[^\"]+\"|\S+)", body, re.IGNORECASE)
                names: List[str] = []
                if m_names:
                    raw = m_names.group(1).strip()
                    if raw.startswith("(") and raw.endswith(")"):
                        names = re.findall(r"['\"]?([a-zA-Z0-9_\-\.;]+)['\"]?", raw[1:-1])
                    else:
                        names = re.findall(r"['\"]?([a-zA-Z0-9_\-\.;]+)['\"]?", raw)
                kind = "STRUCTURAL"
                if re.search(r"\bAUXILIARY\b", body, re.IGNORECASE):
                    kind = "AUXILIARY"
                elif re.search(r"\bABSTRACT\b", body, re.IGNORECASE):
                    kind = "ABSTRACT"
                for n in names:
                    clean = n.strip("'\"")
                    if clean and clean not in ("$",):
                        loaded_ocs[clean.lower()] = kind

            # Match olcAttributeTypes or attributeTypes
            m_at = re.match(r"^(?:olcAttributeTypes|attributeTypes):\s*\((.*)\)\s*$", trimmed, re.IGNORECASE | re.DOTALL)
            if m_at:
                body = m_at.group(1)
                m_names = re.search(r"\bNAME\s+(\([^)]+\)|'[^']+'|\"[^\"]+\"|\S+)", body, re.IGNORECASE)
                names = []
                if m_names:
                    raw = m_names.group(1).strip()
                    if raw.startswith("(") and raw.endswith(")"):
                        names = re.findall(r"['\"]?([a-zA-Z0-9_\-\.;]+)['\"]?", raw[1:-1])
                    else:
                        names = re.findall(r"['\"]?([a-zA-Z0-9_\-\.;]+)['\"]?", raw)
                for n in names:
                    clean = n.strip("'\"")
                    if clean and clean not in ("$",):
                        loaded_attrs.add(clean.lower())

        if loaded_ocs or loaded_attrs:
            standard_operational = {
                "objectclass", "structuralobjectclass", "entryuuid", "entrycsn",
                "createtimestamp", "modifytimestamp", "creatorsname", "modifiersname",
                "subschemasubentry", "hassubordinates", "numsubordinates", "contextcsn",
                "entrydn", "memberof", "authzto", "authzfrom", "vendorname", "vendorversion",
            }
            loaded_attrs.update(standard_operational)
            for k, v in KNOWN_OBJECT_CLASSES.items():
                if k not in loaded_ocs and (k.startswith("olc") or k.startswith("pwd")):
                    loaded_ocs[k] = v
            return loaded_ocs, loaded_attrs, "runtime-image"
    except Exception:
        pass

    return dict(KNOWN_OBJECT_CLASSES), set(KNOWN_ATTRIBUTES), "static-fallback"


def normalize_dn(dn: str) -> str:
    """Normalize DN for case-insensitive comparison."""
    parts = [p.strip().lower() for p in dn.split(",") if p.strip()]
    return ",".join(parts)


def is_under_base_dn(dn: str, base_dn: str) -> bool:
    """Check whether dn matches or is a subordinate of base_dn."""
    norm_dn = normalize_dn(dn)
    norm_base = normalize_dn(base_dn)
    if not norm_base:
        return True
    if norm_dn == norm_base:
        return True
    return norm_dn.endswith("," + norm_base)


def redact_text(text: str) -> str:
    """Redact userPassword or password patterns from messages/text."""
    # Matches userPassword: <value> or userPassword::<base64>
    text = re.sub(r"(userPassword\s*::?\s*)([^\s,;]+)", r"\1" + REDACTED_PASSWORD, text, flags=re.IGNORECASE)
    return text


def parse_slapadd_log(log_path: str, entries: List[LDIFEntry]) -> List[Dict[str, str]]:
    """Parse slapadd stderr/stdout log and associate errors with entry DNs."""
    if not os.path.exists(log_path):
        return []

    errors: List[Dict[str, str]] = []
    line_to_entry: Dict[int, LDIFEntry] = {}
    for entry in entries:
        for l in range(entry.start_line, entry.end_line + 1):
            line_to_entry[l] = entry

    dn_to_entry = {normalize_dn(e.dn): e for e in entries}

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue

            # Look for line number pattern: slapadd: line N: <message>
            m_line = re.search(r"slapadd:\s+line\s+(\d+):\s*(.*)", line_str, re.IGNORECASE)
            m_dn = re.search(r'dn="([^"]+)"', line_str)

            matched_dn = ""
            msg = line_str

            if m_dn:
                raw_dn = m_dn.group(1)
                norm = normalize_dn(raw_dn)
                if norm in dn_to_entry:
                    matched_dn = dn_to_entry[norm].dn
                else:
                    matched_dn = raw_dn
            elif m_line:
                ln = int(m_line.group(1))
                if ln in line_to_entry:
                    matched_dn = line_to_entry[ln].dn

            if m_line:
                msg = m_line.group(2).strip() or line_str

            if not matched_dn and "error" in line_str.lower():
                matched_dn = "unknown"

            if matched_dn:
                clean_msg = redact_text(msg)
                err_record = {"dn": matched_dn, "message": clean_msg}
                if err_record not in errors:
                    errors.append(err_record)

    return errors


def analyze_ldif(
    entries: List[LDIFEntry],
    base_dn: str,
    slapadd_errors: Optional[List[Dict[str, str]]] = None,
    known_ocs: Optional[Dict[str, str]] = None,
    known_attrs: Optional[Set[str]] = None,
    schema_source: str = "static-fallback",
    unique_attributes: Optional[List[str]] = None,
    unique_filter: str = "objectClass=inetOrgPerson",
) -> Tuple[Dict, int]:
    """Analyze entries and produce the reconciliation report dictionary and exit code."""
    if known_ocs is None:
        known_ocs = dict(KNOWN_OBJECT_CLASSES)
    if known_attrs is None:
        known_attrs = set(KNOWN_ATTRIBUTES)
    if unique_attributes is None:
        unique_attributes = ["uid", "mail"]

    entry_count_by_objectclass: Dict[str, int] = {}
    unknown_object_classes: Dict[str, int] = {}
    unknown_attributes: Dict[str, int] = {}
    entries_outside_base_dn: List[str] = []
    entries_with_no_structural_oc: List[str] = []

    # Value tracking for duplicate detection per unique attribute
    # attr_name -> { norm_value -> (original_value, [dn, ...]) }
    unique_trackers: Dict[str, Dict[str, Tuple[str, List[str]]]] = {}
    for ua in unique_attributes:
        unique_trackers[ua.lower()] = {}

    # Parse the unique filter to determine which objectClass to scope to
    unique_filter_oc = ""
    uf_match = re.match(r"objectClass=(\S+)", unique_filter)
    if uf_match:
        unique_filter_oc = uf_match.group(1).lower()

    generated_errors: List[Dict[str, str]] = []

    for entry in entries:
        dn = entry.dn

        # 1. Base DN check
        if base_dn and not is_under_base_dn(dn, base_dn):
            entries_outside_base_dn.append(dn)
            generated_errors.append({
                "dn": dn,
                "message": f'entry DN "{dn}" falls outside base DN "{base_dn}"'
            })

        # 2. ObjectClasses check
        entry_ocs = entry.object_classes
        has_structural = False

        seen_entry_ocs: Set[str] = set()
        for oc in entry_ocs:
            low_oc = oc.lower()
            if low_oc not in seen_entry_ocs:
                seen_entry_ocs.add(low_oc)
                entry_count_by_objectclass[oc] = entry_count_by_objectclass.get(oc, 0) + 1

            if low_oc in known_ocs:
                if known_ocs[low_oc] == "STRUCTURAL":
                    has_structural = True
            else:
                unknown_object_classes[oc] = unknown_object_classes.get(oc, 0) + 1
                generated_errors.append({
                    "dn": dn,
                    "message": f'class "{oc}" not found in schema'
                })

        if not has_structural:
            entries_with_no_structural_oc.append(dn)
            generated_errors.append({
                "dn": dn,
                "message": f'no structuralObjectClass in entry (dn="{dn}")'
            })

        # 3. Attributes check
        # The unique overlay's olcUniqueURI filters (see image/entrypoint.sh)
        # scope enforcement to entries matching unique_filter_oc — an entry
        # outside that objectClass is never a candidate for the overlay, so
        # duplicate tracking must honor the same scope or it reports false
        # positives that slapadd -u never would.
        entry_in_unique_scope = (not unique_filter_oc) or (unique_filter_oc in seen_entry_ocs)

        for low_attr, vals in entry.attributes.items():
            orig_attr_name = entry.attr_casing.get(low_attr, low_attr)
            if low_attr not in known_attrs:
                unknown_attributes[orig_attr_name] = unknown_attributes.get(orig_attr_name, 0) + len(vals)
                generated_errors.append({
                    "dn": dn,
                    "message": f'attributeDescription "{orig_attr_name}": attribute type undefined'
                })

            # Unique tracking, scoped to whichever attributes/filter the
            # unique overlay is actually configured with.
            if entry_in_unique_scope and low_attr in unique_trackers:
                tracker = unique_trackers[low_attr]
                for val in vals:
                    norm_v = val.strip().lower()
                    if norm_v not in tracker:
                        tracker[norm_v] = (val, [])
                    tracker[norm_v][1].append(dn)

    # Compile duplicate collisions, one list per configured unique attribute.
    # "uid" and "mail" keys are always present (even if empty) for report
    # shape stability; any other configured --unique-attributes value adds
    # its own key.
    duplicate_collisions: Dict[str, List[Dict]] = {"uid": [], "mail": []}
    for attr_name, tracker in unique_trackers.items():
        bucket = duplicate_collisions.setdefault(attr_name, [])
        for norm_v, (orig_v, dns) in sorted(tracker.items()):
            if len(dns) > 1:
                bucket.append({"value": orig_v, "dns": sorted(dns)})
                for d in sorted(dns):
                    generated_errors.append({
                        "dn": d,
                        "message": f'unique overlay constraint violation: duplicate {attr_name} "{orig_v}"'
                    })

    # Error collation: merge slapadd errors with generated errors (never drop either)
    final_errors: List[Dict[str, str]] = list(generated_errors)
    if slapadd_errors:
        final_errors.extend(slapadd_errors)

    # Deduplicate errors deterministically
    unique_errors: List[Dict[str, str]] = []
    seen_errs = set()
    for err in final_errors:
        err_key = (err.get("dn", ""), err.get("message", ""))
        if err_key not in seen_errs:
            seen_errs.add(err_key)
            unique_errors.append({
                "dn": err.get("dn", ""),
                "message": redact_text(err.get("message", ""))
            })

    unique_errors.sort(key=lambda x: (x["dn"], x["message"]))
    entries_outside_base_dn.sort()
    entries_with_no_structural_oc.sort()

    duplicate_collision_count = sum(len(v) for v in duplicate_collisions.values())

    findings_count = (
        len(unknown_object_classes)
        + len(unknown_attributes)
        + len(entries_outside_base_dn)
        + duplicate_collision_count
        + len(entries_with_no_structural_oc)
        + len(unique_errors)
    )

    report = {
        "summary": {
            "total_entries": len(entries),
            "clean": findings_count == 0,
            "findings_count": findings_count,
        },
        "schema_source": schema_source,
        "unique_overlay": {
            "attributes": list(unique_attributes),
            "filter": unique_filter,
        },
        "entry_count_by_objectclass": dict(sorted(entry_count_by_objectclass.items())),
        "unknown_object_classes": dict(sorted(unknown_object_classes.items())),
        "unknown_attributes": dict(sorted(unknown_attributes.items())),
        "entries_outside_base_dn": entries_outside_base_dn,
        "duplicate_collisions": {k: v for k, v in sorted(duplicate_collisions.items())},
        "entries_with_no_structural_object_class": entries_with_no_structural_oc,
        "errors": unique_errors,
    }

    exit_code = 0 if findings_count == 0 else 1
    return report, exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Migration LDIF dry-run reconciliation report.")
    parser.add_argument("ldif", help="Path to input LDIF file")
    parser.add_argument("--base-dn", default="dc=example,dc=org", help="Base DN (default: dc=example,dc=org)")
    parser.add_argument("--slapadd-log", help="Path to slapadd dry-run output log")
    parser.add_argument("--schema-ldif", help="Path to runtime schema dump (slapcat -n 0 output)")
    parser.add_argument(
        "--unique-attributes", default="uid,mail",
        help="Comma-separated attributes the unique overlay enforces (default: uid,mail; empty = disabled)")
    parser.add_argument(
        "--unique-filter", default="objectClass=inetOrgPerson",
        help="LDAP filter the unique overlay scopes to (default: objectClass=inetOrgPerson)")
    parser.add_argument("-o", "--output", help="Output JSON report path (stdout if omitted)")

    args = parser.parse_args()

    def emit(report: Dict) -> Optional[int]:
        """Write the report to --output or stdout. Returns 2 on a write failure, else None."""
        output_json = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_json)
            except Exception as e:
                print(f"ERROR: Failed to write output file: {e}", file=sys.stderr)
                return 2
        else:
            sys.stdout.write(output_json)
        return None

    unique_attributes = [a.strip() for a in args.unique_attributes.split(",") if a.strip()]

    try:
        entries = parse_ldif(args.ldif)
    except LDIFParseError as e:
        # Unparseable input is itself a fatal finding, not silence: the report
        # still carries the parse error list (per-entry `dn: "unknown"` where
        # no dn could be recovered) so the caller can see exactly what failed,
        # but the script exits 2 — never 0/1 — because no entry could be
        # trusted enough to analyze.
        unique_errors = sorted(
            ({"dn": err.get("dn", "unknown"), "message": redact_text(err.get("message", ""))} for err in e.errors),
            key=lambda x: (x["dn"], x["message"]),
        )
        report = {
            "summary": {
                "total_entries": 0,
                "clean": False,
                "findings_count": len(unique_errors),
            },
            "schema_source": "n/a",
            "unique_overlay": {"attributes": unique_attributes, "filter": args.unique_filter},
            "entry_count_by_objectclass": {},
            "unknown_object_classes": {},
            "unknown_attributes": {},
            "entries_outside_base_dn": [],
            "duplicate_collisions": {"uid": [], "mail": []},
            "entries_with_no_structural_object_class": [],
            "errors": unique_errors,
        }
        print(f"ERROR: Unparseable LDIF: {args.ldif}", file=sys.stderr)
        write_failed = emit(report)
        return write_failed if write_failed is not None else 2
    except Exception as e:
        print(f"ERROR: Failed to parse LDIF: {e}", file=sys.stderr)
        return 2

    slapadd_errors: Optional[List[Dict[str, str]]] = None
    if args.slapadd_log:
        try:
            slapadd_errors = parse_slapadd_log(args.slapadd_log, entries)
        except Exception as e:
            print(f"ERROR: Failed to parse slapadd log: {e}", file=sys.stderr)
            return 2

    known_ocs, known_attrs, schema_source = load_schema(args.schema_ldif)

    try:
        report, exit_code = analyze_ldif(
            entries,
            args.base_dn,
            slapadd_errors,
            known_ocs=known_ocs,
            known_attrs=known_attrs,
            schema_source=schema_source,
            unique_attributes=unique_attributes,
            unique_filter=args.unique_filter,
        )
    except Exception as e:
        print(f"ERROR: Analysis failed: {e}", file=sys.stderr)
        return 2

    write_failed = emit(report)
    if write_failed is not None:
        return write_failed

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
