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
    """Parse LDIF file into LDIFEntry objects, handling RFC 2849 line continuations."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"LDIF file not found: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()

    entries: List[LDIFEntry] = []
    current_entry: Optional[LDIFEntry] = None

    logical_lines: List[Tuple[int, str]] = []
    # Unfold lines
    for idx, line in enumerate(raw_lines, 1):
        line_stripped = line.rstrip("\r\n")
        if not line_stripped:
            logical_lines.append((idx, ""))
            continue
        if line_stripped.startswith(" ") or line_stripped.startswith("\t"):
            if logical_lines:
                orig_idx, prev_content = logical_lines[-1]
                logical_lines[-1] = (orig_idx, prev_content + line_stripped[1:])
            else:
                logical_lines.append((idx, line_stripped.lstrip()))
        else:
            logical_lines.append((idx, line_stripped))

    entry_start_line = 1
    in_entry = False

    for line_num, line in logical_lines:
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            if in_entry and current_entry and current_entry.dn:
                current_entry.end_line = line_num - 1
                entries.append(current_entry)
                current_entry = None
                in_entry = False
            continue

        if not in_entry:
            in_entry = True
            entry_start_line = line_num
            current_entry = LDIFEntry(entry_start_line, line_num)

        # Parse attribute: value
        if ":" in line:
            parts = line.split(":", 1)
            attr = parts[0].strip()
            rest = parts[1]
            val = ""
            if rest.startswith(":"):
                # base64
                b64_str = rest[1:].strip()
                try:
                    val = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                except Exception:
                    val = b64_str
            elif rest.startswith("<"):
                # URL reference
                val = rest[1:].strip()
            else:
                val = rest.strip()

            if current_entry:
                current_entry.add_attribute(attr, val)

    if in_entry and current_entry and current_entry.dn:
        current_entry.end_line = len(raw_lines)
        entries.append(current_entry)

    return entries


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
) -> Tuple[Dict, int]:
    """Analyze entries and produce the reconciliation report dictionary and exit code."""
    entry_count_by_objectclass: Dict[str, int] = {}
    unknown_object_classes: Dict[str, int] = {}
    unknown_attributes: Dict[str, int] = {}
    entries_outside_base_dn: List[str] = []
    entries_with_no_structural_oc: List[str] = []

    # Value tracking for duplicate detection (case-insensitive key -> original value, list of DNs)
    uid_tracker: Dict[str, Tuple[str, List[str]]] = {}
    mail_tracker: Dict[str, Tuple[str, List[str]]] = {}

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

        seen_entry_ocs = set()
        for oc in entry_ocs:
            low_oc = oc.lower()
            if low_oc not in seen_entry_ocs:
                seen_entry_ocs.add(low_oc)
                entry_count_by_objectclass[oc] = entry_count_by_objectclass.get(oc, 0) + 1

            if low_oc in KNOWN_OBJECT_CLASSES:
                if KNOWN_OBJECT_CLASSES[low_oc] == "STRUCTURAL":
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
        for low_attr, vals in entry.attributes.items():
            orig_attr_name = entry.attr_casing.get(low_attr, low_attr)
            if low_attr not in KNOWN_ATTRIBUTES:
                unknown_attributes[orig_attr_name] = unknown_attributes.get(orig_attr_name, 0) + len(vals)
                generated_errors.append({
                    "dn": dn,
                    "message": f'attributeDescription "{orig_attr_name}": attribute type undefined'
                })

            # Unique tracking
            if low_attr == "uid":
                for val in vals:
                    norm_v = val.strip().lower()
                    if norm_v not in uid_tracker:
                        uid_tracker[norm_v] = (val, [])
                    uid_tracker[norm_v][1].append(dn)
            elif low_attr == "mail":
                for val in vals:
                    norm_v = val.strip().lower()
                    if norm_v not in mail_tracker:
                        mail_tracker[norm_v] = (val, [])
                    mail_tracker[norm_v][1].append(dn)

    # Compile duplicate collisions
    duplicate_uid: List[Dict] = []
    for norm_v, (orig_v, dns) in sorted(uid_tracker.items()):
        if len(dns) > 1:
            duplicate_uid.append({"value": orig_v, "dns": sorted(dns)})
            for d in sorted(dns):
                generated_errors.append({
                    "dn": d,
                    "message": f'unique overlay constraint violation: duplicate uid "{orig_v}"'
                })

    duplicate_mail: List[Dict] = []
    for norm_v, (orig_v, dns) in sorted(mail_tracker.items()):
        if len(dns) > 1:
            duplicate_mail.append({"value": orig_v, "dns": sorted(dns)})
            for d in sorted(dns):
                generated_errors.append({
                    "dn": d,
                    "message": f'unique overlay constraint violation: duplicate mail "{orig_v}"'
                })

    # Error collation: prefer slapadd errors if provided, otherwise generated errors
    final_errors: List[Dict[str, str]] = []
    if slapadd_errors is not None and len(slapadd_errors) > 0:
        final_errors = slapadd_errors
    else:
        final_errors = generated_errors

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

    findings_count = (
        len(unknown_object_classes)
        + len(unknown_attributes)
        + len(entries_outside_base_dn)
        + len(duplicate_uid)
        + len(duplicate_mail)
        + len(entries_with_no_structural_oc)
        + len(unique_errors)
    )

    report = {
        "summary": {
            "total_entries": len(entries),
            "clean": findings_count == 0,
            "findings_count": findings_count,
        },
        "entry_count_by_objectclass": dict(sorted(entry_count_by_objectclass.items())),
        "unknown_object_classes": dict(sorted(unknown_object_classes.items())),
        "unknown_attributes": dict(sorted(unknown_attributes.items())),
        "entries_outside_base_dn": entries_outside_base_dn,
        "duplicate_collisions": {
            "uid": duplicate_uid,
            "mail": duplicate_mail,
        },
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
    parser.add_argument("-o", "--output", help="Output JSON report path (stdout if omitted)")

    args = parser.parse_args()

    try:
        entries = parse_ldif(args.ldif)
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

    try:
        report, exit_code = analyze_ldif(entries, args.base_dn, slapadd_errors)
    except Exception as e:
        print(f"ERROR: Analysis failed: {e}", file=sys.stderr)
        return 2

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

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
