#!/usr/bin/env python3
"""Resolve entry DN to entryUUID for replication-conflict-raw records at export time.

This script acts as a stream filter between extraction awk stages and
audit-normalize.py in scripts/export-audit-log.sh.

For any record where source == 'replication-conflict-raw' and an 'entry' DN is
present, it resolves the DN to entryUUID using ldapsearch (or a fixture stub map
when LDAP_STUB_OBJECTID_MAP is set) with one lookup per distinct DN (cached).
All other records pass through unmodified.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys


def dn_key(dn: str) -> str:
    return re.sub(r",\s*", ",", dn.strip()).lower()


def load_stub_map(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {dn_key(k): str(v) for k, v in data.items()}
    except Exception as exc:
        print(f"resolve-conflict-objectid.py: failed to load stub map {path}: {exc}", file=sys.stderr)
    return {}


def resolve_live_ldap(
    dn: str,
    namespace: str,
    statefulset: str,
    admin_dn: str,
    password: str,
) -> str | None:
    if not (namespace and statefulset):
        return None
    pod = f"{statefulset}-0"
    cmd = [
        "kubectl",
        "-n",
        namespace,
        "exec",
        pod,
        "-c",
        "openldap",
        "--",
        "ldapsearch",
        "-x",
        "-o",
        "ldif-wrap=no",
    ]
    if admin_dn and password:
        cmd.extend(["-D", admin_dn, "-w", password])
    cmd.extend(["-b", dn, "-s", "base", "(objectClass=*)", "entryUUID"])

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        print(f"resolve-conflict-objectid.py: ldapsearch failed for {dn}: {exc}", file=sys.stderr)
        return None

    if proc.returncode != 0:
        return None

    m = re.search(r"^entryUUID:\s*([0-9a-fA-F-]+)", proc.stdout, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", "-n", default="", help="Kubernetes namespace")
    parser.add_argument("--statefulset", "-s", default="", help="StatefulSet name")
    parser.add_argument("--admin-dn", default="", help="Admin bind DN for ldapsearch")
    parser.add_argument(
        "--stub-map",
        default=os.environ.get("LDAP_STUB_OBJECTID_MAP", ""),
        help="Path to JSON stub map (DN -> entryUUID) for offline/fixture testing",
    )
    args = parser.parse_args(argv)

    password = os.environ.get("LDAP_ADMIN_PASSWORD", "")
    cache: dict[str, str | None] = {}
    stub_map = load_stub_map(args.stub_map) if args.stub_map else {}

    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = json.loads(stripped)
        except json.JSONDecodeError:
            # Pass unparseable line to normalizer so normalizer's own drop handling applies
            sys.stdout.write(line)
            continue

        if rec.get("source") == "replication-conflict-raw" and "entry" in rec:
            entry_dn = rec.get("entry")
            if entry_dn:
                key = dn_key(entry_dn)
                if key not in cache:
                    if stub_map:
                        cache[key] = stub_map.get(key)
                    else:
                        cache[key] = resolve_live_ldap(
                            entry_dn,
                            args.namespace,
                            args.statefulset,
                            args.admin_dn,
                            password,
                        )
                uuid = cache.get(key)
                if uuid:
                    rec["entryUUID"] = uuid

            sys.stdout.write(json.dumps(rec, separators=(",", ":")) + "\n")
        else:
            sys.stdout.write(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
