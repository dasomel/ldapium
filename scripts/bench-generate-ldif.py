#!/usr/bin/env python3
"""Generate a synthetic LDIF of N inetOrgPerson entries for a load benchmark.

Not sample data shipped with the product — see CONTRIBUTING.md's "No sample
data" rule, which is about what the image ships, not about a benchmark tool
an operator runs deliberately against a scratch database. Output goes to a
file the operator names; nothing here writes to a real deployment.

    ./scripts/bench-generate-ldif.py --count 100000 --base dc=example,dc=org > /tmp/bench.ldif

Deterministic (a fixed count always produces the same entries, in the same
order) so a load timing run is comparable across repeats — the variable
under test is slapadd's speed, not the data.
"""
import argparse
import sys


def entry(i: int, base: str) -> str:
    uid = f"bench{i:09d}"
    return (
        f"dn: uid={uid},ou=people,{base}\n"
        f"objectClass: inetOrgPerson\n"
        f"uid: {uid}\n"
        f"cn: Bench User {i}\n"
        f"sn: User{i}\n"
        f"givenName: Bench{i}\n"
        f"mail: {uid}@bench.invalid\n"
        # A search benchmark needs something to filter on besides the unique
        # uid — mod picked so a single-value equality filter (mail domain
        # aside) returns a realistic, non-trivial slice of the tree rather
        # than either one entry or all of them.
        f"employeeType: dept{i % 200:04d}\n"
        "\n"
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--count", type=int, required=True, help="number of entries to generate")
    p.add_argument("--base", required=True, help="base DN, e.g. dc=example,dc=org")
    args = p.parse_args()

    if args.count < 1:
        print("error: --count must be at least 1", file=sys.stderr)
        return 2

    out = sys.stdout
    out.write(f"dn: ou=people,{args.base}\n")
    out.write("objectClass: organizationalUnit\n")
    out.write("ou: people\n\n")
    for i in range(args.count):
        out.write(entry(i, args.base))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
