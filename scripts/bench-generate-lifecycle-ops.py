#!/usr/bin/env python3
"""Generate a deterministic joiner/mover/leaver operation queue for
scripts/bench-lifecycle.sh.

Pure and side-effect-free (no docker, no network) by design, per AGENTS.md's
testing philosophy — this is the kind of helper meant to be unit-tested with
plain fixtures, unlike the LDAP-wire-touching parts of bench-lifecycle.sh
itself.

Targets a base load already produced by scripts/bench-load.sh /
scripts/bench-generate-ldif.py: uid=bench<9-digit-index>,ou=people,<base>,
indices 0..identities-1.

    ./scripts/bench-generate-lifecycle-ops.py --identities 20000 --ops 2000 \
        --mix 50:30:20

Output (stdout):
  line 1:  "#counts\t<joinerCount>\t<moverCount>\t<leaverCount>"
  line 2+: "<kind>\t<arg>" per operation, in the run order the caller should
           execute them in — already shuffled (see SEED below), one line
           per operation, kind in {joiner, mover, leaver}. `arg` is the
           joiner's sequence number (uid=join-<arg>) for a joiner op, or the
           loaded identity's index (uid=bench<9-digit arg>) for mover/leaver.

Disjoint ranges, not random sampling, keep mover and leaver targets from
ever colliding on the same loaded identity (a mover and a leaver racing the
same DN would make both operations' latency/error numbers meaningless):
leavers get indices [0, leaverCount), movers get the next
[leaverCount, leaverCount+moverCount). Joiners create new entries
(uid=join-<n>) so they never touch the loaded range at all.
"""
import argparse
import random
import sys

# Fixed, not derived from --identities/--ops/--mix: determinism here means
# "the same invocation always produces the same op sequence", not "every
# parameter combination gets its own sequence" — a fixed seed gives that
# with one less thing to keep in sync between runs being compared.
SEED = 124124


def largest_remainder(total: int, weights: list) -> list:
    """Split `total` into len(weights) non-negative integer counts
    proportional to `weights`, summing to exactly `total`. Standard
    largest-remainder apportionment; ties broken by weights' own order
    (stable, deterministic) rather than by value, so equal fractional
    remainders always resolve the same way."""
    weight_sum = sum(weights)
    if weight_sum <= 0:
        raise ValueError("mix ratio must have at least one positive part")
    raw = [total * w / weight_sum for w in weights]
    counts = [int(x) for x in raw]
    remainder = total - sum(counts)
    fractions = sorted(range(len(weights)), key=lambda i: raw[i] - counts[i], reverse=True)
    for i in fractions[:remainder]:
        counts[i] += 1
    return counts


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--identities", type=int, required=True, help="loaded base identity count (uid=bench0..N-1)")
    p.add_argument("--ops", type=int, required=True, help="total lifecycle operations to generate")
    p.add_argument("--mix", required=True, help="joiner:mover:leaver ratio, e.g. 50:30:20")
    args = p.parse_args()

    if args.identities < 1:
        print("error: --identities must be at least 1", file=sys.stderr)
        return 2
    if args.ops < 1:
        print("error: --ops must be at least 1", file=sys.stderr)
        return 2

    parts = args.mix.split(":")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        print(f"error: --mix must be J:M:L with non-negative integers (got: {args.mix!r})", file=sys.stderr)
        return 2
    joiner_w, mover_w, leaver_w = (int(x) for x in parts)
    if joiner_w + mover_w + leaver_w <= 0:
        print("error: --mix must have at least one positive part", file=sys.stderr)
        return 2

    joiner_count, mover_count, leaver_count = largest_remainder(args.ops, [joiner_w, mover_w, leaver_w])

    if mover_count + leaver_count > args.identities:
        print(
            f"error: --ops {args.ops} with --mix {args.mix} needs "
            f"{mover_count} mover + {leaver_count} leaver targets "
            f"({mover_count + leaver_count} total) but only --identities "
            f"{args.identities} are loaded — increase --identities, lower "
            f"--ops, or shift --mix toward joiner",
            file=sys.stderr,
        )
        return 2

    ops = []
    for i in range(1, joiner_count + 1):
        ops.append(("joiner", i))
    for idx in range(0, leaver_count):
        ops.append(("leaver", idx))
    for idx in range(leaver_count, leaver_count + mover_count):
        ops.append(("mover", idx))

    random.Random(SEED).shuffle(ops)

    out = sys.stdout
    out.write(f"#counts\t{joiner_count}\t{mover_count}\t{leaver_count}\n")
    for kind, arg in ops:
        out.write(f"{kind}\t{arg}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
