# Scale benchmarks

"This holds up to N entries" is a claim; this document is the reproducible
measurement behind it instead. It covers five things: offline load
throughput, search throughput/latency, write-and-replication convergence,
identity-lifecycle (joiner/mover/leaver) operation timing, and where to run
all four.

## Where to run this

GitHub-hosted runners cannot do 10M/30M+ honestly: that scale needs disk and
wall-clock time neither the runner's ephemeral disk nor CI's time budget can
absorb, and a number produced by truncating the run early is noise, not
evidence. So 10M/30M+ stays **local reproduction tooling, not a CI job** —
`scripts/bench-generate-ldif.py`, `scripts/bench-load.sh`,
`scripts/bench-search.sh`, `scripts/bench-replication.sh`, the
`scripts/bench-profile.sh` runner that wraps the first three (see "The
profile runner" below), and `scripts/bench-lifecycle.sh` (see "Identity-
lifecycle load profile" below), run by hand on whatever machine you actually
care about the numbers for. The 1M profile is the exception: it fits a
GitHub-hosted runner's disk and time budget, so `.github/workflows/
bench-profile.yml` (`workflow_dispatch` only — not on every push or PR, see
that file's own comment for why) runs it on demand, which is what keeps the
tooling itself from silently rotting between real large-scale runs. 10M and
30M+ are not scheduled anywhere and never will be from a shared runner.

Before trusting any number this tooling produces, at any scale:

- **`olcDbMaxSize` must exceed the loaded data's on-disk size**, or `slapadd`
  fails partway through with the map full instead of producing a load-time
  number. `bench-load.sh --db-max-size-gb` (`bench-profile.sh
  --db-max-size-gb`) controls this; size it for the target `--count` before
  you start, not after a failed run. The chart's own `ldap.dbMaxSize`
  (`charts/ldapium/values.yaml`) is the same knob for a real deployment.
  **The raw LDIF size is not a usable sizing basis** — live-verified while
  building the profile runner below: this chart's 10 default indices
  (`image/ldifs/01-cn-config.ldif`: `objectClass`, `entryUUID`, `entryCSN`,
  `uid`, `cn`, `mail`, `memberOf`, `member`, `sn`, `givenName`) dominate the
  in-map footprint, not entry payload. A first sizing attempt using the
  measured ~217 bytes/entry raw-LDIF ratio died at 705,499/1,000,000 entries
  with the map full; a second attempt at exactly this document's own
  previously-published 4GiB-for-1M figure (see "1M / 10M / 30M+ load
  profile" below for why that number stopped being sufficient) died at
  931,999/1,000,000 (re-confirmed 2026-09-06 at 931,499/1,000,000 —
  `bench-profile.sh`'s own default formula, at the time, still computed
  exactly this insufficient 4GiB for `--entries 1000000`). Budget for
  indices explicitly, not from LDIF bytes. `bench-profile.sh`'s default
  formula has since been raised (see its own header comment) so that an
  unqualified `--entries 1000000` — the invocation
  `.github/workflows/bench-profile.yml` actually runs — succeeds without an
  explicit `--db-max-size-gb`; that default still over-allocates badly past
  a few million entries, so pass `--db-max-size-gb` explicitly, sized from a
  measured run at a nearby scale, for anything beyond a quick smoke test.
- **Indices must already be in place before a search benchmark means
  anything.** A search benchmark run against an unindexed attribute measures
  a full-table scan, not the product. `bench-search.sh` queries `uid`, which
  this chart indexes (`eq`) by default (`image/ldifs/01-cn-config.ldif`), so
  the default numbers below are already meaningful; benchmarking a different
  attribute means confirming it's indexed first.

## Reproducing it

### Load

```bash
docker build -t ldapium:bench -f image/Dockerfile image/
./scripts/bench-load.sh --image ldapium:bench --count 1000000 --db-max-size-gb 4
```

Bootstraps a real release (so `cn=config` is the product's own bootstrap, not
a hand-built stand-in), stops it, then times an **offline** `slapadd -n 1`
against the same two Docker volumes. Offline, not the `LDAP_SEED_DIR`
mechanism: that path applies entries one at a time over the wire after
`slapd` is already serving, which is the right tool for a handful of
bootstrap entries and dramatically slower than offline `slapadd` for bulk
data — this measures the latter because that's the operation a real
migration or restore actually uses at this scale.

The two volumes it leaves behind (`ldapium-bench-<count>-config` /
`-data`, printed at the end) are the deliverable, not cleanup debris — they
feed directly into the search benchmark below. `docker volume rm` them
yourself once you're done with both.

### Search

```bash
./scripts/bench-search.sh --image ldapium:bench \
  --config-volume ldapium-bench-1000000-config \
  --data-volume ldapium-bench-1000000-data \
  --entry-count 1000000 --concurrency 20 --queries-per-worker 200
```

Starts a server against the volumes the load run produced, then runs
`concurrency × queries-per-worker` equality lookups (`uid=benchNNNNNNNNN`,
uniformly sampled across the loaded range) and reports p50/p95/p99 latency
(nearest-rank) plus achieved QPS.

**Caveat that matters more than the numbers themselves:** each query is a
fresh `docker exec ... ldapsearch`, so the reported latency includes process
spawn and `docker exec` overhead on top of the actual LDAP search — it is a
throughput/scaling benchmark, not a measurement of raw protocol latency. A
real client holding one connection and issuing many searches on it will see
meaningfully lower per-query latency than these numbers show. Use this
benchmark to compare *relative* behavior across scale and index
configuration, not as the literal number to put in an SLA.

### Write + replication convergence

```bash
./scripts/bench-replication.sh --image ldapium:bench --namespace ldapium-bench-repl --count 5000
```

Installs a real `replicaCount=3` Helm release (multi-provider syncrepl, the
same topology `charts/ldapium/README.md`'s "HA / replication" section
describes — not a stand-in for it), writes a burst of entries against
provider 0, then polls `contextCSN` across all three providers until they
agree or `--timeout-seconds` elapses. This is the identical convergence
check `.github/workflows/replication-chaos-e2e.yml` already uses to prove
convergence after a partition, reused rather than reinvented so a
"converged" verdict means the same thing in both places. Needs a working
`kubectl` context with Helm 3 and capacity for a 3-replica StatefulSet — a
local `kind` cluster is enough.

### The profile runner

```bash
docker build -t ldapium:e2e -f image/Dockerfile image/
./scripts/bench-profile.sh --entries 1000000 --out scripts/bench-results
```

`scripts/bench-profile.sh` is a single entry point over the three commands
above, built for #124's ask (a repeatable 1M/10M/30M+ profile, not three
commands and three stdout blobs an operator stitches together by hand). One
invocation:

1. generates the LDIF (streaming, one entry at a time — RAM stays flat
   regardless of `--entries`, only disk grows);
2. bootstraps a real release and bulk-loads it with **offline `slapadd -q`**
   — `-q` (quick/no-verify mode) is the fastest supported bulk-load path,
   which is why this runner uses it in place of bare `slapadd` — sampling
   load progress and container memory every 5s (small runs) or 30s (100K+)
   via a read-only `slapcat` peek against the still-loading volume (safe:
   LMDB readers never block on a concurrent writer);
3. enforces an optional `--timeout-seconds` wall-clock cap on the load phase
   only — past it, the loader is killed and whatever the last progress
   sample showed is reported as a partial, honest result rather than left
   to run unbounded or silently discarded;
4. runs `bench-search.sh` against the freshly loaded volumes, plus a new
   single-connection online write-latency micro-benchmark (sequential
   `ldapadd`, p50/p95/p99 — distinct from `bench-replication.sh`'s
   multi-provider write+convergence burst, which stays k8s-only and
   small-scale, see "Write + replication convergence" above);
5. writes one JSON + one Markdown report (`bench-profile-<N>-<timestamp>.*`)
   with environment (CPU/mem, image digest, OpenLDAP version, disk headroom)
   folded into the same record, then deletes its volumes — unlike
   `bench-load.sh`, which deliberately leaves them for a separate
   `bench-search.sh` invocation, this runner is meant to be a self-contained
   one-shot.

**Three gotchas found live while building this that change how you size a
run and how you read its output, not just cosmetic:**

- **`-q`'s reported "on-disk size" and the disk it actually consumes are two
  different numbers, and they can diverge sharply.** `-q` allocates
  (`ftruncate`s) the full configured `--db-max-size-gb` immediately at load
  start, not lazily as data is written — the *apparent* file size hits the
  configured map size right away (confirmed with a tiny 500-entry/256MiB
  test: apparent size was an exact 256MiB, vs. 1.4MB for the same load
  without `-q`). But apparent size is not the same as *allocated* size on a
  filesystem that supports sparse files, and this one does: a real 1M-entry
  run measured **9.0GiB apparent vs. 1.4GiB actually allocated on disk —
  6.3x apart** (live-verified 2026-09-06; the 500-entry test above was too
  small to show this and an earlier draft of this doc wrongly generalized
  from it). `bench-profile.sh` now records both as separate fields —
  `dbApparentBytes` (`du -sb`, what `stat`/`ls -l` would report; confirms
  the configured map size took effect but is *not* a capacity-planning
  number under `-q`) and `dbAllocatedBytes` (plain `du`, real device blocks;
  the number that matters for "how much disk does this actually need").
  `ldifBytes` remains the closer proxy for actual *data* volume (excluding
  index/LMDB overhead) than either.
- **The right sizing basis for `--db-max-size-gb` is indices, not raw LDIF
  bytes.** This chart ships 10 default indices
  (`image/ldifs/01-cn-config.ldif`), and their in-map footprint dominates
  over entry payload at any real scale. A sizing formula based on the ~217
  bytes/entry raw-LDIF ratio undersizes badly — live-verified, see the
  "olcDbMaxSize must exceed..." bullet above for the failed attempts that
  found this the hard way.
- **The default formula itself was silently insufficient at 1M until this
  PR.** `bench-profile.sh --entries 1000000` with no `--db-max-size-gb`
  override — exactly what `.github/workflows/bench-profile.yml` runs —
  computed 4GiB by default and died with the map full at 931,499/1,000,000
  entries (re-confirmed live 2026-09-06; see the "olcDbMaxSize must
  exceed..." bullet above). The committed 1M/10M results below were
  produced with an explicit `--db-max-size-gb` override, which is why the
  bug had gone unnoticed. The default now derives from an empirically-
  grounded ~9,400 bytes/entry (4,700 base + 2.0x headroom) instead of the
  previous, proven-insufficient ~3,960 bytes/entry (1,800 base + 2.2x
  headroom) — a live rerun at 1M with the corrected default (no override)
  succeeded (`bench-profile-1000000-20260906T063039Z.json`). This default
  is still a last resort, not a sizing recommendation: it scales worse than
  linearly in practice (per-entry map overhead is not constant across
  scale — the committed 10M result completed with an explicit override of
  only ~2.1KB/entry, far below what this formula would compute at that N,
  though that is evidence a smaller size *can* work, not proof of the
  minimum). Pass `--db-max-size-gb` explicitly, sized from a measured run
  at a nearby scale, for anything beyond a quick smoke test.

The 1M profile also runs in CI on demand — see `.github/workflows/
bench-profile.yml` (`workflow_dispatch`, capped at 1M, see that file's
own guard step for why a larger value is rejected rather than silently
attempted on a GitHub-hosted runner).

### Identity-lifecycle load profile

```bash
docker build -t ldapium:e2e -f image/Dockerfile image/
./scripts/bench-lifecycle.sh --identities 1000000 --ops 100000 --out scripts/bench-results
```

Closes the gap the "What this does not cover" section used to call out:
issue #124's AC absorbed from #19 asked specifically for joiner/mover/leaver
operation timing, not the generic `inetOrgPerson` write/search numbers
`bench-profile.sh` measures. `scripts/bench-lifecycle.sh` reuses
`bench-load.sh` for the base population (same offline `slapadd` path, same
generator, same sizing formula as `bench-profile.sh` — see that script's own
header) and adds a third phase: a deterministic, seeded queue of lifecycle
operations (`scripts/bench-generate-lifecycle-ops.py` — pure and separately
testable, unlike the LDAP-wire phases around it) run over the wire against a
real server with `--concurrency` parallel workers.

What "joiner", "mover", and "leaver" mean here, mapped to the same
operations the console's backend performs (not a reinterpretation of them):

| Term | Console operation | Wire operation here |
|---|---|---|
| Joiner | create a new identity | `ldapadd` a new `uid=join-<i>,ou=people,<base>` entry |
| Mover | move an identity to a new org unit (`ui/backend/internal/ldapclient/tree.go`'s `MoveEntry`) | `ldapmodrdn -r -s ou=people-moved,<base>` — RDN preserved, `deleteOldRDN=true`, matching `buildMoveRequest` exactly |
| Leaver | deactivate then remove an identity (`users.go`'s `Lock`, `pwdAccountLockedTime: 000001010000Z`) | `ldapmodify` (replace `pwdAccountLockedTime`) then `ldapdelete` — the same two-step sequence, not a single combined operation |

`--mix joiner:mover:leaver` (default `50:30:20`) sets the op counts as a
ratio of `--ops`; movers and leavers are assigned disjoint ranges of the
loaded `uid=bench<N>` identities up front (leavers get the low end, movers
the next slice) specifically so a mover and a leaver can never race the same
DN — a race there would make both operations' latency and error numbers
meaningless, not just noisy. `--identities` must cover at least
mover-count + leaver-count or the script fails fast (exit 2) before starting
any container.

**ppolicy is auto-detected, not assumed.** The ppolicy overlay module is
loaded unconditionally in `image/ldifs/01-cn-config.ldif` regardless of
`LDAP_PASSWORD_POLICY_ENABLED` (only the `olcPPolicyDefault` policy pointer
is conditional on that flag — confirmed by reading that file, not assumed),
so `pwdAccountLockedTime` is legal schema on every stock `ldapium:e2e`/
`-chaos`/`-security` image. The script still probes `cn=config` for the
overlay (retried up to 5 times — live-verified this can miss on the very
first query right after the readiness check passes, since the mdb backend
and the cn=config backend don't necessarily finish coming up in the same
instant) rather than hardcoding that assumption: against a custom `--image`
without ppolicy compiled in, leaver ops silently become delete-only and the
report's `ppolicyDetected: false` field says so.

Post-run sanity checks (all three must pass, in one query each rather than
per-operation, for the same reason `bench-profile.sh` keeps its own progress
sampling O(1) — see that script's header): `ou=people-moved` holds exactly
the mover count, the remaining `uid=bench*` count under `ou=people` equals
`identities - movers - leavers` (leavers verifiably gone, movers verifiably
elsewhere), and every `uid=join-*` entry exists. Any sanity failure, or any
nonzero per-operation error count, fails the run (`status: "failed"`) —
this is meant to catch a lifecycle operation silently no-op'ing, not just
time the happy path.

`--timeout-seconds` bounds the **operations phase only** (the base load has
no cap here — use `bench-load.sh` directly if that needs bounding), and is
deliberately cooperative rather than a preemptive kill: this repo's other
`timeout`-based CI-only shell isn't available by default on macOS, which is
this benchmark's other required run target per `AGENTS.md`. A worker
finishes its current operation, then stops once the deadline has passed;
`status` becomes `"timed-out"` and sanity checks are skipped, the same way
`bench-profile.sh` skips search/write on a non-`"ok"` load status.

A 1M-scale run has not been committed to `scripts/bench-results/` as of this
writing — see the PR that added this section for whether one has landed
since. Small local runs (tens of thousands of identities) are the everyday
way to exercise this tool; see `.github/workflows/bench-lifecycle.yml` for
the on-demand CI job.

## Measured results

Measured in this sandbox: Colima (Docker Desktop's Linux VM equivalent) on
Apple Silicon, 4 vCPU / 6GiB allotted to the VM, `arm64`. **This is not
production hardware** — it's a resource-constrained developer VM, and the
numbers below describe that environment, not a bare-metal or cloud-VM
deployment. Re-run the commands above on your own target hardware for
numbers that mean something for a real capacity decision; what these numbers
are good for is proving the tooling and the product behave correctly at
scale, and giving a relative baseline.

| Scale | Load time | Load rate | Search concurrency | Search QPS | p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| 20,000 entries (`bench-load.sh`, no `-q`) | 114.4s | 174.8 entries/s | 10 × 30 | 85.0 | 104ms | 143ms | 157ms |
| 1,000,000 entries (`bench-load.sh`, no `-q`) | 9,072.8s (151.2min) | 110.2 entries/s | 20 × 100 | 89.5 | 207ms | 295ms | 338ms |

Search concurrency differs between the two runs above (10 workers × 30
queries at 20K vs. 20 × 100 at 1M), so the QPS/latency columns are not a
pure apples-to-apples scale comparison — higher concurrency alone would be
expected to raise both QPS and per-query latency somewhat independent of
data volume. Re-run with matched `--concurrency`/`--queries-per-worker` if
you need an isolated scale effect.

**Colima aarch64 VM, 3 vCPU/6 GiB cap, shared host** — `scripts/bench-profile.sh`
(offline `slapadd -q`), measured for #124, on a *shared* 6 vCPU/12GiB host
VM with two other workloads active concurrently (not the dedicated 4
vCPU/6GiB sandbox the two rows in the table above used); search concurrency
20 workers × 100 queries/worker (`--search-concurrency 20
--search-queries-per-worker 100`, matching the older 1M non-`-q` row above)
for both rows below — see "The profile runner" above for why this is
dramatically faster than the non-`-q` rows above and not directly
comparable to them:

| Scale | Load time | Load rate | Search QPS | Search p50/p95/p99 | Write p50/p95/p99 (single conn, online) |
|---|---|---|---|---|---|
| 1,000,000 entries | 46.9s | 21,334.7 entries/s | 113.68 | 157ms / 216ms / 247ms | 62ms / 71ms / 75ms |
| 10,000,000 entries | 2,340.9s (39.0min) | 4,271.9 entries/s | 116.06 | 155ms / 213ms / 240ms | 57ms / 65ms / 70ms |

`slapadd -q` is ~194x faster than the non-`-q` path at 1M (21,334.7 vs. 110.2
entries/s) — consistent with `-q` skipping the per-entry schema/constraint
re-verification `bench-generate-ldif.py`'s own guaranteed-valid, guaranteed-
unique output doesn't need. Search QPS/latency at the 1M scale and matched
concurrency (20 × 100) landed close to the older non-`-q` measurement
(113.68 QPS / 157-247ms vs. 89.5 QPS / 207-338ms) — search performance
depends on the loaded data and indices, not on which `slapadd` mode built
them, so the modest improvement here is plausibly host/contention noise
(shared VM) rather than a `-q` effect. Write-latency (single online
connection, sequential `ldapadd`) is a new metric this profile runner adds;
there is no prior number to compare it against.

**1M → 10M scaling, under this profile runner specifically:**

- **Load rate drops sharply, worse than linearly.** 4,271.9 entries/s at
  10M is ~20% of the 21,334.7 entries/s measured at 1M — a 5x throughput
  drop for a 10x increase in entries — so total load *time* scaled ~50x
  (46.9s → 2,340.9s), not the 10x a constant rate would imply. Consistent
  with the same `slapadd`-single-transaction B+tree-depth effect already
  documented for the non-`-q` path above, just measured again here on the
  faster `-q` path: the effect isn't specific to which `slapadd` mode
  builds the tree.
- **Search latency and QPS stayed flat 1M → 10M** (113.68 QPS / 157ms p50
  at 1M vs. 116.06 QPS / 155ms p50 at 10M — within run-to-run noise on a
  shared host), unlike the roughly 2x p50 degradation measured 20K → 1M on
  the older non-`-q` row above. The likely explanation is that
  `bench-search.sh`'s `docker exec`-per-query fixed overhead (see the SLO
  section's own caveat below) dominates the measurement at this range, and
  a real index-depth cost — present but smaller between 1M and 10M
  (`log₂` depth grows by ~3.3 levels vs. ~5.6 levels between 20K and 1M) —
  is masked by it. This is **not** evidence that search performance is
  scale-invariant past 10M; it's evidence that this harness's fixed
  measurement overhead currently exceeds the real per-query cost
  difference at this range. Write latency (single-connection online
  `ldapadd`) is similarly flat (62ms → 57ms p50) for the same reason.
- Loader RSS during the 10M load peaked at ~2.75GiB (sampled via `docker
  stats`, see `scripts/bench-results/bench-profile-10000000-*.json`'s
  `progressSamples`), comfortably inside the 6GiB cap; the equivalent 1M
  sample is inconclusive (`0B` — the load finished before the first 30s
  sampling interval elapsed) and is not usable as a comparison point.

Raw evidence records (machine-readable, one JSON object per run):

```json
{"benchmark":"load","image":"ldapium:bench","entryCount":20000,"loadedCount":20000,"loadSeconds":114.390,"entriesPerSecond":174.84,"ldifBytes":4246746,"dbMaxSizeBytes":1073741824,"status":"ok"}
{"benchmark":"search","image":"ldapium:bench","entryCount":20000,"concurrency":10,"totalQueries":300,"failedQueries":0,"wallSeconds":3.530,"queriesPerSecond":84.99,"latencyMsP50":104.342,"latencyMsP95":143.054,"latencyMsP99":156.945}
{"benchmark":"load","image":"ldapium:bench","entryCount":1000000,"loadedCount":1000000,"loadSeconds":9072.757,"entriesPerSecond":110.22,"ldifBytes":216666746,"dbMaxSizeBytes":4294967296,"status":"ok"}
{"benchmark":"search","image":"ldapium:bench","entryCount":1000000,"concurrency":20,"totalQueries":2000,"failedQueries":0,"wallSeconds":22.354,"queriesPerSecond":89.47,"latencyMsP50":207.402,"latencyMsP95":295.447,"latencyMsP99":338.481}
{"benchmark":"replication","image":"ldapium:bench","entryCount":500,"writeSeconds":2.745,"entriesPerSecond":182.15,"convergenceSeconds":1,"converged":true}
```

Write + replication convergence, 3 providers, 500-entry burst: 2.75s to
write (182.2 entries/s), **converged across all 3 providers within 1s** of
the write completing.

The `scripts/bench-profile.sh` runs' full JSON records (environment,
progress samples, search, write-latency) are committed at
`scripts/bench-results/bench-profile-1000000-20260903T232834Z.json` (1M,
table row above) and `scripts/bench-results/bench-profile-10000000-
20260903T233629Z.json` (10M, table row above; run with an explicit
`--db-max-size-gb 20`, labeled "disk-budget-constrained attempt" in its own
report — chosen to fit this shared VM's available disk, not derived from
any sizing formula, so its sufficiency margin at 10M is unknown). Both of
these two 0903 records predate the apparent/allocated split described in
"The profile runner" above and carry the older single `dbOnDiskBytes` field
(equal to the configured map size) instead of `dbApparentBytes`/
`dbAllocatedBytes` — read their on-disk-size numbers as apparent size only,
not real disk consumption. A third
record, `scripts/bench-results/bench-profile-1000000-20260906T063039Z.json`,
is a later 1M-only rerun made after this PR raised the `--db-max-size-gb`
default and split `dbApparentBytes`/`dbAllocatedBytes` (see "The profile
runner" above) — it exists to evidence those two fixes (the corrected
default succeeding unmodified, and the 6.3x apparent-vs-allocated gap) and
is not part of the 1M/10M scaling comparison above, which uses the original
matched-concurrency runs.

### 1M / 10M / 30M+ load profile

A real 1,000,000-entry run was executed against this same sandbox
(`--db-max-size-gb 4`) rather than relying on extrapolation from the 20K
number alone, and it is a good thing it was: **the load rate is not
constant with scale**. It dropped from 174.8 entries/s at 20K to 110.2
entries/s at 1M — a 37% slowdown — consistent with `slapadd`'s single
LMDB write transaction doing more B+tree page-split and rebalancing work
as the tree gets deeper, not a sandbox artifact (confirmed live via a
read-only `slapcat` peek into the still-running loader mid-benchmark,
using LMDB's MVCC readers-never-block-writers guarantee — count climbed
steadily with elapsed time, it wasn't stalled). Search latency degraded
similarly: p50 roughly doubled (104ms → 207ms) between 20K and 1M.

That means a naive linear extrapolation from the 20K rate understates 10M
and 30M+ durations under the non-`-q` path — the projection above (10M
~25h, 30M+ ~76h) was made before a real 10M run existed and used the 20K→1M
non-`-q` trend as its only evidence. It is now superseded for `-q`: #124
went on to actually run 10M under `scripts/bench-profile.sh`'s offline
`slapadd -q` path (see "Measured results" above), which is both the
faster, currently-recommended bulk-load path and a different code path
with its own scaling behavior, not a simple multiple of the non-`-q`
numbers above.

**30M+ projection, derived from the two real `-q` measurements (1M and
10M) instead of extrapolating from a single point:**

Fitting a power law (`time ≈ a · entries^k`) through the two measured `-q`
load times — 46.9s at 1M and 2,340.9s at 10M — gives `k ≈ 1.70` (load time
grows faster than linearly with entry count, consistent with the B+tree
page-split/rebalancing cost documented above). Projecting the same curve to
30M:

| | 1M (measured) | 10M (measured) | 30M (projected) |
|---|---|---|---|
| Load time | 46.9s | 2,340.9s (39.0min) | ~15,127s (~4.2h) |
| Load rate | 21,334.7 entries/s | 4,271.9 entries/s | ~1,983 entries/s |
| LDIF size | 217MB | 2.20GB | ~6.59GB (linear — LDIF size scales with entry count, not with the index effects that drive load time) |

**Assumptions and honest limits of this projection:**

- It assumes the same `k ≈ 1.70` degradation trend continues unchanged from
  10M to 30M. The doc's own prior projection (for the non-`-q` path) made
  the same kind of assumption and flagged it as "likely still optimistic,
  since the degradation trend has no reason to flatten" — the same caveat
  applies here: a two-point power-law fit is the best evidence available,
  not a guarantee the curve doesn't get steeper (or flatter) past 10M.
- **Disk sizing for a 30M run is the least certain part of this
  projection.** The 10M run above used an explicit, disk-budget-constrained
  `--db-max-size-gb 20` (~2.1KB/entry apparent) chosen to fit this shared
  VM's available disk, not derived from a sizing formula or known to be a
  tight bound — we don't know how close to full the map actually got.
  Scaling that configured value linearly to 30M gives ~60GiB as a rough
  reference point, but a separate, controlled 1M measurement in this same
  PR found the *apparent* configured size can be ~6.3x larger than the
  *actually allocated* disk (9.0GiB apparent vs. 1.4GiB allocated — see
  "The profile runner" above) — so real disk consumption at 30M could be
  meaningfully lower than 60GiB, or the ratio could shift at higher scale;
  this has not been measured at 30M and should not be assumed. Budget disk
  using `bench-profile.sh`'s own (now-corrected, still-conservative)
  `--db-max-size-gb` default formula as an upper bound if you cannot
  measure first, or run the 10M profile on your own target infrastructure
  and read its `dbAllocatedBytes` to calibrate a tighter number before
  attempting 30M.
- RAM: loader RSS at 10M peaked at ~2.75GiB inside a 6GiB cap (see
  "Measured results" above); nothing here predicts whether that stays
  roughly flat or grows measurably by 30M, since it wasn't tracked across
  more than one real data point.

Both the projected load time and the disk estimate are outside what this
shared sandbox's session budget can safely absorb in one run — this is
exactly the constraint the issue itself calls out for CI runners, playing
out here too, just at smaller scale than 30M would need on a GitHub-hosted
runner. 30M+ is left to be run directly against target hardware.

**Runbook: running 30M+ on your own infrastructure**

```bash
docker build -t ldapium:e2e -f image/Dockerfile image/

# Pick --db-max-size-gb from a real measurement on your own hardware if you
# can (run --entries 10000000 first and read dbAllocatedBytes from its
# JSON), not from the projection above — see the disk-sizing caveat.
./scripts/bench-profile.sh \
  --entries 30000000 \
  --out /path/to/persistent/results \
  --db-max-size-gb 80 \
  --timeout-seconds 43200 \
  --label "<your infrastructure, e.g. 'bare-metal, 16 vCPU / 64GiB, NVMe'>"
```

- `--timeout-seconds` time-boxes the load phase only: past it, the loader
  is killed and whatever the last progress sample showed is written as an
  honest partial result (entries loaded, elapsed, on-disk size) instead of
  running unbounded or being silently discarded — set it to whatever
  wall-clock budget your infrastructure/session actually has, padded above
  the projected ~4.2h above for margin.
- Use real target hardware, not a developer VM — 16+ vCPU, 64+ GiB RAM, and
  fast persistent (NVMe-class) storage with headroom well above whatever
  `--db-max-size-gb` you choose. Do not cap the container at `--cpus
  3 --memory 6g` the way this sandbox's measurements above did; that cap
  exists here specifically because this VM is shared with other concurrent
  workloads.
- `--keep-volumes` if you want to inspect the loaded data afterward (run
  `bench-search.sh`/`bench-replication.sh` against the same volumes) instead
  of the default one-shot cleanup.
- The tooling itself scales to 30M+ unchanged from 1M/10M — only wall-clock
  time, disk, and RAM requirements grow; nothing in `bench-profile.sh`'s
  logic is scale-limited below that.

## SLO judgment criteria

These are starting thresholds for judging a search-latency measurement, not
a guarantee this product meets them on every deployment — pick numbers that
match your own availability/latency requirements and re-measure against
them the same way:

| Percentile | Suggested threshold | Reasoning |
|---|---|---|
| p50 | ≤ 50ms | Typical single-indexed-attribute equality lookup, real client connection (not `docker exec`-wrapped) |
| p95 | ≤ 200ms | Allows for GC/compaction pauses and moderate concurrent load without masking a real regression |
| p99 | ≤ 500ms | Tail latency headroom for the slowest realistic query under contention |

A measurement against these thresholds should use a real persistent LDAP
connection (a load-testing tool, or a loop over one held connection), not
`bench-search.sh`'s `docker exec`-per-query numbers above — those already
include roughly a `docker exec` invocation's worth of fixed overhead, which
skews every percentile upward by a roughly constant amount and would produce
a false SLO failure on infrastructure that is actually fine. Use
`bench-search.sh` to compare scale/index configuration changes against each
other; use a real client for an actual SLO verdict.

## What this does not cover

- No production bare-metal or cloud-VM numbers — everything measured above
  ran in a sandboxed developer VM.
- Search latency is measured through `docker exec`, not a persistent client
  connection — see the caveat above.
- 10M entry load/search **has** been run in this sandbox under
  `scripts/bench-profile.sh`'s offline `slapadd -q` path (see "Measured
  results" above) with an explicit, disk-budget-constrained
  `--db-max-size-gb`, not the tool's own sizing formula — its disk
  sufficiency margin at that scale is unknown (see the "1M / 10M / 30M+
  load profile" section's disk-sizing caveat).
- 30M+ entry load/search has not been run anywhere in this repo's history;
  the "1M / 10M / 30M+ load profile" section's 30M projection is derived
  from the two real 1M/10M `-q` measurements, not from a real 30M run, and
  states its own assumptions and limits — treat it as a planning estimate,
  not a measurement, until it is actually run on target infrastructure
  using the runbook in that section.
- The identity-lifecycle-specific load profile (joiner/mover/leaver
  operations, as distinct from this document's raw LDAP write/search
  benchmarks) called out in issue #124's absorbed AC from #19 is addressed
  by `scripts/bench-lifecycle.sh` (see "Identity-lifecycle load profile"
  above) — but only at the scale actually run so far: local smoke runs
  (tens of thousands of identities) and the CI job's 200000-identity cap.
  No 1M+ identity-lifecycle run has been committed to
  `scripts/bench-results/` as of this writing; see that section for the
  scoping this leaves open, same as this document's own 30M+ raw-load
  caveat above.
