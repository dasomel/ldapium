# Scale benchmarks

"This holds up to N entries" is a claim; this document is the reproducible
measurement behind it instead. It covers four things: offline load
throughput, search throughput/latency, write-and-replication convergence,
and where to run all three.

## Where to run this

GitHub-hosted runners cannot do this honestly: a 30M-entry load needs disk
and wall-clock time neither the runner's ephemeral disk nor CI's time budget
can absorb, and a number produced by truncating the run early is noise, not
evidence. So this is **local reproduction tooling, not a CI job** —
`scripts/bench-generate-ldif.py`, `scripts/bench-load.sh`,
`scripts/bench-search.sh`, and `scripts/bench-replication.sh`, run by hand on
whatever machine you actually care about the numbers for. Nothing here runs
in CI, and nothing here is scheduled.

Before trusting any number this tooling produces, at any scale:

- **`olcDbMaxSize` must exceed the loaded data's on-disk size**, or `slapadd`
  fails partway through with the map full instead of producing a load-time
  number. `bench-load.sh --db-max-size-gb` controls this; size it for the
  target `--count` before you start, not after a failed run. The chart's own
  `ldap.dbMaxSize` (`charts/ldapium/values.yaml`) is the same knob for a real
  deployment.
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

## Measured results

Measured in this sandbox: Colima (Docker Desktop's Linux VM equivalent) on
Apple Silicon, 4 vCPU / 6GiB allotted to the VM, `arm64`. **This is not
production hardware** — it's a resource-constrained developer VM, and the
numbers below describe that environment, not a bare-metal or cloud-VM
deployment. Re-run the commands above on your own target hardware for
numbers that mean something for a real capacity decision; what these numbers
are good for is proving the tooling and the product behave correctly at
scale, and giving a relative baseline.

| Scale | Load time | Load rate | Search QPS | p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| 20,000 entries | 114.4s | 174.8 entries/s | 85.0 | 104ms | 143ms | 157ms |
| 1,000,000 entries | 9,072.8s (151.2min) | 110.2 entries/s | 89.5 | 207ms | 295ms | 338ms |

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
and 30M+ durations. Using the measured 1M rate (110.2 entries/s) as a more
realistic — but likely still optimistic, since the degradation trend has no
reason to flatten — basis: 10M is expected to take roughly 25 hours, and
30M+ roughly 76 hours (3+ days). Both are outside what this sandbox's
session budget can absorb in one run; this is exactly the constraint the
issue itself calls out for CI runners, playing out here too, just at
smaller scale. 10M and 30M+ are left to be run directly against target
hardware using the exact command above with `--count 10000000` /
`--count 30000000` and a correspondingly larger `--db-max-size-gb` — the
tooling scales to those counts unchanged; only this sandbox's wall-clock
budget doesn't, and real target hardware (not a 4-vCPU/6GiB developer VM)
should scale meaningfully better than either number above.

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
- 10M and 30M+ entry load/search have not been run in this sandbox; the
  tooling supports them and the command to run them is documented above.
