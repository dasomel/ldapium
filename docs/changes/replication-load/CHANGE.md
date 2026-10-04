# Three-node LDAP replication load validation

- Change class: `B` (verification tooling only; no server topology or defaults change)
- Related issue: none
- Status: `Implemented and locally verified` — load path passed; capacity remains uncharacterized
- Accepted by / date: user request, 2026-10-01

## Problem

The repository already has a 3-provider bulk-write/convergence benchmark and a
replication chaos workflow. It does not offer a sustained concurrent LDAP
operation load across all three local demo nodes with portable latency/error
reports.

## Intent

Make it repeatable to measure LDAP read-operation behavior on each provider and
use existing repository evidence to assess write throughput, convergence, and
node/partition failure separately.

## Scope

- In scope: an Apache JMeter LDAP Extended read-load plan, a local runner,
  Make target, and documentation for combining it with existing replication
  benchmark/chaos paths.
- Affected users/systems: developers running the disposable three-node local
  LDAP demo or another explicitly configured LDAP endpoint.

## Non-goals

- No changes to N-way multi-provider semantics, production LDAP data, image,
  chart topology, dependency manifests, or CI toolchain.
- No claim that one load profile proves production capacity or correctness.

## Requirements

- `REQ-001` — Send sustained concurrent LDAP read searches to all three nodes
  using persistent per-thread LDAP sessions and return latency/error evidence.
- `REQ-002` — Keep test credentials out of the JMX plan and source control;
  default target addresses are local demo ports.
- `REQ-003` — Document a validation sequence that combines operation load,
  replicated-write convergence, and the existing failure/partition workflow.

## Acceptance scenarios

### `AC-001` — read load across three providers

- Covers: `REQ-001`, `REQ-002`
- Given a protected local JMeter properties file and three reachable LDAP
  providers
- When the runner starts its three-node JMeter plan
- Then it records LDAP sample results and an HTML summary for each node without
  modifying directory entries.

### `AC-002` — stability assessment

- Covers: `REQ-003`
- Given the JMeter baseline and existing replication benchmark/chaos workflow
- When an operator follows the documented validation sequence
- Then read performance, write convergence, and failure recovery have distinct
  evidence and are not conflated into one pass/fail claim.

## Architecture and decisions

- ADR/design links: [HA profile](../../ha-profile.md),
  [scale benchmarks](../../scale-benchmarks.md)
- ADR threshold result: `not required` — optional test tooling only; JMeter is
  not added as a build or runtime dependency.
- Alternatives: repository benchmarks remain authoritative for write
  convergence and fault behavior; JMeter adds the missing sustained concurrent
  LDAP operation load. The plan is read-only to avoid introducing cleanup and
  conflict risks into the stress workload.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | Optional shell runner and JMX plan |
| Dependencies / lockfiles | N/A — JMeter is an operator-installed optional tool |
| Runtime / toolchain | Java + JMeter required only to run this profile |
| CI / CD | N/A — avoid adding a heavyweight performance gate with host-sensitive thresholds |
| Release / packaging | N/A — no released artifact changes |
| Generated output | Local JTL/HTML report under ignored `.local/` |
| Security / supply chain | Password in ignored 0600 properties file; runner refuses broad file permissions |
| Offline / air-gap | JMeter can be preinstalled from verified Apache release artifacts |
| Documentation / operations | Load profile and complementary checks documented |
| Portfolio / downstream repositories | N/A |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | Parse/load JMX with Apache JMeter and run a bounded read-only profile | Three local demo containers | Per-node successful sample counts, errors, percentiles and report |
| `AC-002` | Review command/coverage links and existing workflow assertions | Local repository | Bench, chaos and JMeter scopes clearly separated |

Observed verification on 2026-10-01: JMeter 5.6.3, invoked through
`make ldap-replication-load LDAP_LOAD_THREADS=10 LDAP_LOAD_LOOPS=200`, against
healthy local demo providers at `127.0.0.1:1390-1392`. It completed 6,060
samples, including 2,000 searches per provider, with zero errors. Search
latency per provider was p50 0 ms, p95 1 ms, p99 1 ms, max 2 ms. A separate
LDAP search confirmed the same eight matching demo entries on each node. The
profile has only bind/search/unbind samplers, so the load run itself cannot
write directory entries. Raw JTL and HTML are in the ignored
`.local/ldap-load-results/20261001T130521Z/` directory. These results verify
the small demo path; they do not characterize large-dataset capacity, host
resource saturation, write availability under load, or failure recovery.

## Rollout, rollback and recovery

- Rollout: install JMeter locally, create a 0600 `.local` properties file, then
  invoke the Make target.
- Rollback trigger and procedure: remove the optional JMX/runner/docs; no server
  state is changed by the new load plan.
- Data/configuration recovery: N/A — the JMeter plan only binds and searches.
- Compatibility or migration obligations: N/A.

## Evidence and durable synchronization

- Evidence location/format: local JTL and generated HTML report under `.local/ldap-load-results/`.
- Tests or checks that become durable regression controls: JMeter smoke parse/run
  is recorded for the plan; repository benchmark/chaos checks remain separate.
- Documentation to update: scale benchmark guide and contributing local targets.
- ADR/evidence/portfolio records to update: none; D11–D13 remain unchanged.

## Review record

- Accepted scope/requirements: user asked for researched LDAP load testing to be
  applied to the current multi-provider profile.
- Material changes after acceptance and re-review: none.
- Open questions or blockers: JMeter is not installed by default; operator must
  provide it and a test bind account with read access to the target base.
