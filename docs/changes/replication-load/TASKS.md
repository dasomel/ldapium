# Tasks: Three-node LDAP replication load validation

Link: [CHANGE.md](CHANGE.md)

## Inspect and establish evidence

- [x] `T-001` (`REQ-001`) Review existing write/convergence benchmark and replication chaos workflow.
- [x] `T-002` (`REQ-001`) Research Apache JMeter LDAP Extended sampler and CLI reporting.
- [x] `T-003` Review repository JMeter availability and local three-node demo ports.

## Implement

- [x] `T-010` (`REQ-001`) Add 3-node read-only JMeter plan and protected config runner.
- [x] `T-011` (`REQ-002`) Add local Make target and ignored report/config path.
- [x] `T-012` (`REQ-003`) Document tool choice and end-to-end stability evidence sequence.

## Verify

- [x] `T-020` (`AC-001`) Run a bounded profile against the local three-node demo.
- [x] `T-021` (`AC-001`) Check JMeter error/sample report and confirm the profile contains only bind/search/unbind operations.
- [x] `T-022` (`AC-002`) Validate shell, JMX and documentation diffs.

## Synchronize durable truth

- [x] `T-030` Update scale benchmark and local development documentation.
- [x] `T-031` Record measured result and environment in local ignored artifacts.

## Completion review

- [x] Requirements map to observed verification.
- [x] No production data or config was changed; the disposable local profile uses only bind/search/unbind.
- [x] Report the exact workload and any limits.
