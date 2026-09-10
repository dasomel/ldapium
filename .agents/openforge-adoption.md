# OpenForge adoption

Follow the canonical OpenForge standards:
- https://github.com/dasomel/openforge/blob/main/docs/model-agnostic-agent-instructions.md
- https://github.com/dasomel/openforge/blob/main/docs/agent-engineering.md
- https://github.com/dasomel/openforge/blob/main/docs/user-centric-validation.md

Keep LDAP schema, auth/ACL, replication, audit, backup/restore, and container/runtime invariants local. Model/tool files are thin adapters. For LDAP-wire behavior, auth, backup/restore, upgrade, browser/UI, install/configuration, and destructive directory operations, use risk-proportional validation against a real LDAP/container path where mocks cannot prove behavior. Confirmed user-visible defects become regression evidence.

Safe local/disposable work within scope may proceed autonomously. Shared/production directory mutation, destructive external actions, release/publish, credential/permission widening, or unrelated external mutation requires explicit authorization unless already granted.
