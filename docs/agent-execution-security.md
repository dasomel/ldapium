# Agent Execution Security Profile

ldapium adopts the OpenForge Agent Execution Security Contract as a **reduced directory-control profile**.

ldapium is not a general-purpose AI agent runtime. Its relevant boundary is the path from authenticated/authorized API or operator intent to a concrete LDAP operation, followed by directory-side effects and audit/verification. The project must preserve LDAP, API, authentication, authorization, credential, and audit boundaries rather than add a parallel agent authorization system.

Reference contract: https://github.com/dasomel/openforge/blob/main/docs/agent-execution-security.md

## Profile mapping

| OpenForge concept | ldapium mapping |
|---|---|
| identity | authenticated user/service identity and directory bind identity |
| tool contract | explicit LDAP/API operation and versioned server/API behavior |
| resolved target | canonical directory endpoint + base/scope + normalized DN/entry target |
| resolved arguments | validated attributes/filter/change set after domain/service normalization |
| request-side authorization | application authorization + directory ACL/bind authority |
| execution boundary | backend LDAP client/service; never frontend-controlled raw directory execution |
| post-state verification | LDAP result plus follow-up state checks where operation semantics require them |
| evidence | application/directory audit events and operation result metadata without secret material |

## Risk classes

- **read** — bounded search/read/health/metrics operations.
- **mutation** — add/modify operations that change directory state.
- **destructive** — delete, restore-overwrite, schema/config replacement, or equivalent irreversible/high-blast-radius operations.
- **bulk** — any operation that expands one request into changes across multiple entries; treat at least as mutation and escalate to destructive when rollback/recovery is not bounded.
- **credential/privilege** — password, bind credential, ACL, role, admin, replication, or equivalent authority changes; always high risk.

## Required invariants

1. Resolve and validate the concrete LDAP operation before executing it; UI text or model-generated natural language is never authority.
2. Keep DNs, filters, attributes, and low-level LDAP details behind existing domain/service validation and escaping boundaries.
3. Never expose `userPassword`, bind secrets, private credentials, or equivalent sensitive values in execution evidence, logs, UI responses, or an agent context.
4. A future AI/interactive mutation interface must bind authorization/approval to the exact resolved operation and target, not to a generic "approved" flag.
5. Destructive, bulk, credential, and privilege-changing operations require an explicit product-level approval/recovery design before being exposed to an AI agent. Existing human/API behavior is not automatically an agent grant.
6. Audit evidence records what operation class and target were actually attempted and its result; it must not record secrets merely to make evidence more detailed.
7. Unit/helper tests do not prove LDAP-wire behavior. Claims about bind, ACL, replication, backup/restore, upgrade, or destructive directory effects require the existing live integration/E2E evidence class.
8. Tool/server output is untrusted input to any future model loop. LDAP values, error text, and imported directory content must not override system policy or expand authority.

## Adoption boundary

This profile is intentionally documentation-first. It does not widen API surface, LDAP privileges, Tauri/browser capabilities, or directory mutation behavior. A full OpenForge session-grant/invocation-grant/human-approval implementation becomes mandatory only if ldapium adds an autonomous or conversational execution path capable of directory mutation, destructive action, credential/privilege changes, or external side effects.
