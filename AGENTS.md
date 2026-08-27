# AGENTS.md

ldapium follows the OpenForge context-efficient agent engineering model.

Read `README.md`, `CONTRIBUTING.md`, `RELEASING.md`, UI/backend architecture docs, and the relevant issue/spec before editing.

- Make the smallest coherent change that solves the requested problem.
- Do not auto-fix unrelated findings; report them separately.
- Preserve directory-service, API, UI, authentication, authorization, and audit boundaries.
- Treat exported API changes, LDAP schema/operation semantics, privilege/credential handling, destructive directory actions, and bulk operations as design changes.
- Keep DNs, identifiers, and low-level LDAP details behind the appropriate domain/service abstraction where possible.
- Let formatter/linter rules own deterministic style. Comments explain why, invariants, hazards, or compatibility constraints.
- For bugs, prefer: reproduce -> failing test/evidence -> minimal fix -> same test passes -> relevant regression suite.
- Use integration/E2E evidence for LDAP, auth, backup/restore, upgrade, and browser behavior when unit tests cannot prove the real path.
- Do not claim completion without stating which checks actually ran and their scope.
- End substantive work as A) complete/verified, B) meaningful verified progress with the next blocker isolated, or C) stop with evidence when further work requires unjustified scope, fragile patches, unsupported assumptions, or unacceptable risk.

Reference: https://github.com/dasomel/openforge/blob/main/docs/agent-engineering.md
