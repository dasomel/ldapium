# Research Evidence

LDAPium follows the OpenForge Research Evidence Collection Standard:
https://github.com/dasomel/openforge/blob/main/docs/research-evidence.md

Collect sanitized machine-readable evidence during normal development when practical. Useful evidence includes unit/E2E duration and results, LDAP/auth/backup/restore/upgrade outcomes, runtime/performance measurements where relevant, failures/recovery/retries, and agent-assisted attempts, elapsed time, human interventions, review corrections, CI retries, and final verification.

Preserve failed and partial runs and distinguish pure-helper/unit evidence from live LDAP/container/browser evidence.

## Public-data rule

Only sanitized records may be committed publicly. Never publish credentials, password hashes, directory contents containing personal data, private URLs/IPs/hostnames, customer/employer/tenant data, confidential prompts/source, raw LDAP output, arbitrary environment dumps, or security-sensitive infrastructure details. Raw access logs, LDIF, CI logs, screenshots, traces, and security output are sensitive-by-default.

Before public storage: validate against the OpenForge schema, run secret/pattern checks, review free-form fields, normalize environment labels, and publish aggregate/categorized measurements when raw artifacts cannot be proven safe.
