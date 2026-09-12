# Research Evidence

LDAPium follows the OpenForge Research Evidence Collection Standard:
https://github.com/dasomel/openforge/blob/main/docs/research-evidence.md

Collect machine-readable evidence during normal development when practical. Useful evidence includes unit/E2E duration/results, LDAP/auth/backup/restore/upgrade outcomes, runtime/performance measurements, failures/recovery/retries, and agent-assisted attempts/interventions/review corrections/CI retries/final verification. Preserve failed/partial runs and distinguish helper/unit evidence from live LDAP/container/browser evidence.

## Legacy evidence on discovery

During implementation, fixes, verification, backup/restore/upgrade work, releases, or documentation, catalog historical unit/E2E results, LDAP integration evidence, compatibility results, CI outputs, recovery records, performance measurements, and dated implementation evidence encountered from earlier work. Preserve originals and classify them rather than rewriting history.

Use `dasomel/openforge#89` as the portfolio-level legacy catalog source of truth. Record source/path, known date, evidence class/strength, environment scope, metrics/facts, limitations, and likely paper use. Never fabricate missing historical values; retain failures, partial results, and superseded-version evidence when useful longitudinally.

## Public-data rule

This is a personal OSS/test project. Test DNs/users that are synthetic, RFC1918 addresses, local LDAP/container/service names, local topology, and reproducibility-relevant environment details may remain when intentionally public test data.

Never publish actual passwords, password hashes, credentials/tokens/private keys, real personal directory data, or accidental personal data. Review future third-party/non-public artifacts separately. Validate structured evidence against the OpenForge schema and run secret/pattern checks before publication.