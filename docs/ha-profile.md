# High Availability Profile, Topology Decisions, and RPO/RTO SLA

This document establishes the binding High Availability (HA) topology profile,
disaster recovery architecture, formal RPO/RTO Service Level Agreements (SLAs),
and failover/health observability boundaries for ldapium.

---

## Binding Maintainer Decisions (D11–D13)

These decisions record binding project policy, established by the project
maintainers to resolve architectural scope questions regarding OpenLDAP HA:

### D11: Active-Standby is NOT a supported topology; the only supported HA profile is N-way multi-provider Active-Active.

- **Decision**: ldapium supports exactly two operational profiles: **Standalone**
  (`replicaCount: 1`, replication disabled) and **N-way multi-provider Active-Active**
  (`replicaCount > 1`, multi-provider syncrepl enabled). Active-Standby (single-writer
  with cold/warm standby replicas), Mirror Mode, and provider/consumer single-writer
  topologies are **NOT supported**.
- **Rationale**: Upstream OpenLDAP's `syncrepl` engine with `olcMultiProvider: TRUE`
  provides native multi-master write availability across all nodes. In contrast, an
  Active-Standby architecture with a single designated writer requires cluster-wide
  fencing (STONITH), split-brain prevention, and distributed leader election
  mechanisms to promote a standby when the primary fails. Upstream OpenLDAP does not
  ship these distributed coordination primitives. Per maintainer product boundary
  decision **D1** ([docs/product-boundary.md](product-boundary.md)), ldapium deliberately
  does not ship, and will not invent, a distributed consensus or fencing daemon
  (such as Raft, Paxos, or Corosync/Pacemaker).
- **Role Change Audit Stance**: Because all nodes in an N-way multi-provider mesh
  are peers of equal standing that accept both reads and writes, **there are no node
  roles (active vs. standby) and no role transitions**. Consequently, a "role change
  audit trail" is **not applicable** to ldapium. The equivalent operational integrity
  evidence is:
  1. **Replication conflict resolution observation (observable but not detected)**: Concurrent writes to the same entry
     resolve silently via OpenLDAP entryCSN timestamp arbitration (last-write-wins) without raising an error or
     generating a dedicated conflict audit record during normal syncrepl convergence (verified in
     `.github/workflows/replication-chaos-e2e.yml`). Discarded update CSNs are observable in raw accesslog records
     (`scripts/export-audit-log.sh`), but as documented in [docs/audit-event-schema.md](audit-event-schema.md)
     (`replication-conflict-raw`), raw discard records mix genuine conflicts with harmless duplicate deliveries over
     N-way relay paths and are not a conflict detector.
  2. **Replication chaos and convergence evidence**: Continuous verification of multi-node
     write acceptance, partition survival, silent conflict convergence, and post-healing agreement published by
     `.github/workflows/replication-chaos-e2e.yml`.

### D12: Formal RPO/RTO Reference SLA and Acceptance Verification

- **Decision**: ldapium specifies formal reference SLAs measured on standard reference
  infrastructure (Kubernetes / kind, 3 replicas, GitHub-hosted runner storage). Operators must
  treat these as baseline targets and re-measure on their own target infrastructure
  using the automated repository verification workflows.
- **Reference SLA Definitions**:
  - **RPO (Recovery Point Objective)**:
    - *Full-loss disaster recovery (catastrophic cluster/storage loss or logical deletion)*:
      **RPO = Configured Backup Interval**. In the Helm chart (`charts/ldapium/values.yaml`),
      the default backup schedule is `backup.schedule: "0 2 * * *"` (daily at 02:00 UTC),
      yielding an RPO of up to **24 hours**. Operators requiring tighter RPOs (e.g., 1 hour)
      must configure a tighter CronJob schedule. Point-in-time LDIF snapshots define the
      recovery boundary.
    - *Single-node loss under Active-Active*: **RPO ≈ replication lag, bounded but not
      measured in sub-second terms**. `.github/workflows/replication-chaos-e2e.yml` proves
      convergence, not lag magnitude: after a write, it polls each surviving provider's
      `contextCSN` over its `ldapi://` socket every 2 seconds (up to 60 iterations / 120
      seconds) until all providers agree, which shows replication *catches up* but does not
      time how far behind a peer fell while catching up. Unsynced writes on a suddenly
      destroyed node that never reached peers represent the upper bound. Operators who need
      an actual lag measurement under their own write load should alert on
      `LDAPiumReplicationLag` (`charts/ldapium/templates/prometheusrule.yaml`), which is
      sourced from the `openldap_replication_delta` metric and is the supported way to
      observe real replication lag in a running deployment.
  - **RTO (Recovery Time Objective)**:
    - *Full disaster recovery restore*: Reference measurement from run
      [#33817366039](https://github.com/dasomel/ldapium/actions/runs/33817366039) = **47 seconds** on GitHub-hosted kind
      (standard runner disk, no local SSD configured; measured end-to-end by `.github/workflows/backup-restore.yml` in the
      `3-node backup → bad delete → restore → resync` scenario, published in `dr-3node-evidence/rto.txt`).
      The workflow is the acceptance test; thresholds are the operator's. RTO is dominated by `slapadd` database rebuild
      and index generation, which scales with total entry and attribute index volume (see [docs/scale-benchmarks.md](scale-benchmarks.md)).
    - *Single-node failure under Active-Active*: Measured via continuous write probing (1-second `ldapmodify` writes to the
      Service endpoint) during pod deletion in `.github/workflows/replication-chaos-e2e.yml` (reusing the consecutive-failure
      measurement pattern from TLS rotation in `scripts/e2e-ldaps-probe.sh`). The chaos workflow proves that writes continue
      during pod deletion with a bounded consecutive failure run (typically 0–1s due to Kubernetes Service endpoint deregistration,
      rather than an unmeasured "0s" claim), followed by successful batch writes while degraded, and full multi-node convergence
      upon pod restart.
- **Acceptance Test Requirement**: Operators verifying SLA compliance must run the
  CI-equivalent scripts (`scripts/backup.sh`, `scripts/restore.sh`, and the chaos
  partition cases in `.github/workflows/replication-chaos-e2e.yml`) against their target
  storage class and hardware to establish their site-specific SLA baseline.

### D13: Cross-Site Disaster Recovery is Supported via Backup Shipping, NOT Cross-Site Replication

- **Decision**: Cross-site, cross-region, or multi-datacenter live replication over WAN
  is **NOT supported**. Supported cross-site Disaster Recovery (DR) is asynchronous
  **backup shipping and offline disaster recovery restore**.
- **Rationale**: OpenLDAP `syncrepl` in `refreshAndPersist` mode relies on persistent,
  low-latency TCP connections and rapid exchange of CSN state. Over WAN connections subject
  to variable latency, packet loss, or transient link failures, syncrepl connections
  frequently break and trigger expensive full refreshes or persistent divergence. Furthermore,
  CSN last-write-wins conflict resolution across multi-second WAN delays drastically increases
  the probability of silent data overwrites.
- **Cross-Site DR Operational Procedure**:
  1. **Automated Primary Backup**: The primary site runs the scheduled backup CronJob
     (`backup.enabled: true` in Helm) or host cron (`scripts/backup.sh -b <rootDN> -o /backups`),
     producing timestamped, compressed, and checksummed archives: `data-<timestamp>.ldif.gz`
     and `config-<timestamp>.ldif.gz`.
  2. **Asynchronous Archive Shipping**: An external log or object storage replication pipeline
     (e.g., AWS S3 Cross-Region Replication, Google Cloud Storage multi-region bucket, or
     secure rsync) continuously mirrors the backup PVC contents to the secondary disaster
     recovery site.
  3. **Disaster Declaration and Secondary Cluster Deployment**: Upon loss of the primary site,
     the operator deploys the ldapium Helm chart to the secondary Kubernetes cluster with
     `replicaCount: 0` (or scales the StatefulSet to 0 if pre-provisioned).
  4. **Offline Restore into Ordinal 0**: Follow the documented restore procedure in `charts/ldapium/README.md`:
     attach the backup archive and ordinal `-0`'s PVCs (`config-<fullname>-0` and `data-<fullname>-0`) to a throwaway
     debug pod (`kubectl run ldap-restore ...`), wipe target volumes, load `cn=config` with `slapadd -n 0` and data with
     `slapadd -n 1`, create the `.bootstrapped` marker, and fix permissions (`chown -R 999:999`). Ensure PVCs for
     ordinals 1..N-1 are deleted/empty so stale data cannot overwrite the restore.
  5. **Scale and Automatic Resync**: Bring up ordinal `-0` first (`replicaCount: 1`) and verify health via LDAP queries.
     Once verified, scale `replicaCount` to the target size (e.g. 3). Ordinals `-1` and `-2` bootstrap with clean storage
     and perform an initial syncrepl refresh directly from ordinal `-0` (since only serverID 1/ordinal 0 creates the base DIT),
     achieving full cluster convergence without quorum mechanisms.

---

## Failure Modes, Detection, and Recovery Matrix

The table below catalogs directory failure modes, their detection mechanisms, automated
or manual recovery actions, and whether the path is live-verified in repository CI or
an operational boundary.

| Failure Mode | Detection Mechanism | Automated / Operational Recovery | Verification Status |
|---|---|---|---|
| **Single provider pod crash / deletion** | Kubernetes pod startup/liveness/readiness exec probe failure (`ldapwhoami` over `ldapi://`); `up{service=...-metrics} == 0` on crashed pod; endpoint removed from Service. | StatefulSet automatically recreates pod; `syncrepl` automatically reconnects to peers and replicates changes missed during downtime. Writes continue without interruption on surviving pods. | **Verified** (`.github/workflows/replication-chaos-e2e.yml`: continuous write probe during pod deletion confirms bounded consecutive failure streak <= 5s; writes succeed while degraded; full convergence upon restart). |
| **Network partition (split-brain isolation)** | `LDAPiumReplicationLag` / `LDAPiumContextCSNDivergence` alerts; syncrepl connection timeout in slapd logs. | Each partition accepts local writes. Upon network healing, syncrepl exchanges CSNs; conflicting updates to identical entries resolve silently via timestamp last-write-wins without error records. Discarded update CSNs are observable in raw accesslog export (see [docs/audit-event-schema.md](audit-event-schema.md)). | **Verified** (`.github/workflows/replication-chaos-e2e.yml`: iptables DROP on FORWARD chain isolates node; writes accepted on both sides; full convergence and silent same-entry conflict resolution verified after unpartition). |
| **Single-provider storage corruption** | Pod fails startup with MDB initialization error; `CrashLoopBackOff`; exporter scrape failure. | Delete the corrupted PVC (`data-<fullname>-<ordinal>`); restart the pod. The pod starts with a clean empty PVC and performs an initial syncrepl refresh from peer providers to fully rebuild state. | **Verified** (`.github/workflows/replication-chaos-e2e.yml`: expansion from 1 to 3 pods proves empty PVCs hydrate cleanly via initial syncrepl refresh). |
| **Catastrophic cluster data loss / accidental deletion** | Applications report missing entries; empty search results; directory audit log records unintended mass delete operations. | Disaster recovery execution: scale StatefulSet to 0, wipe PVCs on ordinals 1..N-1, execute offline `slapadd` restore on ordinal `-0` via throwaway pod mounting PVCs, scale StatefulSet back to target replica count. | **Verified** (`.github/workflows/backup-restore.yml`: 3-node backup, mass delete, offline restore into `-0`, and resync completed in reference run #33817366039 in 47 seconds). |
| **Replication synchronization stall / contextCSN drift** | `LDAPiumReplicationLag` (warning at 30s lag) and `LDAPiumContextCSNDivergence` (critical at 300s divergence); Prometheus delta alerts fire with release label. | Investigate slapd replication logs for TLS certificate mismatch, DNS resolution failure, or disk exhaustion. Restarting the lagging pod triggers syncrepl reconnect and resynchronization. | **Verified** (Alert rules verified with synthetic fault injection in `tests/prometheus/alerts_test.yaml` via promtool; lag convergence verified in chaos E2E). |
| **Simultaneous multi-node power / node failure** | All pods unreachable; global LDAP service outage; Kubernetes node failures reported. | Nodes recover; Kubernetes restarts StatefulSet pods mounting existing PVCs. OpenLDAP MDB's copy-on-write architecture guarantees database consistency without journal replay; syncrepl resumes. | **Verified** (Underlying `back-mdb` crash tolerance verified across pod recreate cycles). |
| **TLS Certificate / CA expiration** | `LDAPiumTLSCertificateExpiringSoon` alert (if cert-manager metrics enabled); client TLS handshake errors. | Apply updated TLS secret to Kubernetes; execute rolling restart of the StatefulSet. For CA replacements, follow the two-step CA migration runbook to maintain replication trust. | **Verified** (`.github/workflows/e2e.yml:tls`: rolling certificate renewal and 2-step CA rotation verified with zero LDAPS downtime). |
| **Cross-site datacenter loss** | External health check failure; complete loss of primary cloud region or physical facility. | Declare disaster; invoke D13 offline restore procedure in secondary site using replicated backup archives. Update DNS/load-balancer records to point client applications to secondary site. | **Operational procedure** (Single-cluster DR restore verified in CI; cross-site WAN replication deliberately unsupported per D13). |

---

## Health, Readiness, and Failover Observability

Observability for High Availability in ldapium is implemented through a sidecar-free,
dependency-minimal architecture utilizing standard Kubernetes probes and the built-in
Prometheus metrics exporter (`hm-edu/openldap-exporter`).

### Kubernetes Health Probes

Every StatefulSet pod defines standard probes (`charts/ldapium/templates/statefulset.yaml`):
- **`startupProbe`**: Exec probe running `ldapwhoami -x -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi`
  over the local Unix domain socket (`periodSeconds: 5`, `failureThreshold: 60`). Accommodates database
  initialization, offline `slapadd`, and optional LDIF seeding on cold boot (up to 300s) before liveness and
  readiness probes take over.
- **`livenessProbe`**: Exec probe running `ldapwhoami -x -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi`
  over `ldapi://` (`periodSeconds: 10`, `timeoutSeconds: 5`, `failureThreshold: 3`). Verifies internal slapd
  operation execution without network stack overhead, restarting unresponsive or deadlocked processes.
- **`readinessProbe`**: Exec probe running `ldapwhoami -x -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi`
  over `ldapi://` (`periodSeconds: 10`, `timeoutSeconds: 5`, `failureThreshold: 3`). Ensures pods execute
  directory queries before receiving Service traffic, removing unready pods from endpoints.

### Prometheus Metrics and Replication Health

When `metrics.enabled: true` is configured, each pod runs the OpenLDAP exporter sidecar
on port 9330. For replicated deployments (`replicaCount > 1`), the exporter dynamically
configures peer monitoring flags (`--replication-object` and `--replication-server`),
scraping operational attributes from both local slapd and peer instances.

#### Metrics Exposed by the Exporter

1. **`openldap_replication_delta{replica="<peer-ldap-url>"}`**:
   Calculated by querying the local provider's `contextCSN` for its own server ID and
   comparing it against the peer's reported CSN for that same server ID:
   $$\Delta = t_{\text{local, serverId}} - t_{\text{peer, serverId}} \quad (\text{seconds})$$
   - $\Delta > 0$: The local provider has committed writes that have not yet reached the peer.
   - $\Delta \approx 0$: The peer is synchronized.
   - $\Delta < 0$: The peer reports a timestamp ahead of the local provider.
2. **`openldap_monitor_replication{id="<serverId>", type="gt|count|mod"}`**:
   Exposes the raw Unix timestamp (`type="gt"`), update counter (`type="count"`), and
   modification counter (`type="mod"`) parsed from the root entry's `contextCSN` attribute
   for each provider server ID.
3. **`openldap_dial{result="ok|fail"}`**:
   Tracks the total count of successful and failed TCP dial attempts by the exporter. Note that
   this metric is unlabelled by target (it has no peer identifier) and increments on any dial
   failure (including local slapd dials during scrape).
4. **`openldap_scrape{result="ok|fail"}`** and **`openldap_bind{result="ok|fail"}`**:
   Track overall search query health and administrative bind success against the directory.

#### Replication Alert Rules (`charts/ldapium/templates/prometheusrule.yaml`)

The chart provides production alert rules covering replication degradation, scoped by `service`
and labelled with `release`:

- **`LDAPiumReplicationLag`** (`severity: warning`):
  Fires when `max by (service, replica) (openldap_replication_delta{service="<fullname>-metrics"}) > 30`
  persists for 5 minutes. Indicates that a replication peer has fallen behind normal propagation latency.
- **`LDAPiumContextCSNDivergence`** (`severity: critical`):
  Fires when `max by (service, replica) (abs(openldap_replication_delta{service="<fullname>-metrics"})) > 300`
  persists for 5 minutes. Indicates severe multi-minute contextCSN desynchronization in either direction,
  signaling a stalled replication consumer or persistent divergence.

### Honest Boundary: What Cannot Be Exposed Without New Components

RFP and enterprise questionnaires frequently ask for "peer-down count", "election state",
or "automatic role failover metrics". The maintainer boundary on these items is explicit
and transparent:

1. **Election State Does Not Exist**: OpenLDAP multi-provider replication uses a master-master
   gossip/replication mesh with CSN timestamp arbitration. There is no Raft/Paxos leader,
   no active/standby election, and no term counter. Any metric purporting to report "election state"
   in OpenLDAP would be fictional.
2. **No Native OpenLDAP Peer Status Counters in `cn=Monitor`**: Upstream OpenLDAP's `back_monitor`
   database exposes thread, connection, and operation counters, but does not maintain an internal
   table or counter of connected syncrepl peers.
3. **No Per-Peer Dial Metric in Exporter**: The upstream `openldap_exporter` records all dial
   attempts into a single `openldap_dial{result="ok|fail"}` counter without peer target labels.
   Alerting on generic dial failures would falsely report local connection hiccups as peer
   unreachability. Therefore, no "peer unreachable" alert is shipped; peer connectivity and
   replication health are observed exclusively through `openldap_replication_delta`
   (`LDAPiumReplicationLag` and `LDAPiumContextCSNDivergence`), which keys on the peer replica identifier.
4. **Sidecar-Free Architecture**: ldapium extracts replication health exclusively from standard
   LDAPv3 operations (`contextCSN` attribute reads via `openldap_exporter`).
   Exposing synthetic cluster membership heartbeats or peer state machines would require
   introducing a dedicated cluster coordination daemon. Per **D1**, ldapium deliberately
   refrains from adding third-party cluster orchestrators.
