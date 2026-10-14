# 머신 bearer 인증 운영: 롤백, 긴급 차단, 호환성

대상: `MACHINE_AUTH_ENABLED=true`로 켠 배포의 운영자. 기능 설명은 [`api.md`](api.md) "머신 bearer 인증", Keycloak 쪽은
[`machine-keycloak-client.md`](machine-keycloak-client.md), LDAP 쪽은 [`machine-ldap-account.md`](machine-ldap-account.md), 설계는
[CHANGE.md](changes/machine-principal-auth/CHANGE.md)(D7, REQ-018, AC-019)입니다.

> 이 절차의 라이브 드릴(`scripts/test/test-machine-revocation-drill.py`, 실제 Keycloak·slapd, revision당 UI replica 2개, 이전 컨테이너 0개 확인, 같은 토큰 401, 진행 중 요청 정상 종료)은 CI job `machine bearer auth (real Keycloak)`에서 실행됩니다(TASKS T-027). replica는 docker 컨테이너이며 Helm/pod가 아니고 `terminationGracePeriodSeconds`는 `docker stop -t 15`로 대체했습니다.
> 아래 절차는 코드와 차트를 읽어 확인했고(근거를 각 항목에 적었습니다), 위 드릴이 docker replica에서 실행했습니다. Kubernetes 클러스터(Helm 롤아웃)에서는 한 번도 실행해 보지 않았습니다(후속 #284).

## 1. 핵심: 토큰은 기본적으로 즉시 폐기되지 않는다

**기능이 꺼져 있을 때(기본, `MACHINE_REVOCATION_ENABLED=false`)**: ldapium은 토큰을 저장하지 않고 요청마다 서명과 claim만 검증합니다(introspection 없음). 그러므로:

- **Keycloak client를 비활성화하거나 secret을 회전해도 이미 발급된 access token은 만료까지 검증을 통과합니다**(실제 Keycloak 26.7.4 관측,
  [EVIDENCE §2.7](changes/machine-principal-auth/EVIDENCE.md)). 막히는 것은 **새 토큰 발급**뿐입니다.
- 서버 쪽 조치를 하지 않았을 때의 최대 노출은 **남은 토큰 수명 + `MACHINE_CLOCK_SKEW`**(기본 10분 상한 + 30초 이내)입니다.
- 따라서 긴급 차단의 1차 수단은 **ldapium의 설정을 바꿔 모든 replica를 교체**하는 것이고, Keycloak 조치는 그 다음의 보조 수단입니다.

**기능이 켜져 있을 때(`MACHINE_REVOCATION_ENABLED=true`, 아래 "LDAP revocation writer" 절 준비 후)**: 검증을 통과한 토큰은 LDAP 폐기 스냅샷으로 한 번 더 검사되어, 폐기 항목을 기록하면 롤아웃 없이 모든 replica에서 401이 됩니다. 단 상한은 아래 절의 조건부 수식이 성립할 때만 유효하고, 스냅샷이 없거나 오래되면 인증된 요청은 503으로 닫힙니다. 설정 변경 + replica 교체(2절)는 이 경우에도 **백스톱**으로 유지합니다.

## 2. 긴급 차단 (토큰 유출·오용 의심)

순서를 지킵니다. 앞 단계가 끝나기 전에 3단계만 하면 이미 발급된 토큰은 그대로 쓸 수 있습니다.

**1) 서버에서 차단**: 아래 둘 중 하나로 설정을 바꿔 배포합니다. v1은 설정을 다시 읽지 않으므로(리로드 없음) **재배포(롤아웃)만이 반영 수단**입니다.

- 특정 client만: `MACHINE_ALLOWED_CLIENTS`(Helm `ui.machineAuth.allowedClients`)에서 그 client를 뺍니다. 그 client의 토큰은 401(`azp`가 목록 밖)이 됩니다. 목록이 비면 기동이 실패하므로 마지막 client를 빼려면 2번 방법을 씁니다.
- 기능 전체: `MACHINE_AUTH_ENABLED=false`(Helm `ui.machineAuth.enabled=false`). `Authorization`은 무시되고 쿠키 없는 요청은 기존 401 `unauthenticated`가 됩니다.

```bash
# Helm 예: client 하나를 빼거나 기능을 끈다 (values 파일을 고쳐 적용)
helm upgrade <release> ./charts/ldapium -n <ns> -f values.yaml          # allowedClients에서 제거
helm upgrade <release> ./charts/ldapium -n <ns> -f values.yaml --set ui.machineAuth.enabled=false
```

**2) 모든 replica가 교체됐는지 확인** — 롤아웃 도중에는 일부 pod가 아직 옛 설정으로 bearer를 받습니다.

```bash
D=<release>-ldapium-ui        # 차트의 UI Deployment 이름(ldapium.ui.fullname). 확인: kubectl get deploy -n <ns> -l app.kubernetes.io/component=ui
kubectl rollout status deploy/$D -n <ns>
# 이전 revision의 pod가 하나도 남지 않았는지: 모든 pod의 이미지/설정 세대가 새 것이어야 한다
kubectl get pods -n <ns> -l app.kubernetes.io/component=ui -o wide
kubectl get rs -n <ns> -l app.kubernetes.io/component=ui     # 이전 ReplicaSet의 READY/DESIRED가 0
```

그리고 **진행 중이던 요청이 끝났는지**: 차트는 기능이 켜져 있는 동안 `terminationGracePeriodSeconds`를 `max(30, 요청 timeout+15)`초로 둡니다
(`templates/ui-deployment.yaml`). 서버의 graceful shutdown 대기는 설정에서 유도됩니다(`ui/backend/cmd/server/shutdown.go`):
머신 인증이 꺼져 있으면 10초, 켜져 있으면 `max(10초, 인증 단계 10초+MACHINE_REQUEST_TIMEOUT+5초)`이며 상한은 315초(timeout 최대 5분+15초)입니다.
차트의 `terminationGracePeriodSeconds`(`max(30, 요청 timeout+15)`)는 항상 이 값 이상이라 진행 중 요청은 자기 deadline까지 끝날 수 있습니다.
차트 없이 직접 배포한다면 오케스트레이터의 종료 유예 시간을 `MACHINE_REQUEST_TIMEOUT+15초` 이상으로 직접 맞추세요(미만이면 유예 시간 도달 시 SIGKILL로 요청이 끊깁니다).
종료 시 로그 `shutting down, waiting up to <grace> for in-flight requests`로 적용된 값을 확인할 수 있습니다.

**3) 같은 토큰으로 확인**: 차단 대상 client의 (유출된 것으로 보이는) 토큰이 아닌, 같은 client로 **차단 전에 받아 둔 테스트 토큰**을 보냅니다.

```bash
# $HDR: "Authorization: Bearer <token>" 한 줄이 든 0600 파일 (docs/api.md 예). 토큰을 인자에 쓰지 않는다(ps에 보임)
curl -sS -o /dev/null -w '%{http_code}\n' -H @"$HDR" https://ldapium.example.com/api/users
# client 제거: 401 (code token_invalid), 기능 끔: 401 (code unauthenticated)
```

**4) 그 다음 Keycloak**: client 비활성화 또는 secret 회전으로 새 토큰 발급을 막습니다. secret 유출이 원인이면 회전합니다. 이 단계만으로는 기존 토큰이 죽지 않습니다(1절).

**5) 감사 확인**: 차단 시각 이후 해당 client의 `event=machine_access` 줄에 `result=success`가 없는지 로그로 확인합니다
([`audit-event-schema.md`](audit-event-schema.md)). 단 핸들러 이전에 Go HTTP 서버가 거절한 요청은 이 줄이 없습니다(D25, 같은 문서). 접근 기록이 필요하면 ingress/프록시 접근 로그가 있어야 합니다.

추가로 LDAP 쪽을 막으려면(선택): 머신 계정을 잠그거나 삭제하고, ACL을 롤백합니다 — [`machine-ldap-account.md`](machine-ldap-account.md) 롤백 절. 롤백하면 그 계정은 일반 사용자 권한으로 돌아가므로 **먼저 `MACHINE_AUTH_ENABLED=false`로 전 replica를 교체**한 뒤에 합니다.

## 3. 롤백 (기능 정지, 코드 롤백 없음)

예기치 않은 401/403 오분류, 권한 노출 의심, JWKS 장애 파급이면 `MACHINE_AUTH_ENABLED=false`로 재배포하고 2절의 2)·3)과 같이 **모든 replica 교체와 이전 pod 0개**를 확인합니다.

- 영속 데이터가 없습니다(토큰·키를 저장하지 않음). 되돌릴 상태는 설정뿐입니다.
- 끄면 `Authorization`은 완전히 무시되고, 기존 쿠키 경로·응답·OpenAPI의 기존 오퍼레이션 의미는 그대로입니다(기본 꺼짐 상태와 같음).
- 머신 LDAP 계정과 ACL은 남습니다. 필요하면 `machine-ldap-account.md`의 롤백으로 지웁니다(끈 뒤에).

## 4. 호환성

- **기본 꺼짐**: `MACHINE_AUTH_ENABLED`를 켜지 않으면 어떤 `MACHINE_*`도 읽지 않으며 요청·응답·라우트가 달라지지 않습니다. Helm 기본 `ui.machineAuth.enabled=false`는 렌더 결과가 기능 추가 이전과 바이트 동일입니다(TASKS T-016).
- **OpenAPI는 additive**: `securitySchemes.machineBearer`와 허용 8개 오퍼레이션의 `security`(`cookieAuth` 유지)·`x-machine-scope`만 추가됐고, 기존 오퍼레이션의 기존 인증(`cookieAuth`)·경로·응답은 그대로입니다. 전역 기본 `security`는 `cookieAuth`입니다.
- **오류 코드는 append-only**: 새 코드 `token_invalid`, `token_expired`, `scope_denied`, `machine_rate_limited`가 닫힌 집합에 추가됐습니다(모르는 코드는 상태 코드로 처리하라는 기존 계약 그대로).
- **쓰기·비밀번호·백업·프로파일·`entry/move`·`getMe`는 어떤 경우에도 머신으로 호출할 수 없습니다**(403 `scope_denied`).
- 기능을 켜면 새로 생기는 요구: `UI_TRUSTED_PROXIES`를 `private`(기본) 대신 CIDR 목록 또는 `none`으로, 머신 전용 LDAP 계정과 ACL, 모든 LDAP 노드에서의 ACL 적용, issuer/JWKS 도달성(에어갭은 [`air-gap.md`](air-gap.md)).

## 5. 켜기 전 점검

1. 모든 LDAP 노드에 머신 ACL이 적용되고 규칙 순서가 `{0}`–`{2}`임을 읽어 확인([`machine-ldap-account.md`](machine-ldap-account.md)). `LDAP_REPLICATION_IDENTITY=prepare`와는 함께 쓰지 않음(D30).
2. Keycloak client가 [`machine-keycloak-client.md`](machine-keycloak-client.md) 요건을 충족(특히 audience mapper, lightweight Off).
3. ingress가 클라이언트가 보낸 `X-Forwarded-For`를 덮어쓰거나 정리하고, `UI_TRUSTED_PROXIES`가 그 ingress의 CIDR(또는 `none`)이며, **ingress/프록시 접근 로그가 켜져 있음**(핸들러 이전 거절은 ldapium 로그에 없음).
   - kind 클러스터의 ingress-nginx에서 실측(`scripts/test/test-chart-machine-auth-kind.sh`): 컨트롤러 ConfigMap에 `use-forwarded-headers: "true"`를 켜고 `proxy-real-ip-cidr`를 제한하지 않으면(기본 0.0.0.0/0) 클라이언트가 보낸 위조 `X-Forwarded-For`가 그대로 신뢰되어 IP 실패 throttle이 우회됩니다(위조값마다 새 IP, 10회 모두 401, 429 없음). `proxy-real-ip-cidr`를 실제 상위 프록시 대역으로 제한하면 예산이 유지됩니다. 기본 설정(`use-forwarded-headers` 꺼짐)은 헤더를 덮어써 안전합니다.
4. limiter는 replica별 상태입니다(전역 한도가 아님). replica 수만큼 한도가 늘어납니다. 공유 한도는 도입하지 않는 것으로 제안되어 있습니다([D14](changes/machine-token-revocation/FOLLOWUP-DECISIONS.md), 수용 대기).

## LDAP revocation writer (#286 T-013)

The operator tool is the only supported writer of `ou=revocations`. A recorded entry
invalidates a token only on replicas running with `MACHINE_REVOCATION_ENABLED=true`
(Helm `ui.machineAuth.revocation.enabled`, default off); with the feature off, entries are
ignored. The allowlist removal and replica replacement procedure (section 2) remains the backstop.

Run `scripts/machine-revocation.sh` on an operator host with Python 3 and the
OpenLDAP CLI (`ldapsearch`, `ldapadd`, `ldapmodify`, `ldapdelete`). Use verified
`ldaps://` and the normal LDAP client CA configuration. The password is read
through `--password-file`, never an argument. `--container NAME` runs the LDAP
commands inside a local container; the password-file path then belongs to that
container. It does not copy the credential to the host. The writer binds as an
operator/admin identity; the API machine identity remains read-only.

Create `ou=revocations,ou=system,<root>` as an `organizationalUnit` with a single
`ou: revocations`. Run `init` once before enabling the future API consumer:

```sh
scripts/machine-revocation.sh init --uri ldaps://ldap.example.org:636 \
  --base 'ou=revocations,ou=system,dc=example,dc=org' \
  --bind-dn 'cn=admin,dc=example,dc=org' --password-file /run/secrets/admin
```

Every mutating command takes those same connection arguments. `init` refuses an
existing sentinel or any entries; it never resets a generation. `add --kind jti
--client CLIENT --id-file FILE` reads only the jti identifier from a file (no
newline, no NUL, no JWT). `add --kind cutoff --client CLIENT` adds a new immutable
cutoff before removing that client's old cutoffs. The directory supplies its
`createTimestamp`; operators must not replace it. `remove --cn CN` explicitly
undoes one revocation, so use it only when reaccepting that token/client is
intended; removing the sentinel is refused. A failed command may already have
written entries: repair malformed entries, then run `heartbeat` to republish.
Do not restore an old sentinel as a rollback: it can reenable revoked tokens and
its generation may be rejected by a running consumer.

`heartbeat` and `prune` remove jti entries older than the retention period and
publish a new sentinel. `add` also prunes. Cutoffs are never pruned automatically.
`retention` prints the minimum (4440 seconds); `--retention` can increase it up to
86400 seconds and never decreases a previously published value. Every mutation
checks all descendants without a device-only filter: stray, nested, malformed,
multi-valued cn/ou and newline/NUL values block writes. More than 80% of
`--max-entries` (default 2000, range 1–2500) emits a warning. Reaching the cap
refuses a new entry; reduce the load before enabling the consumer. Failed LDAP
commands and partial results are errors. Sentinel generation/count/digest/time/
retention are changed atomically by deleting the exact old attribute values and
adding the new values. rc 16 means another writer won; the tool rereads,
recalculates and retries at most eight times. Exhaustion exits nonzero.

Schedule `heartbeat` at no more than one third of `SENTINEL_MAX_AGE`
(`MACHINE_REVOCATION_SENTINEL_MAX_AGE`, default 300 s, range 30 s to 1 h), e.g. every
minute for the default, and alert on nonzero status. Each run prunes expired jti entries and
republishes the sentinel, so a quiet deployment whose entries age past the retention period
keeps a fresh sentinel. If heartbeats stop, authenticated machine requests answer 503 after
about `SENTINEL_MAX_AGE + MAX_STALE` (default about 5 m 15 s); that is intended fail-closed
behavior, not a bug. A
CronJob uses an operator tools image containing Python 3, the OpenLDAP CLI, and
both `scripts/machine-revocation.sh` and `scripts/lib/machine_revocation.py`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: machine-revocation-heartbeat
spec:
  schedule: '* * * * *'
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: heartbeat
              image: YOUR_PINNED_OPERATOR_TOOLS_IMAGE
              command: ['/opt/ldapium/scripts/machine-revocation.sh']
              args: ['heartbeat', '--uri', 'ldaps://ldap.example.org:636',
                     '--base', 'ou=revocations,ou=system,dc=example,dc=org',
                     '--bind-dn', 'cn=admin,dc=example,dc=org',
                     '--password-file', '/run/secrets/admin']
              volumeMounts:
                - {name: credential, mountPath: /run/secrets, readOnly: true}
          volumes:
            - name: credential
              secret:
                secretName: machine-revocation-operator
                defaultMode: 0400
```

Supply trusted CA configuration and mount permissions for the image's operator
UID. This example is not installed by Helm; the stock LDAPium image has no Python
writer runtime. The credential comes from a Secret file (`--password-file`), never from
argv or an environment variable, and `defaultMode: 0400` must be readable by that UID.
It carries an admin credential, so restrict access to the Job and its Secret.
Monitor the heartbeat and directory capacity before API rollout. `concurrencyPolicy:
Forbid` avoids overlapping runs; a rare overlap with an operator command loses the
sentinel compare-and-set (rc 16) and is retried by the tool.

For a client incident: (1) block issuance at the IdP and **confirm** new
`client_credentials` requests fail, repeating the check across the IdP nodes;
(2) write a cutoff (or known jti); (3) after the consumer ships, confirm the same
previously issued token returns 401 on every API replica; (4) apply the allowlist
and replica replacement backstop. Under healthy replication, synchronized clocks
(NTP), successful refreshes and the configured query budgets, the planned
visibility bound is `REFRESH + 2 × 5s + replication delay`. This is a conditional
bound, not a measured guarantee for an arbitrary cluster. `REFRESH` is
`MACHINE_REVOCATION_REFRESH` (default 5 s) and 5 s is the per-refresh query budget; while
refreshes fail the bound becomes `max(that value, MAX_STALE)`, measured from the
query start. The premises are P1 (the heartbeat runs on schedule) and P2 (every replica
reads one stable LDAP node, or read-your-writes holds, and replication delay is shorter
than `SENTINEL_MAX_AGE`). If P1 or P2 breaks the bound does not hold; a lagging node shows
up as fail closed within `SENTINEL_MAX_AGE`. Round-robin LDAP URLs break P2 and may make
503 flicker. A partitioned LDAP node may serve old data until sentinel aging forces
unavailability.

Clocks: cutoff time T is the directory server's `createTimestamp`, and a token is revoked
when `iat <= T + MACHINE_CLOCK_SKEW`. This assumes NTP-synchronized IdP, directory and
API clocks; skew beyond `MACHINE_CLOCK_SKEW` can let a token issued after T pass. Normal
tokens issued within `T` to `T + skew` are over-revoked (fail closed) and a fresh token
fixes that.

Remaining windows (D7): (i) issuance blocking may not have propagated to every IdP
node when you confirm step (1), so repeat the confirmation at least twice; (ii) IdP-to-
directory skew beyond `MACHINE_CLOCK_SKEW`. Use known-jti revocation and the backstop
together if those windows are unacceptable. Issuing a cutoff before issuance is blocked
lets the client fetch a new token whose `iat` is later than T, which then passes.

Rollback caveat: setting `MACHINE_REVOCATION_ENABLED=false` ignores all entries, so
**every earlier revocation is lifted** and those tokens are accepted again until they
expire; combine with the allowlist backstop when rolling back during an incident. It also
turns off the API guard on `ou=revocations` (`revocationWriteGuard` returns nil when the
feature is off), so administrator writes through the UI API into that subtree are permitted
again. Deciding not to keep the guard on when the feature is off (D-363c): the protected DN comes from `MACHINE_REVOCATION_*`, which is deliberately not read while disabled, and a default-path guard would change administrator write behavior for every deployment. Do not let the UI API write there; keep using this tool only, and re-run `heartbeat`
before re-enabling so the sentinel is fresh and any stray entry is found.

### Write identity configuration stage (machine-write-scope T-011)

`MACHINE_WRITE_ENABLED` stays off by default. Enabling it requires machine authentication, `UI_IDEMPOTENCY_ENABLED=true`, and both `MACHINE_WRITE_DATA_BIND_DN` and `MACHINE_WRITE_DATA_BIND_PASSWORD`. `MACHINE_WRITE_LOCK_ENABLED` defaults to false; when enabled it additionally requires `MACHINE_WRITE_LOCK_BIND_DN` and `MACHINE_WRITE_LOCK_BIND_PASSWORD`. Bind passwords follow the existing Secret injection convention and never appear in validation diagnostics. The data and lock identities must differ from one another, the read identity, administrators, service accounts, root DNs and the fixed replication identity. Non-canonical naming types (including schema aliases and numeric OIDs), non-ASCII values and ambiguous whitespace in either write or protected identity DNs are refused: the startup check must prove separation on both sides of the comparison.

While the write switch is off, subordinate write variables are not read. While the lock switch is off, its DN/password variables are not read. Since T-013 the operation table holds the five first-ship operations (see "Machine write emergency block" below); configured identities never change the read execution identity. Opened write scopes in a client ceiling parse and grant nothing while the switch is off; other write scopes (lock, group create/update/delete, password) are refused at start-up. Enabling the switch refuses itself: it also needs at least one `MACHINE_WRITE_SUBTREES` client whose `MACHINE_ALLOWED_CLIENTS` ceiling names an opened write scope, the write limits and the machine access audit, otherwise the server does not start. Credential/password writes have no configuration in this stage; the accepted Q1 decision requires separate approval. No Helm values or LDAP ACLs are installed by this change.

### Revocation source implementation stage (T-014)

With `MACHINE_REVOCATION_ENABLED=true`, the source refreshes using the machine LDAP identity. Its readiness is observable on the private metrics listener as `ldapium_ui_machine_revocation_ready`; `ldapium_ui_machine_revocation_refresh_total{result="success"|"failure"}` counts refresh outcomes. No series is emitted when disabled. A failed refresh retains the last complete snapshot until its query-start age exceeds `MAX_STALE`. Invalid machine credentials back off from 60 seconds (a fixed floor, so the shared machine DN is never retried faster and the default ppolicy lockout of 5 failures stays out of reach of the refresher) doubling to a 4 minute cap, so after the password is fixed the 503s last at most about 4 minutes; a successful refresh resets the backoff. There is no faster retry on purpose: restarting the pod forces an immediate attempt. LDAP diagnostics and identifiers are omitted from refresh error logs.

`audit.read` and revocation (D-363b): `listAuditActions` and the `recentLogs` of `getMonitor` drop accesslog events whose `reqDN` is inside the revocation subtree (is empty, or cannot be parsed canonically) for machine callers and blank the logged filter of the rest, so the revoked ids and cutoffs written by the tool are not readable through the machine path. Administrator sessions still see them. A page can therefore hold fewer events than `limit`; this applies only while `MACHINE_REVOCATION_ENABLED=true`.

When revocation is enabled, every verified bearer token needs a nonempty JTI and is checked before the client budget or LDAP execution. A revoked token returns 401; an absent or stale snapshot returns 503 with Retry-After: 1. Invalid tokens cannot probe snapshot readiness. Machine entry/tree reads and API writes by human administrators refuse the protected revocation subtree, including DN naming aliases and moves of an ancestor. The full multi-replica live drill remains required before production acceptance. The 1 MiB guard bounds retained decoded search data; one oversized entry can be allocated by the LDAP decoder before the guard runs. A refresh uses one connection to one node; round-robin URLs can still alternate snapshots between refreshes, so production replica/partition acceptance remains required.


### Machine write target-type prerequisite (T-018)

The LDAP layer can attach an atomic `entryCSN AND objectClass` assertion to marked machine write contexts. Wrong user/group target types are refused by slapd, including when the supplied revision is current. Protected-DN identity comparison and member-type prechecks must also land before opening; those reads have a documented read/write race and do not replace atomic target assertions.

## Machine write emergency block (machine-write-scope T-022, REQ-012, AC-011, D12, D24)

Machine writes are open for the five first-ship operations in every build since T-013, but act only with `MACHINE_WRITE_ENABLED=true` (default off; a server without the switch answers every write 403 `scope_denied`). The earlier drill-only image (Go build tag `machinewritedrill`) is retired. The measurements below were taken on that tag build (T-022); the drill now runs unchanged against the normal image. Everything below was
measured by `scripts/test/test-machine-write-drill.py` with a real Keycloak and slapd, two UI replicas, the `W_data`/`W_lock` accounts and the write ACL fragments of
[machine-write-account.md](machine-write-account.md). Numbers are from that docker setup, not from a Kubernetes rollout (not run). Raw output:
[EVIDENCE-drill.md](changes/machine-write-scope/EVIDENCE-drill.md). Only measured values are quoted; the unmeasured items are listed at the end.

### Which lever, how fast

| Lever | Effect on writes | Reads | Measured |
|---|---|---|---|
| **1. Rotate the `W_data` LDAP password** (admin `replace: userPassword`; the Secret still holds the old value) | the **next** write on **every** replica is 503 (`reason=bind_failed`, `code=unavailable`), no directory change | 200, unchanged (`M` is a different identity) | first request after the modify returned: 503 on both replicas at +17 ms / +31 ms; four refused writes = exactly four failed `W_data` binds at slapd |
| **2. Write-only redeploy** (`MACHINE_WRITE_ENABLED=false`, everything else unchanged) | 403 `scope_denied` (operation not permitted for machine clients) | 200 | the first request on each new replica was already 403 (two replicas replaced one after the other in 0.8 s in docker; replicas that are not yet replaced keep writing until they are) |
| `pwdAccountLockedTime` set by an operator on `W_data` | 503, same as lever 1 | 200 | only with the default policy or a lockout policy; ignored under a `pwdLockout: FALSE` policy (see below) |

Lever 1 is the faster one because every write request binds `W_data` itself (no connection is reused across requests: after a write the number of open LDAP connections is 0),
so there is nothing to roll out. `W_lock` is not used by the five first-ship operations: rotating it left `createUser` at 201.

Procedure:

1. Rotate: `printf 'dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n' "$WDATA_DN" "$NEW" | docker exec -i <ldap> ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin`
   (use a file or stdin for the value, never argv). Confirm: a write returns 503 and the `machine_access` line shows `reason":"bind_failed"` with `outcome":"rejected"`.
2. Keep reads running; they are unaffected. Do **not** put the new password in the Secret yet.
3. Investigate, then either restore (step 4) or change the allow-list/scopes with a write-only redeploy (lever 2) and put the new password in the Secret with the rollout.
4. Restore: set the password back to the value in the Secret (or roll out the Secret with the new one). The very next write succeeds on every replica (measured +30 ms), with the **same token** and even the
   **same `Idempotency-Key`s** that got the 503: a refusal before the write releases the key, it is not recorded as an outcome.
5. Check `(pwdAccountLockedTime=*)` for the writer (next section) before declaring the block over.

### The write-identity lockout trap (D24, measured)

With the image's default policy (`pwdLockout TRUE`, `pwdMaxFailure 5`, `pwdLockoutDuration 900`):

- 5 wrong-password binds lock `W_data`. Each write the UI refuses after a rotation is one more failed bind, so a rotation plus **5 writes** locks the account by itself (the lock appeared at the 5th refused write).
  While locked, the correct password also fails: writes 503, reads 200, `M` binds normally; further refused writes do not extend the lock.
- Restoring by an admin password reset also cleared the lock (next write 201). Without a reset, `delete: pwdAccountLockedTime` unlocks; `pwdFailureTime` cannot be deleted (constraint violation 19).
- Anyone who can reach LDAP can cause the lock with wrong binds: it is a write outage, never a read outage.
- **Mitigation**: a dedicated policy for the `W_*` accounts with `pwdLockout: FALSE` and **no** `pwdMaxFailure` (LDIF in machine-write-account.md 9.1). Measured: 25 wrong binds neither lock nor mark the account;
  the rotation block still works (8 refused writes, no lock) and restoring recovers the next write. With only the flag flipped and `pwdMaxFailure 5` kept, the attribute is still set after 25 failures (writes work) and alerts on it are false positives.
  The cost: an operator-set `pwdAccountLockedTime` is then ignored (measured), so the block is the rotation or lever 2. Alternative that keeps the lock: `pwdLockoutDuration` short (3 failures / 8 s: recovered by itself 7.7 s after the lock).
- **Alerting** (both queries verified live): `(&(objectClass=inetOrgPerson)(pwdAccountLockedTime=*))` under `ou=system`, and the accesslog failures
  `(&(reqType=bind)(reqDN=<W_data>)(reqResult=49))`. Application side: 503 on writes with `reason=bind_failed` and reads still 200.

### Limits (what the block does not do)

- **Issued tokens are not revoked.** After lever 1 or 2 the same pre-event token still verifies: writes fail (503 / 403) and reads stay 200; after the restore it writes again. Its remaining lifetime is bounded by
  `MACHINE_TOKEN_MAX_TTL` (default 10 min) + `MACHINE_CLOCK_SKEW`. Enabling the #286 revocation snapshot (`MACHINE_REVOCATION_ENABLED=true`) is **recommended** for write use to shorten that window; it is not a start-up requirement (Q9).
- **A write already in flight can complete.** A write whose operation reached its already-bound `W_data` connection before the rotation completed after it: 201, entry applied (measured with the operation held at the
  LDAP connection for 1.3 s while the password was rotated; it completed 0.05 s after being released). Slapd checks the bound DN, not the password, for that connection.
- **How long an in-flight write can run is the request timeout, `MACHINE_REQUEST_TIMEOUT`** (default 10 s). A write stalled at the LDAP connection ended after exactly 10.0 s (the UI closed the connection itself), and
  after 4.0 s with `MACHINE_REQUEST_TIMEOUT=4s`; with a rotation 2.3 s into the request it ended 7.7 s after the rotation. The result is 409 (`the result of this request could not be determined`): the outcome is unknown
  (it may have been applied by a real, un-partitioned directory), a retry with the same key is 409 as well, so read the resource before retrying. The window after a rotation is therefore **at most the
  configured `MACHINE_REQUEST_TIMEOUT` for a request that was already bound** (measured at 10 s and 4 s only); a request that has not yet bound uses the old password and gets 503.
- **Idempotent replays are served without a directory write.** While `W_data` was rotated, replaying a key that had completed earlier returned its stored 201 (`Idempotent-Replayed: true`), a new key returned 503.
  A replay does not write; it does re-authorize first (D23).
- **Deletions are irreversible** (`deleteUser`, `removeGroupMember`); the damage window of a leaked token is narrowed by `If-Match` (one concrete tag per target), leaf-only deletes and the per-client subtree ceilings, not undone.
- Rolling redeploy: lever 2 only takes effect on a replica once it is replaced.

Not measured: a Kubernetes rolling update, multi-node LDAP, a request stalled in the `M` identity pre-read before the `W_data` bind, `W_lock` operations (none are opened in the first ship), and the natural expiry of the default
900 s lock (the 8 s policy was used to measure self-recovery).

## Password compartment emergency block (machine-write-scope-v2 T-025, REQ-017, AC-011)

`setPassword` (v2c) binds its own identity, `W_cred`, so it has its own levers; `W_data`, `W_lock` and the read identity `M` are separate accounts. `setPassword` is open since T-026 (with `MACHINE_WRITE_CRED_ENABLED` and the scope in a client's ceiling). This section is the drill's result: `scripts/test/test-machine-write-cred-drill.py` (70 checks on the T-026 tree, real slapd with the documented v2c layout including the 8.1 no-lockout policy of `W_cred`, in-process replicas running the production write table with configurations built in code, a TCP proxy that holds one LDAP message; **no Kubernetes rollout**). Numbers are from that docker run.

| Lever | Effect on `setPassword` | Other compartments | Measured |
|---|---|---|---|
| **1. Rotate the `W_cred` LDAP password** (administrator `replace: userPassword`; the Secret still holds the old value) | the **next** request on **every** replica is 503 `unavailable`, audit `reason=bind_failed`, no directory change; slapd refuses the old credential | **on replicas that keep running**: `W_data` createUser 201, `W_lock` lockUser 204, `M` read 200. **A replica that restarts, and any new pod, does not start at all** while the Secret holds the old value (the start-up canary probe binds as `W_cred`: `wcred_bind_failed`), so the whole UI is down for it, reads included | first request after the Modify: 503 on replica 1 at +0.1 s and replica 2 at +0.2 s; replica started with the old Secret refused with `wcred_bind_failed` |
| **2. Redeploy with `MACHINE_WRITE_CRED_ENABLED=false`** | **403 `scope_denied`** ("dn is not permitted for this machine client", `reason=scope`), **zero** `W_cred` binds, no connection: with the flag off the application reads no other `MACHINE_WRITE_CRED_*` value, so there is no cred ceiling (T026-F1; measured on the `config.Load` shape built in code). Same 403 with `directory.users.password.write` also gone from the ceiling. The pods start either way: a ceiling may keep the password scope with the flag off (T026-D1) | same as above; the redeployed pods start (no `W_cred` canary probe with the flag off); `createUser` with `credentialPending` is 400 | the redeployed server refused with 0 `W_cred` binds attempted; the replica that was not redeployed still set the password |

**Lever 1 is not free of side effects: do not rotate `W_cred` and then wait.** Rotation at slapd and the new Secret must reach the pods in the same rollout, in this order: (1) stop anything that would restart or add pods (no scale-out, no node drain, no other rollout) until step 3; (2) rotate at slapd (the block starts now); (3) roll out the Secret with the new value immediately: each pod that restarts then starts with the right value, pods still running with the old value keep serving reads and the other compartments with `setPassword` closed. A pod that restarts between 2 and 3 crash-loops until step 3. If the aim is only to stop `setPassword` and a rollout is not ready, use lever 2 (a redeploy of the flag) instead; it needs no `W_cred` value at all.

Rotation procedure (the value from a 0600 file, never argv): `{ printf 'dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword:: ' "$WCRED_DN"; base64 < "$NEWPW_FILE" | tr -d '\n'; echo; } | docker exec -i <ldap> ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin`. Restore: a replica built with the new Secret starts and sets passwords (200); replicas still on the old Secret stay 503. While `W_cred` is rotated the periodic premise cycle on a stale replica also fails (`wcred_bind_failed`, the canary probe binds as `W_cred`) and the password operation stays closed on its own.

**Flag-only redeploy: 403, no start-up failure (AC-011 (a) as revised, Q19 decided 2026-10-14).** T-025 measured 503 (identity not configured) with a configuration built in code that kept every other cred value. `config.Load` reads none of them when the flag is off (unit-tested), so the configuration it builds has no `MACHINE_WRITE_CRED_SUBTREES` and the target guard answers 403 `scope_denied` before any connection; the drill asserted that 403 on a configuration built in code in the shape `config.Load` produces (no live run went through `config.Load` from real environment variables; EVIDENCE.md 2m, T026-F1). What T025-F1 kept on purpose holds either way: the redeploy starts (a ceiling with the password scope is accepted with the flag off, T026-D1), and nothing binds as `W_cred`. Read a 403 `scope_denied` on `setPassword` right after such a redeploy as the block working, not as a lost grant.

### The `W_cred` lockout trap

Every refused request after a rotation is one failed `W_cred` bind. With the image's default policy (`pwdLockout TRUE`, `pwdMaxFailure 5`), from a clean failure count `W_cred` was locked (`pwdAccountLockedTime`) by exactly the **5th** refused request (measured 5 of `pwdMaxFailure` 5). Failed binds from other sources (a stale-Secret start-up probe, the T-028 cycle) count towards the same total, so the lock can come earlier in practice. While locked, even the correct Secret does not start a replica (`wcred_bind_failed`). Unlock: administrator `delete: pwdAccountLockedTime` on `W_cred`, then roll out. Anyone who can reach LDAP can lock `W_cred` with wrong binds (a `setPassword` outage, never a read outage). Since T-026 a `W_cred` on the default policy no longer starts at all (`wcred_policy_missing`, below), so this trap is what a deployment gets only between detaching the 8.1 policy and the next start-up or 60 s cycle.

**Decided (CHANGE.md Q17, maintainer 2026-10-14): `W_cred` carries the no-lockout policy.** machine-write-account.md 8.1 attaches the 9.1 policy (`pwdLockout FALSE`, no `pwdMaxFailure`; fixture `wcred-policy.ldif`) as an install step, so the trap above is what a deployment that skipped that step gets (the drill detaches the policy to measure it). With the policy attached: 13 refused requests, not locked, and a new replica passed the T-028 start-up checks and set a password (200). The price is that guesses at `W_cred`'s password are not limited by the directory; the operator owns the mitigation (8.1): a long random password, LDAP reachable only from the UI and administration paths, and an alert on failed `W_cred` binds that triggers rotation. **The premise checks enforce it (Q18 (b), 2026-10-14):** at start-up and every 60 s, `M` reads `W_cred`'s `pwdPolicySubentry` and that entry; anything but one dedicated policy with `pwdLockout: FALSE` and no `pwdMaxFailure`/`pwdMaxAge`/`pwdMustChange TRUE` refuses start-up or closes `setPassword` (503) until fixed (drill: a replica on the default policy refused with `wcred_policy_missing`). Re-attaching the policy is also the way out of the trap: under `pwdLockout FALSE` slapd ignores the `pwdAccountLockedTime` the default policy stamped (drill: a replica with the correct Secret started and set a password while the stamp was still there); delete the stamp anyway so lock alerts stay quiet.

### How long an in-flight `setPassword` can run

The request has one budget, `MACHINE_REQUEST_TIMEOUT`; the Password Modify gets the budget minus a 2 s reserve (at most half of it) kept for the pending cleanup. Measured with the Password Modify held at the `W_cred` connection:

| `MACHINE_REQUEST_TIMEOUT` | held, no other event | held, `W_cred` rotated 1.1 s in |
|---|---|---|
| 10 s (default) | ended after **8.0 s** (asserted 7.5-8.5 s); the UI closed the LDAP connection itself; the held message never reached slapd | not measured |
| 4 s | not measured | ended after **2.0 s** (asserted 1.5-2.5 s), 0.9 s after the rotation |

Both ended 409 `idempotency_outcome_unknown` (asserted), the same key and body again is 409 as well (asserted): read the resource before retrying. The target stayed pending without a password. Bound: **a stalled in-flight request ends within `MACHINE_REQUEST_TIMEOUT`** (at timeout minus the reserve); measured at 10 s and 4 s only.

**An already-bound write can complete after the rotation, and then its cleanup cannot run.** A Password Modify held for 1.3 s while `W_cred` was rotated completed 200 when released (slapd checks the bound DN, not the password), but the cleanup binds `W_cred` afresh with the old Secret and both attempts were refused (2 failed binds, asserted); the audit line says `cleanup=failed`. The account now has a password plus the marker and the pending policy: a stuck entry, open to the F-5 match oracle until it is cleaned.

### Manual cleanup while `W_cred` is rotated or blocked (Revision 8)

The sweeps clean as `W_cred`, so they cannot during a rotation: the stuck sweep found the entry and cleaned 0 (`wcred_bind_failed`), and a new replica refuses to start while any stuck entry exists (`sweep_stuck_at_startup`; with the old Secret it already refuses on the canary probe). Clean by hand; the drill ran exactly these steps:

1. As `M` (read-only) search the candidates: `ldapsearch -x -H ldap://... -D "$M_DN" -y <file> -LLL -b "$LDAP_BASE_DN" "(pwdPolicySubentry=$PENDING_POLICY_DN)" employeeType pwdChangedTime creatorsName`. That list also holds accounts that are only pending (no password yet, legitimate) and the canaries (6 in the drill), so it is **not** the delete list. A stuck entry has a password: use `(&(pwdPolicySubentry=$PENDING_POLICY_DN)(pwdChangedTime=*))` and drop the DNs listed in `MACHINE_WRITE_CRED_CANARIES` (the configured list, not a name pattern). The drill got exactly the one stuck account.
2. **Pause.** Wait one `MACHINE_REQUEST_TIMEOUT` (default 10 s) after the last event: a request that was in flight may still complete or clean itself. Search again and use this second result; if it differs from the first, start over.
3. As the administrator delete only what the feature added: the `employeeType` value(s) that begin with `ldapium-credential-pending:` (the exact value read in step 2) and the exact pending policy value. Never a whole attribute: the account may carry other `employeeType` values (the drill's account had `contractor`, which survived):
   `dn: <entry>` / `changetype: modify` / `delete: employeeType` / `employeeType: ldapium-credential-pending:<tag>` / `-` / `delete: pwdPolicySubentry` / `pwdPolicySubentry: $PENDING_POLICY_DN`, piped to `docker exec -i <ldap> ldapmodify ...`.
4. Check: no marker value and no policy value left, other attributes unchanged, the set password still binds, a read-only sweep finds `stuck=0`.
5. Roll out the rotated Secret; the new replica starts and sets passwords.

Not measured: a Kubernetes rolling update, multi-provider, `MACHINE_REQUEST_TIMEOUT` values other than 10 s and 4 s, the stall without a rotation at 4 s and with one at 10 s, and the natural expiry of the default 900 s `W_cred` lock.
