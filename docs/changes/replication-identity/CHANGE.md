# Change: syncrepl을 관리자 DN이 아닌 전용 복제 신원(replicator)으로 바인드

- Change class: `D` — 자격 증명 취급·보안 경계·복제 토폴로지(AGENTS.md "Risk-scaled change workflow")
- Owner: 미지정 — 수용 전 지정
- Related issue: [#229](https://github.com/dasomel/ldapium/issues/229) 두 번째 항목 (첫 번째 항목 `/proc/1/environ`은 `image/entrypoint.sh:1598-1603`에서 이미 처리). 선행 기록: [generated-credentials D43](../generated-credentials/CHANGE.md)
- Status: `Proposed / awaiting review`
- Accepted by / date: 미수용 — 이 문서는 제안이며 Class D 수용 전 구현 착수 금지
- 작성일: 2026-10-06

> 이 문서는 설계 제안이다. 저장소의 코드·ACL·Helm·스크립트는 변경하지 않았다. 아래 "실험(E1–E12)"은
> 1회용 컨테이너(OpenLDAP 2.6.15, `docker build -t l5-ldap:1 -f image/Dockerfile ./image`, HEAD 0baf3ea)에서
> 실제로 실행한 결과이며, 실험용 스크립트는 저장소에 없다(T-022에서 `scripts/test/`로 재현 가능하게 만든다).
> 실험에 쓴 "프로토타입 이미지"는 부트스트랩 LDIF 두 개에 sed로 ACL/엔트리를 덧붙인 일회용 파생 이미지이며
> 코드 구조 제안이 아니다. 검증하지 못한 항목은 "미검증"으로 명시했다.

## Problem

| # | 관찰 | 근거 |
|---|---|---|
| P1 | syncrepl이 관리자 DN(rootDN)과 **공유 관리자 비밀번호**로 바인드한다. 복제 비밀번호 기본값이 관리자 비밀번호다. | `image/entrypoint.sh:570-580` (`LDAP_REPLICATION_BIND_DN` 기본 `$LDAP_ADMIN_DN`, 비밀번호 폴백 `$LDAP_ADMIN_PASSWORD`) |
| P2 | `olcSyncrepl ... credentials="<평문>"`이 모든 노드의 cn=config에 평문으로 저장된다. 관리자 비밀번호면 곧 rootDN 전권이다. | `image/entrypoint.sh:1567-1568`; E1에서 `ldapsearch -D cn=admin,cn=config`로 `credentials="replpw1"` 평문 조회 확인 |
| P3 | cn=config 관리자(`cn=admin,cn=config`)도 같은 관리자 비밀번호를 쓴다 → 복제 비밀번호 유출 = 설정 탈취 + 전 노드 쓰기. | `image/ldifs/02-cn-config-admin.ldif:12-15,23-27` |
| P4 | D43: 복제 시 관리자 비밀번호를 자동 생성할 수 없고 **모든 노드가 같은 명시적 관리자 비밀번호**를 가져야 한다. | `image/entrypoint.sh:100-107`, [generated-credentials D43](../generated-credentials/CHANGE.md) |
| P5 | 지금도 `LDAP_REPLICATION_BIND_DN`/차트 `replication.bindDN`으로 비관리자 DN을 줄 수 있지만 **ACL이 없으면 조용히 망가진다**: 엔트리는 복제되나 `userPassword`가 빠진다(E1, E3). 차트 values 주석은 존재하지 않는 `REPLICATION-CONTRACT.md D3`을 가리킨다. | `charts/ldapium/values.yaml:246-253`, `image/README.md:305-309`; 저장소에 해당 파일 없음(grep) |
| P6 | **contextCSN 일치는 데이터 일치를 증명하지 않는다.** ACL이 속성을 가려도 contextCSN은 같다(E1, E3, E10, E11). 기존 지연 알림은 이 실패를 못 잡는다. | `docs/ha-profile.md:224-233`, `scripts/bench-replication.sh:129`; 실험 |

## Intent

모든 노드가 서로를 **전용 읽기 전용 복제 신원**으로 바인드한다. 이 신원은 복제에 필요한 만큼만(모든 엔트리·`userPassword`
해시·운영 속성 읽기, 크기/시간 제한 해제) 권한을 갖고, 잠금·만료·쓰기 권한이 없다. 그 결과 공유 관리자 비밀번호는 복제에
필요 없고(D43 → "명시적 **공유 복제** 비밀번호"로 완화), cn=config에는 복제 비밀번호만 남는다. 기본값은 바뀌지 않는다
(opt-in 먼저, 기본값 전환은 별도 결정). 복제가 조용히 멈추거나 속성이 빠지는 실패를 **능동 점검**으로 잡는다.

## Scope

- In scope: 복제 신원 엔트리·정책 생성, ACL/limits 렌더링(신규·기존 볼륨), olcSyncrepl 빌더 분기, 생성/회전/폐기 절차,
  점검 스크립트, 차트 값·Secret, 마이그레이션·롤백, 라이브 검증, 문서.
- Affected: `image/entrypoint.sh`, `image/ldifs/01-cn-config.ldif`·`03-base-structure.ldif`, `charts/ldapium`
  (`replication.*`), `scripts/`(점검·운영 CLI·테스트), `.github/workflows/e2e.yml`·`replication-chaos-e2e.yml`,
  `image/README.md`, `charts/ldapium/README.md`, `docs/ha-profile.md`, `docs/migration.md`.
- 대상: 복제를 운영하는 사람(compose/Helm), 보안 검토자. 단일 노드(복제 꺼짐)는 영향 없음.

## Non-goals

- 기본값을 `dedicated`로 바꾸는 것(별도 결정, OQ-2). 복제 토폴로지·rid·서버 ID 규칙·트랜스포트 변경. cross-site(D13) 복제.
- 침해된 **프로바이더 노드**의 쓰기 주입 방지(다중 프로바이더에서 로컬 쓰기는 모든 피어로 복제된다 — 위협 모델 참조).
- 관리자 신원 분리(`cn=admin`/`cn=admin,cn=config`의 자격 증명 통합), 메트릭 사이드카의 `LDAP_PASS`(`charts/ldapium/templates/statefulset.yaml:288-312` 부근).
- cn=config 자격 증명 파일 참조(slapd가 지원하는지 미검증 — 아래).
- SASL EXTERNAL 구현(대체안으로 평가·실증만; 후속 패키지).

## Requirements

- `REQ-001` — 복제 신원은 **읽기 전용 + `userPassword`/`shadowLastChange` 읽기 + 운영 속성 읽기 + 크기·시간 무제한**이며, 쓰기·자기 비밀번호 변경·cn=config/cn=accesslog 읽기는 불가하다.
- `REQ-002` — 신원 엔트리는 **노드 1이 베이스 DIT를 만들 때 같은 트랜잭션으로** 생성되어 피어가 첫 바인드 때 이미 존재한다. 전용 모드에서 복제 비밀번호 미지정이면 기동 실패(관리자 비밀번호로 폴백 금지).
- `REQ-003` — ACL·limits는 **slapd가 처음 기동하기 전** cn=config에 있어야 한다(신규 부트스트랩 + 기존 볼륨 모두, 부팅마다 멱등 보정). 어느 한 프로바이더에라도 없으면 그 프로바이더를 읽는 소비자는 속성을 조용히 잃는다.
- `REQ-004` — 신원은 ppolicy 잠금·만료에서 제외된다(전용 정책 엔트리 `pwdLockout: FALSE`). 대신 비밀번호는 생성된 고엔트로피(≥32바이트 랜덤)여야 하고 사람이 고른 값은 거부한다.
- `REQ-005` — 비밀번호 회전은 **복제 중단 없이** 롤링으로 가능해야 한다(이중 값 창).
- `REQ-006` — 기본값 불변: `LDAP_REPLICATION_IDENTITY` 미지정/`admin`이면 olcSyncrepl 출력이 현재와 동일하고 기존 E2E가 그대로 통과한다. 커스텀 `LDAP_REPLICATION_BIND_DN`은 동작 유지 + 경고 로그.
- `REQ-007` — 기존 클러스터 마이그레이션은 **ACL 선행 → 신원 생성 → 노드별 전환**의 순서를 강제·점검하며, 혼합 모드(일부는 admin, 일부는 replicator)와 롤백이 안전하다.
- `REQ-008` — **능동 점검**: 신원 바인드, 관리자 엔트리 `userPassword` 읽기, 운영 속성 읽기, 복제 신원이 보는 엔트리 수 = root가 보는 수, 잠금 상태, contextCSN 일치를 노드·피어별로 확인하고 비정상이면 비0 종료한다. contextCSN만으로 건강하다고 판정하지 않는다.
- `REQ-009` — 신원 바인드(성공·실패)는 프로바이더의 cn=accesslog에서 추적 가능하다(accesslog 활성 시), 비밀번호는 로그·API·`/proc/1/environ`에 남지 않는다(`entrypoint.sh:1598-1603` 불변).
- `REQ-010` — 전용 모드에서는 관리자 비밀번호가 노드마다 달라도 복제가 동작한다(D43 완화). 단 admin 엔트리 해시가 복제되는 한 노드 간 관리자 비밀번호가 "분리"되지는 않음을 문서화한다.
- `REQ-011` — 첫 부팅 피어 탐지(`#203/#204`, `#206` 의미)와 wiped-node 재동기화는 전용 신원에서도 불변이며 sid 1·sid 2 wipe 모두 통과한다.
- `REQ-012` — 차트: `replication.identity`(기본 `admin`), 복제 Secret(`existingSecret` 또는 lookup 기반 1회 생성 + `helm.sh/resource-policy: keep` + 오프라인 렌더 실패, D42 패턴), 값 스키마 검증.

## Acceptance scenarios

### `AC-001` — 전용 신원으로 3노드 동시 콜드 스타트가 수렴한다
- Covers: `REQ-001`, `REQ-002`, `REQ-003`
- Given `identity=dedicated`, 노드 3개를 동시에 기동, 모든 노드에 같은 복제 비밀번호
- When 각 노드에서 add / modify / password 변경 / delete를 수행
- Then 모든 노드가 같은 엔트리·같은 해시를 갖고(엔트리 수·해시 수 일치) 각 노드에서 로그인이 된다. 복제 신원 엔트리와 정책 엔트리가 3노드 모두에 있고 베이스 entryUUID가 같다.

### `AC-002` — 신원의 권한이 좁다 (부정 테스트)
- Covers: `REQ-001`, `REQ-004`
- Given AC-001의 클러스터
- When 복제 신원으로 (a) 엔트리 수정 (b) 자기 비밀번호 변경 (c) cn=config 읽기 (d) cn=accesslog 읽기 (e) 관리자 엔트리 `userPassword`·`entryCSN`·`entryUUID`·`contextCSN` 읽기를 시도
- Then (a)(b) `insufficientAccess(50)`, (c)(d) `noSuchObject(32)`, (e) 모두 성공. 신원 엔트리에 `pwdAccountLockedTime`이 생기지 않는다.

### `AC-003` — ACL 누락·과소 ACL이 능동 점검에서 드러난다
- Covers: `REQ-003`, `REQ-008`
- Given 한 프로바이더에서 복제 신원 ACL 절을 제거 / `LDAP_SIZE_LIMIT`보다 많은 엔트리 + limits 제거 / 신원 비밀번호 불일치
- When 해당 프로바이더에서 비밀번호를 바꾸거나 노드를 wipe해 재동기화, 점검 스크립트 실행
- Then 점검 스크립트가 비0으로 종료하고 원인(속성 미열람 / 엔트리 수 불일치 / 바인드 49)을 출력한다. contextCSN은 같아도 실패로 판정한다.

### `AC-004` — wiped 노드 재동기화
- Covers: `REQ-011`, `REQ-002`
- Given AC-001 상태에서 엔트리 추가 후
- When sid 1 노드, 이어서 sid 2 노드의 볼륨을 지우고 같은 환경으로 재기동
- Then 두 노드 모두 이전 엔트리·해시를 전부 되찾고, 베이스 entryUUID가 같고, 노드 1 로그에 `peer already has the base DIT`가 남으며, 피어에서 엔트리가 삭제되지 않는다(`#206` 불변식).

### `AC-005` — 이중 값 창으로 무중단 회전
- Covers: `REQ-005`, `REQ-004`
- Given AC-001 상태
- When 신원 엔트리에 새 `userPassword` 값을 **추가** → 노드를 하나씩 새 비밀번호로 재기동하며 각 단계에서 카나리 쓰기 → 구 값을 제거
- Then 모든 단계에서 구·신 비밀번호가 모두 바인드되고(추가 후 ~ 제거 전), 카나리가 모든 노드에 도달하며, 제거 후 구 비밀번호는 49, 신 비밀번호는 성공, 이후 쓰기가 복제된다.

### `AC-006` — 기존 클러스터 마이그레이션·혼합 모드·롤백
- Covers: `REQ-006`, `REQ-007`
- Given 구 이미지, admin 바인드 2노드 클러스터(데이터·비밀번호 보유)
- When ① 새 이미지로 전 노드 롤아웃(ACL 설치, 여전히 admin 바인드) ② `ensure`로 신원 생성 ③ 노드 하나씩 전환(혼합 모드) ④ 전부 전환 ⑤ 롤백(admin 바인드로 복귀)
- Then 각 상태에서 양방향 비밀번호 변경이 반영된다. ①이 끝나기 전(어느 프로바이더에 ACL 없음)에 전환을 시도하면 점검 스크립트가 거부한다. 롤백 후 olcSyncrepl의 binddn이 관리자 DN이다.

### `AC-007` — 기본값 불변
- Covers: `REQ-006`
- Given `LDAP_REPLICATION_IDENTITY` 미지정
- When 기존 `test-wiped-node-resync.sh`·`replication-chaos-e2e.yml`·`test-bootstrap-seed.sh` 실행, 렌더된 olcSyncrepl 비교
- Then 모두 통과하고 olcSyncrepl 줄이 변경 전과 동일(ACL 절·limits 추가는 비활성 상태로 허용되며 릴리스 노트에 기재).

### `AC-008` — D43 완화
- Covers: `REQ-010`, `REQ-002`
- Given 전용 모드, 노드마다 다른 `LDAP_ADMIN_PASSWORD`, 같은 복제 비밀번호
- When 노드 2에서 관리자로 쓰기
- Then 노드 1에 반영된다. 전용 모드가 아니면 기존 D43 기동 실패가 그대로다.

### `AC-009` — 신원 바인드 감사·비밀 비노출
- Covers: `REQ-009`
- Given accesslog 활성(기본 ops `reads bind`)
- When 올바른/틀린 비밀번호로 신원 바인드
- Then 프로바이더 cn=accesslog에 `reqDN=<신원>`, `reqResult=0`/`49`가 남는다. 컨테이너 `/proc/1/environ`에 복제·관리자 비밀번호가 없다.

### `AC-010` — 차트 렌더
- Covers: `REQ-012`
- Given `replication.identity=dedicated` 와 미지정, 오프라인 렌더
- When `helm template`·`verify-chart-schema.sh`
- Then 미지정은 현재와 같은 매니페스트, 전용은 복제 Secret env 주입, Secret 부재+오프라인이면 안내와 함께 실패한다.

## Architecture and decisions

- Relevant ADR/design links: [openldap-2.6-hardening D3·D8·D10·D13](../openldap-2.6-hardening/CHANGE.md), [issue-206](../issue-206/CHANGE.md), [generated-credentials D40–D45](../generated-credentials/CHANGE.md), [docs/ha-profile.md](../../ha-profile.md).
- ADR threshold result: `required` — 보안 경계(자격 증명 수용 경로·ACL)와 D43 변경. 수용 시 ADR 초안 작성(T-005).

### 사실(코드 근거)

| 항목 | 현재 동작 | 근거 |
|---|---|---|
| 복제 켜기·peer | `LDAP_REPLICATION_ENABLED`, `LDAP_REPLICATION_PEERS`(자기 포함, 서수 순서) | `image/entrypoint.sh:490-492`; 차트 계약 `charts/ldapium/values.yaml:236-240` |
| 바인드 DN/비밀번호 | `..._BIND_DN` 기본 admin DN; `..._PASSWORD(_FILE)`, 폴백 admin 비밀번호; 개행 금지 | `entrypoint.sh:570-583` |
| olcSyncrepl | 부팅마다 통째로 `replace`; rid=peer 위치; self 제외; `bindmethod=simple`·`credentials` 평문 | `entrypoint.sh:1541-1585` |
| 순서 | `olcSyncrepl` 먼저, 그다음 `olcMultiProvider TRUE` | `entrypoint.sh:1541-1546,1576-1582` |
| 오프라인 편집 | cn=config는 `slapmodify -n 0`/`slapadd`/`slapcat`로만(임시 slapd 금지) — `#206` | `entrypoint.sh:1472-1482`, [issue-206](../issue-206/CHANGE.md) |
| 베이스 DIT 선출 | 노드 1만 생성, 피어에 베이스가 있으면 양보. 탐지는 복제 DN으로 바인드해 `1.1` 검색, **실패는 "없음"으로 취급** | `entrypoint.sh:1109-1131` |
| 시드 | 베이스를 만든 노드에서만, 마커 이전, 실패 시 롤백 | `entrypoint.sh:1155-1181`(#203/#204) |
| 기본 ACL | `{0} userPassword,shadowLastChange: self write / anonymous auth / * none`, `{1}`/`{2}` `by users read` | `image/ldifs/01-cn-config.ldif:90-93`, `entrypoint.sh:794-813` |
| 크기 제한 | `olcSizeLimit` 기본 10000(rootDN은 무제한이라 그동안 문제 없었음) | `entrypoint.sh:157-169`, `01-cn-config.ldif:74-75` |
| accesslog | 별도 DB(`cn=accesslog`)라 복제 대상 아님(searchbase=root DN); `olcAccessLogSuccess: FALSE` = 실패도 기록; 기본 ops `reads bind` | `entrypoint.sh:953-963`, `entrypoint.sh:1567`(searchbase) |
| mTLS | `olcTLSVerifyClient: try`, `olcAuthzRegexp`(CN→DN); 해당 CA가 서명한 어떤 인증서든 `by users` 권한 | `entrypoint.sh:459-484,739-740` |
| 평문 노출 제거 | 부팅 끝에서 `LDAP_ADMIN_PASSWORD`·`LDAP_REPLICATION_PASSWORD` unset | `entrypoint.sh:1598-1603` |
| 차트 | 모든 파드가 같은 admin Secret을 env로 받음; `replication.bindDN`/`existingSecret` 노브는 있으나 ACL 없음; 프로브는 ldapi `-Y EXTERNAL` `ldapwhoami`뿐(소비자 정체 비감지) | `charts/ldapium/templates/statefulset.yaml:88-92,193-211,212-243`; `values.yaml:246-253` |
| 기존 모니터링 | `openldap_replication_delta`(자기 sid CSN 시각 차), `LDAPiumReplicationLag`(30s)/`ContextCSNDivergence`(300s); 사이드카 없는 구조 | `docs/ha-profile.md:189-233,252-255`; 쓰기가 없으면 지연이 0으로 보여 정체를 못 잡음(추론) |

### 실험 결과 (OpenLDAP 2.6.15, Colima, 2026-10-06)

| ID | 무엇을 | 결과 |
|---|---|---|
| E1 | 2노드, `LDAP_REPLICATION_BIND_DN=cn=replicator,<base>` + 엔트리 생성, **ACL 변경 없음** | 엔트리 6개 복제됨, 소비자에 admin·사용자 `userPassword` **없음**(복제자 자신 것만 self로 보임), contextCSN 동일. cn=config에서 `credentials="replpw1"` 평문 조회됨 |
| E2 | `{0}` 규칙에 `by dn.exact="<신원>" read` 삽입 + `olcLimits` (양 노드) | add/modify/delete/비밀번호 변경이 양방향 반영, wipe 후 재동기화에서 admin 해시 도착(수: 0→1) |
| E3 | 기본 ACL의 새 노드를 **프로바이더**로 두고 거기서 비밀번호 변경 | 피어에서 해당 사용자의 `userPassword`가 **통째로 사라짐**(해시 줄 0, 구 비밀번호 49), contextCSN 동일 |
| E4 | 잘못된 복제 비밀번호 | 소비자 `rc 49 retrying`, 노드는 정상 서비스, 새 쓰기 미반영, 프로바이더 accesslog에 `reqDN=<신원> reqResult=49`. 5회 실패 후 `pwdAccountLockedTime` 생성, **올바른 비밀번호도 49**(잠금 900s 기본값, `entrypoint.sh:251-264`) |
| E5 | 프로토타입 이미지, 3노드 동시 콜드 스타트 | 3노드 모두 DN 6개·admin 해시·신원 엔트리·동일 contextCSN. 각 노드 쓰기·비밀번호 변경·삭제 전파. 신원: 쓰기 50, 자기 비밀번호 변경 50, admin 해시·`entryCSN/entryUUID/contextCSN` 읽기 성공, cn=config·cn=accesslog 32, 잠금 없음 |
| E6 | 이중 값 회전 + 롤링 재시작(n1→n2→n3, 단계마다 카나리 쓰기) | 추가 후 3노드 모두 구·신 바인드 성공, 롤 후 카나리 3/3/3 도달, 구 값 제거 후 구 49·신 성공, 이후 쓰기 복제 |
| E7 | sid 1, sid 2 노드 wipe(신원 사용) | 각각 DN 12·해시 8 복구, 베이스 entryUUID 일치, 노드 1 로그 `peer already has the base DIT`(신원으로 탐지 성공) |
| E8 | `LDAP_SIZE_LIMIT=5`, 엔트리 18개, 노드 2 wipe | limits 있음: 18개 전부 도착. limits 제거: **5개에서 멈춤**, `rc -101 retrying` 반복, 소비자 contextCSN 없음 |
| E9 | 구 이미지 2노드 admin 바인드 → ACL 전 노드 → 노드 2 전환 → 노드 1 전환 → 롤백 | 각 단계 양방향 비밀번호 변경 반영, 롤백 후 binddn=admin DN |
| E10 | ACL이 노드 2에만 있고 노드 2가 먼저 전환(프로바이더 노드 1은 ACL 없음) | 노드 1에서 바꾼 비밀번호가 노드 2에서 사라짐(해시 0), contextCSN 동일 |
| E11 | TLS+mTLS 클러스터(ldaps), `bindmethod=sasl saslmech=EXTERNAL tls_cert/tls_key/tls_cacert`로 온라인 전환 | 클라이언트 인증서 CN=replicator → SASL 신원 `cn=replicator`(**엔트리 없이**), `dn.exact` ACL 적용, add·해시 복제 성공, cn=config에는 키 **경로**만. ACL 절 제거 시 해시 조용히 누락. accesslog에 `SASL(EXTERNAL)` 바인드는 `reqDN`이 **빈 값** |
| E12 | 전용 모드, 노드마다 다른 관리자 비밀번호 | 복제 정상, 노드 2에서 관리자 쓰기가 노드 1에 반영. 노드 2는 두 관리자 비밀번호를 **모두** 수락(olcRootPW + 복제된 admin 엔트리 해시) |

### 결정

| ID | 결정 | 이유 · 비용 · 탈출구 |
|---|---|---|
| D50 | **주 설계**: 단순 바인드 전용 신원 `cn=replicator,<LDAP_ROOT_DN>`(관리자와 같은 레벨). 신규 env `LDAP_REPLICATION_IDENTITY=admin\|dedicated`(기본 `admin`). 전용이면 `..._BIND_DN` 기본값이 위 DN, 복제 비밀번호 필수 | 평문 네트워크(README는 plain `ldap://` 전제, `image/README.md:334-336`)와 TLS 비의존에서 동작 · cn=config에 복제 비밀번호는 여전히 평문 · `admin`으로 즉시 롤백 |
| D51 | ACL: 기존 `{0}` 규칙의 **첫 by 절**로 `by dn.exact="<신원>" read` 삽입(E2). `olcLimits: dn.exact="<신원>" size=unlimited time=unlimited`. 나머지 읽기는 기존 `by users read`가 이미 제공(운영 속성 포함, E5) | 신원이 자기 비밀번호도 못 바꾼다(self write보다 앞). 크기 제한은 증명(E8), 시간 제한은 미분리 검증 · 운영자 커스텀 ACL이 `by users read`를 좁히면 깨질 수 있어 REQ-008 점검이 필수 |
| D52 | ACL·limits는 **복제가 켜져 있으면 항상** 렌더(신원 엔트리가 없으면 비활성). 신규 부트스트랩은 01-cn-config.ldif, 기존 볼륨은 부팅 시 오프라인 `slapmodify -n 0`로 멱등 보정(`hd_clear` 계열 패턴, `entrypoint.sh:1210-1216`) | 혼합 모드 안전(E9/E10): 모든 프로바이더가 ACL을 가진 뒤에만 전환할 수 있어야 한다 · 예약 DN 규칙(운영자가 같은 DN을 다른 용도로 쓰면 권한 상속), mTLS+`cn=$1` 매핑이면 CN=replicator 인증서가 같은 권한을 얻음(위협 모델) · OQ-1 |
| D53 | 신원 엔트리와 정책(`cn=replication,ou=policies,<root>`, `pwdLockout FALSE`, `pwdMaxAge 0`, `pwdAllowUserChange FALSE`; 엔트리에 `pwdPolicySubentry`)은 **노드 1의 베이스 DIT 생성에 포함**(`03-base-structure.ldif`, `slappasswd -T`로 해시). `LDAP_PASSWORD_POLICY_ENABLED=false`면 정책 엔트리 없이 신원만 | 첫 바인드 순서 문제 해결(E5: 동시 콜드 스타트 수렴) · 잠금 제외로 온라인 추측 방어가 없어 고엔트로피 필수·accesslog 감시(E4 대비) · 정책 비활성이면 ppolicy 기본 정책이 없어 잠금 없음(추론, 미검증) |
| D54 | 기존 클러스터: 신원 엔트리는 **온라인 복제 쓰기**로 만든다(`scripts/replication-identity.sh ensure`). 오프라인 쓰기는 CSN sid 000이라 복제되지 않는다(`openldap-2.6-hardening` D13) | 노드 1 부트스트랩 경로는 새 클러스터 전용 · 운영 CLI가 필요 |
| D55 | 회전: 신원 엔트리에 `userPassword` 값을 **추가**(다중 값) → 롤링 재시작(새 `LDAP_REPLICATION_PASSWORD`) → 완료 후 `replace`로 새 값만 유지(E6). 비밀번호는 부팅 시 cn=config에 구워지므로(`entrypoint.sh:1555-1568`) Secret만 바꿔서는 반영 안 됨 → 재시작 필수 | 중단 없음 · 재시작 누락이 조용한 정체가 될 수 있어 점검 스크립트가 신원별 바인드를 확인 |
| D56 | 전용 모드에서만 `entrypoint.sh:100-107`의 D43 기동 실패를 완화(복제 비밀번호 명시 필수로 대체). 기본·`admin` 모드는 D43 유지 | E12 · 노드 1의 admin 해시가 복제되어 모든 노드에서 유효 → "노드별 관리자 비밀번호 분리"가 아님 |
| D57 | **대체안(후속)**: SASL EXTERNAL + TLS 클라이언트 인증서(`bindmethod=sasl saslmech=EXTERNAL tls_cert/tls_key/tls_cacert`). ACL(D51)·limits·점검(REQ-008)은 그대로 재사용 | E11로 가능함은 실증, 단 (a) 차트 TLS 경로가 "UNVERIFIED"(`values.yaml:210-215`), (b) 엔트리 없이 DN이 부여되므로 `LDAP_TLS_CA_FILE`은 복제 전용 CA여야 함(`entrypoint.sh:463-472` 주석), (c) accesslog에 신원이 안 남음(E11), (d) 키 회전=인증서 회전 절차 신규 · OQ-3 |
| D58 | 기본값 불변: `identity` 미지정/`admin`이면 olcSyncrepl 동일. 커스텀 `LDAP_REPLICATION_BIND_DN`(비관리자)는 동작 유지 + "ACL이 필요하며 `check`로 점검하라"는 경고 로그 | 기존 배포 호환 · 경고는 로그뿐이라 강제력 없음(OQ 아님, 기록) |
| D59 | 능동 점검 `scripts/check-replication-identity.sh`(운영자·CI·`helm test`). 피어별로 신원 바인드→admin 엔트리 `userPassword` 읽기→`entryCSN/entryUUID` 읽기→`(objectClass=*)` 개수를 신원 vs root로 비교→잠금 속성→contextCSN 집합 비교. 종료코드 0/1/2 | E1·E3·E8·E10이 보여준 "조용한" 실패를 직접 잡는 유일한 방법. 라이브 메트릭이 아님: exporter는 외부 컴포넌트라 소비자 상태 지표가 없고 사이드카 없는 구조(`ha-profile.md:252-255`)를 유지 → 주기 실행은 운영자/CronJob 몫. 보조 신호: slapd 로그 `rc 49`/`rc -101`/`ldap_sasl_bind_s failed`, accesslog `reqResult=49 & reqDN=<신원>` |

### 잔여 위험 (정직하게)

- cn=config의 `credentials`는 **여전히 평문**이다. 달라지는 것은 그 값이 admin이 아니라 읽기 전용 신원의 비밀번호라는 점뿐이다. 읽을 수 있는 주체: `cn=admin,cn=config`(E1), 파드의 ldapi root, cn=config 볼륨 접근자. slapd 2.6.15가 `credentials`에 파일/SASL 비밀 참조를 지원하는지는 **미검증**(바이너리에 `tls_cert`, `saslmech` 등 키워드는 존재, 파일 참조 키워드는 확인 못 함). SASL EXTERNAL이 이 잔여 위험을 없애는 유일한 검증된 경로(D57).
- 잠금 제외(D53)는 신원에 대한 온라인 추측 방어를 없앤다. 비밀번호 엔트로피와 accesslog 감시로만 보완.
- 신원 엔트리를 UI/API의 관리자 세션이 지우거나 바꿀 수 있다(보호 DN 개념 없음, `ui/backend`에 해당 기능 없음; rootDN은 ACL 우회). 삭제는 복제되어 클러스터 전체가 49로 정체한다(추론, 미검증). 점검 스크립트와 알림으로만 보완.
- 첫 부팅 피어 탐지는 "실패 = 베이스 없음"이다(`entrypoint.sh:1124-1131`). 신원 비밀번호가 틀리거나 잠긴 상태에서 노드 1을 wipe하면 베이스 DIT를 다시 만들어 entryUUID 충돌이 날 수 있다(추론, 미검증; admin 바인드에서도 같은 구조).

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `image/entrypoint.sh`(env 파싱, ACL/limits 보정, 베이스 DIT 확장, olcSyncrepl 분기), `01-cn-config.ldif`·`03-base-structure.ldif`, 신규 `scripts/check-replication-identity.sh`·`scripts/replication-identity.sh`. HTTP API 변경 없음 |
| Dependencies / lockfiles | N/A — 신규 의존성 없음(`ldap*`, `slappasswd`는 이미 이미지에 있음) |
| Runtime / toolchain | OpenLDAP 2.6.15 기준 동작만 검증. 업그레이드 시 `olcLimits`/ACL 문법 재검증 |
| CI / CD | `e2e.yml`에 신규 라이브 테스트 1개, `replication-chaos-e2e.yml`에 전용 모드 시나리오 추가(T-021) |
| Release / packaging | 릴리스 노트: 복제 시 cn=config에 비활성 ACL·limits 추가(D52), 신규 env/값. 이미지 롤아웃이 끝나야 전환 가능(점검이 강제) |
| Generated output | N/A — 생성 산출물 없음(차트 `values.schema` 확인은 `verify-chart-schema.sh`) |
| Security / supply chain | Class D. 위협 모델 참조. 자격 증명 노출 면적 축소(admin→읽기 전용), 잠금 제외·평문 잔존은 위험으로 기록. 기존 `credentials="..."` 마스킹(`scripts/detect-config-drift.sh:122-134`, `scripts/export-incident-evidence.sh:530-534`)은 단순 바인드 형식에 그대로 유효 — 신원 DN이 바뀌어도 패턴 불변이며 T-003이 회귀로 확인 |
| Offline / air-gap | 영향 없음(스크립트는 이미지 내 도구만 사용). 차트 Secret 생성은 오프라인 렌더 실패 규칙(D42) 준수 |
| Documentation / operations | `image/README.md:300-309`는 임시 slapd 서술이 `#206` 이후 틀림(오프라인 편집) — 같이 수정, `charts/ldapium/values.yaml:246-248`의 존재하지 않는 `REPLICATION-CONTRACT.md` 참조 제거, `docs/ha-profile.md` 모니터링 한계 갱신, D43 후속 기록 |
| Portfolio / downstream repositories | N/A — 이 저장소 내부 변경(UI는 신원 엔트리를 디렉터리 트리에서 볼 수 있음; 별도 보호 기능은 비범위) |

## 위협 모델

| 시나리오 | 현재(admin 바인드) | 제안(전용 신원) |
|---|---|---|
| 복제 비밀번호 유출 | = 관리자 비밀번호 → rootDN 전권 + `cn=admin,cn=config`(같은 비밀번호, `02-cn-config-admin.ldif:23-27`)로 설정 탈취, 모든 노드 쓰기 | 모든 엔트리·`userPassword` 해시 **읽기**(오프라인 크래킹 가능, 이미 복제본이 전체 데이터를 가지므로 새 노출은 아님), 쓰기 50·자기 비밀번호 변경 50·cn=config/accesslog 32(E5). 잠금이 없어 온라인 추측 가능 |
| 관리자 비밀번호 유출 | 위와 동일(복제도 동일 비밀번호) | 관리자 전권(그대로) 하지만 복제 자격과 분리되어 복제 비밀번호 회전과 무관 |
| 침해된 소비자(파드/볼륨) | cn=config에서 admin 비밀번호 획득 → 모든 피어에 쓰기·설정 변경 | cn=config에서 읽기 전용 신원 비밀번호만 획득 → 피어 읽기만 가능. **단 침해 노드 자체의 로컬 쓰기는 여전히 모든 피어로 복제된다**(다중 프로바이더 LWW) — 완화되지 않음 |
| `userPassword` 해시 복제 | 평문 `ldap://`이면 해시가 와이어에 노출(README 전제) | 동일. 복제 신원이 해시를 읽는 것은 필수 요건(REQ-001) |
| 복제 바인드 감사 | 프로바이더 cn=accesslog에 `reqDN=<admin>` | `reqDN=<신원>`, 실패는 `reqResult=49`(`olcAccessLogSuccess: FALSE`, E4). EXTERNAL은 `reqDN` 빈 값(E11) |
| ACL 누락/축소 | N/A(root는 ACL 우회) | **조용한 데이터 손상**: 속성 누락·해시 삭제(E1, E3, E10), 크기 제한으로 정체(E8). contextCSN 불변. REQ-003 + REQ-008이 방어 |
| 신원 엔트리 삭제/변조 | N/A | 삭제는 복제되어 전 클러스터 정체(추론). 점검·알림으로 보완 |
| 대체안: 클라이언트 키 유출 | N/A | 신원 비밀번호 유출과 동급(읽기 전용). 인증서 폐기/만료로 회수 가능, cn=config에 비밀 없음. CA가 서명한 임의 CN=replicator 인증서도 동일 권한(D52 연동) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 신규 `scripts/test/test-replication-identity.sh` 3노드 동시 기동, 노드별 add/modify/pw/delete, 엔트리·해시 수 비교 | Docker, `ldapium:e2e` | PASS 로그, 노드별 DN/해시 수 |
| `AC-002` | 같은 스크립트의 부정 테스트(쓰기·자기 비밀번호·cn=config·accesslog·읽기 허용 속성) | 동일 | 결과 코드 50/50/32/32/성공 |
| `AC-003` | ACL 절 제거·`LDAP_SIZE_LIMIT` 소량+limits 제거·비밀번호 불일치 주입 후 점검 스크립트 실행 | 동일 | 점검 비0 + 원인 문구, contextCSN은 동일했음을 함께 기록 |
| `AC-004` | `test-wiped-node-resync.sh` 확장(전용 모드, sid 1 + sid 2) | 동일 | 엔트리/해시/entryUUID 일치, 탐지 로그 |
| `AC-005` | 회전 시나리오(추가→롤링→제거) 스크립트 + 카나리 | 동일 | 단계별 바인드 결과·카나리 도착 |
| `AC-006` | 구 이미지(직전 릴리스)→신 이미지 마이그레이션 시나리오, 혼합·롤백 | 동일(두 이미지 태그 필요) | 단계별 양방향 비밀번호 변경, olcSyncrepl binddn 확인 |
| `AC-007` | 기존 e2e 3종 + olcSyncrepl 비교 | CI | 기존 통과, diff 없음 |
| `AC-008` | 노드별 다른 관리자 비밀번호 시나리오 | 동일 | 쓰기 전파 |
| `AC-009` | accesslog 조회 + `/proc/1/environ` 검사 | 동일 | `reqResult` 레코드, 비밀번호 부재 |
| `AC-010` | `helm template`(미지정/전용/Secret 부재 오프라인), `verify-chart-schema.sh` | CI | 렌더 diff, 실패 메시지 |

단위/정적(셸 `shellcheck`, 순수 함수) 증거와 라이브 LDAP 증거를 분리해 기록한다. 라이브 LDAP 경로를 모킹으로 대체하지 않는다(AGENTS.md "Testing philosophy").

### 추적성 매트릭스

| REQ | AC | Tasks | 증거(이 패키지에서 이미 확보) |
|---|---|---|---|
| REQ-001 | AC-001, AC-002 | T-010, T-013, T-020 | E2, E5 |
| REQ-002 | AC-001, AC-004, AC-008 | T-013, T-014, T-020 | E5, E7 |
| REQ-003 | AC-001, AC-003, AC-006 | T-010, T-011, T-020, T-021 | E1, E3, E8, E10 |
| REQ-004 | AC-002, AC-005 | T-013, T-020 | E4(잠금 문제), E5(정책 효과) |
| REQ-005 | AC-005 | T-015, T-020 | E6 |
| REQ-006 | AC-006, AC-007 | T-012, T-017, T-020 | E9 |
| REQ-007 | AC-006 | T-011, T-015, T-020 | E9, E10 |
| REQ-008 | AC-003 | T-011, T-020 | E1, E3, E4, E8, E10 |
| REQ-009 | AC-009 | T-014, T-020 | E4, E11 |
| REQ-010 | AC-008 | T-014, T-020 | E12 |
| REQ-011 | AC-004 | T-020, T-021 | E7 |
| REQ-012 | AC-010 | T-016, T-020 | (미실행) |

## Rollout, rollback and recovery

- Rollout sequence (기존 클러스터, **opt-in**, 기본 admin 유지):
  1. 새 이미지를 **모든 노드**에 롤아웃. ACL·limits가 비활성으로 설치됨. 복제는 그대로 admin 바인드(E9 단계 1).
  2. `check-replication-identity.sh`로 모든 프로바이더가 ACL을 가졌는지 확인(전환 게이트).
  3. `replication-identity.sh ensure`: 신원 엔트리·정책을 온라인 복제 쓰기로 생성, 복제 Secret 준비.
  4. 노드를 하나씩 `LDAP_REPLICATION_IDENTITY=dedicated` + 복제 비밀번호로 재시작. 각 노드 후 점검(혼합 모드 안전, E9 단계 2).
  5. 전부 전환 후 점검, 선택적으로 관리자 비밀번호 노드별 분리(D56).
  신규 클러스터는 처음부터 전용 모드로 시작 가능(노드 1이 신원 생성, E5).
- Rollback trigger and procedure: 점검 실패·복제 정체 시 `LDAP_REPLICATION_IDENTITY=admin`(또는 미지정)으로 노드를 재시작 → olcSyncrepl이 admin DN으로 재작성(E9 단계 4). 관리자 비밀번호가 모든 노드에 아직 유효해야 한다(차트는 공유 Secret이라 충족). 신원 엔트리는 남겨도 무해, `retire`로 제거. **ACL 없는 프로바이더가 있는 상태에서 전환하지 않는다**(E10: 해시 손실).
- Data/configuration recovery: 속성이 이미 누락된 소비자는 ACL을 고쳐도 복구되지 않는다(syncrepl은 변경분만 보냄, E2에서 wipe로 해결). 복구는 해당 노드 wipe 후 재동기화(`#206` 안전 경로, E7) 또는 영향받은 엔트리를 프로바이더에서 다시 수정. 이미지 롤백(구 이미지)은 비활성 ACL을 cn=config에 남기지만 무해(구 이미지는 `olcAccess`를 건드리지 않음 — `grep olcAccess image/entrypoint.sh`로 부트스트랩 렌더 외 사용처 없음 확인).
- Compatibility or migration obligations: 기본값 불변(REQ-006). 커스텀 `LDAP_REPLICATION_BIND_DN` 사용자는 그대로 동작, 경고 로그. 이미지 버전이 섞인 클러스터(구+신)는 전환 금지.

## Evidence and durable synchronization

- Evidence location/format: 실험 원본은 일회용 스크립트(저장소 밖). T-022가 `scripts/test/test-replication-identity.sh`로 재현 가능하게 만들고 CI 로그를 근거로 삼는다. `research/README.md` 규칙에 따라 기회적으로 기록.
- Tests or checks that become durable regression controls: `test-replication-identity.sh`(AC-001–006, 008, 009), `check-replication-identity.sh`(운영·CI·helm test), chaos e2e 전용 모드 시나리오.
- Documentation to update: `image/README.md`(env·신원·절차, 300-309행 드리프트), `charts/ldapium/README.md`·`values.yaml`(주석의 `REPLICATION-CONTRACT.md` 참조), `docs/ha-profile.md`(점검·알림 한계), `docs/migration.md`, [generated-credentials](../generated-credentials/CHANGE.md)에 D43 후속(D56) 메모, `CHANGELOG*`.
- ADR/evidence/portfolio records to update: ADR(수용 시), `docs/IMPLEMENTATION-STATUS.md`.

## Review record

- Accepted scope/requirements: 미수용.
- Material changes after acceptance and re-review: 없음.
- Open questions or blockers (유지보수자 결정 3개):
  1. **OQ-1 비활성 ACL 상시 설치(D52)** — 복제가 켜진 모든 노드의 cn=config에 예약 DN용 ACL·limits를 항상 추가할지, `identity=dedicated`일 때만 추가할지. 권고: **항상 설치**. 이유: 전환 전에 전 프로바이더가 ACL을 가져야 안전(E10)하고, 조건부면 롤아웃 순서가 이미지 롤아웃 + 설정 변경 2단계로 늘어 실수 여지가 커진다. 비용은 예약 DN 규칙과 cn=config 변경 1건.
  2. **OQ-2 기본값 전환·D43** — 이 패키지 완료 후 신규 클러스터 기본을 `dedicated`로 바꿀지, D43의 기동 실패를 `dedicated`에서만 완화(D56)할지. 권고: **이 패키지에서는 opt-in 유지 + D43은 `dedicated`에서만 완화**, 기본값 전환은 라이브 E2E(AC-001–006)가 CI에서 한 릴리스 동안 녹색인 뒤 별도 패키지로.
  3. **OQ-3 SASL EXTERNAL 투자 시점(D57)** — cn=config 평문 잔존 위험을 없애는 대체안을 후속 패키지로 만들지. 권고: **주 설계(단순 바인드)를 먼저 구현**하고, 차트 TLS 경로의 "UNVERIFIED" 해소(`values.yaml:210-215`) 이후 EXTERNAL을 후속으로 추진. ACL·limits·점검은 공용이라 선택이 서로를 막지 않는다.
- 검증하지 못한 주장: (a) `credentials`의 파일/SASL 비밀 참조 지원 여부(2.6.15 문서·바이너리 키워드로 확인 못 함), (b) `olcLimits time=unlimited`가 지속 검색(refreshAndPersist)에 필요한지(size만 분리 검증), (c) 신원 엔트리 삭제/잠금 상태에서 노드 1 wipe 시 베이스 DIT 재생성(탐지 실패=없음 구조에서 추론), (d) `LDAP_PASSWORD_POLICY_ENABLED=false`일 때 신원에 잠금 없음, (e) SASL EXTERNAL의 wiped 노드·롤링 재시작·인증서 만료 동작과 차트(k8s) 경로, (f) 전체 코드 경로(entrypoint 구현, 차트)와 `ui`의 신원 엔트리 노출 동작, (g) wipe 후 일부 sid의 contextCSN이 전진하는 현상(E7 관찰, 데이터 손실은 없었고 원인은 조사하지 않음), (h) Kubernetes/Helm 경로 전체, 4노드 이상.
