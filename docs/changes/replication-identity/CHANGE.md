# Change: syncrepl을 관리자 DN이 아닌 전용 복제 신원(replicator)으로 바인드

- Change class: `D` — 자격 증명 취급·보안 경계·복제 토폴로지(AGENTS.md "Risk-scaled change workflow")
- Owner: 미지정 — 수용 전 지정
- Related issue: [#229](https://github.com/dasomel/ldapium/issues/229) 두 번째 항목 (첫 번째 항목 `/proc/1/environ`은 `image/entrypoint.sh:1598-1603`에서 이미 처리). 선행 기록: [generated-credentials D43](../generated-credentials/CHANGE.md)
- Status: `Proposed / awaiting review`
- Accepted by / date: 미수용 — 이 문서는 제안이며 Class D 수용 전 구현 착수 금지
- 작성일: 2026-10-06 · 개정 2 (독립 검토 지적 F1–F9 반영, "Review record" 참조)

> 이 문서는 설계 제안이다. 저장소의 코드·ACL·Helm·스크립트는 변경하지 않았다. 아래 "실험(E1–E24)"은
> 1회용 컨테이너(OpenLDAP 2.6.15, `docker build -t l5-ldap:1 -f image/Dockerfile ./image`, HEAD 0baf3ea)에서
> 실제로 실행한 결과이며, 실험용 스크립트는 저장소에 없다(T-020–T-023에서 `scripts/test/`로 재현 가능하게 만든다).
> "프로토타입 이미지"는 부트스트랩 LDIF에 신원·정책 엔트리를 덧붙인 일회용 파생 이미지이고, ACL/limits는 `cn=config`
> 온라인 수정으로 적용했다(코드 구조 제안이 아님). 점검 스크립트 프로토타입(E22)도 저장소 밖이다.
> 검증하지 못한 항목은 "미검증"으로 명시했다.

## Problem

| # | 관찰 | 근거 |
|---|---|---|
| P1 | syncrepl이 관리자 DN(rootDN)과 **공유 관리자 비밀번호**로 바인드한다. 복제 비밀번호 기본값이 관리자 비밀번호다. | `image/entrypoint.sh:570-580` |
| P2 | `olcSyncrepl ... credentials="<평문>"`이 모든 노드의 cn=config에 평문으로 저장된다. | `image/entrypoint.sh:1567-1568`; E1 |
| P3 | cn=config 관리자(`cn=admin,cn=config`)도 같은 관리자 비밀번호를 쓴다 → 복제 비밀번호 유출 = 설정 탈취 + 전 노드 쓰기. | `image/ldifs/02-cn-config-admin.ldif:12-15,23-27` |
| P4 | D43: 복제 시 관리자 비밀번호 자동 생성 불가, **모든 노드가 같은 명시적 관리자 비밀번호**. | `image/entrypoint.sh:100-107`, [generated-credentials D43](../generated-credentials/CHANGE.md) |
| P5 | 지금도 `LDAP_REPLICATION_BIND_DN`/차트 `replication.bindDN`으로 비관리자 DN을 줄 수 있지만 **ACL이 없으면 조용히 망가진다**(엔트리는 복제되나 `userPassword`가 빠지거나 지워짐: E1, E3). 차트 values 주석은 존재하지 않는 `REPLICATION-CONTRACT.md D3`을 가리킨다. | `charts/ldapium/values.yaml:246-253`, `image/README.md:305-309` |
| P6 | **contextCSN 일치는 데이터 일치를 증명하지 않는다.** ACL이 속성을 가려도 contextCSN·엔트리 수·관리자 해시는 정상으로 보인다(E1, E3, E10, E22). 기존 지연 알림은 이를 못 잡는다. | `docs/ha-profile.md:224-233`, `scripts/bench-replication.sh:129` |
| P7 | 기본 ACL의 catch-all이 `by self write`를 준다. 비관리자 신원을 그냥 쓰면 **자기 엔트리를 수정**할 수 있다(`description`, 과거 `pwdEndTime`, 정책 속성). | `image/entrypoint.sh:803,814` |
| P8 | **wipe된 sid-1 노드가 인증 실패를 "베이스 없음"으로 읽어 새 DIT를 만든다.** 틀린/회전 중인 복제 비밀번호면 라이브 DIT가 지워진다(E19: 사용자 3명 소실). | `image/entrypoint.sh:1124-1131,1140-1141` |

## Intent

모든 노드가 서로를 **전용 읽기 전용 복제 신원**으로 **검증된 TLS 위에서** 바인드한다. 이 신원은 복제에 필요한 만큼만(모든 엔트리·`userPassword`
해시·운영 속성 읽기, 크기/시간 제한 해제) 권한을 갖고, 쓰기(자기 엔트리 포함)·잠금·만료가 없다. 그 결과 공유 관리자 비밀번호는 복제에
필요 없고(D43 → "명시적 **공유 복제** 비밀번호", 조건부), cn=config에는 복제 비밀번호만 남는다. 기본값은 바뀌지 않는다(opt-in).
복제가 조용히 멈추거나 속성이 빠지는 실패, 자격 증명 회전 중단, 인증 실패 시 DIT 재생성을 **능동 점검과 fail-closed 규칙**으로 막는다.

## Scope

- In scope: 신원 엔트리·정책 생성, ACL/limits 렌더링(신규·기존 볼륨, 준비 단계 포함), TLS 강제, olcSyncrepl 빌더 분기, 노드 1 부트스트랩 판정 규칙,
  생성/회전/폐기 상태 기계, 점검 스크립트와 주기 실행, 차트 값·Secret·NetworkPolicy, 마이그레이션·롤백, 라이브 검증, 문서.
- Affected: `image/entrypoint.sh`, `image/ldifs/01-cn-config.ldif`·`03-base-structure.ldif`, `charts/ldapium`
  (`replication.*`, `networkpolicy.yaml`, 점검 CronJob), `scripts/`, `.github/workflows/e2e.yml`·`replication-chaos-e2e.yml`,
  `image/README.md`, `charts/ldapium/README.md`, `docs/ha-profile.md`, `docs/migration.md`.
- 대상: 복제를 운영하는 사람(compose/Helm), 보안 검토자. 단일 노드(복제 꺼짐)는 영향 없음.

## Non-goals

- 기본값을 `dedicated`로 바꾸는 것(별도 패키지). 복제 토폴로지·rid·서버 ID 규칙 변경. cross-site(D13).
- 침해된 **프로바이더 노드**의 쓰기 주입 방지(다중 프로바이더에서 로컬 쓰기는 모든 피어로 복제된다).
- 관리자 신원 분리, 메트릭 사이드카의 `LDAP_PASS`(`charts/ldapium/templates/statefulset.yaml:288-312` 부근).
- cn=config 자격 증명 파일 참조(slapd 지원 여부 미검증).
- SASL EXTERNAL 구현(후속 패키지; 실증만 E11, E23).

## Requirements

- `REQ-001` — 복제 신원은 **읽기 전용**이다: 모든 엔트리·`userPassword`/`shadowLastChange`·운영 속성 읽기, 크기·시간 무제한. **자기 엔트리를 포함한 어떤 쓰기도 불가**(description, `pwd*` 정책 속성, 자기 비밀번호, 삭제)하고 cn=config/cn=accesslog 읽기도 불가. 신원은 **기존 규칙보다 앞선 명시적 첫 규칙**으로 허용/거부가 결정되며 다른 주체의 권한은 변하지 않는다.
- `REQ-002` — 신원 엔트리는 **노드 1이 베이스 DIT를 만들 때 같은 트랜잭션으로** 생성되어 피어가 첫 바인드 때 이미 존재하고, **자체 정책을 가리키는 명시적 `pwdPolicySubentry`**를 가진다. 전용 모드에서 복제 비밀번호 미지정이면 기동 실패(관리자 비밀번호 폴백 금지).
- `REQ-003` — ACL·limits는 **slapd가 처음 기동하기 전** cn=config에 있어야 한다(신규 부트스트랩 + 기존 볼륨, 부팅마다 멱등 보정). 설치는 **준비 단계(`prepare`)에서만** 일어나며, 그 전에 **예약 DN 충돌 검사**(같은 DN의 기존 엔트리, 인증서→DN 매핑)를 통과해야 한다. 한 프로바이더에라도 없으면 그 프로바이더를 읽는 소비자는 속성을 조용히 잃는다.
- `REQ-004` — 신원은 ppolicy 잠금·만료에서 **정책 on/off, 신규/기존 볼륨, 강화된 기본 정책, 회전 중**에도 제외된다. 비밀번호는 생성된 고엔트로피(≥32바이트 랜덤)여야 하고 사람이 고른 값은 거부한다.
- `REQ-005` — 비밀번호 회전은 **복제 중단 없이** 가능해야 하며 단계 상태·재개 규칙·롤백·정리 게이트가 정의된다. **모든 소비자의 자격 증명 지문이 새 값으로 확인되기 전에는 구 값을 제거하지 않는다.**
- `REQ-006` — 기본값 불변: `LDAP_REPLICATION_IDENTITY` 미지정/`admin`이면 olcSyncrepl 출력이 현재와 동일하고 cn=config가 바뀌지 않는다. 커스텀 `LDAP_REPLICATION_BIND_DN`은 동작 유지 + 경고 로그.
- `REQ-007` — 기존 클러스터 마이그레이션은 **준비(충돌 검사 + 전 프로바이더 ACL) → 신원 생성 → 노드별 전환**을 강제한다. 게이트는 **엔트리 생성 전 설정 검사(G1)**와 **생성 후 권한·전파 검사(G2)**로 나뉜다. 혼합 모드와 롤백의 전제 조건을 명시한다.
- `REQ-008` — **능동 점검**: (a) 노드별 신원 시점 vs root 시점의 엔트리별 속성 체크섬과 DN 단위 `userPassword` 존재·해시 비교, 노드 간 교차 비교(양방향) (b) 소비자의 실제 `olcSyncrepl` 바인드 DN·자격 증명 지문 vs 기대값 (c) 노드별 카나리 쓰기와 다른 노드에서의 해시 포함 관측 (d) 주기 실행과 알림 계약. 못 잡는 것은 목록으로 문서화한다. contextCSN·엔트리 수만으로 건강하다고 판정하지 않는다.
- `REQ-009` — 신원 바인드는 프로바이더에서 추적 가능하다(단순 바인드: cn=accesslog `reqDN`; EXTERNAL: slapd `stats` 로그). 비밀번호는 로그·API·`/proc/1/environ`에 남지 않는다(`entrypoint.sh:1598-1603` 불변).
- `REQ-010` — 전용 모드에서 노드마다 다른 관리자 비밀번호로도 복제가 동작하는 D43 완화는 **결함 수정과 중단 회전·복구 E2E가 존재한 뒤에만**, `dedicated`에서만 적용한다. 노드별 관리자 비밀번호에서는 `admin` 신원으로의 즉시 롤백이 성립하지 않음을 문서화한다.
- `REQ-011` — 노드 1 부트스트랩 판정은 **피어 도달 불가(네트워크 수준: 현재 동작 유지)**와 **피어 도달 가능하나 인증/TLS/기타 오류(fail-closed)**를 구분한다. 후자는 `LDAP_REPLICATION_FIRST_NODE=true` 없이는 베이스 DIT·신원을 만들지 않고 기동 실패한다. wiped 노드 재동기화(`#206`)와 `#203/#204` 의미는 불변이며 sid 1·sid 2 wipe가 통과한다.
- `REQ-012` — 차트: `replication.identity`(기본 `admin`), 복제 Secret(`existingSecret` 또는 lookup 1회 생성 + `keep` + 오프라인 렌더 실패, D42 패턴), `identity=dedicated`이면 `tls.enabled` 필수, `FIRST_NODE`는 `Release.IsInstall`일 때만, 점검 CronJob·알림, 값 스키마.
- `REQ-013` — 전용 모드는 **검증된 TLS를 요구**한다(`ldaps://` + `tls_reqcert=demand` + CA, 또는 `starttls=critical`). TLS가 없으면 기동 거부. 신원 ACL은 `ssf=128`을 요구해 평문 바인드로는 아무것도 읽을 수 없다.
- `REQ-014` — 신원 접근 면적 문서화·점검: 피어 제한(`peername`/`sockurl`)은 선택 사항이며, Kubernetes에서 네트워크 수준 제한은 NetworkPolicy에 속한다(`networkPolicy.ingressFrom` 기본값 경고 + 렌더 검사).

## Acceptance scenarios

### `AC-001` — 전용 신원으로 3노드 동시 콜드 스타트가 수렴한다
- Covers: `REQ-001`, `REQ-002`, `REQ-003`, `REQ-013`
- Given `identity=dedicated`, TLS 활성, 노드 3개를 동시에 기동, 모든 노드에 같은 복제 비밀번호
- When 각 노드에서 add / modify / password 변경 / delete를 수행
- Then 모든 노드가 같은 엔트리·같은 해시를 갖고 각 노드에서 로그인이 된다. 신원·정책 엔트리가 3노드에 있고 베이스 entryUUID가 같다.

### `AC-002` — 신원의 권한이 좁고 잠기지 않는다 (부정 테스트)
- Covers: `REQ-001`, `REQ-004`
- Given AC-001의 클러스터
- When 복제 신원으로 (a) 자기 엔트리 `description` 수정 (b) `pwdEndTime`·`pwdAccountLockedTime`·`pwdPolicySubentry` 설정 (c) 자기 비밀번호 변경(정책이 허용하도록 바꾼 상태에서도) (d) 자기 엔트리 삭제·엔트리 추가 (e) 다른 엔트리 수정 (f) cn=config·cn=accesslog 읽기를 시도하고, 일반 사용자가 신원 엔트리 수정도 시도
- Then (a)–(e) `insufficientAccess(50)`, (f) `noSuchObject(32)`, 읽기 허용 속성(`userPassword`·`entryCSN`·`entryUUID`·`contextCSN`)은 성공. 일반 사용자의 자기 쓰기·인증·읽기는 변경 전과 동일.
- And 잠금 매트릭스: 틀린 비밀번호 반복(≥12회)에도 잠기지 않음 — (1) 기존 볼륨, 정책 활성 (2) 기존 볼륨에서 `LDAP_PASSWORD_POLICY_ENABLED=false`로 재시작 (3) 기본 정책을 `pwdMaxFailure 1`·영구 잠금·`pwdMaxAge 60`으로 강화 (4) 정책 비활성으로 **처음 부트스트랩**한 볼륨 (5) 회전 중 이중 값 상태. 대조군(신원 아닌 사용자)은 잠긴다.

### `AC-003` — 점검이 ACL 누락·속성 손실·자격 증명 불일치를 잡는다
- Covers: `REQ-003`, `REQ-008`
- Given (a) 하위 트리 한정 `userPassword` 거부 ACL (b) `LDAP_SIZE_LIMIT`보다 많은 엔트리 + limits 제거 (c) 신원 비밀번호 불일치 (d) 새 비밀번호는 외부에서 유효하나 소비자 cn=config는 구 값
- When 점검 스크립트 실행
- Then 각각 비0 종료 + 원인(엔트리별 해시 불일치 DN / 엔트리 수 불일치 / 바인드 49 / 지문 불일치). (a)에서 관리자 해시·엔트리 수·contextCSN은 정상이어도 실패. 베이스 카나리만으로는 (a)를 놓치므로 DN 단위 비교가 필수임을 테스트로 고정.

### `AC-004` — wiped 노드 재동기화
- Covers: `REQ-011`, `REQ-002`
- Given AC-001 상태에서 엔트리 추가 후
- When sid 1 노드, 이어서 sid 2 노드의 볼륨을 지우고 같은 환경으로 재기동
- Then 두 노드 모두 이전 엔트리·해시를 되찾고, 베이스 entryUUID가 같고, 노드 1 로그에 `peer already has the base DIT`가 남으며 피어에서 엔트리가 삭제되지 않는다(`#206` 불변식).

### `AC-005` — 회전 상태 기계: 무중단, 중단·재개, 롤백
- Covers: `REQ-005`, `REQ-004`
- Given AC-001 상태
- When (1) 새 값 추가 → 노드를 하나씩 새 비밀번호로 재기동(단계마다 카나리) → 지문 게이트 통과 후 구 값 제거 (2) **중간 중단**(일부만 재기동)에서 게이트가 닫혀 구 값 제거를 거부 (3) (운영 CLI가 아닌 직접 `ldapmodify`로) 구 값을 일찍 제거하고 재연결을 유발 (4) 롤백: 재기동한 노드를 구 Secret으로 복원 후 새 값 제거 (5) 복구: 구 값 재추가
- Then (1) 모든 단계에서 카나리 도달, 제거 후 구 49·신 성공 (2) 게이트 닫힘 메시지 (3) 소비자가 49로 정체(재연결 전에는 기존 세션이 유지되므로 잠복 위험임을 기록) (4) 롤백 후 복제 정상 (5) 재추가 즉시 소비자가 재시도로 복구.

### `AC-006` — 기존 클러스터 마이그레이션·혼합 모드·롤백·충돌
- Covers: `REQ-003`, `REQ-006`, `REQ-007`
- Given 구 이미지, admin 바인드 2노드 클러스터(데이터·비밀번호 보유)
- When ① 새 이미지로 롤아웃(여전히 admin) ② 충돌 검사 + `prepare`(전 프로바이더 ACL 설치) ③ G1 통과 ④ 신원 생성 ⑤ G2 통과 ⑥ 노드 하나씩 전환(혼합 모드) ⑦ 전부 전환 ⑧ 롤백(admin 복귀)
- Then 각 상태에서 양방향 비밀번호 변경이 반영된다. G1은 엔트리 생성 전에 ACL·limits·TLS·충돌 부재만 보고, G2가 비로소 신원 바인드·권한·전파를 검사한다. 예약 DN에 기존 일반 엔트리가 있으면 `prepare`가 거부한다. 노드별 관리자 비밀번호 상태에서의 롤백은 한 방향이 정체함을 명시적으로 경고/거부.

### `AC-007` — 기본값 불변
- Covers: `REQ-006`
- Given `LDAP_REPLICATION_IDENTITY` 미지정
- When 기존 `test-wiped-node-resync.sh`·`replication-chaos-e2e.yml`·`test-bootstrap-seed.sh` 실행, cn=config 전체와 렌더된 olcSyncrepl 비교
- Then 모두 통과하고 cn=config가 변경 전과 동일(ACL·limits는 `prepare`/`dedicated`에서만 설치).

### `AC-008` — D43 완화 (게이트된 마지막 단계)
- Covers: `REQ-010`, `REQ-002`
- Given 전용 모드, 노드마다 다른 `LDAP_ADMIN_PASSWORD`, 같은 복제 비밀번호, AC-005·AC-011·AC-012가 CI에서 녹색
- When 노드 2에서 관리자로 쓰기
- Then 노드 1에 반영된다. 전용 모드가 아니면 기존 D43 기동 실패가 그대로다.

### `AC-009` — 신원 바인드 감사·비밀 비노출
- Covers: `REQ-009`
- Given accesslog 활성(기본 ops `reads bind`), 기본 로그 레벨 `stats`
- When 올바른/틀린 비밀번호로 신원 바인드(단순), EXTERNAL 소비자
- Then 단순 바인드는 cn=accesslog에 `reqDN=<신원>`, `reqResult=0`/`49`. EXTERNAL은 cn=accesslog의 바인드 레코드가 `reqDN`·`reqAuthzID` 비어 있고, 신원은 slapd `stats` 로그의 `authcid="cn=replicator"`로만 확인된다. 컨테이너 `/proc/1/environ`에 비밀번호 없음.

### `AC-010` — 차트 렌더
- Covers: `REQ-012`, `REQ-014`
- Given `replication.identity=dedicated`/미지정, TLS 켬/끔, `networkPolicy.ingressFrom` 기본/좁힘, 오프라인 렌더
- When `helm template`·`verify-chart-schema.sh`
- Then 미지정은 현재와 같은 매니페스트. 전용+TLS 꺼짐은 렌더 실패. 전용+기본 `ingressFrom`은 경고. 전용은 복제 Secret env와 `FIRST_NODE`(`IsInstall`일 때만), 점검 CronJob·NetworkPolicy 허용 규칙을 낸다. Secret 부재+오프라인이면 안내와 함께 실패.

### `AC-011` — TLS 강제와 평문 거부
- Covers: `REQ-013`
- Given 전용 모드, TLS 클러스터(저장소 TLS E2E와 같은 구성: 서버 인증서 SAN + `tls.caFile`)
- When (a) 평문 `ldap://` 바인드로 읽기 (b) 소비자를 평문 `ldap://`로 지정 (c) `starttls=critical` (d) 틀린 CA (e) TLS 없이 전용 모드로 기동
- Then (a) 아무것도 읽히지 않음(엔트리 0) (b) 데이터가 오지 않고 정체(rc -101) (c) 정상 복제 (d) 정체(rc -1), 평문 폴백 없음, CA 복구 시 자동 복구 (e) 기동 거부.

### `AC-012` — 노드 1 부트스트랩 판정(fail-closed)
- Covers: `REQ-011`
- Given 라이브 데이터가 있는 클러스터에서 sid-1 볼륨을 지움
- When (a) 틀린 복제 비밀번호 (b) 틀린 CA/TLS 실패 (c) 피어 중지(DNS 실패) (d) 피어 포트 닫힘 (e) 첫 클러스터 생성(피어 비어 있음/미기동) (f) (a)에 `FIRST_NODE=true`
- Then (a)(b) 기동 실패, 베이스·신원 미생성, 피어 데이터 불변 (c)(d) 현재 동작 유지(베이스 생성), 로그에 "unreachable" 분류 (e) `FIRST_NODE=true` 필요(없으면 거부), 있으면 생성 (f) 생성(경고 로그) — 단 어떤 피어든 베이스가 확인되면 생성하지 않는다. 마커가 있으면 플래그는 무시되고 경고.

## Architecture and decisions

- Relevant ADR/design links: [openldap-2.6-hardening D3·D8·D10·D13](../openldap-2.6-hardening/CHANGE.md), [issue-206](../issue-206/CHANGE.md), [generated-credentials D40–D45](../generated-credentials/CHANGE.md), [docs/ha-profile.md](../../ha-profile.md).
- ADR threshold result: `required` — 보안 경계(자격 증명 수용 경로·ACL·TLS 요구)와 D43 변경. 수용 시 ADR 초안(T-005).

### 사실(코드 근거)

| 항목 | 현재 동작 | 근거 |
|---|---|---|
| 복제 켜기·peer | `LDAP_REPLICATION_ENABLED`, `LDAP_REPLICATION_PEERS`(자기 포함, 서수 순서) | `image/entrypoint.sh:490-492`; `charts/ldapium/values.yaml:236-240` |
| 바인드 DN/비밀번호 | `..._BIND_DN` 기본 admin DN; `..._PASSWORD(_FILE)`, 폴백 admin 비밀번호; 개행 금지 | `entrypoint.sh:570-583` |
| olcSyncrepl | 부팅마다 통째로 `replace`; rid=peer 위치; self 제외; `bindmethod=simple`·`credentials` 평문; **`starttls`/`tls_*` 없음** | `entrypoint.sh:1541-1585` (빌더 `:1567-1568`) |
| 순서 | `olcSyncrepl` 먼저, 그다음 `olcMultiProvider TRUE` | `entrypoint.sh:1541-1546,1576-1582` |
| 오프라인 편집 | cn=config는 `slapmodify -n 0`/`slapadd`/`slapcat`로만(임시 slapd 금지) — `#206` | `entrypoint.sh:1472-1482`, [issue-206](../issue-206/CHANGE.md) |
| 베이스 DIT 선출 | 노드 1만 생성, 피어에 베이스가 있으면 양보. 탐지는 복제 DN으로 바인드해 `1.1` 검색, **어떤 실패든 "없음"** | `entrypoint.sh:1109-1131`, 생성 `:1140-1141` |
| 시드 | 베이스를 만든 노드에서만, 마커 이전, 실패 시 롤백 | `entrypoint.sh:1155-1181`(#203/#204) |
| 기본 ACL | `{0} userPassword,shadowLastChange: self write / anonymous auth / * none`; 렌더되는 catch-all `{2}`/`{4}`가 `by self write` 후 `by users read` | `image/ldifs/01-cn-config.ldif:90-93`, `entrypoint.sh:794-815`(`by self write` `:803,814`) |
| 크기 제한 | `olcSizeLimit` 기본 10000(rootDN은 무제한) | `entrypoint.sh:157-169`, `01-cn-config.ldif:74-75` |
| ppolicy 기본 정책 | `olcPPolicyDefault`는 **부트스트랩 시에만** 렌더(마커 기록 `:1186` 이전). 기존 볼륨에서 `LDAP_PASSWORD_POLICY_ENABLED=false`로 바꿔도 제거되지 않음. 기본 잠금 5회/900s | `entrypoint.sh:979-993,1186`; `:251-264` |
| accesslog | 별도 DB(`cn=accesslog`)라 복제 대상 아님; `olcAccessLogSuccess: FALSE` = 실패도 기록; 기본 ops `reads bind` | `entrypoint.sh:953-963` |
| 로그 레벨 | 기본 `stats`(+복제 시 `sync`) | `entrypoint.sh:143,510` |
| mTLS | `olcTLSVerifyClient: try`, `olcAuthzRegexp`(CN→DN); 해당 CA가 서명한 어떤 인증서든 `by users` 권한 | `entrypoint.sh:459-484,739-740` |
| TLS와 복제 | `LDAP_REQUIRE_TLS`는 피어를 `ldaps://`로만 강제. 인증서 검증 매개변수 없음 | `entrypoint.sh:551`; 차트 TLS 경로는 "UNVERIFIED" `charts/ldapium/values.yaml:210-215` |
| 평문 노출 제거 | 부팅 끝에서 `LDAP_ADMIN_PASSWORD`·`LDAP_REPLICATION_PASSWORD` unset | `entrypoint.sh:1598-1603` |
| 차트 | 모든 파드가 같은 admin Secret을 env로; `replication.bindDN`/`existingSecret` 노브는 있으나 ACL 없음; 프로브는 ldapi `-Y EXTERNAL` `ldapwhoami`뿐 | `charts/ldapium/templates/statefulset.yaml:88-92,193-211,212-243`; `values.yaml:246-253` |
| NetworkPolicy | 복제는 차트 파드 간 허용, 그러나 389/636은 `ingressFrom`(기본 같은 네임스페이스 전체)에도 열려 있고 **바인드 신원은 구분하지 못함** | `charts/ldapium/templates/networkpolicy.yaml:23-41`; `values.yaml:519-520` |
| 기존 모니터링 | `openldap_replication_delta`, `LDAPiumReplicationLag`(30s)/`ContextCSNDivergence`(300s); exporter는 외부 컴포넌트 | `docs/ha-profile.md:189-233,252-255`; `statefulset.yaml:288-312` |
| 기존 마스킹 | `credentials="..."` 마스킹 | `scripts/detect-config-drift.sh:122-134`, `scripts/export-incident-evidence.sh:530-534` |

### 실험 결과 (OpenLDAP 2.6.15, Colima, 2026-10-06)

개정 1의 E1–E12는 유지한다. **E2·E5·E9–E12의 ACL은 개정 1의 "`{0}` 규칙 첫 by 절" 방식이었고 D51(개정 2)로 대체**되었으나, 거기서 입증한 복제 동작(속성 전달·수렴)은 E13–E14에서 새 ACL로 재확인했다.

| ID | 무엇을 | 결과 |
|---|---|---|
| E1 | 2노드, 복제 DN + 엔트리 생성, **ACL 변경 없음** | 엔트리 6개 복제, 소비자에 admin·사용자 `userPassword` **없음**, contextCSN 동일. cn=config에서 `credentials="replpw1"` 평문 조회 |
| E2 | 개정 1: `{0}`의 첫 by 절 + `olcLimits` | add/modify/delete/비밀번호 변경 양방향 반영, wipe 재동기화에서 admin 해시 도착(0→1) |
| E3 | 기본 ACL 새 노드를 프로바이더로 두고 비밀번호 변경 | 피어에서 `userPassword` **통째로 삭제**, contextCSN 동일 |
| E4 | 잘못된 복제 비밀번호 | 소비자 `rc 49 retrying`, 새 쓰기 미반영, accesslog `reqDN=<신원> reqResult=49`. 5회 후 `pwdAccountLockedTime`, **올바른 비밀번호도 49**(900s) |
| E5 | 개정 1 프로토타입, 3노드 동시 콜드 스타트 | 3노드 수렴(DN 6, admin 해시, 신원 엔트리), 각 노드 쓰기·비밀번호·삭제 전파. 신원 쓰기 50, cn=config·accesslog 32 |
| E6 | 이중 값 회전 + 롤링 재시작(카나리) | 구·신 바인드 모두 성공, 카나리 3/3/3, 구 값 제거 후 구 49·신 성공 |
| E7 | sid 1, sid 2 wipe | DN 12·해시 8 복구, 베이스 entryUUID 일치, `peer already has the base DIT` |
| E8 | `LDAP_SIZE_LIMIT=5`, 엔트리 18 | limits 있음 18/18, 제거 시 **5개에서 정체**, `rc -101` 반복 |
| E9 | 구 이미지 → ACL 선행 → 노드별 전환 → 롤백 | 각 단계 양방향 비밀번호 변경 반영, 롤백 후 binddn=admin |
| E10 | ACL이 전환 노드에만 있음(프로바이더 무ACL) | 비밀번호 변경이 소비자에서 해시 손실 |
| E11 | TLS+mTLS, `bindmethod=sasl saslmech=EXTERNAL` + `tls_*` 온라인 전환 | 인증서 CN=replicator → SASL 신원 `cn=replicator`(엔트리 없이), `dn.exact` ACL 적용, 해시 복제 성공, cn=config엔 키 **경로**만 |
| E12 | 전용 모드, 노드마다 다른 관리자 비밀번호 | 복제 정상. **admin 해시가 복제되도록 ACL이 있을 때** 노드 2는 두 비밀번호를 모두 수락(E21에서 ACL 부재 시 다름을 확인) |
| E13 | **D51 ACL**: `to * by dn.exact="<repl>" read by * break`를 `{0}`에 삽입(2노드, 온라인) | 읽기: admin 해시 1, 사용자 해시 1, 운영 속성 3. **쓰기 전부 50**: 자기 `description`, `pwdEndTime` 추가, `pwdPolicySubentry` 변경, `pwdAccountLockedTime` 추가, 자기 비밀번호 replace(정책 `pwdAllowUserChange: FALSE`일 때 50 "User alteration…"; **정책을 TRUE로 바꿔도 ACL이 50으로 거부**), 타 엔트리 수정, 자기 삭제·엔트리 추가("no write access to parent"). 엔트리 불변. rootDN(`cn=admin`)은 신원 엔트리를 수정 가능(회전 경로) |
| E14 | 같은 ACL에서 일반 사용자 회귀 | alice 자기 `description` 쓰기 성공, admin `userPassword` 읽기 0·`cn` 읽기 1, alice 인증 성공, alice의 신원 엔트리 수정 50 → 다른 주체 권한 불변 |
| E15 | 잠금 매트릭스 | 12회 틀린 바인드 후 올바른 바인드 성공·잠금 속성 없음: (1) 기존 볼륨 정책 활성 (2) `LDAP_PASSWORD_POLICY_ENABLED=false` 재시작(`olcPPolicyDefault` **여전히 존재**) + 기본 정책 `pwdMaxFailure 1`·영구 잠금·`pwdMaxAge 60` 강화 (3) 회전 중 이중 값. 대조군 alice는 6회 후 잠김. E15b(`cn=replication-policy,<root>`, 개정 2 구조): 정책 비활성으로 **처음** 부트스트랩한 볼륨(`olcPPolicyDefault` 없음)도 12회 후 성공; 해당 정책을 일부러 `pwdLockout TRUE`로 바꾸면 3회 후 잠김 → **명시적 `pwdPolicySubentry`가 기본 정책 없이도 적용됨** |
| E16 | 예약 DN 충돌 | 일반 엔트리 `cn=ghost`(비밀번호 보유)는 규칙 설치 전 admin `userPassword` 읽기 0, **설치 직후 1** → "비활성 ACL"은 같은 DN의 기존 엔트리에 즉시 활성 |
| E17 | TLS(저장소 TLS E2E와 같은 구성: CA 서명 서버 인증서, `LDAP_TLS_CA_FILE`), ACL `ssf=128` 포함: `to * by dn.exact="<repl>" ssf=128 read by dn.exact="<repl>" none by * break` | 저장소 ldaps 경로(단순 바인드, `tls_*` 없음)로 클러스터·해시 복제 정상(T1). **평문 바인드**: admin `userPassword` 0, 베이스 엔트리 0, 서브트리 0. ldaps·`-ZZ`(StartTLS): 해시 읽힘. 양방향 add+해시 OK. 소비자를 평문 `ldap://`로: **정체(rc -101)**. `starttls=critical tls_reqcert=demand`: 정상·밀린 쓰기도 도착. 틀린 CA(`tls_cacert=ca2`): **정체(rc -1)**, 평문 폴백 없음, CA 복구 시 도착. 매개변수 없는 기본 ldaps 경로도 전역 CA를 틀리게 하면 정체(=검증함), 복구 시 도착 |
| E18 | **회전 중단·조기 제거·롤백**(3노드) | n1만 새 비밀번호로 재기동 → 지문 n1=신, n2·n3=구(게이트 닫힘). **구 값을 일찍 제거해도 즉시는 정체하지 않음**(지속 세션 유지, 제거가 복제됨). **재연결을 유발(n1 재시작)하면** n2·n3 소비자 `rc 49` 10–11회, n1에서 쓴 카나리가 n2·n3에 없음(c2: 1/0/0), n2·n3에서 쓴 것은 n1에 도착. n1에 구 값 재추가 → 50초 내 전부 수렴. 이후 n2·n3 롤 → 지문 전부 신 → 게이트 열림 → 정리(`replace`) → 구 49/신 성공. 롤백(E18b): n1을 신→구 Secret으로 복원(구 값 유효) → 복제 정상, 신 값 제거 후 n2 재시작에도 정상 |
| E19 | **현재 코드**: 데이터(사용자 3)가 있는 2노드에서 sid-1 wipe + 틀린 복제 비밀번호 | 노드 1 로그 `loading base DN + admin entry (slapadd -n 1)`(새 DIT 생성). 30초 후 n1·n2 모두 사용자 0, n2에서 `syncrepl_del_nonpresent` 3건. 비밀번호를 고쳐도 복구되지 않음(데이터 영구 소실) |
| E20 | 프로브 결과 신호(`ldapsearch ... 1.1`) | 성공 rc=0; 틀린 비밀번호 rc=49; 포트 닫힘·DNS 실패·피어 중지 rc=255 + 디버그 `Connection refused (111)`/`getaddrinfo failed`; **TLS 실패(틀린 CA)도 rc=255 + "Can't contact LDAP server"**이나 디버그 출력의 앞 2건에는 `refused/getaddrinfo`가 **없고** TLS 트레이스만 있음(전체 출력 대조는 구현 시 T-022) → rc만으로는 구분 불가, **디버그 출력 패턴으로 "도달 불가"를 판정하고 그 외 비0은 모두 fail-closed**. 타임아웃(블랙홀)은 미검증 |
| E21 | 노드별 다른 관리자 비밀번호 + `admin` 신원 롤백(ACL 양 노드) | 롤백 후 n1은 One만, n2는 One·Two 모두 수락. **n1→n2 방향(소비자 n2가 Two로 n1에 바인드)은 `rc 49` 10회로 정체**, 다른 방향은 정상. (ACL 없는 변형에서는 admin 해시가 복제되지 않아 n2도 Two만 수락 → 양방향 정체) |
| E22 | 점검 프로토타입(원격 모드: root + 신원 바인드, `slapcat` 불필요) | 정상: PASS. **하위 트리 한정 `userPassword` 거부**(운영자 커스텀 ACL을 첫 규칙으로): 관리자 해시 1, 엔트리 수 9/9, contextCSN 동일 — 즉 모든 단순 신호는 정상 — 인데 점검은 FAIL: 신원 시점 ≠ root 시점(alice·bob `uid=…,ou=people`의 해시 체크섬이 `e3b0c442`=빈 값), n1↔n2 교차 비교도 FAIL. 베이스 카나리는 이 결함에서 통과(카나리만으로 불충분). 이중 값 단계: 새 비밀번호가 외부 바인드로는 성공해도 소비자 지문(`87de02da`)≠기대(`661d2dab`)로 FAIL. **ldapi EXTERNAL로는 cn=config를 읽을 수 없음(`No such object (32)`)**, 온노드 읽기는 `slapcat -n 0 -o ldif-wrap=no`로 성공, 원격은 `cn=admin,cn=config` |
| E23 | EXTERNAL 소비자의 감사 증거 | cn=accesslog의 `SASL(EXTERNAL)` 바인드 레코드는 `reqDN`·`reqAuthzID`가 **빈 값**이고 같은 세션(reqSession)에 다른 레코드 없음; `reqAuthzID=<신원>`인 레코드는 단순 바인드 시기의 검색뿐(EXTERNAL 시기 0). 영속 검색은 accesslog에 기록되지 않음. slapd `stats` 로그에는 `conn=1034 op=0 BIND authcid="cn=replicator" authzid="cn=replicator"`가 있음. accesslog 세션 번호(1035)와 `conn=`(1034)의 대응은 **입증하지 못함** |
| E24 | ssf 없는 구성의 평문 동작(별도 실험 아님, 기존 결과 재해석) | E2·E5·E9·E13은 `ssf` 없이 평문 `ldap://`로 해시까지 복제했다 → **`ssf` ACL과 TLS 요구 없이는 평문으로 해시가 전달되는 것을 막는 것이 없다**. E17의 평문 소비자 정체는 `ssf=128` ACL의 효과 |

### 결정

| ID | 결정 | 이유 · 비용 · 탈출구 |
|---|---|---|
| D50 | **주 설계**: 단순 바인드 전용 신원 `cn=replicator,<LDAP_ROOT_DN>`. 신규 env `LDAP_REPLICATION_IDENTITY=admin\|prepare\|dedicated`(기본 `admin`). `dedicated`면 `..._BIND_DN` 기본값이 위 DN, 복제 비밀번호 필수, **TLS 필수**(D60) | cn=config에 복제 비밀번호는 여전히 평문 · `admin`으로 롤백(조건: D62) |
| D51 (개정) | ACL: **기존 `{0}` 앞에 명시적 첫 규칙** `olcAccess: {0}to * by dn.exact="<신원>" ssf=128 read by dn.exact="<신원>" none by * break`. 신원은 TLS 위에서 모든 것을 읽고 **무엇도 쓰지 못한다**(자기 엔트리·`pwd*` 포함, E13), TLS가 아니면 **아무것도 못 읽는다**(E17). `by * break`로 다른 주체는 기존 규칙 그대로(E14). `olcLimits: dn.exact="<신원>" size=unlimited time=unlimited`. 신원 엔트리를 바꿀 수 있는 것은 **rootDN뿐**(ACL 우회, E13) — 비root 관리자는 회전할 수 없으며 필요하면 별도 규칙을 운영자가 추가 | 개정 1의 "첫 by 절 삽입"은 catch-all `by self write`(`:803,814`)를 막지 못했다 · `ssf=128`은 E17의 TLS 연결에서 충족됐다(협상된 프로토콜·암호는 기록하지 않음) · 운영자 커스텀 ACL이 첫 규칙 앞에 오면 깨질 수 있어 D59 점검 필수(E22). `time=unlimited` 필요성은 미분리 검증 |
| D52 (Q1 결정) | **비활성 ACL을 무조건 설치하지 않는다.** 모든 프로바이더에 **먼저**(어느 노드가 전환하기 전에) 설치하되, `LDAP_REPLICATION_IDENTITY=prepare`(또는 `dedicated`)일 때만, **충돌 검사 통과 후**: (1) 예약 DN에 기존 엔트리가 있고 관리 표식(`description: ldapium-managed replication identity`)이 없으면 거부(E16) (2) `LDAP_TLS_MUTUAL_AUTH`이고 `LDAP_TLS_AUTHZ_REGEXP/DN`이 `cn=replicator`를 예약 DN으로 매핑하면(셸에서 평가) 거부 (3) 이미 같은 ACL이 있으면 멱등. 설치는 신규 부트스트랩=01-cn-config.ldif, 기존 볼륨=부팅 시 오프라인 `slapmodify -n 0`(`hd_clear` 패턴 `entrypoint.sh:1210-1216`) | 예약 DN의 기존 엔트리·인증서 매핑이 ACL을 즉시 활성화(E16, E11) → "비활성"은 조건부이므로 사전 검사와 명시적 준비 단계가 필요 · 비용: 모드 하나 추가, 준비 롤아웃 1회 · 인증서 매핑 평가는 미구현·미검증 |
| D53 (개정) | 신원 엔트리는 **노드 1의 베이스 DIT 생성에 포함**(`slappasswd -T` 해시, 관리 표식 `description`)하고, **항상 자체 정책 `cn=replication-policy,<root>`**(`pwdLockout FALSE`, `pwdMaxAge 0`, `pwdAllowUserChange FALSE`)를 **`pwdPolicySubentry`로 명시**한다. `ou=policies`·`LDAP_PASSWORD_POLICY_ENABLED`와 무관(정책 DN을 `ou=policies` 아래에 두지 않음) | 기본 정책에 의존하면 `LDAP_PASSWORD_POLICY_ENABLED=false` 재시작이 `olcPPolicyDefault`를 지우지 않아(`:986-993`는 부트스트랩 전용) 강화된 기본 정책이 신원을 잠글 수 있다(E15) · 명시적 subentry는 기본 정책 부재에서도 적용됨(E15b) · 잠금 제외로 온라인 추측 방어가 없어 고엔트로피 필수·accesslog 감시 |
| D54 | 기존 클러스터: 신원 엔트리·정책은 **온라인 복제 쓰기**로 만든다(`replication-identity.sh ensure`). 오프라인 쓰기는 sid 000 CSN이라 복제되지 않는다(`openldap-2.6-hardening` D13) | 운영 CLI 필요 |
| D55 (개정) | **회전 상태 기계**: R0 안정(값 1) → R1 신 값 추가(값 2, 모두 유효) → R2 롤링(노드별 새 `LDAP_REPLICATION_PASSWORD`로 재기동, 노드마다 지문 확인) → R3 게이트(모든 노드 지문=신) → R4 정리(`replace`로 신 값만). 재개 규칙: 상태는 **디렉터리에서 유도**(값 개수 + 노드별 지문)하며 R1–R3 어디서든 같은 명령을 다시 실행하면 이어진다. **R3 게이트가 닫혀 있으면 R4를 거부**(우회 옵션 없음). 롤백: R1–R3에서 재기동한 노드를 **구 Secret으로 복원**하고(구 값 유효, E18b) 신 값을 제거. 조기 제거 복구: 구 값을 그 값을 잃은 노드에 재추가(E18) — 지속 세션은 제거 후에도 유지되므로 **재연결(재시작·파드 이동·네트워크 순단) 때 처음 드러나는 잠복 위험**(E18). 비밀번호는 부팅 시 cn=config에 구워지므로(`entrypoint.sh:1555-1568`) Secret만 바꿔서는 반영 안 됨 → 재시작 필수 | E6, E18 · 차트가 Secret 변경 시 자동 롤아웃하는지는 결정 후(T-017) |
| D56 (Q2 결정) | opt-in 유지. D43 기동 실패는 **`dedicated`에서만**, **결함 수정 + 중단 회전·복구·fail-closed 부트스트랩 E2E가 존재한 뒤**에야 완화(마지막 Implement 단계, 게이트). 기본·`admin`·`prepare` 모드는 D43 유지 | E12/E21 · 노드 1의 admin 해시가 복제되어 노드 간 관리자 비밀번호가 "분리"되지 않음 |
| D57 (Q3 결정) | SASL EXTERNAL은 **후속 패키지**. 먼저 단순 바인드 + TLS를 검증. 실증: E11, E23. 감사 정정: EXTERNAL은 cn=accesslog에서 신원이 **보이지 않는다(바인드 레코드 `reqDN`·`reqAuthzID` 빈 값, 영속 검색 미기록)**; slapd `stats` 로그에는 있음 | 차트 TLS 경로 "UNVERIFIED"·인증서 회전 절차·CA 전용화 필요 |
| D58 | 기본값 불변: `identity` 미지정/`admin`이면 olcSyncrepl·cn=config 동일. 커스텀 `LDAP_REPLICATION_BIND_DN`(비관리자)은 동작 유지 + "ACL이 필요, `check`로 점검" 경고 로그 | 기존 배포 호환 · 경고는 로그뿐 |
| D59 (개정) | **점검 `scripts/check-replication-identity.sh`**: 모드 `--local`(노드 안: `slapcat -n 1`/`-n 0`, ldapi) / `--remote`(네트워크: root·신원·`cn=admin,cn=config` 바인드, 비밀번호는 파일). 검사: (a) 노드별 root 시점과 신원 시점의 **DN 단위 체크섬**(`dn`·`entryCSN`·`userPassword` 값 해시 — 값 순서 정규화 필요; 실제 구현은 전 속성 체크섬으로 확장)과 엔트리 수를 비교하고, 노드 간 교차 비교(둘 다 양방향) (b) 노드의 실제 `olcSyncrepl` 바인드 DN과 `credentials` 지문 vs 기대(`slapcat -n 0 -o ldif-wrap=no` 또는 원격 cn=config) (c) 노드마다 카나리를 쓰고 다른 노드에서 **신원으로 해시 포함** 관측 후 삭제 (d) 주기 실행. 게이트는 **G1(엔트리 생성 전, 설정만 검사)**: 모든 프로바이더의 ACL·limits·`ssf` 규칙 존재, TLS 검증 설정, 예약 DN 충돌 부재(신원으로 바인드하지 않는다 — 아직 없음) / **G2(생성 후, 권한·전파 검사)**: 신원·정책 엔트리 존재, 각 피어에 TLS로 신원 바인드, 신원 시점=root 시점, 전파 카나리, 지문. 종료코드 0/1/2 | E22 · **못 잡는 것**: 점검 간격 사이의 일시적 정체, 이미 속성이 사라진 뒤 root 시점 자체가 틀린 경우(손실은 root 시점도 동일), LWW로 버려진 쓰기, 해시가 "작동하는지"(비교만), 카나리가 심지어 놓인 하위 트리 밖의 ACL 결함(DN 단위 비교만 잡음), 지속 세션이 쓰는 자격 증명(구성 vs 실행 중 소비자) — 재연결 전에는 구성과 실행이 다를 수 있음, 점검자가 root 자격이 없을 때 root 시점 |
| D59b | **주기 실행 계약**: 차트 `replication.check.enabled`(기본 꺼짐)가 CronJob을 만들어 `--remote`로 헤드리스 DNS의 각 파드에 접속(관리자·복제 Secret 마운트). **결과 노출 위치는 Job 종료 상태**이며 kube-state-metrics의 `kube_job_status_failed`를 쓰는 PrometheusRule 알림(`LDAPiumReplicationIdentityCheckFailed`)과 Job 로그. exporter(외부 `openldap_exporter`)에는 소비자 상태 지표가 없고 사이드카 없는 구조(`ha-profile.md:252-255`)를 유지한다. "#218c 메트릭 사이드카"는 저장소에서 찾지 못함(미확인). CronJob은 관리자 Secret을 가지므로 LDAP 파드와 같은 권한이며 `networkpolicy.yaml`에 점검 파드 허용 규칙이 필요하다(백업 CronJob 규칙 `:54-` 패턴). 운영자 대안: `--local`을 `kubectl exec`/`docker exec`로 실행 | 구현 가능성은 설계 수준 · 알림은 `promtool` 단위 테스트 필요(T-018) |
| D60 (신규, F4) | **전용 모드는 검증된 TLS 필수**: `LDAP_TLS_ENABLED=true`, 모든 피어 `ldaps://`(또는 `starttls=critical`), 렌더되는 olcSyncrepl에 `tls_reqcert=demand`·`tls_cacert=$LDAP_TLS_CA_FILE`, 차트는 `tls.enabled` 없이 `identity=dedicated`면 렌더 실패. ACL의 `ssf=128`(D51)이 평문 바인드의 읽기를 막는다(E17). 선택적 피어 제한(`peername.ip`/`sockurl`)은 **문서화만**(문법·동작 미검증); Kubernetes에서는 파드 IP가 바뀌므로 NetworkPolicy가 담당 — 다만 389/636은 `ingressFrom`(기본 같은 네임스페이스)에도 열려 있고 NetworkPolicy는 바인드 신원을 구분하지 못하므로 `ingressFrom` 축소가 통제이며(`networkpolicy.yaml:23-41`, `values.yaml:519-520`), 전용 모드+기본값은 렌더 경고(T-017) | E17 · 비용: TLS 운영 의존(차트 TLS 경로 미검증, 이 패키지 검증에 포함) · 평문 `ldap://` 배포는 전용 모드 사용 불가(탈출구: `admin` 모드 유지) |
| D61 (신규, F2) | **노드 1 부트스트랩 판정(전용 모드)**: 피어별 프로브를 분류 — `OK`(rc 0, 베이스 확인), `UNREACHABLE`(rc 255 + 디버그에 `Connection refused`/`getaddrinfo failed`/타임아웃/`unreachable` 패턴), `REACHABLE_FAIL`(그 외 모든 비0: 49·50·TLS 실패·예상 밖 결과, **분류 불가는 여기**). 규칙: (1) 어느 피어든 `OK` → 베이스 생성 안 함(불변). (2) 아니고 어느 피어든 `REACHABLE_FAIL` → **기동 실패**(베이스·신원 미생성). 단 `LDAP_REPLICATION_FIRST_NODE=true`이면 진행(경고). (3) 모든 피어 `UNREACHABLE` → **현재 동작 유지**(생성). 따라서 **첫 클러스터 생성**에서 피어가 이미 떠 있으나 비어 있으면(신원 엔트리가 아직 없어 49) 플래그가 필요하고, 복구에서 인증/TLS 오류면 플래그 없이는 막힌다. 플래그는 **마커가 없을 때만** 의미가 있고 마커가 있으면 무시+경고; 차트는 `Release.IsInstall`일 때만 설정(업그레이드에서는 빠짐 → 이후 wipe된 pod 0는 fail-closed); compose는 첫 기동 후 제거. 관리자 모드(`admin`)의 프로브는 변경 없음 | E19(현재 코드 데이터 손실)·E20(신호) · **잔존 위험(현행 유지)**: 피어가 부팅 중이라 포트가 막혀 있으면 `UNREACHABLE`로 분류돼 생성될 수 있다 · 타임아웃 분류와 `FIRST_NODE` 흐름은 구현·테스트 전(T-014, AC-012) |
| D62 (신규, F7) | **롤백 전제**: `admin` 신원으로 즉시 롤백은 **모든 노드의 관리자 비밀번호가 모든 피어에서 유효**할 때만 성립한다(공유 관리자 비밀번호). 노드별 관리자 비밀번호(D56 완화 상태)에서는 한 방향 소비자가 정체한다(E21) → 완화 모드에서는 롤백 대신 "신원 앞으로 고침"(복제 비밀번호 복구·재추가)을 절차로 한다. 점검이 이 조건을 롤백 전에 경고 | E21 |

### 잔여 위험 (정직하게)

- cn=config의 `credentials`는 **여전히 평문**이다. 달라지는 것은 그 값이 admin이 아니라 읽기 전용 신원의 비밀번호라는 점뿐이다. 읽을 수 있는 주체: `cn=admin,cn=config`(E1), 볼륨 접근자. 파일/SASL 비밀 참조는 미검증. EXTERNAL이 이를 없애는 유일한 검증된 경로(D57).
- 잠금 제외(D53)는 신원에 대한 온라인 추측 방어를 없앤다. 고엔트로피와 accesslog 감시로만 보완. (이제 신원은 자기 `pwdEndTime`/정책을 못 바꾸므로 "자기 만료로 소비자 정체" 경로는 막힘: E13.)
- 신원 엔트리를 UI/API의 **rootDN 세션**이 지우거나 바꿀 수 있다(ACL 우회, 보호 DN 개념 없음). 삭제는 복제되어 클러스터가 49로 정체한다(추론, 미검증). D59 점검과 알림으로만 보완.
- D61: 피어가 부팅 중이거나 블랙홀이면 `UNREACHABLE`로 분류되어 현재와 같이 베이스를 만들 수 있다(현행 위험 유지). 타임아웃 신호는 미검증.
- 침해된 프로바이더 노드의 로컬 쓰기는 모든 피어로 복제된다(완화 불가).

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `image/entrypoint.sh`(env 파싱, `prepare` 충돌 검사·ACL/limits, 베이스 DIT 확장, 프로브 분류, olcSyncrepl TLS 분기), `01-cn-config.ldif`·`03-base-structure.ldif`, 신규 `scripts/check-replication-identity.sh`·`scripts/replication-identity.sh`. HTTP API 변경 없음 |
| Dependencies / lockfiles | N/A — 신규 의존성 없음(`ldap*`, `slappasswd`, `openssl`은 이미지에 있음; `nc`는 없음 → 프로브는 `ldapsearch -d` 출력 패턴 사용) |
| Runtime / toolchain | OpenLDAP 2.6.15 기준 동작만 검증. 업그레이드 시 `olcLimits`/`ssf` ACL 문법 재검증 |
| CI / CD | `e2e.yml`에 신규 라이브 테스트, `replication-chaos-e2e.yml`에 전용 모드 시나리오, TLS E2E에 전용 모드 매트릭스(T-021/T-023) |
| Release / packaging | 릴리스 노트: 신규 env/값, `prepare` 단계(기본에서 cn=config 변경 없음). 이미지 롤아웃·`prepare` 완료 전 전환 불가(G1) |
| Generated output | N/A — 생성 산출물 없음(차트 스키마는 `verify-chart-schema.sh`) |
| Security / supply chain | Class D. 위협 모델 참조. 기존 `credentials="..."` 마스킹(`scripts/detect-config-drift.sh:122-134`, `scripts/export-incident-evidence.sh:530-534`)은 단순 바인드 형식에 유효 — T-003이 회귀로 확인. 점검 CronJob이 관리자 Secret을 가짐 |
| Offline / air-gap | 영향 없음(이미지 내 도구만). 차트 Secret 생성은 오프라인 렌더 실패 규칙(D42) |
| Documentation / operations | `image/README.md:300-309` 임시 slapd 서술이 `#206` 이후 틀림 — 같이 수정, `values.yaml:246-248`의 존재하지 않는 `REPLICATION-CONTRACT.md` 참조 제거, `docs/ha-profile.md` 모니터링 한계, D43 후속 |
| Portfolio / downstream repositories | N/A — 이 저장소 내부(UI는 신원 엔트리를 트리에서 볼 수 있음; 보호 기능은 비범위) |

## 위협 모델

| 시나리오 | 현재(admin 바인드) | 제안(전용 신원 + TLS) |
|---|---|---|
| 복제 비밀번호 유출 | = 관리자 비밀번호 → rootDN 전권 + `cn=admin,cn=config`(같은 비밀번호)로 설정 탈취, 모든 노드 쓰기 | 모든 엔트리·`userPassword` 해시 **읽기**(TLS 위에서만; 오프라인 크래킹 가능, 복제본이 이미 전체 데이터를 가지므로 새 노출은 아님). **쓰기·자기 엔트리 수정·자기 비밀번호 변경·pwd 정책 속성 변경 전부 50**(E13), cn=config/accesslog 32. 평문 접속으로는 아무것도 못 읽음(E17). 잠금이 없어 온라인 추측 가능 |
| 관리자 비밀번호 유출 | 위와 동일 | 관리자 전권(그대로)이나 복제 자격과 분리 |
| 침해된 소비자(파드/볼륨) | cn=config에서 admin 비밀번호 획득 → 모든 피어 쓰기·설정 변경 | 읽기 전용 신원 비밀번호만 획득 → 피어 읽기만. **침해 노드의 로컬 쓰기는 여전히 복제됨**(미완화) |
| `userPassword` 해시 전송 | 평문 `ldap://`이면 와이어 노출 | 전용 모드는 TLS 필수(D60) → 와이어 보호 |
| 복제 바인드 감사 | accesslog `reqDN=<admin>` | 단순: `reqDN=<신원>`, 실패 `reqResult=49`(E4). EXTERNAL: accesslog에 **신원이 없음**(E23), `stats` 로그에만 |
| ACL 누락/축소 | N/A(root는 우회) | **조용한 데이터 손상**(E1, E3, E10) 또는 정체(E8). contextCSN 불변. D52 준비 단계 + D59 점검 |
| 신원 엔트리 삭제/변조 | N/A | rootDN만 가능(ACL). 삭제는 복제되어 전 클러스터 정체(추론). 점검·알림 |
| 예약 DN 충돌/인증서 매핑 | N/A | 같은 DN의 일반 엔트리·매핑된 인증서가 ACL을 즉시 얻음(E16, E11) → D52 사전 검사 |
| 비밀번호 회전 중단 | N/A | 구 값 조기 제거 + 재연결 시 소비자 정체(E18) → D55 게이트 |
| 인증 실패 중 노드 1 wipe | 새 DIT 생성·데이터 소실(E19) | D61 fail-closed |
| 대체안: 클라이언트 키 유출 | N/A | 신원 비밀번호 유출과 동급(읽기 전용); 인증서 폐기/만료로 회수, cn=config에 비밀 없음. CA가 서명한 CN=replicator 인증서도 동일 권한(D52 검사) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 신규 `scripts/test/test-replication-identity.sh` 3노드 동시 기동(TLS), 노드별 add/modify/pw/delete | Docker, `ldapium:e2e` | PASS 로그, 엔트리·해시 수 |
| `AC-002` | 같은 스크립트: 부정 테스트(자기 `description`/`pwd*`/비밀번호/삭제·타 엔트리·cn=config/accesslog, 일반 사용자 회귀) + 잠금 매트릭스 5종 + 대조군 | 동일 | 결과 코드 50×N/32, 잠금 속성 부재 |
| `AC-003` | ACL 누락·하위 트리 거부·크기 제한·비밀번호 불일치·미롤 소비자 주입 후 점검 스크립트 | 동일 | 비0 + 원인, 단순 신호는 정상이었음을 함께 기록 |
| `AC-004` | `test-wiped-node-resync.sh` 확장(전용 모드, sid 1 + sid 2) | 동일 | 엔트리/해시/entryUUID 일치, 탐지 로그 |
| `AC-005` | 회전 상태 기계 5시나리오 + 카나리 + 지문 게이트 | 동일 | 단계별 바인드·카나리·게이트 메시지·복구 |
| `AC-006` | 직전 릴리스 이미지→새 이미지: 충돌 검사, `prepare`, G1/G2, 혼합, 롤백, 노드별 관리자 비밀번호 롤백 경고 | 동일(두 이미지 태그) | 단계별 양방향 변경, 거부 메시지 |
| `AC-007` | 기존 e2e 3종 + cn=config 전체·olcSyncrepl diff | CI | 기존 통과, diff 없음 |
| `AC-008` | 노드별 다른 관리자 비밀번호(게이트 통과 후) | 동일 | 쓰기 전파 |
| `AC-009` | accesslog 조회(단순·EXTERNAL) + `stats` 로그 + `/proc/1/environ` | 동일 | 레코드 필드, 비밀번호 부재 |
| `AC-010` | `helm template`(미지정/전용/TLS 꺼짐/`ingressFrom` 기본/Secret 부재 오프라인), `verify-chart-schema.sh`, `promtool` 알림 테스트 | CI | 렌더 diff, 실패·경고 메시지 |
| `AC-011` | TLS 클러스터: 평문 읽기, 평문 소비자, `starttls=critical`, 틀린 CA, TLS 없는 전용 기동 | 동일(저장소 TLS E2E 구성) | 엔트리 0, rc -101/-1, 복구, 기동 거부 |
| `AC-012` | sid-1 wipe + 틀린 비밀번호/틀린 CA/피어 중지/포트 닫힘/첫 생성 + `FIRST_NODE` | 동일 | 기동 실패·생성 여부, 피어 데이터 불변 |

단위/정적(셸 `shellcheck`, 순수 함수) 증거와 라이브 LDAP 증거를 분리해 기록한다. 라이브 LDAP 경로를 모킹하지 않는다(AGENTS.md "Testing philosophy").

### 추적성 매트릭스

| REQ | AC | Tasks | 증거(이 패키지에서 이미 확보) |
|---|---|---|---|
| REQ-001 | AC-001, AC-002 | T-012, T-020 | E13, E14, E17 |
| REQ-002 | AC-001, AC-004, AC-008 | T-013, T-015, T-020 | E5, E7, E15b |
| REQ-003 | AC-001, AC-003, AC-006 | T-012, T-010, T-020, T-021 | E1, E3, E8, E10, E16 |
| REQ-004 | AC-002 | T-013, T-020 | E4, E15, E15b |
| REQ-005 | AC-005 | T-016, T-021 | E6, E18 |
| REQ-006 | AC-006, AC-007 | T-011, T-017, T-020 | E9 |
| REQ-007 | AC-006 | T-010, T-012, T-016, T-021 | E9, E10, E16, E21 |
| REQ-008 | AC-003 | T-010, T-018, T-020 | E1, E3, E4, E8, E10, E22 |
| REQ-009 | AC-009 | T-015, T-020 | E4, E11, E23 |
| REQ-010 | AC-008 | T-019 | E12, E21 |
| REQ-011 | AC-004, AC-012 | T-014, T-020, T-022 | E7, E19, E20 |
| REQ-012 | AC-010 | T-017, T-018, T-020 | (미실행) |
| REQ-013 | AC-001, AC-011 | T-011, T-015, T-023 | E17 |
| REQ-014 | AC-010, AC-011 | T-017 | (미실행) |

## Rollout, rollback and recovery

- Rollout sequence (기존 클러스터, **opt-in**, 기본 `admin` 유지):
  0. 전제: TLS 활성·검증(차트 TLS 경로), `networkPolicy.ingressFrom` 검토, 복제 비밀번호 생성(≥32바이트).
  1. 새 이미지를 **모든 노드**에 롤아웃(여전히 `admin`; cn=config 불변, E9 단계 1).
  2. **충돌 검사 + `prepare`**: 전 노드를 `LDAP_REPLICATION_IDENTITY=prepare`로 롤링 재시작 → 비활성 아님 ACL·limits 설치(예약 DN에 엔트리가 이미 있으면 거부, D52).
  3. **G1(엔트리 생성 전)**: 모든 프로바이더 ACL·limits·TLS·충돌 부재 확인.
  4. `replication-identity.sh ensure`: 신원·정책 엔트리를 온라인 복제 쓰기로 생성.
  5. **G2(생성 후)**: 신원·정책 존재, 피어마다 TLS로 신원 바인드, 신원 시점=root 시점, 전파 카나리.
  6. 노드를 하나씩 `dedicated` + 복제 비밀번호로 재시작, 노드마다 점검(혼합 모드 안전, E9 단계 2).
  7. 전부 전환 후 점검, 주기 점검(D59b) 활성화.
  신규 클러스터는 처음부터 `dedicated`(+ `FIRST_NODE`, 첫 설치만)로 시작 가능(E5).
- Rollback trigger and procedure: 점검 실패·복제 정체 시 `LDAP_REPLICATION_IDENTITY=admin`으로 재시작 → olcSyncrepl이 admin DN으로 재작성(E9 단계 4). **전제: 모든 노드의 관리자 비밀번호가 모든 피어에서 유효(공유 관리자 비밀번호)** — 노드별 관리자 비밀번호면 한 방향이 정체하므로(E21) 앞으로 고침(복제 비밀번호 복구·재추가)으로 대응. 신원 엔트리는 남겨도 무해, `retire`로 제거. **어느 프로바이더라도 ACL이 없으면 전환하지 않는다**(E10).
- Data/configuration recovery: 속성이 이미 누락된 소비자는 ACL을 고쳐도 복구되지 않는다(syncrepl은 변경분만) → 해당 노드 wipe 후 재동기화(`#206` 안전 경로, E7) 또는 영향 엔트리를 프로바이더에서 다시 수정. 인증 실패 중 sid-1 wipe는 D61이 막는다(미구현 상태에서는 E19처럼 데이터 소실 — 구현 전 운영 규칙: 복제 비밀번호 점검 후 wipe). 이미지 롤백은 `prepare`가 설치한 ACL을 cn=config에 남기지만 구 이미지는 `olcAccess`를 건드리지 않아 무해(`image/entrypoint.sh`에서 부트스트랩 렌더 외 `olcAccess` 쓰기 없음) — 단 예약 DN에 훗날 엔트리가 생기면 활성화됨(D52).
- Compatibility or migration obligations: 기본값 불변(REQ-006). 커스텀 `LDAP_REPLICATION_BIND_DN` 사용자는 그대로, 경고 로그. 이미지 버전이 섞인 클러스터는 전환 금지.

## Evidence and durable synchronization

- Evidence location/format: 실험 원본은 일회용 스크립트(저장소 밖). T-020–T-023이 `scripts/test/test-replication-identity.sh` 등으로 재현 가능하게 만들고(T-022가 E1–E24 대응표를 남긴다) CI 로그를 근거로 삼는다. `research/README.md` 규칙에 따라 기회적으로 기록.
- Tests or checks that become durable regression controls: `test-replication-identity.sh`(AC-001–006, 008, 009, 011, 012), `check-replication-identity.sh`(운영·CI·helm test·CronJob), chaos e2e 전용 모드 시나리오, TLS E2E 전용 모드.
- Documentation to update: `image/README.md`(env·신원·절차, 300-309행 드리프트), `charts/ldapium/README.md`·`values.yaml`(죽은 `REPLICATION-CONTRACT.md` 참조), `docs/ha-profile.md`, `docs/migration.md`, [generated-credentials](../generated-credentials/CHANGE.md)에 D43 후속(D56) 메모, `CHANGELOG*`.
- ADR/evidence/portfolio records to update: ADR(수용 시), `docs/IMPLEMENTATION-STATUS.md`.

## Review record

- Accepted scope/requirements: 미수용.
- Material changes after acceptance and re-review: 없음(미수용).
- **개정 2 (2026-10-06, 독립 검토 반영)** — 지적과 처리:

| 지적 | 처리 | 재실행한 실험 |
|---|---|---|
| F1 HIGH `by self write`로 읽기 전용이 아님 | D51: 명시적 첫 규칙, 자기 쓰기·`pwd*` 불가, rootDN만 회전, 부정 테스트 AC-002 | E13, E14 |
| F2 HIGH wipe sid-1 + 인증 실패 → 새 DIT | D61 fail-closed + `FIRST_NODE`, REQ-011/AC-012 | E19, E20 |
| F3 HIGH 점검이 해시 손실·자격 증명 오류를 놓침 | D59/D59b: DN 단위 체크섬·지문·카나리·주기 실행·못 잡는 목록 | E22, E18 |
| F4 HIGH 평문·무제한 덤프 허용 | D60: TLS 필수, `ssf=128` ACL, NetworkPolicy 과제, AC-011 | E17 |
| F5 MED 정책 비활성 가정·공허한 AC-002 | D53 명시적 subentry + AC-002 잠금 매트릭스 | E15, E15b |
| F6 MED 회전 중단·롤백 미정 | D55 상태 기계·게이트·롤백·정리 | E18, E18b |
| F7 MED "비활성 ACL"·"즉시 롤백"은 조건부 | D52 충돌 검사·준비 단계, D62 롤백 전제 | E16, E21 |
| F8 MED 게이트 순서 | D59 G1(생성 전)/G2(생성 후) 분리, REQ-007 | E22 |
| F9 EXTERNAL 감사 주장 | D57 정정(accesslog 부재·`stats` 로그 존재, 세션 대응 미입증) | E23 |

- Resolved questions: **Q1** 무조건 설치 아님 — 모든 프로바이더에 먼저 설치하되 충돌 검사·예약 DN 준비 이후에만(D52). **Q2** opt-in 유지, D43은 `dedicated`에서만·결함 수정과 중단 회전/복구 E2E 이후에만 완화(D56, T-019 게이트). **Q3** SASL EXTERNAL은 후속, 단순 바인드 TLS 검증이 먼저(D57, D60).
- Open questions or blockers: 유지보수자 결정이 필요한 질문은 없음. 구현 중 확인할 설계 세부는 T-004(미검증 항목)에 모았다.
- 검증하지 못한 주장: (a) `credentials`의 파일/SASL 비밀 참조 지원, (b) `olcLimits time=unlimited` 필요성(size만 분리), (c) 신원 엔트리 삭제 시 클러스터 정체, (d) `UNREACHABLE` 분류의 타임아웃(블랙홀)·부팅 중 피어 신호, `FIRST_NODE` 흐름 전체(구현 전; 신호와 현재 코드 결과만 확인), (e) 인증서→예약 DN 매핑 셸 평가·`prepare` 충돌 검사(구현 전; 충돌 효과만 E16), (f) 피어 제한 `peername`/`sockurl` 문법·동작, (g) SASL EXTERNAL의 wiped 노드·롤링·인증서 만료·k8s 경로, accesslog 세션 번호와 `conn=` 대응, (h) 차트(k8s)·CronJob·`promtool` 알림·`kube_job_status_failed` 경로 전체(미실행), 4노드 이상, (i) 점검 프로토타입은 단일 속성(`userPassword`)·값 순서 비정규화 상태(전 속성 체크섬·정규화는 구현 과제), 대량(수천 엔트리) 성능, (j) wipe 후 일부 sid의 contextCSN이 전진하는 현상(E7, 조사 안 함).
