# Change: syncrepl을 관리자 DN이 아닌 전용 복제 신원(replicator)으로 바인드

- Change class: `D` — 자격 증명 취급·보안 경계·복제 토폴로지(AGENTS.md "Risk-scaled change workflow")
- Owner: dasomel
- Related issue: [#229](https://github.com/dasomel/ldapium/issues/229) 두 번째 항목 (첫 번째 항목 `/proc/1/environ`은 `image/entrypoint.sh:1598-1603`에서 이미 처리). 선행 기록: [generated-credentials D43](../generated-credentials/CHANGE.md)
- Status: `Accepted (design only; implementation conditions below)`
- Accepted by / date: dasomel / 2026-10-06 — 근거: 사용자의 상시 지시("현재 pr 3개와 이슈 10개 다 처리", "gpt 하고 팀구성해서 멀티로 구현해서 머지")와, 독립 Codex 검토 4회(최종 4차는 "계약 보강 후 구현 시점 조건부 수용 가능", 그 보강 D64–D67은 8dffe45에서 반영, 기계적으로 확인). 수용 범위는 **설계**이며 아래 "수용 조건"이 구현 단계 완료 조건이다. 구현 PR은 Class D로서 별도 독립 검토를 받는다.
- 작성일: 2026-10-06 · **개정 5 (단순화 + 4차 검토의 계약 보강)**: 자동 생성·토큰·훅·takeover·정규식 평가 기구를 모두 폐기하고 "명시적 운영자 명령 + fail-closed 거부"로 재설계했다(아래 "폐기한 것").

## 수용 조건 (Accepted가 과대 주장하지 않도록, 구현 시점 조건을 먼저 명시)

수용은 **설계의 수용**이며 아래는 구현 단계의 완료 조건이다. 이 중 하나라도 미충족이면 해당 기능을 `dedicated`의 지원 범위로 선언하지 않는다.

1. **Kubernetes 복구 검증**: 차트·StatefulSet(기본 OrderedReady)에서 sid 1·sid 2 wipe, 틀린 Secret, 피어 부재, 롤링 회전을 실제 클러스터로 검증(지금까지의 실험은 Docker 2노드까지).
2. **D63 전체 소실 절차**: `restore.sh` 복원 노드가 `dedicated`로 기동하고 나머지가 복제로 채워지는지, 복원 후 자격 증명 reconcile(D66)과 함께 검증.
3. **점검의 노드 간 교차 비교·수렴 대기**(지금은 단일 노드 시점 비교만 실측)와 값 순서 정규화·대량 성능.
4. 엔트리포인트·명령·차트의 구현 자체(지금까지는 설계 + 일회용 이미지 실험): `prepare` 검사, `dedicated` 거부 조건 전체(D61·D64·D65), `ensure`/`rotate`/`retire`/`reconcile`/`rollback-admin`.
5. 미검증 주장 목록(문서 끝)의 (a)–(k) 해소 또는 한계로 문서화.

> 이 문서는 설계 제안이다. 저장소의 코드·ACL·Helm·스크립트는 변경하지 않았다. 아래 "실험(E1–E17)"은 1회용 컨테이너
> (OpenLDAP 2.6.15, `docker build -t l5-ldap:1 -f image/Dockerfile ./image`, HEAD 0baf3ea)에서 실제로 실행한 결과이며
> 실험 스크립트는 저장소 밖이다(T-020–T-024에서 `scripts/test/`로 재현 가능하게 만든다). 실험의 ACL/엔트리는 `cn=config`·디렉터리
> 온라인 수정으로 적용했고, "dedicated에서 sid 1도 소비자 전용"은 엔트리포인트 한 줄(`:1111` 조건)을 sed로 바꾼 일회용 이미지로 흉내 냈다
> (코드 구조 제안이 아님). **모든 주장은 실험으로 확인했거나 "설계만"으로 표시했다.**

## Problem

| # | 관찰 | 근거 |
|---|---|---|
| P1 | syncrepl이 관리자 DN과 **공유 관리자 비밀번호**로 바인드한다(복제 비밀번호 기본값이 관리자 비밀번호). | `image/entrypoint.sh:570-580` |
| P2 | `olcSyncrepl ... credentials="<평문>"`이 모든 노드의 cn=config에 평문 저장. 관리자 비밀번호면 곧 rootDN 전권이고 `cn=admin,cn=config`도 같은 비밀번호. | `entrypoint.sh:1567-1568`; `image/ldifs/02-cn-config-admin.ldif:12-15,23-27`; E1 |
| P3 | D43: 복제 시 관리자 비밀번호 자동 생성 불가, 모든 노드가 같은 명시적 관리자 비밀번호. | `entrypoint.sh:100-107` |
| P4 | 비관리자 `LDAP_REPLICATION_BIND_DN`은 **ACL이 없으면 조용히 망가진다**(엔트리는 복제되나 `userPassword`가 빠지거나 삭제됨, contextCSN은 동일). 차트 노브(`replication.bindDN`)가 이 함정이다. | `charts/ldapium/values.yaml:246-253`, `image/README.md:305-309`; E1 |
| P5 | 기본 ACL의 catch-all이 `by self write`를 줘서 비관리자 신원을 그냥 쓰면 자기 엔트리를 수정할 수 있다. | `entrypoint.sh:803,814`; E2 |
| P6 | wipe된 sid-1은 프로브 실패를 "베이스 없음"으로 읽어 새 DIT를 만든다 → 라이브 데이터 소실. | `entrypoint.sh:1111,1124-1131,1140-1141`; E8 |

## Intent

모든 노드가 서로를 **전용 읽기 전용 신원**으로 **검증된 TLS 위에서** 바인드한다. 신원 엔트리는 **운영자가 명시적 명령으로 한 번 만든다**(엔트리포인트는 절대 만들지 않는다).
`dedicated` 모드의 노드는 **전부 소비자 전용**(sid 1 포함)이라 베이스 DIT를 새로 만들 수 없고, 자격 증명·TLS·인증 설정이 안전하지 않으면 **고정 메시지로 기동을 거부**한다(관리자 신원으로 폴백하지 않음).
wipe된 노드의 복구는 "피어가 엔트리와 데이터를 갖고 있으므로 복제로 돌아온다"가 전부다. 기본값은 바뀌지 않는다(opt-in).

## 설계 요약 (개정 4)

1. **모드** `LDAP_REPLICATION_IDENTITY` = `admin`(기본, 변경 없음) / `prepare` / `dedicated`.
2. **`prepare`**: 복제는 지금처럼 admin 신원, **ACL·limits만 설치**. 설치 조건: 로컬에 예약 DN 엔트리가 **없거나** 이미 같은 ACL이 저장돼 있음(재부팅 멱등). 엔트리가 이미 있는데 ACL이 없으면 **거부**("먼저 `retire`로 삭제"). wipe된 노드는 DB가 비어 있어 통과하고 ACL이 먼저 깔린다(엔트리는 복제로 온다).
3. **`ensure`(운영자 명령, 관리자 자격으로 라이브 클러스터에 1회)**: `cn=replication-policy,<root>`와 `cn=replicator,<root>`(명시적 `pwdPolicySubentry`, OS CSPRNG 32바이트 비밀번호)를 **온라인 복제 쓰기**로 만들고 자격 증명을 0600 파일/표준 출력으로 한 번 내준다. 엔트리가 이미 있으면 거부.
4. **`dedicated`**: 엔트리포인트는 엔트리를 만들지 않고, 피어를 프로브하지 않고, 토큰·훅을 보지 않는다. **모든 노드가 베이스를 만들지 않는 소비자 경로**를 쓴다(E12). 필수 조건 — 복제 비밀번호(`LDAP_REPLICATION_PASSWORD(_FILE)`, 위생 검사 통과), 검증된 TLS, mTLS·`olcAuthzRegexp` 부재 — 하나라도 어기면 기동 거부.
5. **순서**: 신규·기존 클러스터 모두 `admin`(또는 `prepare`)으로 먼저 기동 → 전 노드 `prepare` → `ensure` → 노드별 `dedicated`. 처음부터 `dedicated`로 새 클러스터를 만드는 경로는 **지원하지 않는다**(단순함 우선).
6. **회전/폐기**: 신원 엔트리에 `userPassword` 값을 추가 → 롤링 재시작 → 모든 노드 자격 증명 지문이 새 값이면 구 값 제거(`rotate`), `retire`로 삭제.
7. **점검**: 열거된 속성 집합만 `entryCSN` 안정성 기준으로 신원 시점 vs root 시점 비교 + 소비자 자격 증명 지문 + 카나리(E11).

## Scope / Non-goals

- In scope: 위 설계, `image/entrypoint.sh`·`01-cn-config.ldif`, `scripts/replication-identity.sh`·`scripts/check-replication-identity.sh`, 차트 값·렌더 가드·점검 CronJob, 문서, 라이브 테스트.
- Non-goals: 기본값 전환, 엔트리 자동 생성, 처음부터 dedicated인 신규 클러스터, mTLS 클라이언트 인증과의 공존, SASL EXTERNAL(후속), 침해된 프로바이더의 쓰기 주입 방지, 관리자 신원 분리, cn=config 자격 증명 파일 참조, 차트의 복제 Secret 자동 생성(운영자가 `ensure` 출력으로 Secret을 만든다).

## 폐기한 것 (근거 없이 키운 기구)

| 폐기 | 이유 |
|---|---|
| 1회성 초기화 토큰·ConfigMap·pre/post-install 훅·Role | 읽기 전용 마운트는 소비 불가, 훅 미실행·uninstall 잔존·재시작에서 재실행 없음 → 진정한 1회성이 아님. 자동 생성 자체를 없애 필요가 사라짐 |
| `LDAP_REPLICATION_FIRST_NODE`/프로브 분류로 생성 허용 | 같은 이유. dedicated는 아예 생성하지 않는다 |
| `takeover`·`entryUUID` 대조·`description` 표식 | 소유자가 표식을 위조 가능, UUID 배포 경로 없음. 대신 `prepare`가 기존 엔트리를 거부 |
| 합성 주체 정규식 평가·catch-all 매핑 | 앞선 임의 정규식(`service42`)을 증명할 수 없음(E13). 대신 mTLS·`olcAuthzRegexp`를 **금지** |
| 전 속성 체크섬 비교 | 다른 엔트리 쓰기로 suffix `contextCSN`이 움직여 거짓 실패(E11). 열거 집합만 비교 |
| 차트 복제 Secret 생성(lookup/keep) | 자동 생성 경로 폐기와 함께 불필요 |
| D43 상시 완화 | 게이트된 마지막 선택 단계로만 남김(D56) |

## Requirements

- `REQ-001` — 신원은 **읽기 전용**: 모든 엔트리·`userPassword`·운영 속성 읽기, 크기·시간 무제한. 자기 엔트리 포함 어떤 쓰기도 불가, cn=config/cn=accesslog 불가. **기존 규칙보다 앞선 명시적 첫 규칙**이 결정하고 다른 주체의 권한은 불변. 비TLS 연결로는 아무것도 못 읽는다(`ssf=128`).
- `REQ-002` — **엔트리포인트는 신원 엔트리를 만들지 않는다.** 운영자 명령 `ensure`가 1회 생성하고(없을 때만), 명시적 `pwdPolicySubentry`(자체 정책: 잠금·만료 없음, 자기 변경 불가)를 둔다.
- `REQ-003` — ACL·limits는 `prepare`/`dedicated`에서만, 로컬 예약 엔트리가 없거나 ACL이 이미 있을 때만 설치(신규=부트스트랩 LDIF, 기존 볼륨=오프라인 `slapmodify -n 0`). 어느 프로바이더에도 ACL이 없는 상태로 전환하지 않는다(게이트).
- `REQ-004` — 신원은 ppolicy 잠금·만료에서 제외된다(정책 on/off, 신규/기존 볼륨, 강화된 기본 정책, 회전 중). 온라인 추측 방어는 비밀번호 품질·NetworkPolicy·`reqResult=49` 감시에 의존.
- `REQ-005` — 회전은 복제 중단 없이(이중 값 창) 가능하고 **모든 노드의 자격 증명 지문이 새 값으로 확인되기 전에는 구 값을 제거하지 않는다**. 롤백은 구 Secret 복원.
- `REQ-006` — 기본값 불변: `admin`이면 cn=config·olcSyncrepl 바이트 단위 동일. 커스텀 `LDAP_REPLICATION_BIND_DN`은 동작 유지 + 경고.
- `REQ-007` — `dedicated` 노드는 **베이스 DIT를 만들지 않으며 sid 1도 예외가 아니다**, 피어 프로브·대기를 하지 않는다. 비밀번호 미지정/위생 실패, TLS 미검증, mTLS 또는 저장된 `olcAuthzRegexp` 존재 중 하나라도 있으면 **고정 메시지로 기동 거부**하고 admin 신원으로 폴백하지 않는다.
- `REQ-008` — `dedicated`는 검증된 TLS 필수(`ldaps://` + `tls_reqcert=demand` + CA, 또는 `starttls=critical`). 차트는 `tls.enabled` 없이 렌더 실패.
- `REQ-009` — 비밀번호 무작위성은 생성 경로(`ensure`/`rotate`, OS CSPRNG 32바이트)가 보장한다. 외부 공급 값의 무작위성은 **운영자 책임**이며 엔트리포인트는 위생 검사(길이 ≥ 32, 서로 다른 문자 ≥ 10, 관리자 비밀번호와 불일치)만 하고 이것이 무작위성의 증거가 아님을 문서·메시지에 명시한다.
- `REQ-010` — **점검**: 열거된 속성 집합(`userPassword` + 운영자가 지정한 사용자 속성, 기본 `objectClass uid cn sn mail`)만 비교하고 `contextCSN` 등 동적 운영 속성은 비교하지 않는다. 신원 시점 vs root 시점을 `entryCSN` 안정성 확인 후 비교(같은 CSN·다른 내용 = 즉시 실패, CSN 변동 = 경쟁 → 최대 5회 재시도, 지속 쓰기 엔트리만 남으면 경고 통과), 노드 간 교차 비교, 소비자 `olcSyncrepl` 바인드 DN·자격 증명 지문, 노드별 카나리. 게이트는 G1(엔트리 생성 전 설정만)/G2(생성 후 권한·전파)로 분리. 못 잡는 것을 문서화.
- `REQ-011` — **wipe 복구**: 어느 노드(sid 1 포함)를 지워도 피어가 데이터와 엔트리를 갖고 있으면 올바른 자격 증명으로 복제로 복구되고, 틀린 자격 증명이면 아무것도 만들거나 지우지 않는다. 피어가 없어도 파드는 즉시 Ready가 되어 기본 OrderedReady에서 교착하지 않는다. **전체 소실**은 명시적 절차(백업 복원 또는 신규 클러스터 재초기화)로만 복구한다.
- `REQ-012` — 차트: `replication.identity`(기본 `admin`), `replication.existingSecret` 사용, `dedicated`+`tls.enabled=false` 렌더 실패, `dedicated`+mTLS 렌더 실패, `networkPolicy.ingressFrom` 기본값 경고, 점검 CronJob·알림(설계).
- `REQ-013` — **SASL/권한 위임 경로 완전 차단**: `prepare`·`dedicated` 기동은 저장된 `olcAuthIDRewrite`가 하나라도 있으면, `olcAuthzPolicy`가 `none`(또는 미설정)이 아니면, `authzTo`/`authzFrom`을 가진 엔트리가 있으면 거부한다(운영 중 `cn=config` 변경은 다음 점검 G1에서 잡는다).
- `REQ-014` — **예약 DN ≠ 어떤 rootDN**: 예약 DN(정규화)이 `LDAP_ADMIN_DN` 또는 저장된 어떤 `olcRootDN`과 같으면 `prepare`·`ensure`·`dedicated` 기동이 거부한다(rootDN이면 ACL을 우회).
- `REQ-015` — **DN과 Secret은 함께 전환**: 신원 모드가 복제 DN과 복제 Secret을 같이 결정한다(양방향). `admin`/`prepare`에서 복제 Secret이 설정돼 있으면 거부, `admin` 롤백은 관리자 자격으로 돌아가며, **노드가 비었거나 재동기화 중이면 `admin`/`prepare` 롤백을 거부**한다(sid 1이 새 DIT를 만드는 E8 경로).
- `REQ-016` — **백업 복원 후 자격 증명 reconcile**: 회전 전 백업을 복원하면 신원 엔트리의 비밀번호 값이 현재 Secret과 어긋나 모든 소비자가 49로 정체한다. 피어를 시작하기 전에 reconcile + 검증 단계를 거친다.

## Acceptance scenarios

### `AC-001` — prepare → ensure → dedicated 전환과 복제 동작
- Covers: `REQ-001`, `REQ-002`, `REQ-003`, `REQ-007`
- Given `admin` 모드 3노드 클러스터(사용자·해시 보유)
- When 전 노드 `prepare`(엔트리 부재) → `ensure` → 노드를 하나씩 `dedicated`(TLS)로 재시작
- Then 각 단계에서 add/modify/비밀번호 변경/delete가 양방향 반영되고 모든 노드의 해시 수가 같다. olcSyncrepl의 binddn은 신원, 관리자 비밀번호는 복제에 쓰이지 않는다.

### `AC-002` — 신원 권한이 좁고 잠기지 않는다 (부정 테스트)
- Covers: `REQ-001`, `REQ-004`
- When 신원으로 (a) 자기 `description` (b) `pwdEndTime`·`pwdAccountLockedTime`·`pwdPolicySubentry` (c) 자기 비밀번호(정책이 허용하도록 바꾼 상태 포함) (d) 자기 삭제·엔트리 추가 (e) 타 엔트리 수정 (f) cn=config·cn=accesslog 읽기, 일반 사용자의 신원 엔트리 수정, 평문 연결 읽기
- Then (a)–(e) 50, (f) 32, 평문은 엔트리 0, 읽기 허용 속성은 성공, 일반 사용자 권한 불변. 틀린 비밀번호 ≥12회에도 잠기지 않음: 기존 볼륨 정책 활성 / `LDAP_PASSWORD_POLICY_ENABLED=false` 재시작 / 강화된 기본 정책 / 정책 비활성 최초 부트스트랩 / 회전 중. 대조군은 잠긴다.

### `AC-003` — `prepare`의 거부와 멱등
- Covers: `REQ-003`
- When (a) 예약 DN에 기존 엔트리가 있는 노드 (b) 엔트리 없음 (c) 이미 ACL이 있는 노드 재부팅 (d) wipe된 노드(빈 DB)
- Then (a) 거부(메시지: 먼저 삭제) (b) 설치 (c) 멱등 (d) 설치되고 이후 엔트리가 복제로 도착.

### `AC-004` — wipe 복구(sid 1·sid 2, 틀린 자격 증명, 피어 부재)
- Covers: `REQ-007`, `REQ-011`
- Given `dedicated` 클러스터
- When (a) sid 1 wipe + 틀린 비밀번호 (b) 고친 비밀번호로 재기동 (c) 피어가 내려간 상태에서 sid 1 wipe (d) sid 2 wipe
- Then (a) 새 DIT를 만들지 않고 피어 데이터 불변, `rc 49` (b) 전부 복구, 베이스 entryUUID 동일 (c) 즉시 Ready, 아무것도 만들지 않음, 피어 복귀 시 복구 (d) 복구. **전체 소실**: 문서화된 절차(아래)를 테스트로 고정.

### `AC-005` — 회전: 무중단·중단·롤백·조기 제거 복구
- Covers: `REQ-005`
- When (1) 새 값 추가→롤링→지문 게이트→구 값 제거 (2) 일부만 재기동한 상태에서 게이트가 닫혀 제거 거부 (3) (직접 `ldapmodify`로) 구 값을 일찍 제거하고 재연결 유발 (4) 롤백 (5) 구 값 재추가
- Then (1) 카나리 도달, 구 49·신 성공 (2) 거부 (3) 소비자 `rc 49` 정체(재연결 전에는 기존 세션이 유지되는 잠복 위험) (4) 정상 (5) 즉시 복구.

### `AC-006` — 점검: 거짓 실패 없음, 결함은 즉시 실패
- Covers: `REQ-010`
- Given 비밀번호 변경이 초당 수 회 지속되는 건강한 클러스터
- When 점검 반복, 이어서 (a) 하위 트리 `userPassword` 거부 (b) 크기 제한 + limits 제거 (c) 비밀번호 불일치 (d) 소비자는 구 값인데 새 값이 외부에서 유효
- Then 건강한 상태에서 거짓 실패 0(전 속성 비교는 같은 조건에서 실패해야 대조 성립), (a) 안정 엔트리에서 즉시 실패, (b)–(d) 비0 + 원인. 열거되지 않은 속성의 결함은 못 잡는다는 한계가 문서에 있다.

### `AC-007` — 기본값 불변
- Covers: `REQ-006`
- When 기존 `test-wiped-node-resync.sh`·`replication-chaos-e2e.yml`·`test-bootstrap-seed.sh`와 cn=config 전체·olcSyncrepl diff
- Then 통과, diff 없음.

### `AC-008` — 안전하지 않은 설정은 기동 거부
- Covers: `REQ-007`, `REQ-008`, `REQ-009`
- When `dedicated`에서 (a) 비밀번호 없음 (b) 31자·반복 문자·관리자 비밀번호와 동일 (c) TLS 없음 (d) `LDAP_TLS_MUTUAL_AUTH` 켬 (e) 저장된 `olcAuthzRegexp`가 `^cn=service42$ → <신원 DN>` 하나 (f) `olcTLSVerifyClient: try`
- Then 전부 고정 메시지로 거부, 관리자 신원 폴백 없음. TLS만(mTLS 없음)이면 통과하고 주체가 예약 DN인 클라이언트 인증서로 `-Y EXTERNAL`이 실패한다.

### `AC-009` — 차트 렌더
- Covers: `REQ-012`
- When `helm template`·`verify-chart-schema.sh`: 미지정/dedicated, TLS 켬/끔, mTLS, `ingressFrom` 기본/좁힘
- Then 미지정은 현재와 같은 매니페스트, 위반은 렌더 실패/경고.

### `AC-010` — authz 우회 경로 거부(REQ-013, REQ-014)
- Covers: `REQ-013`, `REQ-014`
- When `prepare`/`dedicated` 기동 전에 (a) 저장된 `olcAuthIDRewrite` 1개 (b) `olcAuthzPolicy: to`/`from`/`both` (c) `authzTo: dn:<신원 DN>`을 가진 엔트리 (d) `LDAP_ADMIN_DN=cn=replicator,<root>` (대소문자·공백 변형 포함) (e) `ensure`를 (d) 구성에 실행
- Then 전부 고정 메시지로 거부. 대조: (b)+(c) 상태에서 일반 사용자의 프록시 권한 제어(`-e '!authzid=dn:<신원>'`)가 신원으로 전환되어 해시를 읽는다(E17 재현), 실제 SASL 바인드 경로(`olcAuthIDRewrite`)도 negative 테스트로 확인한다.

### `AC-011` — DN·Secret 동시 전환과 롤백 거부(REQ-015)
- Covers: `REQ-015`
- When (a) `admin`/`prepare`에서 복제 Secret 설정 (b) 차트에서 identity와 Secret/DN을 어긋나게 설정 (c) `dedicated` → `rollback-admin`을 정상 클러스터에서 (d) 같은 명령을 한 노드가 비었거나 재동기화 중일 때, 특히 sid 1 (e) 롤백 후 admin 자격 동작
- Then (a) 거부 (b) 렌더 실패 (c) DN·Secret이 함께 빠지고 관리자 자격으로 복제가 계속 (d) 거부, 아무것도 만들거나 지우지 않음 (e) 양방향 쓰기 정상. `prepare`가 마커 없는 sid-1 부트스트랩을 거부.

### `AC-012` — 백업 복원 후 자격 증명 reconcile(REQ-016)
- Covers: `REQ-016`
- Given 회전 전에 만든 백업, 이후 회전 완료(현재 Secret ≠ 백업의 신원 비밀번호)
- When (a) reconcile 없이 복원 노드와 피어를 시작 (b) D67 절차(피어 정지 → 복원 → `dedicated` 기동 → `reconcile` → 검증 → 피어 시작)
- Then (a) 모든 소비자가 `rc 49`로 정체(대조), (b) 검증 통과 후 피어 시작, 복제 정상, 점검 G2 통과. 검증 실패 시 피어 시작이 거부됨.

## Architecture and decisions

- Relevant ADR/design links: [openldap-2.6-hardening D3·D8·D10·D13](../openldap-2.6-hardening/CHANGE.md), [issue-206](../issue-206/CHANGE.md), [generated-credentials D40–D45](../generated-credentials/CHANGE.md), [docs/ha-profile.md](../../ha-profile.md).
- ADR threshold result: `required` — 보안 경계(자격 증명·ACL·TLS 요구·mTLS 배제)와 D43 변경(T-005).

### 사실(코드 근거)

| 항목 | 현재 동작 | 근거 |
|---|---|---|
| olcSyncrepl | 부팅마다 통째로 `replace`; `bindmethod=simple`·`credentials` 평문; `starttls`/`tls_*` 없음 | `entrypoint.sh:1541-1585` (`:1567-1568`) |
| 오프라인 편집 | cn=config는 `slapmodify -n 0`/`slapadd`/`slapcat`로만(`#206`) | `entrypoint.sh:1472-1482` |
| 베이스 DIT | sid≠1은 만들지 않고 복제로 채움, sid 1은 피어 프로브로 판단(실패=없음) | `entrypoint.sh:1111-1131,1140-1141` |
| 기본 ACL | `{0}` userPassword; catch-all `{2}/{4}`가 `by self write` | `01-cn-config.ldif:90-93`, `entrypoint.sh:794-815` |
| 크기 제한 | `olcSizeLimit` 기본 10000(rootDN은 무제한) | `entrypoint.sh:157-169` |
| ppolicy | `olcPPolicyDefault`는 부트스트랩 시에만 렌더(기존 볼륨에서 정책 끄기로 제거 안 됨), 잠금 5회/900s | `entrypoint.sh:979-993,1186,251-264` |
| mTLS | `olcTLSVerifyClient: try`·`olcAuthzRegexp`; CA 서명 인증서는 `by users` 권한 | `entrypoint.sh:459-484,739-740` |
| 차트 | 프로브는 ldapi `whoami`뿐; StatefulSet에 `podManagementPolicy` 없음(기본 OrderedReady); 389/636은 `ingressFrom`(기본 같은 네임스페이스)에도 열림 | `statefulset.yaml:212-243`; `networkpolicy.yaml:23-41`; `values.yaml:519-520` |
| 복원 | `restore.sh`는 오프라인 빈 디렉터리에 데이터+cn=config 복원 | `scripts/restore.sh:1-4` |
| 기존 모니터링 | `openldap_replication_delta`, 30s/300s 알림(쓰기가 있을 때만 의미) | `docs/ha-profile.md:189-233,252-255` |
| 마스킹 | `credentials="..."` 마스킹 | `scripts/detect-config-drift.sh:122-134`, `scripts/export-incident-evidence.sh:530-534` |

### 실험 결과 (OpenLDAP 2.6.15, Colima, 2026-10-06)

| ID | 무엇을 | 결과 |
|---|---|---|
| E1 | 비관리자 신원, ACL 없음 / 기본 ACL 노드가 프로바이더 / ACL이 소비자 노드에만 있음 | 엔트리는 복제되나 `userPassword`가 **없거나 통째로 삭제**, contextCSN·엔트리 수·(관리자 해시 외) 정상. cn=config에서 `credentials` 평문 조회 |
| E2 | **D51 ACL**: `{0}to * by dn.exact="<repl>" read by * break` | 읽기: 관리자·사용자 해시, 운영 속성. **쓰기 전부 50**: 자기 `description`, `pwdEndTime`, `pwdPolicySubentry`, `pwdAccountLockedTime`, 자기 비밀번호(정책이 허용해도 ACL이 50), 타 엔트리, 자기 삭제·추가. rootDN은 신원 엔트리 수정 가능(회전 경로). 일반 사용자: 자기 쓰기·인증·읽기·신원 엔트리 수정 50 모두 기존과 동일 |
| E3 | 잠금 매트릭스 | 12회 틀린 바인드 후 성공·잠금 속성 없음: 기존 볼륨 정책 활성 / `LDAP_PASSWORD_POLICY_ENABLED=false` 재시작(`olcPPolicyDefault` 잔존) + 기본 정책 `pwdMaxFailure 1`·영구 잠금·`pwdMaxAge 60` / 회전 중 / `cn=replication-policy,<root>` 명시 subentry로 정책 비활성 **최초 부트스트랩** 볼륨. 그 정책을 `pwdLockout TRUE`로 바꾸면 3회 후 잠김(명시 subentry가 기본 정책 없이 적용됨). 대조군 사용자는 6회 후 잠김 |
| E4 | TLS(저장소 TLS E2E 구성) + ACL `ssf=128` | 저장소 ldaps 경로(단순 바인드)로 클러스터·해시 복제 정상. **평문 바인드는 엔트리 0, 해시 0**. ldaps·`-ZZ`는 읽힘. 소비자를 평문으로: 정체(rc -101). `starttls=critical tls_reqcert=demand`: 정상. 틀린 CA: 정체(rc -1), 평문 폴백 없음, 복구 시 도착. `ssf` 없는 구성은 평문으로도 해시가 전달됨(이전 실험들) |
| E5 | `LDAP_SIZE_LIMIT=5`, 엔트리 18, 노드 wipe | limits 있음 18/18, limits 제거 시 5개에서 정체(rc -101) |
| E6 | 잘못된 복제 비밀번호(기본 정책) | `rc 49` 정체, accesslog `reqDN=<신원> reqResult=49`, 5회 후 잠금되어 올바른 비밀번호도 49 |
| E7 | 이중 값 회전·중단·조기 제거·롤백 | 롤링 중 카나리 도달. n1만 새 비밀번호면 지문 n1≠n2·n3(게이트 닫힘). **조기 제거해도 지속 세션은 유지**되어 즉시 정체하지 않고 **재연결(n1 재시작) 시** n2·n3 `rc 49`·n1 카나리 미도달. 구 값 재추가로 50초 내 복구. 구 Secret으로 롤백해도 정상 |
| E8 | **현재 코드**: 사용자 3명, sid-1 wipe + 틀린 복제 비밀번호 | 새 DIT 생성(`slapadd -n 1`), n1·n2 사용자 0(`syncrepl_del_nonpresent` 3건), 비밀번호를 고쳐도 복구 불가 |
| E9 | 신원 사용 sid 1·sid 2 wipe(엔트리 포함 베이스 이미지) | 엔트리·해시 복구, 베이스 entryUUID 동일 |
| E10 | 구 이미지에서 ACL 선행 → 노드별 전환 → 롤백 / 노드별 다른 관리자 비밀번호에서 admin 롤백 | 각 단계 양방향 반영, ACL 없는 프로바이더가 있으면 해시 손실. **노드별 관리자 비밀번호에서 admin 롤백은 한 방향 소비자가 `rc 49`로 정체**(admin 해시가 복제되도록 ACL이 있을 때 한 노드만 두 비밀번호를 수락 — 관리자 격리 아님) |
| E11 | 점검 프로토타입(원격: root·신원 바인드). 판정: R1(root)→V(신원)→R2(root), `entryCSN` 불안정 판정 보류, **같은 CSN·다른 내용 즉시 실패**, ≤5회 재시도, 보류만 남으면 경고 통과. **지속 쓰기(초당 ~3회, 다른 엔트리)** 하에서 6~8회 | 단일 샷 비교는 건강한 상태에서 **8회 중 6회 거짓 실패**. **전 속성(`* +`) 비교는 6회 중 6회 거짓 실패**(suffix 엔트리 `contextCSN`이 다른 엔트리 쓰기로 움직임, `entryCSN`은 불변). **열거 집합(`userPassword objectClass uid cn sn mail`) + CSN 안정성 판정은 0회**. 하위 트리 `userPassword` 거부 주입: 3~4회 중 전부 즉시 실패(`uid=bob`), 관리자 해시·엔트리 수·contextCSN은 정상. 열거 밖 속성(telephoneNumber) 결함은 **못 잡음**. 소비자 지문 불일치 검출. ldapi EXTERNAL로는 cn=config 읽기 불가(32), 온노드는 `slapcat -n 0 -o ldif-wrap=no` |
| E12 | **단순화된 흐름**(일회용 이미지: `dedicated`면 sid 1도 소비자 전용): `admin` 3사용자 클러스터 → `prepare`(양 노드 ACL, 엔트리 **부재**) → `ensure`(온라인으로 정책+엔트리 생성) → n2, n1 순으로 `dedicated` → ① 쓰기·해시 양방향 정상, binddn=신원 ② sid-1 wipe + **틀린 비밀번호**: 새 DIT 생성 없음, n1 비어 있음, **n2 사용자 4명 불변**, n1 `rc 49` ③ 비밀번호 수정 후: n1이 사용자 4명·해시 전부 복구, 베이스 entryUUID 동일 ④ **피어를 내리고** sid-1 wipe: **1초 만에 Ready**, 아무것도 만들지 않음, 피어 복귀 후 40초 내 복구 | E8과 같은 사고가 데이터 소실 없이 끝난다. 기본 OrderedReady에서 피어 대기가 없어 교착 없음. (전체 소실은 이 실험의 범위 밖) |
| E13 | **authz 거부 검사**(mTLS 단일 노드, `ssf=128` ACL, 신원 엔트리 없음): `olcTLSVerifyClient`·`olcAuthzRegexp` 저장 상태를 `slapcat -n 0`로 읽는 검사 | TLS만(mTLS 없음): 검사 PASS(`verify` 미설정, regexp 0), 주체=예약 DN인 인증서의 `-Y EXTERNAL`은 **"Authentication method not supported"**로 실패. `olcTLSVerifyClient: try` + `{0}^cn=service42$ → <신원 DN>`: 검사 REFUSE, **service42 인증서가 admin 해시를 읽음(1)** — 열거 주체 검사는 이를 통과시켰을 것. **마지막 catch-all `{1}^(.+)$`를 추가해도 service42는 여전히 읽음(첫 일치 우선)**. regexp만 저장(verify 미설정)하면 `slapcat`이 regexp 1개를 읽고(실측) 검사 로직상 REFUSE(검사 함수 실행은 verify 절만 실측). 이미지 기본 매핑(`^cn=([^,]+)$ → uid=$1,<root>`)은 예약 DN으로 별칭되지 않지만 주체가 예약 DN 문자열이면 원시 DN으로 인증되어 읽음(mTLS 켠 경우) |
| E14 | 예약 DN에 기존 일반 엔트리 | 규칙 설치 전 admin 해시 읽기 0, 설치 직후 1 → "비활성 ACL"은 조건부 → `prepare`가 기존 엔트리를 거부(설계, 효과만 실측) |
| E15 | SASL EXTERNAL 소비자(후속 패키지용 실증) | 엔트리 없이 `dn.exact` ACL로 해시 복제 성공, cn=config엔 키 경로만. cn=accesslog의 EXTERNAL 바인드 레코드는 `reqDN`·`reqAuthzID` 비어 있고 영속 검색 미기록, slapd `stats` 로그에는 `authcid="cn=replicator"` |
| E16 | 모니터링 신호 | 소비자 로그 `rc 49`/`rc -101`/`rc -1`, 프로바이더 accesslog `reqResult=49`. contextCSN만으로는 속성 손실을 못 봄(E1) |
| E17 | **프록시 권한 위임**(단일 노드, 신원 읽기 ACL, 일반 사용자 `mallory`가 `-e '!authzid=dn:<신원 DN>'` 제어) | 정책 기본값: 거부(123 "not authorized to assume identity"). `olcAuthzPolicy: to`만 설정: 여전히 거부. **`olcAuthzPolicy: to` + `mallory`에 `authzTo: dn:<신원 DN>`: 신원으로 전환되어 admin `userPassword`를 읽음** — 정규식·mTLS·엔트리 없이도 성립. `slapcat`으로 정책값·`authzTo` 보유 엔트리 수·`olcAuthIDRewrite` 수를 오프라인 판독 가능(AuthIDRewrite 경로 자체와 실제 SASL 바인드 경로는 **실행하지 않음, 설계만**) |

### 결정

| ID | 결정 | 이유 · 비용 · 탈출구 |
|---|---|---|
| D50 | 주 설계 = 단순 바인드 전용 신원 `cn=replicator,<root>` + TLS. `LDAP_REPLICATION_IDENTITY=admin\|prepare\|dedicated`(기본 `admin`) | cn=config의 복제 비밀번호는 평문 잔존 · `admin`으로 롤백(D62) |
| D51 | ACL: 명시적 첫 규칙 `olcAccess: {0}to * by dn.exact="<신원>" ssf=128 read by dn.exact="<신원>" none by * break` + `olcLimits: dn.exact="<신원>" size=unlimited time=unlimited`. 신원 엔트리를 바꿀 수 있는 것은 rootDN뿐 | E2·E4·E5 · 운영자 커스텀 ACL이 앞에 오면 깨짐 → 점검 필수 · `time=unlimited` 필요성 미분리 |
| D52 | **엔트리는 운영자가 `ensure`로만 만든다.** `prepare`는 로컬에 엔트리가 없거나 ACL이 이미 있을 때만 ACL을 설치하고, 엔트리가 이미 있으면 거부(메시지: 관리자가 `retire`로 지운 뒤 재시도). 순서는 `prepare`(엔트리 부재) → `ensure`(새 CSPRNG 비밀번호) → `dedicated`: ACL이 생기는 시점에는 항상 신원 엔트리가 없고, 이후 엔트리는 관리자만 만들 수 있으므로(일반 사용자는 읽기만) 옛 소유자가 끼어들 수 없다 | E12·E14 · 표식·UUID·takeover 불필요 · 비용: 운영 명령 1개, 재부팅이 `prepare` 상태인 노드가 엔트리 생성 후에도 ACL이 이미 있으므로 멱등 통과 · **설계만**: `prepare`의 로컬 엔트리/ACL 검사 구현 |
| D53 | 신원 엔트리는 `ensure`가 정책 `cn=replication-policy,<root>`(`pwdLockout FALSE`, `pwdMaxAge 0`, `pwdAllowUserChange FALSE`)와 함께 만들고 **명시적 `pwdPolicySubentry`**를 둔다(`ou=policies`·`LDAP_PASSWORD_POLICY_ENABLED` 무관) | E3 · 잠금 제외로 온라인 추측 방어 없음(REQ-004) |
| D54 | `dedicated` 노드는 **전부 소비자 전용**(`entrypoint.sh:1111` 조건에 `dedicated` 추가: sid 1도 `LOAD_BASE_DIT=0`), 피어 프로브·대기 없음, 토큰·훅 미참조. 필수 조건 위반은 `die` + 고정 메시지(관리자 폴백 없음). 엔트리 존재는 검증하지 않는다(피어 쪽 상태라 기동 전에 알 수 없음) → 틀리면 소비자 `rc 49`로 드러나고 점검·알림이 잡는다 | E12 · 설계만: 엔트리포인트 구현 |
| D55 | 회전: 값 추가 → 롤링 재시작 → **지문 게이트**(모든 노드 `credentials` 지문=새 값) → `replace`로 새 값만. 상태는 디렉터리(값 개수)와 노드별 지문에서 유도, 같은 명령 재실행으로 재개, 게이트가 닫히면 제거 거부. 롤백=구 Secret 복원. 조기 제거는 재연결 시 드러나는 잠복 위험(E7) → 구 값 재추가로 복구 | E7 |
| D56 | D43 완화는 **선택적 마지막 단계**: `dedicated`에서만, AC-004·AC-005·AC-008이 CI에서 녹색인 뒤. 두 관리자 비밀번호 수락은 격리가 아니며 폐기하려면 로컬 `olcRootPW`와 복제된 admin 엔트리 해시를 모두 고쳐야 한다 | E10 |
| D57 | SASL EXTERNAL은 후속 패키지(E15). EXTERNAL 감사: cn=accesslog에는 신원이 보이지 않고 `stats` 로그에만 있음 | — |
| D58 | 기본값 불변: `admin`이면 cn=config·olcSyncrepl 동일. 커스텀 비관리자 `LDAP_REPLICATION_BIND_DN`은 유지 + 경고 | 호환 |
| D59 | **점검**(`scripts/check-replication-identity.sh`, `--local`=`slapcat`, `--remote`=root+신원+`cn=admin,cn=config`): 열거 집합만 비교(기본 `userPassword objectClass uid cn sn mail`, 운영자 확장 가능), `contextCSN`·동적 운영 속성 제외, `entryCSN`은 안정성 토큰으로만 사용, 같은 CSN·다른 내용 즉시 실패, ≤5회 재시도, 보류만 남으면 경고 통과, 노드 간 교차 비교(같은 규칙), 자격 증명 지문, 카나리. G1(생성 전 설정: ACL·limits·`ssf`·TLS·authz 거부 조건)/G2(생성 후 권한·전파). **못 잡는 것**: 열거 밖 속성의 ACL 결함, 점검 간격 사이의 정체, 이미 root 시점도 틀린 손실, LWW로 버려진 쓰기, 지속 세션이 실제로 쓰는 자격 증명(구성과 다를 수 있음), 점검자의 root 자격 부재 | E11 |
| D59b | 주기 실행(설계만): 차트 `replication.check.enabled`(기본 꺼짐) CronJob(`--remote`, 관리자·복제 Secret 마운트, `networkpolicy.yaml`에 허용 규칙 — 백업 CronJob 규칙 `:54-` 패턴), 결과는 Job 종료 상태 → `kube_job_status_failed` 알림 + 로그. exporter에는 소비자 상태 지표가 없고 사이드카 없는 구조 유지(`ha-profile.md:252-255`). CronJob은 관리자 Secret을 가짐; 대안은 `--local`을 `kubectl exec`로 | 구현 가능성은 설계 수준(promtool 테스트 필요) |
| D60 | `dedicated`는 검증된 TLS 필수 + ACL `ssf=128`. 선택적 피어 제한(`peername`/`sockurl`)은 문서화만(미검증). Kubernetes에서는 NetworkPolicy가 담당하되 신원은 구분 못 하므로 `ingressFrom` 축소가 통제 | E4 |
| D61 | **authz 안전은 증명 대신 금지로**: `dedicated`(와 `prepare`)는 `slapcat -n 0`에서 `olcTLSVerifyClient`가 `never` 외 값이거나 `olcAuthzRegexp`가 하나라도 있으면 **기동 거부**. 따라서 `LDAP_TLS_MUTUAL_AUTH`(mTLS 클라이언트 인증)와 dedicated는 **공존하지 않는다**(비용). 임의 매핑의 안전을 증명하려 하지 않는다 | E13: 앞선 `service42` 매핑은 열거 주체 검사를 통과하고 마지막 catch-all로는 못 막음 · 검사 함수의 verify-client 절은 실행 실측, regexp 절은 저장값 판독만 실측(로직은 설계), 엔트리포인트 구현은 설계 |
| D62 | 롤백: `admin`으로 즉시 롤백은 모든 노드의 관리자 비밀번호가 모든 피어에서 유효(공유)할 때만 성립(E10). 점검이 경고 | E10 |
| D63 | **전체 소실 절차**(설계만): 모든 노드의 데이터가 사라지면 피어에 엔트리가 없으므로 복제로 복구될 수 없다. (1) 백업이 있으면 `restore.sh`(오프라인, 데이터+cn=config)로 한 노드에 복원한 뒤 그 노드를 `dedicated`로 기동, 나머지는 빈 상태로 기동해 복제로 채움 (2) 백업이 없으면 신규 클러스터로 재초기화(`admin` → `prepare` → `ensure` → `dedicated`). 엔트리포인트는 어느 경우에도 신원 엔트리를 만들지 않는다. 테스트(T-021) 전에는 "복원이 `dedicated` 상태와 호환되는지"를 검증하지 못했다고 명시 | `restore.sh:1-4` · 미검증 |
| D64 | **거부 조건 확장(REQ-013)**: `slapcat -n 0`/`-n 1` 오프라인 판독으로 `prepare`와 `dedicated` 기동 모두 (a) `olcAuthIDRewrite` 존재 (b) `olcAuthzPolicy`가 `none`/미설정이 아님 (c) `authzTo`/`authzFrom` 보유 엔트리 존재 중 하나라도 있으면 고정 메시지로 거부(D61의 `olcTLSVerifyClient`·`olcAuthzRegexp`와 합쳐 SASL/위임으로 신원에 도달하는 경로를 모두 금지). `authzTo`는 정책이 `none`이면 비활성이지만 정책은 `cn=config`에서 바뀔 수 있어 보수적으로 존재만으로 거부하고, 점검 G1이 운영 중 변경을 재검사한다 | E17(위임 성립 조건 실측), E13 · (a)의 실제 SASL 경로와 `authzFrom`은 **설계만**, 비용: 프록시 권한 위임 사용 앱과 `dedicated`는 공존 불가 |
| D65 | **예약 DN ≠ rootDN(REQ-014)**: 예약 DN `cn=replicator,<root>`(정규화: 소문자, 쉼표 주변 공백 제거)를 `LDAP_ADMIN_DN`과 저장된 모든 `olcRootDN`(`slapcat -n 0`)에 대조해 같으면 `prepare`·`ensure`(라이브 `cn=config` 또는 `--admin-dn`)·`dedicated` 기동이 거부한다. 지원되는 `LDAP_ADMIN_DN=cn=replicator,<root>` 설정에서 `retire`→`ensure`가 신원을 rootDN으로 만들어 ACL을 우회하는 경로를 막는다 | **설계만**(rootDN은 ACL을 우회한다는 기존 사실에 근거, 이번에 실행 안 함) · DN 정규화 방법(`slapdn` 유무 등)은 T-004 |
| D66 | **DN과 Secret의 동시 전환(REQ-015)**: 신원 모드가 DN과 Secret을 같이 결정한다. 엔트리포인트는 `admin`/`prepare`에서 `LDAP_REPLICATION_PASSWORD(_FILE)`가 설정돼 있으면(관리자 DN + 다른 비밀번호로 조용히 정체하는 현재 경로, `entrypoint.sh:575-583`) 거부하고, 차트는 `replication.identity=admin`이면 복제 Secret env(`statefulset.yaml:197-203`)를 **렌더하지 않으며** `dedicated`이면 DN과 Secret env를 함께 렌더한다(한쪽만 렌더하는 값 조합은 스키마/렌더 실패). **롤백(`replication-identity.sh rollback-admin`)**: ① 모든 노드가 비어 있지 않고 재동기화 중이 아님을 확인(비었거나 재동기화 중이면 거부) ② 모든 노드에서 관리자 비밀번호가 모든 피어에 유효한지 확인(D62) ③ 차트 값/환경을 identity=admin으로 바꾸면 DN·복제 Secret이 함께 빠지고 관리자 자격 복귀. `prepare`는 마커 없는 sid-1 부트스트랩(새 DIT 생성)을 거부한다(신규 설치는 `admin`으로 시작). **빈 sid 1에서 `admin` 모드의 부트스트랩은 지금과 같은 위험(E8)이므로** 롤백 명령과 문서가 "먼저 `dedicated`에서 재동기화를 마친 뒤 롤백"을 요구한다 | E8, E10, E12 · **설계만**: 엔트리포인트·차트·명령 구현, 잔존 위험: 운영자가 명령 없이 직접 identity=admin으로 바꾸고 빈 sid 1을 띄우면 E8이 재현된다(`admin` 모드의 기존 성질) |
| D67 | **백업 복원 후 reconcile(REQ-016)**: `restore.sh`는 cn=config(`olcSyncrepl` 자격 증명 포함)와 데이터를 백업 시점으로 되돌리므로 회전 이후 복원하면 엔트리의 `userPassword` 값이 현재 Secret과 어긋난다(E6/E7: 소비자 49 정체). 절차: ① `restore.sh`(오프라인) ② 복원 노드를 **피어를 모두 내린 상태에서** `dedicated`로 기동(부팅 시 olcSyncrepl은 현재 Secret으로 다시 렌더) ③ `replication-identity.sh reconcile`(관리자 온라인): 신원 엔트리 `userPassword`에 현재 Secret 값을 추가 ④ **검증**: 현재 Secret으로 TLS 신원 바인드 성공 + `check --local` 통과 ⑤ 그 뒤에만 피어를 시작하고 점검 G2 ⑥ 필요 시 `rotate`로 정리. 검증이 실패하면 피어를 시작하지 않는다 | E6/E7에서 원인 실측, 절차는 **설계만**(AC-012) · 회전 이전 값이 복원되며 구 값이 복제될 위험은 reconcile 후 `rotate` 정리로 처리 |

### 잔여 위험

- cn=config의 `credentials`는 여전히 평문(E1). 파일/SASL 비밀 참조는 미검증. EXTERNAL이 유일한 검증된 대안(후속).
- 잠금 제외로 온라인 추측 방어 없음: 고엔트로피(`ensure` 경로)·NetworkPolicy·`reqResult=49` 감시에 의존. 외부 공급 비밀번호의 무작위성은 운영자 책임(위생 검사는 증거 아님).
- rootDN 세션(UI/API 포함)은 ACL을 우회해 신원 엔트리를 지우거나 바꿀 수 있고 삭제는 전 클러스터를 `rc 49`로 정체시킨다(추론, 미검증) — 점검·알림으로만 보완.
- `dedicated` 노드가 비어 있는 동안 Service가 빈 디렉터리를 서빙한다(sid≥2 wipe와 같은 기존 성질; E12 ④). 
- 침해된 프로바이더의 로컬 쓰기는 모든 피어로 복제된다.
- 기존 `prepare` 이전에 예약 DN에 적대적 엔트리가 이미 있으면 `prepare`가 거부한다 — 엔트리가 없을 때 ACL을 설치하는 순서를 지킨다는 가정이 운영 절차에 의존한다.

## 위협 모델

| 시나리오 | 현재(admin 바인드) | 제안 |
|---|---|---|
| 복제 비밀번호 유출 | = 관리자 비밀번호 → 전권 + 설정 탈취 | TLS 위에서만 전 데이터·해시 **읽기**, 쓰기·자기 수정 50(E2), 평문으론 0(E4). 잠금 없음 |
| 침해된 소비자 | cn=config에서 admin 비밀번호 → 모든 피어 쓰기 | 읽기 전용 비밀번호만. **침해 노드의 로컬 쓰기는 여전히 복제**(미완화) |
| `userPassword` 해시 전송 | 평문 `ldap://`이면 노출 | TLS 필수 |
| 복제 바인드 감사 | accesslog `reqDN=<admin>` | 단순 바인드 `reqDN=<신원>`, 실패 `reqResult=49`(E6) |
| ACL 누락/축소 | N/A | 조용한 손상(E1)/정체(E5) → 점검(E11) |
| 예약 DN 선점·매핑·원시 주체 | N/A | 기존 엔트리는 `prepare` 거부, mTLS·authzRegexp 금지(E13, E14) |
| 회전 중단 | N/A | 지문 게이트(E7) |
| 인증 실패 중 sid-1 wipe | 새 DIT·데이터 소실(E8) | 소비자 전용·생성 불가(E12) |
| 전체 소실 | 백업 복원 | 명시적 절차(D63, 설계) |

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `image/entrypoint.sh`(env 파싱, `prepare` ACL/limits, `dedicated` 소비자 전용·거부 조건·TLS 렌더), `01-cn-config.ldif`, 신규 `scripts/replication-identity.sh`(`ensure`/`rotate`/`retire`)·`scripts/check-replication-identity.sh`. HTTP API 변경 없음 |
| Dependencies / lockfiles | N/A — 신규 의존성 없음 |
| Runtime / toolchain | OpenLDAP 2.6.15 기준만 검증 |
| CI / CD | `e2e.yml`에 신규 라이브 테스트, chaos·TLS E2E에 dedicated 시나리오 |
| Release / packaging | 신규 env/값, `admin` 기본에서 cn=config 불변. 이미지 롤아웃·`prepare` 완료 전 전환 불가 |
| Generated output | N/A — 생성 산출물 없음 |
| Security / supply chain | Class D. 기존 `credentials` 마스킹은 유효(T-003 회귀). 점검 CronJob이 관리자 Secret을 가짐. mTLS와 비공존 |
| Offline / air-gap | 영향 없음(이미지 내 도구만) |
| Documentation / operations | `image/README.md:300-309` 임시 slapd 서술 오류 수정, `values.yaml:246-248`의 존재하지 않는 `REPLICATION-CONTRACT.md` 참조 제거, `docs/ha-profile.md`, `docs/migration.md`, D43 후속 |
| Portfolio / downstream repositories | N/A |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 신규 `scripts/test/test-replication-identity.sh`: prepare→ensure→dedicated 전환 3노드(TLS) | Docker, `ldapium:e2e` | 단계별 양방향 반영, binddn |
| `AC-002` | 부정 테스트 + 잠금 매트릭스 5종 + 대조군 + 평문 읽기 | 동일 | 50/32/엔트리 0, 잠금 없음 |
| `AC-003` | `prepare` 4케이스 | 동일 | 거부/설치/멱등 |
| `AC-004` | sid 1·2 wipe, 틀린 비밀번호, 피어 부재, 전체 소실 절차 | 동일 | 데이터 불변·복구·즉시 Ready |
| `AC-005` | 회전 5시나리오 + 지문 게이트 | 동일 | 단계별 결과 |
| `AC-006` | 지속 쓰기 중 점검(대조: 단일 샷·전 속성), 결함 주입 4종 | 동일 | 거짓 실패 0, 즉시 실패 |
| `AC-007` | 기존 e2e 3종 + cn=config diff | CI | diff 없음 |
| `AC-008` | 안전하지 않은 설정 6종 + TLS만 통과 + 인증서 `-Y EXTERNAL` | 동일(TLS) | 고정 메시지 거부 |
| `AC-009` | `helm template`·스키마 검증 | CI | 렌더 diff, 실패/경고 |
| `AC-010` | 거부 조건 5종(AuthIDRewrite·AuthzPolicy·authzTo·rootDN 충돌·ensure) + 프록시 권한 위임 대조(E17) + 실제 SASL negative | 동일 | 고정 메시지 거부, 위임 대조 성립 |
| `AC-011` | 모드/Secret 불일치 거부, 차트 렌더, `rollback-admin` 정상·빈 노드·재동기화 중 | 동일 + CI 렌더 | 거부/성공 결과, 롤백 후 양방향 쓰기 |
| `AC-012` | 회전 후 복원: reconcile 없이(49 정체 대조) vs D67 절차 | 동일(`restore.sh`) | 대조 정체, 절차 후 정상 |

라이브 LDAP 경로를 모킹하지 않는다(AGENTS.md "Testing philosophy").

### 추적성 매트릭스

| REQ | AC | Tasks | 이미 확보한 증거 |
|---|---|---|---|
| REQ-001 | AC-001, AC-002 | T-011, T-020 | E2, E4 |
| REQ-002 | AC-001 | T-013, T-020 | E12, E3 |
| REQ-003 | AC-001, AC-003 | T-011, T-020 | E1, E10, E14 |
| REQ-004 | AC-002 | T-013, T-020 | E3, E6 |
| REQ-005 | AC-005 | T-013, T-021 | E7 |
| REQ-006 | AC-007 | T-010, T-016, T-021 | E10 |
| REQ-007 | AC-004, AC-008 | T-012, T-022 | E8, E12, E13 |
| REQ-008 | AC-008, AC-009 | T-012, T-016, T-022 | E4 |
| REQ-009 | AC-008 | T-010, T-013, T-022 | (미실행) |
| REQ-010 | AC-006 | T-014, T-017, T-020 | E11 |
| REQ-011 | AC-004 | T-012, T-021 | E9, E12 |
| REQ-012 | AC-009 | T-016, T-017 | (미실행) |
| REQ-013 | AC-010 | T-012, T-011, T-022 | E17, E13 |
| REQ-014 | AC-010 | T-010, T-013, T-022 | (미실행) |
| REQ-015 | AC-011 | T-010, T-011, T-013, T-016, T-021 | E8, E10, E12 |
| REQ-016 | AC-012 | T-013, T-021 | E6, E7 |

## Rollout, rollback and recovery

- Rollout (신규·기존 동일, opt-in, 기본 `admin`):
  1. 새 이미지를 모든 노드에 롤아웃(여전히 `admin`, cn=config 불변).
  2. 전 노드를 `prepare`로 롤링 재시작(엔트리 부재 확인, ACL·limits 설치, mTLS/authzRegexp 금지 조건은 `prepare`에서도 검사).
  3. **G1**(설정만): 모든 프로바이더 ACL·limits·`ssf`·TLS·authz 거부 조건.
  4. `ensure`(관리자 자격, 1회): 신원·정책 생성, 자격 증명 수령 → 운영자가 Secret 생성(`replication.existingSecret`).
  5. **G2**(권한·전파): 신원 존재, 피어마다 TLS로 신원 바인드, 신원 시점=root 시점, 카나리.
  6. 노드를 하나씩 `dedicated`로 재시작, 노드마다 점검(혼합 모드 안전, E10).
  7. 주기 점검 활성화.
- Rollback: 점검 실패·정체 시 `identity=admin`으로 재시작하면 olcSyncrepl이 admin DN으로 재작성된다(E10). 전제: 모든 노드의 관리자 비밀번호가 모든 피어에서 유효(D62). 신원 엔트리는 남겨도 무해, `retire`로 삭제. ACL 없는 프로바이더가 있는 상태에서 전환하지 않는다.
- Recovery: **wipe된 노드(어느 sid든)** — 피어가 엔트리·데이터를 보유하므로 올바른 자격 증명으로 기동하면 복제로 복구(E12). 틀린 자격 증명이면 아무것도 만들지 않고 정체(`rc 49`). 속성이 이미 누락된 소비자는 ACL을 고쳐도 복구되지 않는다 → 해당 노드 wipe 후 재동기화. **전체 소실**: D63(설계만). 이미지 롤백은 `prepare`가 설치한 ACL을 남기지만 구 이미지는 `olcAccess`를 건드리지 않아 무해.
- Compatibility: 기본값 불변, 커스텀 비관리자 `LDAP_REPLICATION_BIND_DN`은 그대로(경고). 이미지 버전이 섞인 클러스터는 전환 금지.

## Evidence and durable synchronization

- Evidence location/format: 실험은 저장소 밖 일회용 스크립트. T-020–T-024가 `scripts/test/`로 재현하고 E1–E17 대응표를 남긴다.
- Durable regression controls: `test-replication-identity.sh`, `check-replication-identity.sh`(운영·CI·CronJob), chaos·TLS E2E의 dedicated 시나리오.
- Documentation to update: `image/README.md`, `charts/ldapium/README.md`·`values.yaml`, `docs/ha-profile.md`, `docs/migration.md`, [generated-credentials](../generated-credentials/CHANGE.md)에 D43 후속(D56), `CHANGELOG*`.
- ADR/evidence/portfolio records: ADR(수용 시), `docs/IMPLEMENTATION-STATUS.md`.

## Review record

- Accepted scope/requirements: 미수용.
- Implementation authorized by the maintainer on 2026-10-07 (user instruction), staged per TASKS.md; unit 1 = T-010
- Material changes after acceptance and re-review: 없음.
- **개정 4 (세 번째 검토 반영) — 접근을 단순화했다.** 지적 → 처리:

| 지적 | 처리 | 실험 |
|---|---|---|
| H1 토큰이 1회성이 아님(읽기 전용 마운트, 훅 미실행·잔존, 재시작에서 재실행 없음) | 자동 생성 폐기 → 토큰·훅·`FIRST_NODE` 전부 삭제. 엔트리는 운영자 `ensure`로만 생성, `dedicated`는 sid 1도 소비자 전용(D52, D54) | E12 |
| H2 합성 주체 검사가 `service42` 같은 임의 매핑을 못 막음, catch-all은 첫 일치를 못 이김 | 증명 포기 → mTLS·`olcAuthzRegexp` 금지, 존재하면 기동 거부(D61) | E13 |
| H3 복구 교착(OrderedReady), 전체 소실 | `dedicated`는 피어 대기·프로브가 없어 pod-0가 즉시 Ready → 교착 없음, 전체 소실은 명시적 절차 D63(설계만) | E12 ④ |
| M1 승인 UUID 배포 경로 없음 | UUID·takeover·표식 폐기. `prepare`는 기존 엔트리 거부, 순서 `prepare`→`ensure` | E14 |
| M2 전 속성 비교는 `contextCSN` 때문에 거짓 실패 | 열거 속성 집합만 비교, 동적 운영 속성 제외 | E11 |

- 재검토 답변 기록(Codex): Q1 prepare 우선 설치(우회 경로를 막은 뒤), Q2 opt-in·D43 게이트 유지(두 관리자 비밀번호 수락은 격리가 아님), Q3 SASL EXTERNAL은 후속 분리 — 모두 반영(D52, D56, D57).
- Open questions or blockers: 유지보수자 결정 필요 질문 없음. **권고**: 구현은 단계별로 병합하되 매 단계 독립 검토를 받는다(이 패키지는 세 번 검토에서 설계가 계속 커졌고 이번에 줄였다). 그래도 안전하게 컴팩트하게 만들 수 없다고 판단되면 #229 두 번째 항목은 보류가 맞다 — 현재 단순화된 설계는 핵심 위험(E1, E8, E13)을 실험으로 막았다고 본다.
- 검증하지 못한 주장: (a) `credentials`의 파일/SASL 비밀 참조 지원, (b) `olcLimits time=unlimited` 필요성, (c) rootDN 세션이 신원 엔트리를 삭제할 때 클러스터 정체, (d) `prepare`의 로컬 엔트리/ACL 검사, `dedicated` 거부 조건 구현, `ensure`/`rotate`/`retire` 명령(설계만), (e) **전체 소실 절차와 `restore.sh` 복원이 `dedicated`와 호환되는지**(설계만), (f) 점검의 노드 간 교차 비교(E11은 단일 노드 시점 비교만 실측), 대량 엔트리 성능, 값 순서 정규화, (g) 피어 제한 `peername`/`sockurl`, (h) 차트(k8s)·CronJob·`promtool`·`kube_job_status_failed` 경로 전체, 4노드 이상, (i) ldapi peercred(EXTERNAL) 신원이 authz 금지 조건과 무관하다는 점은 기존 동작에 대한 가정, (j) wipe 후 일부 sid의 contextCSN이 전진하는 현상(조사 안 함), (k) `LDAP_REPLICATION_IDENTITY` 한 줄 sed 이미지가 실제 구현과 동등하다는 가정(구현 시 T-012에서 재검증).
