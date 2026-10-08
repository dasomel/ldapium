# Change: 머신 주체(서비스)의 쓰기 범위 — v2, 단계적·기본 꺼짐

- Change class: `D` — 신규 자격 증명→쓰기 경로, 쓰기 가능 LDAP 신원 추가, 디렉터리 쓰기 의미·대량 작업 경계(AGENTS.md "Rules": 권한·자격 증명 취급, 파괴적 디렉터리 동작, 대량 작업은 설계 변경)
- Owner: 유지보수자(2026-10-07 수용, 결정 기록: 대화)
- Related issue: [#285](https://github.com/dasomel/ldapium/issues/285)(닫지 않음). 선행: [#214](https://github.com/dasomel/ldapium/issues/214) 머신 주체 인증 v1(읽기 전용). 연관: [#277](https://github.com/dasomel/ldapium/issues/277)(ACL 순서), [#286](https://github.com/dasomel/ldapium/issues/286)(즉시 폐기·대체 자격 증명)
- Status: `Accepted (2026-10-07, maintainer decision recorded in the conversation; security review: 4 blockers found and resolved in this revision)` — **설계 문서다. 이 패키지는 코드·ACL·Helm·스크립트·`openapi.json`을 바꾸지 않는다.** 수용은 설계 수용이며 구현 단위(TASKS `Implement`)는 아직 하나도 착수·완료되지 않았다. 열 번째 질문까지의 결정은 아래 "Resolved questions", 보안 검토 반영 이력은 "Revision"에 있다.
- 작성일: 2026-10-07
- 형식: [machine-principal-auth](../machine-principal-auth/CHANGE.md)(읽기 전용 v1)와 [api-conditional-writes](../api-conditional-writes/CHANGE.md)(If-Match·Idempotency-Key)를 따른다. 코드 주장은 파일:줄(작업 트리 `main` b0ada28 기준)로 인용하고, 확인하지 못한 것은 "미검증"으로 표시한다.

> v1의 비목표를 그대로 승계한다: "쓰기 오퍼레이션, 비밀번호 오퍼레이션, 백업, 애플리케이션 프로파일, entry/move 허용"([machine-principal-auth CHANGE.md "Non-goals"](../machine-principal-auth/CHANGE.md)). 이 패키지는 그중 **사용자·그룹 쓰기와 비밀번호**만 다루고, 나머지(백업, 프로파일, `moveEntry`)는 이 패키지에서도 **영구 거부**로 유지한다(D2). v1 allowlist를 제자리에서 넓히지 않고, 거부 목록은 결정 기록이 있을 때만 줄어든다(#285 수용 조건).

## Problem

v1 머신 주체는 읽기만 한다. 외부 자동화(프로비저닝 에이전트, 온보딩/오프보딩 파이프라인)가 사용자·그룹을 바꾸려면 오늘은 다음 중 하나뿐이다.

- LDAP 모드: 에이전트에 (대개 관리자급) LDAP 비밀번호를 넘겨 `POST /api/login` 쿠키를 재생한다 — v1이 없애려던 바로 그 상황이다([machine-principal-auth Problem](../machine-principal-auth/CHANGE.md)).
- SSO 모드: 무인 쓰기 경로가 없다.

쓰기를 단순히 허용하면 위험이 읽기와 질적으로 다르다. 근거(코드 확인):

| # | 관찰 | 근거 |
|---|---|---|
| P1 | 머신 요청은 **모든 client가 하나의 LDAP 신원**(`MACHINE_LDAP_BIND_DN`)으로 실행되고, 요청 단위 임시 `Session`의 `DN`이 그 신원이다. 임시 세션은 `ID`가 비어 있다. | `ui/backend/internal/httpapi/machine_exec.go:109` |
| P2 | 허용 오퍼레이션은 정적 표 `machineOps`(8개, 전부 GET)뿐이고, `machineOpFor`는 `GET`이 아니면 무조건 거부한다. 이 함수가 비-GET 거부의 **단일 지점**이다. | `machine_scopes.go:25-37,47-53` |
| P3 | scope→허용 해석은 `토큰 scope ∩ client별 서버 상한`이고, scope 이름은 닫힌 집합 `config.MachineScopes`다. | `machine_scopes.go:56-83`, `config/machine.go:64-67,251-290` |
| P4 | 멱등 저장소의 주체(subject)는 `currentSession(c).DN`이다. 머신 요청에서는 그 값이 **모든 client가 공유하는 bind DN**이라, 쓰기를 허용하면 서로 다른 client가 같은 `Idempotency-Key`로 **서로의 기록을 재생·충돌**시킬 수 있다. | `httpapi/idempotency.go:139`(`s.idem.Begin(sess.DN, key, …)`) |
| P5 | 멱등 기록은 프로세스 메모리이고 단일 replica 전제다(`UI_IDEMPOTENCY_ENABLED` 기본 `false`, 꺼져 있으면 키가 붙은 쓰기는 422 `idempotency_unsupported`). | `idempotency.go:114-117`, [api-conditional-writes ADR D216-9](../api-conditional-writes/ADR.md) |
| P6 | 사용자 생성은 Add → (비밀번호가 있으면) Password Modify → 실패 시 보상 Delete의 2단계이고, 보상은 `creatorsName == 바인드 DN`일 때만 신원을 인정한다. 비밀번호는 요청에서 **선택**이다. | `httpapi/user_handlers.go:35-47`, `ldapclient/create_compensation.go:17-26`, [ADR D216-5](../api-conditional-writes/ADR.md) |
| P7 | 쓰기 후 디렉터리에 남는 행위자는 `modifiersName`/`creatorsName` = **바인드 DN**이다. 머신 쓰기를 공유 DN 하나로 하면 LDAP 쪽 기록만으로는 어떤 client가 썼는지 알 수 없다. | `create_compensation.go:26`(바인드 DN이 creatorsName), 일반 slapd 동작(미검증: accesslog `reqDN`/`reqAuthzID` 쓰기 레코드는 이 패키지에서 실행하지 않음) |
| P8 | 현재 ACL은 읽기 전용 신원 `M`만 다룬다. `M`의 규칙은 메인 DB `{0}`–`{2}`이고 비밀 속성 `none` → `B` read → 나머지 `none`이며 모두 `by * break`로 끝난다. | [machine-ldap-account.md](../../machine-ldap-account.md), `scripts/test/fixtures/machine-acl/main-database.ldif`, [machine-principal-auth D4/D26](../machine-principal-auth/ADR.md) |
| P9 | 복제 신원 패키지는 `prepare`에서 첫 `olcAccess`가 복제 규칙이어야 한다고 검사하고(`image/entrypoint.sh:1747-1748`), SASL/위임 경로(`olcAuthzPolicy`≠`none`, `authzTo`/`authzFrom`, `olcAuthzRegexp`)가 있으면 기동을 **거부**한다(`entrypoint.sh:1727-1741`, [replication-identity D61/D64](../replication-identity/CHANGE.md)). 그래서 머신 ACL과 `prepare`는 아직 함께 쓰지 못한다(#277, [machine-principal-auth D30](../machine-principal-auth/ADR.md)). | 위 인용 |
| P10 | v1 긴급 차단은 서버 allowlist 제거/기능 끄기 + **모든 replica 교체**이고, 이미 발급된 토큰은 Keycloak 비활성화로 폐기되지 않는다(최대 노출 = `MACHINE_TOKEN_MAX_TTL`+skew, 기본 10m+30s). 읽기에서는 감수한 위험이 쓰기에서는 TTL 동안의 **변조·삭제**가 된다. | [machine-auth-operations.md §1–2](../../machine-auth-operations.md), [machine-principal-auth D7](../machine-principal-auth/CHANGE.md), #286 |

## Intent

Keycloak 서비스 client의 access token으로 **좁게 정의된 사용자·그룹 쓰기 부분집합**만 호출할 수 있게 한다. 쓰기는 (1) 읽기 전용 신원 `M`과 **분리된** 쓰기 신원으로만 실행하고, (2) 구획·속성 경계는 LDAP ACL이 백스톱으로 강제하고 client별 범위는 앱이 강제하며(D17), (3) 모든 쓰기는 조건부(`If-Match`)·멱등(`Idempotency-Key`)이어야 하고, (4) 기본 꺼짐이며 각 위험 등급(일반 쓰기 → 잠금 → 비밀번호)이 **따로 켜지는** 단위로 출하한다.

## Scope

- In scope(설계 대상): 쓰기 신원 모델, scope 어휘와 오퍼레이션 매핑, subtree·속성 범위 제한, 멱등·조건부 쓰기 규약의 머신 적용, 쓰기 감사, 쓰기 한도, 쓰기용 ACL과 `M`·복제 신원 ACL의 공존 순서, 긴급 차단, 호환·이행, 증거 계획.
- Affected(구현 시): `ui/backend/internal/httpapi`(`machine*.go`, `idempotency.go`, 라우트·OpenAPI), `internal/config/machine.go`, `ldapclient`(쓰기 신원 bind만; 쓰기 로직은 재사용), `charts/ldapium`(`ui.machineAuth.write.*`), `docs/api.md`·`docs/machine-ldap-account.md`·`docs/machine-auth-operations.md`·`docs/audit-event-schema.md`, 신규 라이브 시험, CI e2e.
- 대상: 외부 시스템/AI 에이전트, 운영자, 보안 검토자.

## Non-goals

- 백업(8개), 애플리케이션 프로파일 x-admin(14개), `moveEntry`, `getMe`: **영구 거부**(D2). 이 패키지는 그 결정을 바꾸지 않는다.
- 비밀번호 **읽기**·해시 노출: 불변(`entryRedactedAttrs`, AGENTS.md "Attribute exposure").
- 즉시 폐기(introspection), 대체 자격 증명(API 키·mTLS): #286이 다룬다. 이 패키지는 그 결과를 **전제하지 않는다**(D12).
- 공유 limiter·공유 멱등 저장소(다중 replica): 쓰기는 단일 replica 전제로 출하한다(D9). 영속 멱등 저장소는 별도 변경.
- 조직·subtree별 사람 인가 모델([oidc-organization-authorization](../oidc-organization-authorization/CHANGE.md)) 변경, 기존 쿠키 흐름·세션 모델 변경.
- 일괄(bulk) 엔드포인트 신설. 단건 오퍼레이션만 허용하고 대량 처리는 클라이언트 반복 + 한도로 다룬다(D8).

## Requirements

- `REQ-001` — 기본 꺼짐·fail closed: 쓰기는 `MACHINE_AUTH_ENABLED`(v1)와 **별개의** 플래그(가칭 `MACHINE_WRITE_ENABLED`)가 켜지고, 쓰기 신원·범위·멱등 저장소가 모두 유효할 때만 열린다. 하나라도 빠지면 **기동 실패**(쓰기 부분 활성 없음). 꺼진 상태에서 v1의 거동·응답·OpenAPI(`machineBearer` == 허용 8개)는 바이트 동일하다.
- `REQ-002` — 신원 분리: 쓰기는 `M`(읽기 전용)이 아닌 **별도 LDAP 신원**으로 실행한다. 쓰기 신원은 `M`·관리자·프로파일 관리자·서비스 계정·rootdn과 `ParseDN` 동등이면 기동 실패한다. `M`의 ACL과 읽기 전용 증명(`scripts/test/test-machine-acl-readonly-live.py`)은 변하지 않는다.
- `REQ-003` — 오퍼레이션별 scope: 쓰기 오퍼레이션마다 **고유한** scope를 두고(와일드카드·`*.write` 포괄 scope 없음), 유효 권한은 v1과 같이 `토큰 scope ∩ client 서버 상한`이다. 어휘에 없는 쓰기 오퍼레이션은 기본 거부(403 `scope_denied`, bind·핸들러 이전).
- `REQ-004` — 범위 제한: client마다 **쓰기 가능 subtree 상한**을 서버 설정으로 둔다(비어 있으면 쓰기 불가). 대상 DN과 생성 부모 DN은 `ParseDN` 후 상한의 하위여야 한다. **보장 수준을 구분한다**: client 단위 격리는 **앱 가드만** 강제한다(`W_data` DN이 client 공유라 LDAP ACL은 client A와 B를 구별하지 못한다). LDAP ACL은 **구획 단위 백스톱**으로, 모든 client 상한의 합집합 밖과 허용되지 않은 속성을 막을 뿐이다(D17). 머신이 쓸 수 있는 속성은 오퍼레이션별 닫힌 목록이고 `pwd*`·`userPassword`(비밀번호 scope 제외)·`memberOf`·운영 속성은 쓸 수 없으며, `objectClass`는 **생성(Add) 시 고정 집합으로만** 쓸 수 있고 수정으로는 쓸 수 없다(D18).
- `REQ-005` — 조건부 쓰기 강제: 수정·삭제·잠금·멤버 변경은 `If-Match`가 **필수**다(없으면 428 `if_match_required`). **이 강제는 현재 코드에 없다**: `if_match_required`는 코드·상태 매핑만 있고(`httpapi/errors.go:72,170,219`) 어떤 핸들러도 내보내지 않으며, `ifMatchCSN`은 헤더 없음과 `*`를 모두 "조건 없음"(무조건 쓰기)으로 돌려준다(`httpapi/conditional.go:36-38`). 따라서 T-017이 새로 구현한다(`REQ-015`). 머신 쓰기 전부는 `Idempotency-Key`가 **필수**다(없으면 428, 새 코드). 규약 의미(412 `revision_conflict`, 재생 `Idempotent-Replayed: true`, 409/422/503 코드)는 api-conditional-writes를 그대로 따른다.
- `REQ-006` — 멱등 주체: 머신 쓰기의 멱등 주체는 **검증된 client**(`machine:` + issuer 길이 접두 + client id)이며 공유 bind DN이 아니다. 다른 client의 같은 키는 독립이어야 한다(키 존재 여부가 새지 않음). 토큰 갱신 후에도 같은 주체다.
- `REQ-007` — 감사 귀속: 모든 머신 쓰기(허용·거부·실패)는 **정확히 한 줄**의 구조화 감사 이벤트로 남고 actor는 검증된 client id다. 대상 DN(또는 그 지문), 오퍼레이션, `If-Match` 유무, 멱등 키 지문, 디렉터리 결과 코드, 재생 여부를 닫힌 필드로 남긴다. 토큰·요청 본문·비밀번호는 남기지 않는다.
- `REQ-008` — 한도: 쓰기는 읽기와 **별도 예산**(rps·동시 실행 1/client·전역 쓰기 슬롯)을 갖고, 단건만 허용하며, 응답에 새 자원 생성 수 상한을 둔다. 초과는 429/503이며 대기열 없음. 읽기 예산을 쓰기가 소진하거나 그 반대가 되지 않는다.
- `REQ-009` — 비밀번호·잠금 격리: 비밀번호 설정/초기화, 비밀번호를 포함한 사용자 생성, 잠금 해제/설정은 **더 높은 위험 등급**의 별도 scope이며 각각 별도 플래그·별도 쓰기 신원 또는 ACL 구획으로만 켠다(기본 꺼짐). 서버 생성 비밀번호 응답(`generatedPassword`)은 머신 경로에서 금지한다(멱등 재생 불가, [ADR D216-6/8](../api-conditional-writes/ADR.md)).
- `REQ-010` — 파괴 통제: 삭제(`deleteUser`, `deleteGroup`)는 단건·`If-Match` 필수이며 subtree 루트·그룹 base 등 컨테이너 DN 삭제를 앱이 거부한다. 리프 아닌 항목 삭제는 LDAP 쪽이 거부(`notAllowedOnNonLeaf`)함을 시험으로 확인한다.
- `REQ-011` — ACL 공존: 쓰기 신원의 ACL 조각은 `M`의 `{0}`–`{2}`와 복제 신원 규칙과 **정의된 순서**로 공존하고, 어느 설치 순서에서도 `M`은 읽기 전용을 유지하며, 기존 비-머신 신원의 권한은 바뀌지 않는다. #277은 병합되었으므로(Resolved Q6) 복제 `{0}`·`M` `{1}`–`{3}` 순서와의 공존을 정의·증명한다(`prepare` 포함).
- `REQ-012` — 긴급 차단: 쓰기 전용 즉시 차단 스위치가 있다. v1의 "allowlist 제거 + 전 replica 교체"보다 **빠른** 경로(쓰기 신원의 LDAP 계정 잠금/ACL 회수, 쓰기만 끄는 재배포)와 그 한계를 문서화하고 드릴로 증명한다(#286과 독립).
- `REQ-013` — 호환·계약: 쓰기 scope는 OpenAPI `x-machine-scope`와 허용 표를 **오퍼레이션 단위로** 늘린다. 계약 테스트는 `machineBearer` 집합 == 코드 allowlist를 유지하고, 거부 목록의 축소는 이 패키지의 결정 기록 D-id가 있을 때만 통과한다. 전수 거부 시험(`TestMachine_EveryProtectedOperationExercised`)은 "현재 거부 목록"을 데이터로 갱신한다.
- `REQ-014` — 위험 단계 출하: 각 단위는 앞 단위 없이도 안전하고 기본 꺼짐이며, 첫 단위는 쓰기 가능 신원·오퍼레이션을 하나도 열지 않는다(읽기 호환).
- `REQ-015` — 머신 `If-Match` 강제(보안 검토 B3): 머신 쓰기(수정·삭제·멤버 변경)는 **정확히 하나의 강한 `entryCSN` 태그**를 담은 `If-Match`만 받는다. 헤더 없음·빈 값 → 428 `if_match_required`, `*`·약한 태그(`W/`)·다중 값·다중 헤더·형식 오류 → 거부(`*`는 머신 경로에서 무조건 쓰기가 되므로 금지; 428 또는 400, T-017에서 확정·표 고정). 사람 경로의 `ifMatchCSN` 거동(헤더 없음·`*` 허용)은 **바이트 불변**이다.
- `REQ-016` — 보호 DN 거부 목록(B1): 앱은 LDAP 연결을 열기 **전에** 대상·부모·멤버 DN이 보호 집합과 `ParseDN` 동등이거나 그 하위(`rootdn` 등 서브트리 의미가 있는 것은 하위 포함)이면 403으로 거부한다. 보호 집합: `M`(`MACHINE_LDAP_BIND_DN`), 모든 `W_*`, `LDAP_SERVICE_ACCOUNT_DN`, 모든 `MACHINE_LDAP_ROOT_DNS`(rootdn), 복제 신원, 관리자·프로파일 관리자 DN, 쓰기 상한 컨테이너 자체. 이 집합은 설정에서 도출하며 client 상한과 무관하게 **항상** 적용된다.
- `REQ-020` — 정규형 DN 판정(B5): 보호 DN 거부·상한 소속·그룹 허용 목록·멤버 DN 검사는 문자열/`ParseDN.EqualFold` 비교에 **의존하지 않는다**. go-ldap v3.4.14는 속성 타입·값을 `strings.EqualFold`로만 비교하고(`dn.go:483`) OID→이름 매핑도 내부 공백 접기도 하지 않으므로 slapd가 같은 항목으로 해석하는 철자(`0.9.2342.19200300.100.1.1=root,…` == `uid=root,…`, `cn=a  b` == `cn=a b`, 앞뒤 공백, `caseIgnoreMatch` 속성의 대소문자)를 앱이 못 알아본다. 강제는 둘을 **모두** 쓴다: (a) **fail closed 형식 검사** — 요청 DN의 모든 AVA 타입이 `^[A-Za-z][A-Za-z0-9-]*$` 이름이 아니거나(OID·`oid.` 접두), 값에 앱이 재현할 수 없는 정규화 대상(연속·앞뒤 공백, `\`/hex escape, `#` BER 값, 다중값 RDN)이 있으면 쓰기 오퍼레이션에서 **거부**한다. (b) **슬랩드 관점 정체성 대조** — 쓰기 전 `M`로 요청 DN을 base 범위 검색해 반환된 `entryDN`·`entryUUID`를 보호 항목들의 `entryDN`/`entryUUID`(기동·갱신 시 같은 방식으로 해석)와 비교하고, 해석 불가(검색 0건/오류)는 거부. 같은 검사를 멤버 DN과 **상한 소속 판정**에도 적용한다(`entryDN`이 상한 컨테이너의 하위인지 `entryDN` 문자열을 파싱해 판정).
- `REQ-017` — 대상 타입 단언(B1): 수정·삭제·멤버 변경은 대상 항목의 objectClass를 LDAP이 검사하게 한다 — 사용자 오퍼레이션은 `inetOrgPerson`, 그룹 오퍼레이션은 `groupOfNames`. RFC 4528 assertion 필터를 `(&(entryCSN=<태그>)(objectClass=<필수>))`로 확장해 실을 수 있으면 그렇게 하고(`If-Match`가 필수이므로 머신 쓰기에는 assertion이 항상 붙는다), 실을 수 없는 경우(멤버 DN의 타입)는 쓰기 전 `M` 읽기로 확인하고 TOCTOU를 문서화한다. 타입 불일치는 쓰기 없이 403/404로 거부(T-018에서 코드 확정). 사용자 오퍼레이션이 그룹을, 그룹 오퍼레이션이 사용자를 건드릴 수 없어야 한다.
- `REQ-018` — 쓰기 가드는 **엄격한 하위**(B2): 머신 **쓰기**의 대상·생성 부모 DN은 client 상한의 **엄격한 후손**이어야 하며 상한 DN 자체는 거부한다(읽기 가드 `dnWithinBase`의 `EqualFold(d) || AncestorOfFold(d)`, `httpapi/machine_guard.go:43`와 달리). 쓰기 전용 헬퍼를 새로 두고 읽기 가드는 바꾸지 않는다. 생성 부모 DN은 상한 자신이거나 그 후손일 수 있다(상한 아래에 만드는 것이므로 신규 항목 DN이 엄격한 후손이 되는 한 허용; T-012가 "부모=상한 허용, 대상=상한 불허"를 표로 고정).
- `REQ-019` — 그룹 멤버십 권한 경계(B4): 그룹 멤버십은 `memberOf`(overlay가 ACL 검사 없이 갱신)를 통해 하위 시스템의 역할이 되므로 subtree 상한과 **별개로** client별 **쓰기 가능 그룹 허용 목록**(`MACHINE_WRITE_GROUPS`, client별 정확 DN 목록, 비면 멤버 변경 불가)과 **특권 그룹 거부 집합**(보호 DN 집합에 특권 그룹 포함)을 앱이 연결 전에 강제한다. 첫 출하에서는 그룹 **생성·수정·삭제를 열지 않는다**(Q2); 열 때는 `CreateGroup`이 seed 멤버로 바인드 DN(`W_data`)을 넣는 동작(`ldapclient/groups.go:86`)을 머신 경로에서 쓰지 않는다(D22).

## Acceptance scenarios

### `AC-001` — 기본 꺼짐과 v1 불변
쓰기 플래그를 켜지 않으면 `POST/PUT/PATCH/DELETE` + bearer는 v1과 같이 403 `scope_denied`·bind 0이고, OpenAPI·`openapi_contract` 시험·읽기 전용 증명은 변하지 않는다. 쓰기 플래그만 켜고 쓰기 신원·멱등 저장소·범위가 없으면 기동 실패한다.

### `AC-002` — 신원 분리와 `M` 읽기 전용 유지
쓰기 신원이 `M` 등과 `ParseDN` 동등이면 기동 실패(변형 12종, v1 D4 표와 같은 방식). 쓰기를 켠 배포에서도 `M`으로의 직접 `ldapadd/modify/delete/passwd` 시도는 전부 `insufficient access`이고 `test-machine-acl-readonly-live.py`는 녹색이다.

### `AC-003` — scope·상한·범위
(a) scope 없는 토큰·상한 밖 scope·읽기 scope만 있는 토큰의 쓰기는 403 `scope_denied`이고 쓰기 신원 bind 0. (b) 상한 밖 subtree의 대상·부모 DN(대소문자·공백·escape·hex·다중값 RDN 변형)은 앱이 LDAP 연결을 열기 전에 403. (c) 닫힌 속성 목록 밖 속성을 담은 `PUT`/`PATCH`는 400/403이고 쓰기 없음. (d) 쓰기 신원으로 직접 **모든 client 상한의 합집합 밖** 항목을 `ldapmodify`하면 ACL이 거부한다(앱 가드를 끈 것과 같은 백스톱 증명). 합집합 안의 client 간 교차 쓰기는 ACL이 막지 않음을 명시 시험으로 문서화한다(D17).

### `AC-004` — 조건부 쓰기·멱등 강제
`If-Match` 없는 수정·삭제 428, 낡은 `If-Match` 412(쓰기 없음), `Idempotency-Key` 없는 머신 쓰기 428. 같은 키+같은 요청 재시도는 한 번만 실행되고 `Idempotent-Replayed: true`로 재생, 다른 지문은 422 `idempotency_key_reused`, 처리 중은 409.

### `AC-005` — client 간 멱등 격리
client A와 B가 같은 `Idempotency-Key`를 쓰면 서로 독립이다(A의 기록이 B에게 재생되지도, 충돌로 보이지도 않음). 토큰 갱신 전후의 A는 같은 기록을 본다. 사람 세션의 키와도 독립이다.

### `AC-006` — 감사 귀속
허용·scope 거부·`If-Match` 412·멱등 재생·LDAP 거부 각각이 줄 1개이고 actor는 client id, 대상·오퍼레이션·결과 코드가 있으며 센티널 토큰·비밀번호·본문 값이 모든 컨테이너 로그에 0건.

### `AC-007` — 한도
쓰기 예산 소진은 429 `machine_rate_limited`+`Retry-After`이고 같은 client의 읽기는 영향이 없다. 한 client의 동시 쓰기 2건 중 하나는 거절. 중단된 요청 후 쓰기 슬롯·연결이 기준선으로 복귀한다. 한도 수치의 경계 표는 v1 AC-011 방식으로 단위 시험한다.

### `AC-008` — 비밀번호·잠금 격리
비밀번호 scope 없이 (a) 비밀번호를 담은 `createUser`, (b) `setPassword`, (c) `lock/unlockUser`는 403. 쓰기 신원 ACL에는 비밀번호 scope가 꺼진 배포에서 `userPassword`·`pwd*` 쓰기 규칙이 **없고**, 직접 시도가 ACL로 거부된다. `generatedPassword`를 요구하는 요청은 머신 경로에서 거부된다.

### `AC-009` — 파괴 통제
컨테이너/루트 DN 삭제 거부, 리프 아닌 항목 삭제는 LDAP `notAllowedOnNonLeaf` → 앱 오류 매핑, `If-Match` 없는 삭제 428.

### `AC-010` — ACL 공존
새로 초기화한 컨테이너에서 (복제 신원 없음 / `dedicated` / #277 해결 후 `prepare`) × (`LDAP_ANONYMOUS_READ_BASE` 설정·미설정) 조합마다 쓰기 ACL 조각을 설치·롤백하고 `olcAccess`를 읽어 정확한 인덱스·순서를 단언한다. 기존 신원(관리자·일반 사용자·익명·`M`·복제 신원)의 접근 결과가 설치 전후 같다.

### `AC-011` — 긴급 차단 드릴
(a) 쓰기만 끄는 재배포, (b) 쓰기 신원 LDAP 계정 비밀번호 회전/잠금으로 모든 replica의 **다음 요청부터** 쓰기가 503으로 실패, (c) 이미 발급된 토큰은 (a)(b) 후에도 쓰기가 실패하고 읽기는 영향이 없음을 실측한다. 노출 상한(TTL+skew)이 아니라 (b)의 상한을 기록한다.

### `AC-013` — If-Match 강제(B3)
머신 경로: `If-Match` 없음·빈 값 → 428 `if_match_required`(쓰기 없음), `*`·`W/"..."`·두 값(쉼표)·헤더 두 줄·따옴표 없는 값 → 거부(쓰기 없음), 유효한 강한 태그만 통과. 같은 입력을 사람 경로에 보내면 현재와 **같은** 응답(헤더 없음·`*`는 무조건 쓰기)이다. 428 응답이 표·골든·OpenAPI에 일치한다.

### `AC-014` — 보호 DN·대상 타입(B1)
subtree 상한이 보호 DN을 덮는 설정(예: 상한이 `BASE_DN` 전체)에서도 `patchUser`/`deleteUser`/멤버 연산이 `M`·`W_*`·서비스 계정·rootdn·복제 신원·관리자 DN(대소문자·escape·hex·다중값 RDN 변형)에 대해 LDAP 연결 전에 403이다. **B5 변형**: 속성 타입을 OID로 쓴 철자(`0.9.2342.19200300.100.1.1=root,…`), 내부 공백 중복(`cn=a  b`), 앞뒤 공백, `caseIgnoreMatch` 속성의 대소문자 변형, `#` BER 값·hex escape — 각각 slapd가 보호 항목으로 해석하는 입력은 **형식 검사(REQ-020a)에서 거부되거나 정체성 대조(REQ-020b)에서 거부**된다. 이 변형들의 시험은 **수정(REQ-020) 없이는 실패**해야 한다(문자열 비교만 쓰는 구현에 대해 보호 DN이 통과하는 것을 먼저 재현). 아래 라이브 부분은 T-013 전에는 머신 경로로 실행할 수 없으므로 **T-018/T-019가 `ldapclient` 수준(실제 slapd, 신원 `W_data`)에서 증명**한다. `deleteUser`/`patchUser`에 **그룹 DN**, 멤버 연산에 **사용자 DN을 그룹으로** 넘기면 타입 단언 실패로 쓰기가 일어나지 않는다(라이브: assertion 필터에 objectClass가 실제로 실렸는지 slapd 응답으로 확인).

### `AC-015` — 엄격한 하위(B2)
쓰기 상한 `B`에 대해 `B` 자신(대소문자·공백·escape·hex 변형 포함, **OID 타입·내부 공백 중복 등 B5 변형도 상한 소속 판정에서 같은 규칙으로 거부/정규 판정**), 부모, 형제, 상대 DN(`uid=x`), 다른 base의 같은 접미 DN은 대상 DN으로 거부된다. 엄격한 후손은 허용된다. 생성의 부모 DN은 `B` 자신과 후손은 허용, `B`의 부모·형제는 거부. 읽기 가드의 기존 시험은 변하지 않는다.

### `AC-016` — 그룹 멤버십 경계(B4)
`addGroupMember`/`removeGroupMember`는 client의 `MACHINE_WRITE_GROUPS`에 없는 그룹 DN에 대해 subtree 상한 안이어도 403(연결 전)이다. 특권 그룹(거부 집합)은 허용 목록에 있어도 거부된다. 멤버 DN도 상한·보호 DN·타입 검사를 통과해야 한다. (라이브 증명은 T-013 전 `ldapclient` 수준, T-019.) `createGroup`/`patchGroup`/`deleteGroup`/`updateGroup`은 첫 출하에서 403 `scope_denied`이고 거부 목록 데이터(D13)에 남는다.

### `AC-017` — 멱등 쿼터·재생 재인가·lockout
(a) 한 client가 per-client 쿼터를 채워도 다른 client의 새 키는 503 `idempotency_capacity`를 받지 않는다. (b) client A의 scope/상한이 회수된 뒤(재시작 없이 설정 갱신 시나리오가 없다면 토큰 scope 변경으로 시뮬레이션) 같은 키 재생 요청은 **먼저 인가를 다시 거쳐** 403이며 저장된 결과를 돌려주지 않는다. (c) `W`를 틀린 비밀번호로 반복 bind해 `pwdLockout`이 걸리는 경우의 거동(쓰기 503, 읽기 `M` 불변)과 완화(운영 문서)를 라이브로 확인한다. (d) `PUT`은 머신에서 403이고 `PATCH`는 `uid`(RDN)를 바꾸지 못한다(DTO에 필드 없음 + 시험).

### `AC-012` — 계약·드리프트
`machineBearer` 집합 == 코드 allowlist(쓰기 포함), 거부 목록은 결정 기록 없이 줄지 않음, 새 코드는 표·골든·OpenAPI enum 동시 갱신, `x-machine-scope` 어휘와 `config.MachineScopes`가 일치.

## Architecture and decisions

- Relevant design links: [machine-principal-auth CHANGE/ADR](../machine-principal-auth/CHANGE.md), [api-conditional-writes CHANGE/ADR](../api-conditional-writes/CHANGE.md), [replication-identity CHANGE](../replication-identity/CHANGE.md), [api-error-envelope](../api-error-envelope/CHANGE.md)(D218-14: 새 코드는 표·골든·OpenAPI enum 동시 갱신), [docs/api.md "머신 bearer 인증"](../../api.md), [machine-ldap-account.md](../../machine-ldap-account.md).
- ADR threshold: `required`(신규 자격 증명→쓰기 경로, 쓰기 신원, 신뢰 경계 확대). 수용 시 `ADR.md`를 같은 패키지에 둔다(T-005).

### 쓰기 신원 모델: 옵션 비교

| 항목 | A. 앱 검사만(기존 관리자·세션 신원 재사용) | B. **쓰기 신원 1개 + ACL 구획**(client 공유, 앱이 client 상한 적용) | C. client마다 쓰기 DN | D. 프록시 권한 위임(RFC 4370 `proxyAuthz`/`authzTo`) |
|---|---|---|---|---|
| 실행 신원 | `LDAP_SERVICE_ACCOUNT_DN`/관리자(rootdn 포함 가능) | 전용 `W`(들) | `W_client` | `W`로 bind 후 authzid=`W_client` 주장 |
| LDAP이 막아 주는 것 | 없음(rootdn은 ACL 우회) | `W`가 닿는 subtree·속성 | client별 subtree·속성 | client별(위임된 신원의 ACL) |
| 앱 버그·scope 오설정의 폭 | 디렉터리 전체 | `W`의 ACL 범위(구획별) | client의 ACL 범위 | client의 ACL 범위 |
| LDAP 쪽 귀속(`modifiersName`) | 공유/관리자 DN | 구획별 `W` DN(client 아님) | client 단위 | (제어가 적용되면) 위임된 신원 — **미검증** |
| 자격 증명 | 기존 | 구획당 1개 | client당 1개(설정·Secret·회전 폭증) | `W` 1개 + 항목별 `authzTo` |
| 필요한 서버 설정 | 없음 | ACL만 | ACL + DN 수만큼 | `olcAuthzPolicy`·`authzTo` + 제어 부착(go-ldap v3.4.14는 `control.go`에 프록시 권한 제어 상수가 **없어** 자체 `Control` 구현 필요; grep으로 확인) |
| 복제 신원 패키지와 | 무관 | 공존(ACL 순서만, D8) | 공존(ACL 순서, 규칙 수 증가) | **충돌**: `prepare`/`dedicated`는 `olcAuthzPolicy`≠`none`·`authzTo`/`authzFrom` 존재 시 기동을 거부한다(`image/entrypoint.sh:1727-1741`, replication-identity D64). 위임 허용은 E17에서 일반 사용자가 복제 신원을 가장하는 데 쓰였다. |
| 판정 | **기각**(REQ-002, 비밀·전체 쓰기) | **권고(v2)** | 후속 선택지(D4 탈출구) | **v2에서 기각**, 위 충돌이 해소될 때까지 재평가 안 함 |

**권고: B — 위험 구획별 소수의 쓰기 신원 + 앱 수준 client 상한/scope + LDAP ACL 백스톱.** 이유:
1. `W`가 ACL을 갖는 전용 신원이라 앱 버그가 나도 폭이 `W`의 ACL로 제한된다(REQ-002/004). A는 이 방어가 없다.
2. v1이 이미 "단일 bind DN + 앱 가드 + ACL"로 증명된 구조라 변경 면적이 가장 작다(`machineExecutor`가 bind DN만 오퍼레이션 등급으로 선택). C·D는 자격 증명·ACL·설정이 client 수에 비례한다.
3. D는 복제 신원 패키지의 거부 조건과 정면충돌하고(P9), 위임 제어 지원이 코드에 없다.
4. 비용은 **LDAP 쪽 client 귀속 상실**이다(P7). 이를 D6의 앱 감사와, 필요 시 C로의 탈출구(D4)로 처리한다.

### 결정 기록

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D1 | 쓰기는 v1과 **별개 플래그**(`MACHINE_WRITE_ENABLED`, 기본 꺼짐)이고 v1 allowlist(`machineOps`)를 제자리에서 넓히지 않는다. 쓰기 오퍼레이션은 별도 표 `machineWriteOps`에 두고 `machineOpFor`는 쓰기 플래그가 켜진 서버에서만 그 표를 참조한다(`machine_scopes.go:47-53`의 비-GET 거부는 플래그 꺼짐에서 그대로). | #285 수용 조건("Do not widen the v1 allowlist in place"), 꺼진 상태 바이트 동일 | 표 2개·계약 테스트 2갈래 | 합치기는 쉬움 |
| D2 | **영구 거부**: `moveEntry`, 백업 8개, 프로파일 14개, `getMe`. 이 패키지는 이들을 열지 않는다. 열려면 새 패키지. | 파괴·자격 증명·cn=config 관여 범위가 가장 크고 기존 `x-admin` 모델(관리자 DN)과 얽힘 | 자동화가 해당 기능을 쓸 수 없음 | 별도 Class D |
| D3 | **쓰기 신원은 위험 구획별**: `W_data`(사용자·그룹 일반 속성, 멤버십), `W_lock`(잠금 속성), `W_cred`(비밀번호). 각각 따로 설정·따로 켠다(기본 꺼짐). 같은 DN을 재사용하면 기동 실패(DN 상호 ParseDN 비교). `M`과도 서로도 달라야 한다. | `W_data`가 침해돼도 비밀번호 쓰기·잠금이 열리지 않음(REQ-009). ACL로 구획을 강제할 수 있는 단위 | 계정 최대 3개·Secret 3개 | 구획 합치기(운영자 선택 시 같은 DN 허용은 하지 않음) |
| D4 | **client별 DN(옵션 C)은 v2에서 만들지 않는다.** 필요하면 `W_*`를 client 단위로 복제하는 후속 변경. 그때까지 LDAP 귀속은 구획 단위, client 귀속은 앱 감사(D6). | 자격 증명·ACL 수가 client에 비례 | LDAP 기록만으로 client 구별 불가 | 후속 변경(감사 요건이 강하면) |
| D5 | **proxyAuthz 기각**(v2). | P9: 복제 신원 거부 조건과 충돌, go-ldap 미지원, 위임 허용 자체가 권한 상승 표면(E17) | 귀속 정밀도 | 충돌 해소(복제 신원 패키지가 위임 금지를 완화) 후 재평가 |
| D6 | **앱 감사 확장**: 쓰기 요청은 v1 `machine_access` 줄에 더해 쓰기 필드(오퍼레이션 id, 대상 DN 지문(+선택적 평문 DN, 질문 Q4), `if_match`/`idempotent` 유무, 멱등 키 지문, `ldap_result` 코드, `replayed`)를 같은 한 줄에 싣는다. 줄이 정확히 1개라는 v1 규칙(D10)은 불변. 대상 DN 평문의 로그 반영은 운영자 선택. | 줄 단위 귀속이 가장 작은 변경, v1 스키마·테스트 재사용 | DN이 로그에 남으면 감사 로그가 민감해짐 | 별도 감사 저장소(후속) |
| D7 | **scope 어휘(안, 오퍼레이션 단위, 최소 권한)**: `directory.users.create`, `directory.users.update`(patch), `directory.users.delete`, `directory.users.lock`, `directory.users.unlock`, `directory.groups.create`, `directory.groups.update`, `directory.groups.delete`, `directory.groups.members.add`, `directory.groups.members.remove`, `directory.users.password.write`. 포괄(`*.write`) scope 없음 — 생성만 필요한 client가 삭제 권한을 갖지 않는다. 오퍼레이션 매핑은 부록 A. | 최소 권한, REQ-003, 구획 D3와 대응 | scope 11개 증가 | scope 합치기는 하지 말 것(분리가 가산적) |
| D8 | **범위·한도**: (a) client별 `write subtree` 상한(`MACHINE_WRITE_SUBTREES`, 클라이언트별, 비면 쓰기 불가, ParseDN 비교), (b) 머신이 쓸 수 있는 속성은 오퍼레이션별 닫힌 목록(부록 A, 재고조사는 T-002), (c) 단건만, 대량 엔드포인트 없음, (d) 쓰기 예산은 읽기와 분리(rps/burst, client당 동시 쓰기 1, 전역 쓰기 슬롯 기본 2), (e) 컨테이너 DN 삭제·리프 아닌 삭제 거부, (f) 모든 쓰기의 대상 DN은 **엄격한 후손**(D20), (g) 보호 DN·타입·그룹 허용 목록(D19/D22). 한도는 replica별(v1 D9와 같음). | 구획·합집합 경계는 앱+ACL 이중, client 간 경계는 앱 가드 단독(D17), 블라스트 반경 축소 | 설정 항목 증가 | 한도 값 조정 |
| D9 | **멱등·조건부 쓰기 강제**: 머신 쓰기는 `Idempotency-Key` 필수(428, 새 코드 `idempotency_key_required`, 이름은 T-014에서 확정), 수정·삭제·잠금·멤버 변경은 `If-Match` 필수(428 `if_match_required` — **코드·매핑만 있고 emit하는 곳이 없어 새로 구현해야 한다**, D21). **주체는 client**(`machine:`+`len(iss)`+`:`+iss+client id, v1 D16 cursor 결속과 같은 구성)이고 공유 bind DN이 아니다 — `idempotency.go:139`의 `sess.DN` 인자를 principal 종류별로 분기하는 변경이 필요하다(P4). 쓰기 활성 시 멱등 저장소가 꺼져 있으면 **기동 실패**, replica가 2 이상이면 차트 렌더 실패(api-conditional-writes D216-9, 메모리 저장소는 단일 replica 전제). **재시작은 기록을 전부 지운다**: `NewStore`는 빈 저장소를 만들고(`ui/backend/internal/idempotency/store.go:79`), 빈 저장소에서 같은 키의 `Begin`은 `KindNew`를 돌려 요청을 **새 요청으로 다시 실행**한다(`store.go:153-181`: 기록이 없으면 신규 등록). 즉 재시작 전에 이미 적용된 쓰기를 같은 키로 재시도하면 **재생이 아니라 재실행**되며 재시도 보호는 그 창에서 사라진다. 두 번째 방어선은 `If-Match`(수정·삭제: 이미 적용됐다면 `entryCSN`이 바뀌어 412)와 DN 유일성(생성: 이미 있으면 LDAP이 `entryAlreadyExists`로 거부)뿐이며, 멤버 추가/제거·잠금처럼 자연 멱등이 아닌 경우의 중복은 `If-Match`에 의존한다. `outcome_unknown`은 재시작이 아니라 **프로세스가 살아 있는 동안** 결과를 판정하지 못한 경우에만 기록된다. | 재시도·응답 유실이 자동화에서 일상이다. 공유 DN 주체는 client 간 교차 재생을 낳는다 | 쓰기 호출 형식이 사람 API보다 엄격. 단일 replica 제약 | 영속 멱등 저장소(별도 변경)가 생기면 완화 |
| D10 | **fail closed**: 쓰기 신원 bind 실패 503(다른 신원 폴백 없음), 쓰기 신원 DN이 `M`·관리자 등과 겹치면 기동 실패(v1 D4 비교 재사용), 쓰기 플래그+`M` 미설정 불가, 쓰기 scope가 어떤 client 상한에도 없으면 경고가 아니라 쓰기 표를 비활성(오퍼레이션 도달 불가). | 부분 활성이 가장 위험 | 설정 실수가 기동 실패로 드러남 | — |
| D11 | **ACL 공존 계약**: 신원별 규칙 묶음은 모두 `to <대상>` + `by dn.exact="<자기 DN>" … ` + `by * break`로 **자기 DN에만** 작용하므로 서로 순서 무관이다. 계약: ① 복제 신원 규칙은 `{0}`(prepare 검사, `entrypoint.sh:1747-1748`) ② 그 뒤에 `M`(`{n}`..`{n+2}`)과 `W_*` 묶음 ③ **모든 기존 allow(`by self write`, `by users read`) 앞**. `W` 묶음은 `M` 묶음 뒤에 둔다. #277이 정의할 순서(복제 `{0}` + `M` `{1}`–`{3}`)를 기준으로 `W`는 `{4}`부터이며, 인덱스는 하드코딩하지 않고 설치 시 `olcAccess`를 읽어 계산한다(복제 신원·익명 읽기 분기에 따라 달라지므로). | 한 번 정한 순서 계약이 신원이 늘어도 유지됨 | 설치 도구(가이드)가 인덱스를 계산해야 함 | #277이 다른 순서를 고르면 그에 맞춤 |
| D12 | **긴급 차단**: (a) 쓰기만 끄는 재배포(`MACHINE_WRITE_ENABLED=false`), (b) **쓰기 신원 LDAP 비밀번호 회전·계정 잠금**: 요청마다 bind하므로(`machine_exec.go:89`) 모든 replica의 다음 요청부터 쓰기 bind가 실패한다(진행 중 요청은 그 요청 안의 연결로 끝까지 수행될 수 있음 — 미검증). 이것이 v1에는 없는 **더 빠른 쓰기 차단**이다. 이미 발급된 토큰 자체는 폐기되지 않는다(#286이 별도). | 쓰기에서는 TTL 창이 길다 | 쓰기 신원 회전이 정상 쓰기도 멈춤 | #286 introspection |
| D13 | **계약 테스트**: `machineBearer` 집합 == `machineOps ∪ machineWriteOps`(쓰기 플래그와 무관하게 문서는 선언), 거부 목록은 "D2 영구 거부 + 아직 안 연 쓰기"를 데이터로 두고 줄이는 PR은 이 패키지 D-id를 인용해야 통과(테스트가 인용 존재를 검사). 쓰기 OpenAPI 선언은 additive. | #285 수용 조건 | 테스트 갱신 비용 | — |
| D14 | **단계 출하**: 읽기 호환 단위(스캐폴딩)부터 시작해 (일반 쓰기 → 그룹 멤버십 → 잠금 → 비밀번호) 순으로, 각 단계는 별도 플래그·별도 `W_*`·별도 증거로 켜진다. 비밀번호 단계는 마지막이며 maintainer가 별도로 명시 승인해야 시작한다(Q1). | 위험 등급별 점진 확대, 실패 시 한 단계만 철회 | 전체 완료까지 오래 걸림 | — |
| D15 | **`createUser`는 비밀번호 없이만**(v2a): 본문에 `password`가 있으면 `directory.users.password.write` 없이는 403. 비밀번호 없는 생성은 `W_data`로 Add만 한다. 사용자가 초기 비밀번호를 가지려면 비밀번호 단계(v2c) 또는 사람 흐름. | P6: 비밀번호는 선택 필드이고 2단계 쓰기라 Password Modify에 `W_cred`가 필요 | 자동 프로비저닝이 비밀번호 설정 못 함 | v2c |
| D16 | **서버 생성 비밀번호 금지**: 머신 경로의 `setPassword`는 `password`를 명시해야 하고 빈 값(서버 생성)은 거부(응답 본문에 비밀이 실리고 재생 불가). 응답·감사·멱등 기록에 비밀 값 없음(기존 규칙). | ADR D216-8, REQ-008 | 클라이언트가 비밀번호 생성·전달 책임 | — |
| D17 | **LDAP ACL의 실제 보장 수준(정직한 한계)**: `W_data`는 client 공유 DN이므로 ACL은 client별 subtree를 강제하지 못한다. ACL이 주는 것은 (a) 모든 client 상한의 **합집합** 밖 쓰기 거부, (b) 속성 목록 밖(`userPassword`·`pwd*` 등) 쓰기 거부, (c) `M`·타 신원 불변이다. client A가 B의 subtree에 쓰는 것을 막는 것은 앱 가드(D8a) **하나뿐**이며 그 버그는 합집합 안에서 교차 쓰기를 허용한다. 하드 격리가 필요한 subtree는 subtree마다 별도 `W` DN(구획 × subtree)을 두고 요청을 그 DN으로 bind하는 것이 유일한 방법이며 이는 D4의 확장(후속, Q3·Q7)이다. 위협 모델·AC-003(d)는 이 수준으로 서술한다. | 설계의 정직성: 기존 문구는 ACL이 client 경계를 강제한다고 읽혔다 | 교차 client 쓰기는 앱 가드 1겹 | subtree별 `W` DN |
| D18 | **생성(Add) 시 `objectClass` 예외**: `ldapclient/users.go:107`이 Add에 `objectClass: top, person, organizationalPerson, inetOrgPerson`를 넣고, slapd는 Add 시 엔트리와 각 속성 값에 대한 ACL 접근을 검사한다(`slapd.access(5)`, 미검증: 이 저장소에서 쓰기 신원으로 확인하지 않음 → T-004⑥). 따라서 `W_data` ACL은 `objectClass`에 대해 **Add 용도**를 허용해야 한다. 설계: (a) 앱은 생성 시 objectClass를 **고정 집합**으로만 보내고(요청 본문의 objectClass 불허), 수정(`patchUser` 등)은 objectClass를 절대 보내지 않는다(속성 가드, T-012). (b) ACL 스케치: `W_data`에 `to attrs=objectClass`로 add 수준(가능하면 `add` 접근 수준 — slapd 2.6의 `add`/`delete` 수준 문법은 T-004⑥에서 확인) 부여, 그것이 불가하면 `write`를 부여하되 ACL은 생성/수정을 구별하지 못하므로 수정 경로의 objectClass 차단은 앱 가드만이 된다(D17과 같은 한계로 기록). (c) 그룹 생성의 `objectClass`(예 `groupOfNames`)도 같은 규칙. | 생성은 objectClass 없이 불가능. 기존 문구("objectClass 쓰기 금지")는 생성 자체를 막는 모순 | 수정 경로 차단이 ACL이 아닌 앱 가드에 의존할 수 있음 | T-004⑥ 결과로 ACL 수준 확정 |
| D19 | **보호 DN 거부 목록 + 대상 타입 단언(B1)**: 확인됨 — `PatchUser`/`DeleteUser`/`PatchGroup`/`DeleteGroup`/`AddMember`/`RemoveMember`는 DN을 그대로 받아 Modify/Del을 보내고 objectClass를 검사하지 않는다(`ldapclient/users.go:239,279`, `groups.go:152,171,192,215`). 앱 가드는 DN 위치만 보므로 상한이 관리자·서비스 계정·`M`·`W_*`를 덮으면 (예) 관리자 `mail` 변경으로 SSO 계정 탈취, `M`/`W_*`/서비스 계정 삭제, `deleteUser`로 그룹 삭제가 가능하다. 설계: (a) REQ-016의 보호 집합을 설정에서 도출해 **연결 전** 403, (b) REQ-017의 objectClass 단언(assertion 필터 확장; 멤버 DN은 `M` 읽기 확인), (c) 보호 집합은 client 상한과 무관하게 항상 적용, (d) 기동 시 어떤 client 상한도 `W_*`·`M`·rootdn의 컨테이너를 **통째로 덮으면** 경고가 아니라 보호 집합이 우선함을 시험으로 고정. | 상한은 "어디"만 말하고 "무엇"을 말하지 않는다. LDAP ACL은 `W_data`가 쓸 수 있는 모든 항목에 쓰기를 허용하므로(D17) 타입·신원 보호는 앱 몫이다 | 설정에서 보호 집합을 도출하는 코드, 멤버 타입 확인용 읽기 1회(TOCTOU) | 후속: 사용자·그룹 컨테이너를 분리하는 배치 요구(운영 가이드) |

  D19 보강: (e) **assertion 폴백** — slapd가 AND assertion 필터(`entryCSN`+`objectClass`)를 평가하지 않는 것으로 T-004/T-018이 실측하면 **`M` 읽기 사전 검사**(대상 `entryDN`/`entryUUID`/objectClass 확인, D26)가 단독 방어가 되며 TOCTOU는 문서화한다. 폴백 없이는 출하하지 않는다. (f) **한계**: 관리자 권한이 DN이 아니라 **그룹 멤버십이나 OIDC 역할**로 주어지는 사용자는 DN 보호 집합에 없다. 완화: 관리자 그룹 DN을 보호 집합(특권 그룹 거부 집합)에 넣고(D22/T-019), 그 그룹의 멤버 변경은 허용 목록에 있어도 거부하며, 멤버가 되는 사용자 항목의 수정(예 `mail`) 자체는 상한 안이면 가능하므로 관리자 역할 사용자를 쓰기 상한 컨테이너 **밖**에 두도록 운영 가이드(T-020)가 요구한다. 컨테이너 분리 배치는 후속이 아니라 **운영 요건**으로 명시한다. (g) **"같거나 그 아래" 의미**: 보호 집합 중 개별 항목(`M`, `W_*`, 서비스 계정, 관리자 DN, 복제 신원)은 **그 DN과 같거나 하위**를 거부하고, 상한 컨테이너는 **그 자신만**(= 엄격한 하위 규칙 D20이 이미 하위는 허용) 거부한다 — 컨테이너의 하위를 거부하면 모든 쓰기가 막히기 때문이다.
| D26 | **정규형 DN 판정(B5)**: 확인됨 — go-ldap v3.4.14 `dn.go:483`의 `AttributeTypeAndValue.EqualFold`는 `strings.EqualFold`로 타입과 값을 비교할 뿐 OID→이름 매핑·내부 공백 접기가 없다. 시나리오: 상한=`BASE_DN`, 관리자 `uid=root,ou=people,…`(`inetOrgPerson`)를 `0.9.2342.19200300.100.1.1=root,ou=people,…`로 `patchUser`하면 앱 비교는 다르다고 보지만 slapd는 같은 항목으로 해석하고 objectClass 단언도 통과해 관리자 `mail`이 덮인다(SSO 탈취). 설계(REQ-020): (a) 평범한 이름 타입(`^[A-Za-z][A-Za-z0-9-]*$`)·재현 가능한 값만 받는 **fail closed 형식 검사**, (b) `M`로 base 범위 검색해 slapd가 해석한 `entryDN`/`entryUUID`를 보호 항목의 것과 대조하는 **정체성 검사**(보호 항목은 기동 시 같은 방식으로 해석해 캐시하고 주기적/요청마다 재확인할지 T-018에서 확정; 해석 실패 시 쓰기 거부), (c) 상한 소속 판정과 멤버 DN에도 동일 적용, (d) 폴백은 D19(e). | 문자열 비교는 slapd의 equality 규칙과 다르다. 정체성은 slapd만 안다 | 쓰기마다 읽기 1회(TOCTOU 문서화), 일부 합법 DN 철자 거부 | — |
| D20 | **쓰기 가드는 엄격한 하위(B2)**: 확인됨 — `dnWithinBase`는 `b.EqualFold(d) || b.AncestorOfFold(d)`로 DN == base를 허용한다(`machine_guard.go:43`). 읽기에서는 의도된 동작이지만 쓰기에서는 상한 루트(컨테이너) 자체를 수정·삭제 대상으로 만든다. D8e는 삭제만 덮었다. 쓰기 전용 헬퍼(`dnStrictlyWithinBase`)를 두고 모든 쓰기 대상에 적용, 생성의 부모는 상한 자신 허용(신규 DN이 엄격한 후손이므로). 읽기 가드 불변. 시험 표: 상한 자신(대소문자·공백·escape·hex), 부모, 형제, 상대 DN, 다중값 RDN(AC-015). | 컨테이너 수정·삭제 방지, 쓰기가 읽기보다 좁아야 함 | 헬퍼 1개 | — |
| D21 | **If-Match 강제는 새 기능이다(B3)**: 확인됨 — `codeIfMatchRequired`는 `errors.go:72,170,219`에만 있고 emit하는 핸들러가 없다. `ifMatchCSN`은 `If-Match: *`와 헤더 없음을 모두 `""`(무조건 쓰기)로 돌려준다(`conditional.go:33-38`). 따라서 "기존 규칙"이 아니다. 설계: 머신 경로 전용 `machineIfMatch(c)`(`ifMatchCSN`을 사람 경로용으로 보존하고 머신 쓰기 핸들러 진입부에서만 호출)가 정확히 하나의 강한 태그를 요구하고 없음/빈 값은 428 `if_match_required`를 emit, `*`·약한 태그·다중·형식 오류는 거부한다(REQ-015). 이를 소유하는 단위는 **T-017**이고 T-013의 병합 선행 조건이다. 사람 경로 불변은 기존 `conditional_test.go`가 그대로 통과함으로 증명한다. | `If-Match: *`가 통과하면 "필수"가 장식이 된다 | 머신 전용 분기, 표·골든 갱신 | — |
| D22 | **그룹 멤버십은 권한 경계(B4)**: 확인됨 — `memberOf`는 overlay가 갱신하므로 `W_data` ACL이 막지 못하고(T-002), `AddMember`는 그룹 DN을 검사하지 않으며(`groups.go:178-193`) `CreateGroup`은 `member: c.dn`(바인드 DN)을 seed로 넣는다(`groups.go:86`). 상한 안의 임의 그룹에 멤버를 넣으면 다운스트림 역할이 바뀐다. 설계: (a) client별 `MACHINE_WRITE_GROUPS`(정확 DN 허용 목록, 비면 멤버 변경 불가)와 특권 그룹 거부 집합을 상한과 같은 방식으로 연결 전 강제(REQ-019, T-019). (b) **그룹 생성·수정·삭제는 첫 출하에서 열지 않는다**(Q2 권고 유지). 후속 단계(T-026)에서 `createGroup`을 열기 전에 seed 멤버를 머신 경로에서 `W_data` DN이 되지 않도록 결정(고정 비특권 placeholder DN 설정 또는 요청의 첫 멤버를 seed)하고 별도 보안 검토를 거친다. (c) 멤버 DN은 상한·보호 DN·타입 검사를 모두 통과해야 한다. | 멤버십 = 권한 부여. 상한은 위치만 제한 | 그룹 허용 목록 운영 비용, 그룹 생성 자동화 지연 | 허용 목록을 패턴으로 확장(별도 결정) |
| D23 | **멱등 쿼터와 재생 재인가(비차단 보강)**: 확인됨 — 저장소는 `maxTotal`(전역 10000)과 `maxSubject`(주체당 1000)을 이미 갖는다(`idempotency/store.go:14-15,173-176`). 그러나 주체가 client가 되면 client 수 × `maxSubject`가 `maxTotal`을 넘길 수 있어 한 client가 전역 한도를 채워 다른 client에 503 `idempotency_capacity`를 줄 수 있다. 설계: 머신 쓰기 주체의 `MaxPerSubject`를 `maxTotal / (허용 쓰기 client 수 + 사람 몫 여유)` 이하로 두는 **기동 검증**(위반 시 실패)을 T-014에 둔다. 또 재생(`KindReplay`)은 **인가(scope·상한·보호 DN·그룹 허용 목록)를 다시 통과한 뒤에만** 저장 결과를 돌려준다 — 현재 `Begin`이 핸들러 인가보다 먼저 재생을 돌려주지 않도록 머신 쓰기 미들웨어 순서를 T-014에서 고정하고 시험한다(미검증: 현재 순서는 T-014가 확인). | 한 client의 자원 고갈·회수된 권한의 재생 방지 | 설정 검증·시험 추가 | 영속 저장소·client별 풀 |
| D24 | **`W` pwdLockout 자기 DoS(비차단)**: 틀린 비밀번호로 `W_*`를 bind하면 기본 정책의 `pwdLockout`이 계정을 잠가 쓰기가 멈춘다(D12(b)가 의도적으로 쓰는 메커니즘의 역). 완화: (a) `W_*`는 ppolicy에서 lockout을 끄거나 duration 짧은 별도 정책 + 알림(운영 문서 T-022), (b) 자동 폴백 없음(D10) 유지, (c) 이 거동을 AC-017(c)에서 실측. | 잠금 정책은 운영 선택 | 정책 객체 1개 추가 | — |
| D25 | **PUT/PATCH 매핑 고정**: `PUT`(`updateUser`/`updateGroup`)은 머신에 열지 않는다(Q2). `PATCH`가 `uid`(RDN)를 바꾸지 못함은 `UserPatch` DTO에 `uid`가 없고 `userPatchModify`가 7개 속성만 Replace한다는 사실에 의존한다(`ldapclient/users.go:216-225`). T-002가 이를 단위 시험으로 고정해 장래 DTO 변경이 RDN 재작성(ModifyDN 의미)을 몰래 열지 못하게 한다. | 계약을 시험으로 | 시험 1개 | — |

### 위협 모델

| 위협 | 시나리오 | 통제 | 잔여 위험 |
|---|---|---|---|
| 토큰 탈취 후 변조 | 유출된 bearer로 TTL 동안 사용자·그룹을 쓰거나 지움 | 짧은 TTL(v1), 쓰기 scope 최소·client 상한(D7/D3), subtree 상한(D8), 쓰기 한도(D8), D12(b) 신원 회전 차단, 감사(D6) | 발급된 토큰은 TTL 동안 상한 범위 안에서 유효. 비가역 삭제는 `If-Match`·리프 한정·subtree 상한으로 폭만 줄임 |
| 권한 상승 | 일반 쓰기 scope로 `objectClass` 수정·`pwd*`·`memberOf`·`userPassword`를 건드림 | 오퍼레이션별 닫힌 속성 목록(D8b), 수정 경로는 objectClass 미전송·생성은 고정 집합(D18), `W_data` ACL이 `pwd*`·`userPassword`에 `none`(AC-008) | objectClass 수정 차단이 ACL로 불가하면 앱 가드 1겹(D18b). 속성 목록 재고조사 오류(T-002) |
| 구획 경계 붕괴 | `W_data` 침해로 비밀번호·잠금 변경 | `W_data` ACL에 `userPassword`·`pwd*`·`pwdAccountLockedTime` 쓰기 규칙 없음, 구획별 DN(D3) | ACL 오구성은 앱이 완전 검증 불가 — 라이브 증명이 유일한 방어 |
| 교차 client 쓰기 | client A의 앱 가드 버그·오설정으로 B의 subtree에 씀 | 앱 가드(D8a), 상한 합집합 밖은 ACL이 거부(D17), 감사(D6) | **ACL은 client를 구별하지 못한다**(공유 `W_data`): 합집합 안의 교차 쓰기는 앱 가드 1겹. 하드 격리는 subtree별 `W` DN(D17, 후속) |
| 교차 client 재생 | client A가 B의 멱등 기록을 재생/관찰 | 주체=client(D9, AC-005) | 단일 replica·메모리 저장소 한계(P5) |
| 중복·유실 | 응답 유실 후 재시도로 이중 생성·이중 삭제 | `Idempotency-Key` 필수(D9), `If-Match` 필수, 생성은 DN 유일성 | **재시작 후에는 같은 키가 새 요청으로 재실행된다**(`store.go:153-181`): 재시도 보호가 사라지고 `If-Match`/DN 유일성만 남음(D9). 단일 replica·무중단 배포 불가 제약 |
| 대량 파괴 | 정상 scope 반복 호출로 대량 삭제·변경 | 단건만, 쓰기 예산·동시 1·전역 슬롯(D8), subtree 상한, 컨테이너 삭제 금지 | 한도 내 반복은 가능 → 감사·알림으로만 탐지 |
| 귀속 소실 | 공유 `W`로 `modifiersName`이 client를 말해 주지 않음 | 앱 감사 줄(D6), 요청 ID | LDAP 로그만으로는 client 구별 불가(D4) |
| 복제 충돌 | 다중 provider LWW로 머신 쓰기가 조용히 사라지거나 사람 쓰기를 덮음 | `If-Match`는 쓰기 받은 노드에서만 평가됨(ADR D216-1 "보장하지 않는 것")을 문서화, 쓰기 요청은 한 노드로 고정 권장 | AGENTS.md "Multi-provider replication": 조용한 손실 가능, 완화 없음 |
| ACL 순서 | W 규칙이 기존 allow 뒤에 삽입되어 `by self write`가 먼저 적용 | D11 계약, AC-010 인덱스 단언 | #277 미해결 시 `prepare` 비공존 |
| DN 철자 우회(OID 타입·공백 접기) | slapd가 정규화하는 철자로 보호 DN·상한 검사 회피 | D26: 형식 fail closed + `entryDN`/`entryUUID` 정체성 대조 | 읽기와 쓰기 사이 TOCTOU |
| 대상 타입 혼동·보호 신원 변조 | 상한이 덮은 관리자·`M`·`W_*`·서비스 계정·그룹을 사용자 오퍼레이션으로 수정·삭제 | 보호 DN 거부 목록(D19), objectClass 단언(D19), 엄격한 하위(D20) | 멤버 DN 타입 확인은 TOCTOU, 보호 집합 도출 오류는 단위 시험 의존 |
| 그룹 멤버십 권한 상승 | 상한 안 그룹에 멤버를 넣어 `memberOf` 기반 역할 획득 | client별 그룹 허용 목록·특권 그룹 거부(D22), 그룹 생성 미개방 | 허용 목록 오설정 |
| 조건 없는 쓰기 | `If-Match: *`·헤더 생략으로 낡은 상태를 덮음 | 머신 전용 강제(D21, REQ-015) | 사람 경로는 의도적으로 옵트인 유지 |
| 멱등 자원 고갈·회수 후 재생 | 한 client가 키 공간을 채움 / 권한 회수 후 재생 | 주체당 쿼터 검증·재생 전 재인가(D23) | 단일 replica·메모리 한계 |
| `W` 자기 잠금 | 틀린 비밀번호로 `W` 잠금 유도 | D24(정책 분리·알림), 읽기 영향 없음 | 쓰기 중단은 가용성 손실 |
| 위임 권한 상승 | 위임 허용(`authzTo`)으로 신원 가장 | D5(사용 안 함), 복제 신원의 거부 조건 유지 | — |
| 서버 생성/반환 비밀 | 쓰기 응답이 비밀을 반환 | D16, `entryRedactedAttrs` 불변 | — |
| 긴급 차단 지연 | 유출 인지 후 차단까지의 쓰기 | D12(b) 신원 회전, 쓰기 단독 끔 | 진행 중 요청·TTL(미검증 부분) |

### 실패 모드

| 상황 | 동작 |
|---|---|
| 쓰기 신원 bind 실패(비밀번호 오류·잠금·LDAP 불가) | 503, 감사 `reason=bind_failed`, 다른 신원 폴백 없음, 읽기(`M`)는 영향 없음. `pwdLockout`이 켜진 기본 정책에서는 틀린 비밀번호가 `W`를 잠글 수 있음(v1 D29와 같은 성질) |
| 멱등 저장소 꺼짐/초과 | 쓰기 활성이면 기동 실패(꺼짐). 상한 도달 시 새 키는 503 `idempotency_capacity`(기존 코드) |
| `If-Match` 불일치 | 412 `revision_conflict`, 쓰기 없음 |
| 쓰기 중 클라이언트 끊김 | 연산은 끝까지 수행되고 결과가 기록됨(ADR D216-8). 재시도는 재생 |
| LDAP 결과 불명(전송 후 네트워크 오류) | `idempotency_outcome_unknown` 기록·재생(ADR) |
| UI 재시작(롤아웃·크래시) | 멱등 기록이 비어 같은 키가 **재실행**된다(재생 아님). 수정·삭제는 `If-Match` 412, 생성은 `entryAlreadyExists`로 보호, 멤버 연산·잠금은 중복이 가능. 클라이언트는 재시작 의심 시 대상을 읽어 확인한다. 롤아웃 중 쓰기 중단(점검 창) 권고 |
| `W` ACL이 의도보다 넓음 | 앱 가드가 일차 방어. 시험(AC-003d)이 설치 직후 증명. 운영 점검 스크립트(T-023) |
| 쓰기 후 복제 지연 | 읽기(`M`)가 다른 노드에서 옛 값을 볼 수 있음 — 호출자가 `If-Match` 재조회로 확인(문서화) |

## Change impact

| 영역 | 영향 |
|---|---|
| `machine_scopes.go` | `machineWriteOps` 표 추가, `machineOpFor`는 플래그 꺼짐에서 현재와 동일 |
| `machine_exec.go` | 오퍼레이션 등급(읽기/쓰기 구획)별 bind DN·슬롯 선택. 현재는 단일 `bindDN`(`:89,109`) |
| `idempotency.go` | 주체를 principal 종류별로 분기(`:139`). 사람 경로 불변 |
| `config/machine.go` | 쓰기 신원·범위·한도 env, 기동 검증(D3/D10) |
| OpenAPI·`docs/api.md`·`llms.txt` | 쓰기 오퍼레이션의 `security`/`x-machine-scope` additive, 새 오류 코드 |
| ACL | 새 LDIF 조각(`W_*`), `docs/machine-ldap-account.md` 확장, #277와 순서 합의 |
| 차트 | `ui.machineAuth.write.*`, 단일 replica·멱등 활성 강제 |
| 사람·쿠키·SSO | 변경 없음(목표) |

### 호환·이행

- 기본 꺼짐. 꺼진 상태는 v1과 바이트 동일(렌더·응답·OpenAPI의 기존 오퍼레이션). 오류 코드는 append-only.
- v1 배포의 이행: 쓰기를 쓰지 않으면 아무 것도 할 필요 없다. 쓰기를 켤 때: `W_*` 계정·ACL 적용 → 멱등 활성(단일 replica) → client 상한에 쓰기 scope·subtree 추가 → 플래그 켬. 롤백은 역순이며 쓰기 플래그 끔은 영속 데이터를 남기지 않는다(멱등 기록은 메모리).
- ~~#277 미해결 구성(`prepare`)은 쓰기를 켜지 못한다~~ → #277 병합으로 폐기(Resolved Q6): `prepare` 구성에서도 쓰기 ACL이 정의된 순서에 놓이는지 T-021/T-023이 증명하고, 위치가 어긋나면 점검 실패.

## Verification plan

- 단위: 쓰기 표·scope 해석·상한 교집합, 속성 목록 가드, subtree ParseDN 변형 표, 멱등 주체 분기·교차 client 격리, 428 강제, 감사 줄 1개(조기 반환 포함), 쓰기 한도 경계 표, 기동 검증(DN 동등 변형, 플래그 조합), 계약 테스트(D13).
- 라이브(실제 slapd, 새 초기화 컨테이너): 쓰기 신원 ACL 허용/거부 속성별 증명(비밀 값 심기 방식은 v1 §4 재사용), `M` 읽기 전용 증명 재실행, 복제 신원/익명 읽기 분기 조합 ACL 인덱스, 직접 ldap 시도로 앱 가드 백스톱 증명, 쓰기 신원 회전 드릴, 멱등 재생·응답 유실, 로그 센티널 스캔. Keycloak 실토큰 e2e는 v1의 `machine-keycloak-e2e` 패턴 확장.
- 변이 시험: 비-GET 거부 제거, subtree 가드 제거, 멱등 주체를 공유 DN으로 되돌림, `If-Match` 강제 제거, ACL `by * break` 제거 → 각각 시험이 실패해야 한다.
- 미실행(설계 시점): 아래 "Not verified".

## Rollout, rollback and recovery

단계 출하(D14, TASKS.md). 각 단계: 기본 꺼짐으로 병합 → 라이브 증명 → 운영자가 켬. 롤백: 해당 단계 플래그 끔 + 재배포(+ `W_*` ACL 규칙 제거는 가이드의 역순 삭제 절차). 긴급: D12. 복구: 쓰기 신원 잠금은 비밀번호 재설정으로 해제.

## Evidence and durable synchronization

수용·구현 시 `EVIDENCE.md`에 실제 명령·출력(실패 포함, `research/README.md`), `ADR.md`로 승격(되돌리기 어려운 결정: D1/D3/D4/D5/D9), `docs/api.md`·`docs/machine-ldap-account.md`·`docs/machine-auth-operations.md`·`docs/audit-event-schema.md`·`llms.txt`·OpenAPI·CHANGELOG를 같은 PR에서 동기화한다.

## Traceability matrix

| REQ | 결정 | AC | TASKS |
|---|---|---|---|
| REQ-001 | D1, D10 | AC-001 | T-010, T-011 |
| REQ-002 | D3, D10 | AC-002 | T-011, T-021 |
| REQ-003 | D7, D13 | AC-003, AC-012 | T-012, T-013 |
| REQ-004 | D8, D20 | AC-003, AC-015 | T-012, T-013, T-021 |
| REQ-005 | D9, D21 | AC-004, AC-013 | T-014, T-017 |
| REQ-006 | D9 | AC-005 | T-014 |
| REQ-007 | D6 | AC-006 | T-015 |
| REQ-008 | D8 | AC-007 | T-016 |
| REQ-009 | D3, D15, D16 | AC-008 | T-030, T-031 |
| REQ-010 | D8e | AC-009 | T-013 |
| REQ-011 | D11 | AC-010 | T-020, T-021 |
| REQ-012 | D12 | AC-011 | T-022 |
| REQ-013 | D13 | AC-012 | T-010 |
| REQ-014 | D14 | — | TASKS 전체 순서 |
| REQ-015 | D21 | AC-013 | T-017 |
| REQ-016 | D19 | AC-014 | T-018 |
| REQ-017 | D19 | AC-014 | T-018 |
| REQ-018 | D20 | AC-015 | T-012 |
| REQ-019 | D22 | AC-016 | T-019, T-026 |
| REQ-020 | D26 | AC-014, AC-015 (B5 변형) | T-018, T-012 |
| REQ-006(보강) | D23 | AC-017a,b | T-014 |
| REQ-012(보강) | D24 | AC-017c | T-022 |
| REQ-004(보강) | D25 | AC-017d | T-002 |

## Open questions for the maintainer

**전부 결정됨 — 아래 "Resolved questions"가 정본이다.** 이 목록은 결정 이력으로 보존한다. 각 항목에 권고안을 적었다.

1. **비밀번호 단계(v2c)를 이 패키지가 설계 범위로 포함할지, 아니면 별도 패키지로 분리할지**. 권고: 이 패키지는 v2a(일반 쓰기)·v2b(잠금·멤버십)까지만 수용하고 비밀번호(D15/D16, `W_cred`)는 **설계만 남기고 구현은 별도 승인**. 비밀번호는 자격 증명 취급 설계 변경이라 별도 보안 검토가 합리적.
2. **지원 대상 오퍼레이션 최소 집합**: 부록 A의 사용자·그룹 쓰기 중 정말 열 것은? 권고: 첫 출하는 `createUser`(비밀번호 없이)·`patchUser`·`deleteUser`·`addGroupMember`·`removeGroupMember`. `PUT`(생략 필드 삭제 위험)은 머신에 열지 않고 `PATCH`만 허용.
3. **쓰기 신원 구획 수**: `W_data`/`W_lock`/`W_cred` 3개(권고) vs 1개(단순). 3개는 계정·Secret이 늘지만 침해 폭을 줄인다.
4. **감사 로그에 대상 DN 평문을 남길지, 지문만 남길지**. 사람 흐름의 기존 감사 이벤트가 DN을 어떻게 다루는지 확인이 필요하다(미검증). 권고: 기본 지문, 운영자 옵션으로 평문.
5. **subtree 상한의 설정 위치**: `MACHINE_ALLOWED_CLIENTS`를 확장(`client=scopes@subtree`)할지, 별도 `MACHINE_WRITE_SUBTREES` env를 둘지. 권고: 별도 env(v1 문법 불변).
6. **#277과의 순서**: 쓰기 ACL 구현 단위(T-020)를 #277 해결 뒤로 미룰지, 아니면 `prepare` 비공존을 명시한 채 먼저 낼지. 권고: 먼저 내되 `prepare`와 비공존(M의 현 상태와 동일).
7. **client별 LDAP 귀속이 요건인지**(D4). 규제상 `modifiersName`에 client가 남아야 하면 옵션 C가 필요해진다. 권고: 아니라고 가정(앱 감사로 충분).
8. **다중 replica**: 쓰기 + 멱등이 단일 replica를 요구하는 제약을 수용하는지. 권고: 수용, 영속 멱등 저장소는 별도 변경.
9. **#286(즉시 폐기)과의 선후**: 쓰기 출하 전에 introspection/denylist가 선행해야 하는지. 권고: 선행 요건 아님, 단 D12(b)와 문서화된 노출 상한을 보안 검토가 승인할 것.
10. **`generatedPassword`**: 머신 경로 영구 금지(D16, 권고) vs 별도 일회성 전달 설계.

## Resolved questions

2026-10-07 유지보수자가 위 열 가지 질문에 대해 오케스트레이터의 권고안을 **모두 수용**했다(결정 기록: 대화). 정본 결정은 다음과 같고, 위 목록의 권고 문구와 의미가 같다(Q6만 #277 병합으로 갱신).

1. **Q1 비밀번호 단계**: 설계만 남기고(D15/D16, `W_cred`) 구현은 **별도 승인**. 이 패키지의 구현 범위는 v2a/v2b까지.
2. **Q2 첫 출하 오퍼레이션**: `createUser`(비밀번호 없이)·`patchUser`·`deleteUser`·`addGroupMember`·`removeGroupMember`. `PUT`은 열지 않는다. 그룹 생성·수정·삭제와 잠금은 첫 출하에 없다(보안 검토 B4와 일치, D22).
3. **Q3 쓰기 신원 구획**: 3개(`W_data`/`W_lock`/`W_cred`).
4. **Q4 감사 DN**: 기본은 **지문**, 평문은 운영자 옵션.
5. **Q5 subtree 상한 설정**: 별도 `MACHINE_WRITE_SUBTREES` env(v1 `MACHINE_ALLOWED_CLIENTS` 문법 불변). 그룹 허용 목록도 같은 방식의 별도 env(`MACHINE_WRITE_GROUPS`, D22).
6. **Q6 ACL 순서(갱신)**: #277이 **병합되었으므로**(`dde826c`) 쓰기 ACL 조각은 정의된 순서에 합류한다: 복제 신원 `{0}`, 머신 읽기 `M` `{1}`–`{3}`([docs/machine-ldap-account.md](../../machine-ldap-account.md) §5.1·D30, [replication-identity](../replication-identity/CHANGE.md) D51a). **T-020/T-021은 쓰기 조각이 그 순서의 어디에 놓이는지(`M` 묶음 뒤, 모든 기존 allow 앞, 인덱스는 설치 시 `olcAccess` 읽기로 계산 — D11)를 정의하고 공존을 라이브로 증명해야 한다.** 이전의 "`prepare` 비공존" 전제는 폐기하며 T-020/T-021이 #277 결과(복제 `{0}` + `M` `{1}`–`{3}`)와의 공존을 단언한다.
7. **Q7 LDAP 귀속**: client별 LDAP 귀속은 **요건이 아니다**(앱 감사로 충분, D4/D6).
8. **Q8 다중 replica**: 단일 replica 제약 수용. 영속 멱등 저장소는 **별도 변경**.
9. **Q9 #286(즉시 폐기)**: 쓰기 출하의 **선행 요건이 아니다**. 단 D12(b)와 문서화된 노출 상한(`MACHINE_TOKEN_MAX_TTL`+skew)은 **보안 검토가 승인해야** 한다(승인 조건: 이 개정의 보안 검토 BLOCKER B1–B4가 설계에서 해소됨; D12(b) 노출 상한의 최종 승인 확인은 T-013 병합 전 보안 검토에서 받는다 — 아직 받지 않았다). #286 구현은 [machine-token-revocation](../machine-token-revocation/)에서 **병행 진행 중**이며, 완료되면 D12의 노출 창이 줄어든다.
10. **Q10 `generatedPassword`**: 머신 경로에서 **영구 금지**(D16).

## Revision

- 2026-10-07 (수용 + 보안 검토 반영): 보안 검토가 BLOCKER 4건을 보고했고 코드로 모두 **확인**했다.
  - **B1** 대상 타입 미검사 — `ldapclient/users.go:239,279`, `groups.go:152,171,192,215` → D19, REQ-016/017, AC-014, **T-018**.
  - **B2** 쓰기 가드가 상한 자신을 허용 — `httpapi/machine_guard.go:43` → D20, REQ-018, AC-015, **T-012** 확장.
  - **B3** If-Match 강제가 존재하지 않음 — `errors.go:72,170,219`(매핑만), `conditional.go:36-38`(`*`=무조건) → "기존 규칙" 문구 정정, D21, REQ-015, AC-013, **T-017**(새 단위, T-013 선행).
  - **B4** 그룹 멤버십이 권한 경계 — `groups.go:86`(seed `member: c.dn`), `AddMember` 무검사 → D22, REQ-019, AC-016, **T-019**, 그룹 생성·삭제는 첫 출하에서 제외.
  - **B5**(2차 재검토) DN 철자 정규화 우회 — `go-ldap v3.4.14 dn.go:483`(`strings.EqualFold`만) → D26, REQ-020, AC-014/AC-015 변형 확장, **T-018/T-012**, 수정 없이는 실패하는 시험. 비차단 5건: 라이브 부분은 T-018/T-019가 `ldapclient` 수준 증명, assertion 폴백(D19e), T-013 선행 조건에 Q9 승인·T-022·T-024 추가, 관리자 그룹/OIDC 역할 한계(D19f), 상한 컨테이너 "같거나 아래" 의미(D19g).
  - 비차단 반영: 멱등 쿼터(D23; 저장소에 `maxSubject`는 이미 있음 `store.go:14-15,173` — 신규는 client 수 × 쿼터 ≤ 전역 검증), 재생 전 재인가(D23), `W` pwdLockout 자기 DoS(D24), PUT/PATCH 매핑 고정(D25, T-002).
  - 결정 Q1–Q10 기록(위 "Resolved questions"), Q6은 #277 병합으로 갱신.
  - 독립 비평(Codex) 라운드는 이전 개정에서 완료. ADR 초안은 같은 패키지의 `ADR.md`(Status: `Proposed`, 구현 단위가 병합될 때 `Accepted`로 승격).

## Not verified

- accesslog에 쓰기 연산이 `reqAuthzID`로 무엇을 남기는지, 쓰기 신원 비밀번호 회전이 진행 중 요청에 미치는 영향(D12), 위임 제어가 `modifiersName`에 위임 신원을 남기는지(D5 비교표): 이 패키지에서 실행하지 않았다.
- OpenLDAP 동작 근거는 `slapd.access(5)`의 first-match·`break`(v1 AC-018이 라이브 확인), RFC 4528 assertion control(ADR D216-2가 라이브 확인), RFC 4370 Proxy Authorization Control과 `slapd.conf(5)`의 `authz-policy`·`authzTo`(저장소 E17이 라이브로 위임 성립 조건을 확인, 이 패키지는 재실행하지 않음). `notAllowedOnNonLeaf`와 `modify` ACL 해석은 일반 slapd 동작이며 이 저장소에서 쓰기 신원으로 확인하지 않았다.
- 속성 목록(부록 A)은 코드 읽기 전 가안이며 T-002가 핸들러·DTO에서 도출한다.
- 재생 요청이 인가보다 먼저 저장 결과를 돌려주는지(D23), assertion 필터에 objectClass를 AND로 추가해도 slapd 2.6이 Modify/Delete에서 평가하는지(D19/REQ-017): 이 패키지에서 실행하지 않았고 T-018/T-004가 실측한다. 보안 검토 B1–B4의 코드 사실(줄 번호)은 이 개정에서 읽어 확인했다.
- 이 문서의 줄 번호는 작업 트리 기준이며 이후 변경으로 어긋날 수 있다.

## 부록 A — 오퍼레이션 → scope → 신원 구획(안)

| operationId | 경로 | scope | 구획 | 조건 | v2 단계 |
|---|---|---|---|---|---|
| `createUser` | `POST /api/users` | `directory.users.create` | `W_data` | `Idempotency-Key`; 본문 `password` 있으면 거부(D15) | a |
| `patchUser` | `PATCH /api/users` | `directory.users.update` | `W_data` | 엄격한 `If-Match`(D21)+키, 닫힌 속성, 보호 DN·`inetOrgPerson` 단언(D19) | a |
| `updateUser` | `PUT /api/users` | — | — | **열지 않음**(생략 필드 삭제, Q2) | — |
| `deleteUser` | `DELETE /api/users` | `directory.users.delete` | `W_data` | 엄격한 `If-Match`(D21)+키, 리프 한정, 보호 DN·`inetOrgPerson` 단언(D19), 엄격한 하위(D20) | a |
| `createGroup` | `POST /api/groups` | `directory.groups.create` | `W_data` | 사용자와 동일 + seed 멤버 결정(D22) | **첫 출하 제외**(T-026) |
| `patchGroup` | `PATCH /api/groups` | `directory.groups.update` | `W_data` | 사용자와 동일 | 첫 출하 제외(T-026) |
| `deleteGroup` | `DELETE /api/groups` | `directory.groups.delete` | `W_data` | 사용자와 동일 | 첫 출하 제외(T-026) |
| `addGroupMember` | `POST /api/groups/members` | `directory.groups.members.add` | `W_data` | `If-Match`+키, 그룹 허용 목록(D22), 멤버 DN도 상한·보호 DN·타입 검사 | a(Q2) |
| `removeGroupMember` | `DELETE /api/groups/members` | `directory.groups.members.remove` | `W_data` | `If-Match`+키, 그룹 허용 목록(D22), 멤버 DN도 상한·보호 DN·타입 검사 | a(Q2) |
| `lockUser` | `POST /api/users/lock` | `directory.users.lock` | `W_lock` | `If-Match`+키 | b |
| `unlockUser` | `POST /api/users/unlock` | `directory.users.unlock` | `W_lock` | `If-Match`+키 | b |
| `setPassword` | `POST /api/users/password` | `directory.users.password.write` | `W_cred` | `password` 필수(서버 생성 금지), `If-Match` 불가(RFC 3062 제약, 400) → 대체 보호 필요(Q1) | c(별도 승인) |
| `updateGroup` | `PUT /api/groups` | — | — | 열지 않음 | — |
| `moveEntry`, 백업 8, 프로파일 14, `getMe` | — | — | — | **영구 거부**(D2) | — |

참고: `setPassword`는 `If-Match`를 지원하지 않는다(ADR D216-2, 비밀번호 확장 연산은 assertion control을 실을 수 없음). 따라서 비밀번호 단계는 조건부 쓰기 강제(REQ-005)를 만족시킬 수 없고, 멱등 키 + 대상 한정 + 한도로만 보호된다 — 비밀번호 단계를 별도 승인으로 두는 이유 중 하나다.


### 부록 A — T-002 확정 속성 목록 (2026-10-08, #328)

실제 DTO·핸들러·LDAP 요청 빌더 재고조사 및 증거: [EVIDENCE.md](EVIDENCE.md) T-002.

| 오퍼레이션 | 쓰는 속성/연산 |
|---|---|
| createUser | objectClass 고정 {top, person, organizationalPerson, inetOrgPerson}; uid, cn, sn; 선택 givenName, mail, departmentNumber, o, ou |
| patchUser | cn, sn, givenName, mail, departmentNumber, o, ou의 Replace만; DN/uid 불변 |
| patchGroup | cn, description; 첫 머신 출하에는 미개방 |
| add/removeGroupMember | member Add/Delete |
| lock/unlockUser | pwdAccountLockedTime Replace |
| setPassword / createUser의 password 입력 | 별도 RFC3062 확장 연산; 일반 데이터 쓰기 입력에서는 금지 |

memberOf·refint의 파생 쓰기는 요청 신원의 대상 속성 쓰기 ACL로 막히지 않음을 라이브 확인했다. POST는 미지원 JSON 속성을 무시하지만 PATCH는 거부한다. 따라서 머신 입력 가드는 POST에도 닫힌 목록을 독립 적용해야 한다. objectClass 수정·uid 수정·memberOf·pwd*·운영 속성은 일반 쓰기 목록에 없다. 이 표는 조사 결과 확정이며 쓰기 오퍼레이션이나 LDAP 권한을 개방하지 않는다.
