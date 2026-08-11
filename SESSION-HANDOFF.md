# openldap-suite Session Handoff — 2026-08-11

새 세션은 이 파일부터 읽을 것. 리포는 `git init` 후 커밋 1건(`f75e7a1`, 91파일)이며 워킹트리는 깨끗하다.

## 무엇을 만들었나

OpenLDAP을 **상류 소스에서 직접 컴파일**하는 서버 이미지 + 자체 제작 관리 UI + (예정) Helm 차트.
beluga와 무관한 독립 프로젝트다.

### 존재 이유 (조사로 확정한 사실, 2026-08-11 실조회)

기존 선택지가 전부 동시에 무너졌다 — README에 표로 정리돼 있다. 요약하면 osixia는 안정 태그가
2021-02-19(OpenLDAP 2.4.57)이고 유일한 현대 태그는 3개월 넘게 alpha 미승격, Bitnami는 2025년
Broadcom 정책 변경으로 유료화, 표준 차트 `jp-gouin/helm-openldap`은 2026-01-31 아카이브,
Symas 이미지(`symascorp/symas-openldap`)는 amd64 전용, LLDAP·GLAuth·Kanidm은 LDAP 와이어상
읽기 전용이라 쓰기 가능한 디렉터리로 못 쓴다. 반면 상류 OpenLDAP은 건강하다(2.6 LTS, 2.6.14가
2026-08-06 릴리스). **문제는 소프트웨어가 아니라 패키징**이라는 것이 이 프로젝트의 전제다.

## 검증 완료 (실제로 실행해서 확인한 것만)

| 항목 | 결과 |
|---|---|
| `docker build --platform linux/arm64` | 성공, 181MB |
| 컨테이너 기동 | 6초 내 `healthy`, `slapd`가 PID 1, 비root(uid 999) |
| 샘플 데이터 | 0건 (베이스 DN + admin만) |
| 재시작 | 부트스트랩 건너뜀, 데이터 보존 |
| `LDAP_SEED_DIR` 시딩 | 첫 기동에만 적용됨 |
| 오버레이 | memberof/refint/ppolicy 활성, 6개 모듈 로드 |
| 익명 uid 검색 | DN 반환 (uid 로그인 가능) |
| 익명의 `cn`/`sn`/`userPassword` | 전부 값 없음 |
| 비밀번호 저장 | `{SSHA}` 해시 |
| 원 평문 비밀번호로 bind | 성공 |
| UI `go build`/`vet`/`test` | 통과, 26 테스트 |
| UI 이미지 | 16.1MB (distroless) |
| **종단 통합** | uid 로그인 200 / 오답 401 / 세션으로 사용자 목록 200 |

## 남은 일 (우선순위 순)

1. **Helm 차트** (`charts/openldap/`) — 디렉터리만 있고 비어 있음. 서버 StatefulSet/Deployment +
   PVC 2종 + Service + 선택적 UI(`ui.enabled`) + values. beluga의 `openldap.yaml`이 참고 자료로
   쓸 만하다(PVC·`strategy: Recreate`·프로브 패턴).
2. **GitHub Actions** (`.github/workflows/`) — 비어 있음. **QEMU를 쓰지 말 것**: GitHub가 공개 리포에
   arm64 네이티브 러너를 GA(2025-08-07)했으므로 아키텍처별 네이티브 러너로 빌드해 매니페스트를
   합치는 방식이 맞다. OpenLDAP의 `configure`는 `AC_TRY_RUN` 런타임 프로브가 많아 QEMU 에뮬레이션에
   특히 취약하다. 주간 재빌드 크론 + GHCR 푸시.
3. **미검증 경로 검증** — TLS(`LDAP_TLS_ENABLED=true` + 인증서), `LDAP_ADMIN_PASSWORD_FILE`,
   UI의 그룹 CRUD·트리 브라우저(코드는 있으나 API 단위 미실행), UI를 브라우저에서 실제로 보기.
4. `make test` 스모크 서브셋을 CI에 편입 (전체 91개 스크립트는 약 1시간이라 부적합.
   `cd tests && ./run -b mdb test001-slapadd` 형태로 개별 실행 가능).

## 반드시 알아야 할 설계 결정

- **기본 admin 비밀번호가 없다.** 미설정 시 기동을 거부한다. vegardit의 `changeit` 같은 기본값은
  편의가 아니라 결함이라는 판단.
- **샘플 데이터를 절대 만들지 않는다.** 이게 차별점이다. vegardit은 첫 기동에 `employee1`/`guest1`/
  `machine1`과 `groupOfUniqueNames` 그룹 4종을 심는데, Keycloak WRITABLE 페더레이션 환경에서는
  그것들이 실제 사용자로 노출된다(beluga에서 실제로 겪었다).
- **ACL이 익명에게 허용하는 것은 `entry`,`uid`,`objectClass` 뿐이다.** 이건 타협이 아니라 필수다 —
  UI가 uid를 DN으로 바꾸려면 익명 검색이 되어야 하고(search-then-bind), 그렇다고 다 열면 개인정보가
  샌다. `userPassword`는 `by anonymous auth`로 인증에만 쓰이고 읽기는 금지.
  **주의**: `{2} to *`의 `by anonymous none`이 `entry` 의사속성까지 막기 때문에, 규칙 `{1}`에 `entry`가
  없으면 익명 검색이 `No such object (32)`로 실패하고 uid 로그인이 통째로 죽는다. 이미 한 번 밟았다.
- **UI는 서비스 계정을 갖지 않는다.** 로그인한 사용자의 bind 커넥션으로 모든 작업을 수행하므로
  디렉터리 ACL이 곧 인가 규칙이다. 세션은 서버 측에 보관하고 브라우저엔 서명된 불투명 ID만 준다.
- **`back-sql`을 빌드하지 않는다.** 그것만 켜면 unixODBC(LGPL/GPL)가 딸려와 카피레프트가 붙는다.
  안 켜면 전체 의존성이 퍼미시브로 유지된다 — `NOTICE`에 근거가 적혀 있다.
- **`# syntax=docker/dockerfile:1`을 다시 넣지 말 것.** 매 빌드마다 원격 프런트엔드를 받으려다
  10분 넘게 멈췄다. BuildKit 전용 문법을 쓰지 않으므로 불필요하고, 없어야 에어갭에서도 빌드된다.

## 실제로 동작하는 명령

```bash
# 빌드
docker build --platform linux/arm64 -t openldap-suite:dev image/

# 서버 기동
docker run -d --name ols -p 389:389 \
  -e LDAP_ROOT_DN="dc=example,dc=org" -e LDAP_ADMIN_PASSWORD="..." openldap-suite:dev

# UI (같은 도커 네트워크에 두고)
docker run -d --name ols-ui -p 8080:8080 \
  -e LDAP_URL="ldap://ols:389" -e LDAP_BASE_DN="dc=example,dc=org" \
  -e LDAP_USER_SEARCH_BASE="ou=people,dc=example,dc=org" \
  -e LDAP_USER_SEARCH_FILTER="(uid=%s)" \
  -e SESSION_SECRET="<32자 이상>" openldap-suite-ui:local

# 로그인 API 필드명은 username이 아니라 identity
curl -X POST localhost:8080/api/login -H 'Content-Type: application/json' \
  -d '{"identity":"alice","password":"..."}'
```

## 작업 방식 메모

레인 워커가 마무리 검증 단계에서 "빌드를 기다리겠다"만 반복하며 진전 없이 반환한 사례가 2회 있었다.
장시간 빌드를 워커에게 맡기지 말고, **빌드·검증은 오케스트레이터가 백그라운드로 직접 돌리는 편이
안정적**이다. 또한 워커 보고서의 "검증 완료"는 증거가 아니다 — 이번에도 두 레인이 각자 통과를
보고한 뒤 오케스트레이터의 통합 테스트에서 비밀번호 평문 노출이 나왔다.

## beluga와의 관계

beluga는 현재 `vegardit/openldap:2.6.10`을 쓴다(그 세션에서 osixia 1.5.0 = 2.4.57에서 전환했다).
openldap-suite가 성숙하면 beluga의 이미지를 이걸로 바꾸는 것이 자연스러운 다음 수순이지만,
**지금은 의도적으로 분리돼 있고 서로 의존하지 않는다.**
