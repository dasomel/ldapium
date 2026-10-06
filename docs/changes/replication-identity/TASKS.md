# Tasks: syncrepl 전용 복제 신원(replicator)

설계: [CHANGE.md](CHANGE.md) (Status: `Proposed / awaiting review`, 개정 3). 모든 항목은 미착수이며 Class D 패키지 수용 전에는 `Implement`
이후 단계를 시작하지 않는다. **수용 표시는 유지보수자만 한다.** `image/entrypoint.sh`·ACL·복제를 건드리는 모든 작업은 먼저
`.agents/skills/ldapium-directory-change/SKILL.md`를 로드한다. 구현은 단계 병합이며 각 단위는 기본값(`LDAP_REPLICATION_IDENTITY=admin`)에서
cn=config·olcSyncrepl·기존 테스트가 그대로인 상태로 main에 들어간다(앞 단위는 뒤 단위 없이도 안전). 라이브 LDAP 경로는 모킹하지 않는다.

## Inspect and establish evidence

- [ ] `T-001` (`REQ-001`, `REQ-003`) HEAD에서 소스 오브 트루스 재확인: `01-cn-config.ldif`의 `olcAccess {0}`이 `LDAP_ANONYMOUS_READ_BASE` 설정 여부와 무관하게 같은 위치인지(첫 규칙 삽입 위치), 렌더되는 catch-all(`entrypoint.sh:794-815`)의 `by self write`, `entrypoint.sh`에 부트스트랩 렌더 외 `olcAccess` 쓰기가 없는지, 베이스 DIT 템플릿(`03-base-structure.ldif`)에 신원·정책 엔트리를 덧붙일 때 `#__PASSWORD_POLICY__` 앵커와 `LDAP_PASSWORD_POLICY_ENABLED=false` 조합이 안전한지(E15b 재확인).
- [ ] `T-002` (`AC-007`) 사전 기준선 캡처: 현재 이미지로 `test-wiped-node-resync.sh`·`test-bootstrap-seed.sh`·`replication-chaos-e2e.yml` 결과, **cn=config 전체 덤프**와 렌더된 `olcSyncrepl` 줄(전환 후 diff 기준).
- [ ] `T-003` 다운스트림·소비자 검토: `detect-config-drift.sh`·`export-incident-evidence.sh`의 `credentials` 마스킹 회귀, 백업/복원(`backup.sh`·`restore.sh`)의 신원 엔트리·해시 처리, UI/API 디렉터리 브라우저의 신원 엔트리 노출·삭제 가능성(rootDN 세션), `detect-entry-drift`·`migration-dryrun`·`docs/migration.md` 영향, 차트 `helm test`(`files/tests/directory-test.sh`) 확장 지점, `networkpolicy.yaml`의 백업 CronJob 허용 규칙 패턴(점검 CronJob용).
- [ ] `T-004` (`REQ-003`, `REQ-008`, `REQ-011`) CHANGE.md "검증하지 못한 주장" (a)–(g) 해소: `credentials` 파일/SASL 비밀 참조 지원(slapd 2.6.15 소스·`man slapd-config`), `olcLimits time=unlimited` 필요성(긴 refreshAndPersist 세션이 `olcTimeLimit`에 걸리는지), 프로브 `UNREACHABLE` 판정의 타임아웃(블랙홀)·부팅 중 피어 신호, 인증서→예약 DN 매핑의 셸 평가 방법, `peername`/`sockurl` 피어 제한 문법·동작, EXTERNAL의 accesslog 세션과 `conn=` 대응. 결과를 CHANGE.md에 반영(재검토 필요 시 표시). 추가: 저장 `olcAuthzRegexp`(POSIX ERE)와 slapd 정규식의 동등성, 초기화 토큰의 소비·ConfigMap 훅 순서, 판정기의 노드 간 교차 비교·수렴 대기.
- [ ] `T-005` (`REQ-001`–`REQ-014`) 수용 선행: Owner 지정, ADR 초안(자격 증명 수용 경로·TLS 요구·D43 변경·예약 DN), `security-reviewer` 검토 요청. **수용 표시는 유지보수자만 한다.** (Q1–Q3은 개정 2에서 결정됨.)

## Implement

수용 이후에만 착수. 순서는 병합 단위(각 단위는 기본값에서 동작 불변).

- [ ] `T-010` (`REQ-007`, `REQ-008`) `scripts/check-replication-identity.sh`(D59): `--local`/`--remote`, 노드별 신원 시점 vs root 시점의 **DN 단위 체크섬**(값 순서 정규화, 전 속성으로 확장)·엔트리 수, 노드 간 양방향 교차 비교, 소비자 `olcSyncrepl` 바인드 DN·자격 증명 지문(온노드 `slapcat -n 0 -o ldif-wrap=no`, 원격 `cn=admin,cn=config`), 노드별 카나리 쓰기·해시 포함 관측, **G1(생성 전: ACL·limits·`ssf`·TLS·충돌 부재·catch-all 매핑, 설정만) / G2(생성 후: 신원·정책·피어별 TLS 바인드·시점 일치·전파)** 분리. **경쟁 안전 판정(E26)**: root 읽기 R1 → 신원 읽기 V → root 읽기 R2, `entryCSN` 불안정 엔트리는 판정 보류, **같은 CSN·다른 내용은 재시도 없이 즉시 실패**, 최대 5회 재시도, 노드 간 비교는 contextCSN 수렴 대기(기본 30초), 계속 쓰이는 엔트리만 남으면 경고 통과(임계 비율 초과 시 실패). 종료코드 0/1/2, 비밀번호는 `-y` 파일, 출력에 비밀 없음. 순수 판정 함수는 fixture 단위 테스트(경쟁·즉시 실패·보류 케이스). 동작 변경 없는 신규 스크립트.
- [ ] `T-011` (`REQ-006`, `REQ-013`, `REQ-015`) `LDAP_REPLICATION_IDENTITY`(`admin` 기본/`prepare`/`dedicated`) 파싱·검증, `dedicated`는 `LDAP_TLS_ENABLED`·모든 피어 `ldaps://`(또는 `starttls=critical`)·`LDAP_TLS_CA_FILE` 필수(없으면 기동 거부). 복제 비밀번호는 명시 필수·개행 금지·**위생 검사(길이 ≥ 32, 서로 다른 문자 ≥ 10, 관리자 비밀번호와 불일치; 무작위성의 증거가 아님을 메시지·문서에 명시)**. `LDAP_REPLICATION_INIT_TOKEN_FILE` 경로 env 파싱(기본 부재). 기본값에서 cn=config·olcSyncrepl 바이트 단위 불변, 커스텀 `LDAP_REPLICATION_BIND_DN`(비관리자)은 동작 유지 + 경고 로그(D58).
- [ ] `T-012` (`REQ-001`, `REQ-003`, `REQ-007`) `prepare`/`dedicated`: **예약 DN 충돌 검사** — (1) 엔트리가 이미 있으면 **표식으로 승인하지 않고 거부**, `takeover`가 출력한 `entryUUID`(`LDAP_REPLICATION_IDENTITY_UUID`)와 로컬 `slapcat -n 1`의 `entryUUID`가 일치할 때만 승인 (2) mTLS면 `slapcat -n 0`의 저장 `olcAuthzRegexp`를 합성 주체(`cn=replicator`, 예약 DN 문자열, 대소문자·공백 변형)에 평가해 예약 DN이면 거부 (3) mTLS면 모든 EXTERNAL 신원을 예약 DN 밖으로 보내는 **catch-all 매핑** 존재를 요구(없으면 거부, 자동 추가는 명시 동의 시에만). 통과 후 **명시적 첫 규칙** `{0}to * by dn.exact="<신원>" ssf=128 read by dn.exact="<신원>" none by * break` + `olcLimits` 설치. 신규 부트스트랩은 `01-cn-config.ldif`, 기존 볼륨은 부팅 시 오프라인 `slapmodify -n 0`(`hd_clear` 패턴, 멱등). 검증: 신규/기존 볼륨, 재부팅 멱등, 충돌 3경로 거부, `admin` 모드에서 cn=config 불변.
- [ ] `T-013` (`REQ-002`, `REQ-004`) 전용 모드 베이스 DIT 확장(D53): 노드 1이 베이스를 만들 때 신원 엔트리(`slappasswd -T`, `LDAP_PASSWORD_HASH` 준수, 관리 표식)와 **`cn=replication-policy,<root>`**(`pwdLockout FALSE`, `pwdMaxAge 0`, `pwdAllowUserChange FALSE`)를 `slapadd -n 1`에 포함하고 신원에 명시적 `pwdPolicySubentry`를 둔다(`LDAP_PASSWORD_POLICY_ENABLED`와 무관). 시드·마커·롤백 의미(`#203/#204`) 불변.
- [ ] `T-014` (`REQ-011`) 노드 1 부트스트랩 판정(D61): **볼륨 밖 1회성 초기화 토큰**. 마커 없는 sid-1 부트스트랩에서 (1) 어느 피어든 프로브 `OK`면 토큰 없이 당겨옴 (2) 그렇지 않으면(인증·TLS 오류, 분류 불가, **도달 불가 포함**) 토큰이 있을 때만 생성, 없으면 안내와 함께 기동 거부 (3) 성공 후 토큰 소비(쓰기 가능하면 삭제, 아니면 로그), 마커가 있으면 무시+경고. 프로브 분류(`UNREACHABLE`/`REACHABLE_FAIL`)는 안내 메시지용(분류 불가는 `REACHABLE_FAIL`). `admin` 모드 프로브는 변경 없음. 순수 분류 함수는 단위 테스트(에러 문자열 fixture). **영구 env는 두지 않는다.**
- [ ] `T-015` (`REQ-002`, `REQ-009`, `REQ-013`) 전용 모드 olcSyncrepl 빌더·탐지: `..._BIND_DN` 기본 `cn=replicator,<root>`, 렌더에 `tls_reqcert=demand`·`tls_cacert`(또는 `starttls=critical`), 첫 부팅 피어 탐지가 신원으로 TLS 바인드. 부팅 끝 `unset`(`entrypoint.sh:1598-1603`)과 `credentials` 마스킹 유지, 신규 비밀번호 변수 포함.
- [ ] `T-016` (`REQ-005`, `REQ-007`, `REQ-015`) `scripts/replication-identity.sh ensure|takeover|rotate|retire`(D54/D55/D52): `ensure`는 엔트리가 없을 때만 온라인 복제 쓰기로 신원·정책 생성하고 `entryUUID` 출력(이미 있으면 거부 → `takeover` 안내), **`takeover`는 관리자 주도로 기존 엔트리를 삭제·재생성(새 CSPRNG 비밀번호, 명시적 `pwdPolicySubentry`)하고 새 `entryUUID` 출력**, `rotate`는 상태를 디렉터리에서 유도하는 R0–R4 상태 기계(재실행으로 재개, **R3 지문 게이트가 닫히면 R4 거부**, 롤백·조기 제거 복구 명령), `retire`. 비밀번호 생성은 OS CSPRNG 32바이트(D40 패턴)이고 모든 비밀번호는 파일/stdin만(`#220` 관례). 롤백 전 노드별 관리자 비밀번호 경고(D62), G1/G2는 T-010 호출.
- [ ] `T-017` (`REQ-006`, `REQ-011`, `REQ-012`, `REQ-014`) 차트: `replication.identity`(기본 `admin`)·값 스키마, 복제 Secret(`existingSecret` 또는 lookup 기반 1회 생성 + `helm.sh/resource-policy: keep` + 오프라인 렌더 실패, D42 패턴), env 주입, `identity=dedicated`+`tls.enabled=false` 렌더 실패, **초기화 토큰: pre-install 훅이 ConfigMap `<fullname>-init-token`을 만들고(선택적 볼륨 마운트) post-install 훅 Job이 파드 Ready 후 삭제(ServiceAccount·해당 ConfigMap `delete`만 허용하는 Role), 업그레이드에는 토큰 없음, 훅 실패 알림 문서화(영구 env 금지)**, `networkPolicy.ingressFrom` 기본값(`podSelector: {}`)에서 전용 모드 렌더 경고, `helm test`에 T-010 연동, 복제 Secret 변경 시 재시작 방법(자동 롤아웃 여부 결정), `replication.bindDN` 주석의 죽은 `REPLICATION-CONTRACT.md` 참조 제거.
- [ ] `T-018` (`REQ-008`, `REQ-012`) 주기 점검(D59b): 차트 `replication.check.enabled`(기본 꺼짐) CronJob(`--remote`, 관리자·복제 Secret 마운트), `networkpolicy.yaml`에 점검 파드 허용 규칙, PrometheusRule `LDAPiumReplicationIdentityCheckFailed`(`kube_job_status_failed` 기반)와 `promtool` 단위 테스트(`tests/prometheus/alerts_test.yaml` 패턴), 결과 노출 위치(Job 상태·로그)를 values·문서에 명시.
- [ ] `T-019` (`REQ-010`) **게이트된 단계 — T-021–T-025가 CI에서 녹색이기 전에는 시작하지 않는다.** `dedicated`에서만 `entrypoint.sh:100-107`의 D43 기동 실패를 완화(복제 비밀번호 명시로 대체)하고 노드별 관리자 비밀번호에서의 롤백 제약(D62)을 경고로 구현. `admin`·`prepare` 모드는 D43 유지.

## Verify

- [ ] `T-020` (`AC-001`–`AC-004`, `AC-009`) 신규 `scripts/test/test-replication-identity.sh`(`test-wiped-node-resync.sh` 형식: 이미지 인자, `ldapium-*` 접두 리소스, 이름 있는 볼륨): 3노드 동시 콜드 스타트(TLS), 노드별 add/modify/pw/delete, 부정 테스트(자기 `description`/`pwd*`/비밀번호(정책 허용 상태 포함)/삭제·타 엔트리·cn=config·accesslog, 일반 사용자 회귀), **잠금 매트릭스 5종 + 대조군**, 점검 스크립트 판정(하위 트리 거부·크기 제한·비밀번호 불일치·미롤 소비자), sid 1·sid 2 wipe, accesslog 단순/EXTERNAL 필드·`stats` 로그, `/proc/1/environ` 부재. **지속 쓰기 부하(비밀번호 변경 초당 수 회, 60초+) 중 점검 반복: 거짓 실패 0, 주입 결함(하위 트리 거부) 즉시 실패(E26 재현).**
- [ ] `T-021` (`AC-005`–`AC-007`) 회전 상태 기계 5시나리오(무중단·중단·조기 제거+재연결 유발·롤백·복구)와 지문 게이트, 직전 릴리스 이미지→새 이미지 마이그레이션(충돌 검사, `prepare`, G1/G2, 혼합 모드, 롤백, 노드별 관리자 비밀번호 롤백 경고)과 `e2e.yml` 연결(`.github/workflows/e2e.yml:107-110` 패턴), `replication-chaos-e2e.yml`에 전용 모드 시나리오(파드 삭제·파티션·확장 중 쓰기). 기존 테스트가 기본값에서 변경 없이 통과함을 함께 기록.
- [ ] `T-022` (`AC-012`) 노드 1 부트스트랩 테스트: sid-1 wipe(토큰 없음) + 틀린 비밀번호/틀린 CA/피어 중지/포트 닫힘/**전 피어 동시 재부팅** → 전부 거부·피어 데이터 불변, 첫 생성은 토큰으로만·소비 후 재wipe 거부·`helm install` 직후 거부(영구 env 부재 확인)·훅 실패 시 토큰 잔존 경로 기록, 현행 코드의 데이터 소실(E19)을 회귀 대비로 기록. 환경·명령·출력을 증거로 캡처하고 CHANGE.md E1–E26을 각각 대체하는 단언 대응표를 남긴다.
- [ ] `T-023` (`AC-011`) TLS 테스트(저장소 TLS E2E 구성: 서버 인증서 SAN + `tls.caFile`): 평문 읽기 거부, 평문 소비자 정체, `starttls=critical`, 틀린 CA 정체·복구, TLS 없는 전용 기동 거부. TLS E2E 매트릭스에 전용 모드 추가. 발견된 회귀 위험("contextCSN 동일 + 속성 누락"을 실패로 보는 단언, ACL 누락 노드를 게이트로 거부하는 단언)을 내구성 있는 검사로 고정.
- [ ] `T-024` (`AC-014`) 예약 DN 우회 테스트(mTLS 클러스터): 기존 엔트리(스스로 `description` 표식 포함)로 `prepare` 거부와 옛 비밀번호로 해시 읽기 불가(`takeover` 후), `cn=$1` 매핑 거부, 주체=예약 DN 인증서가 catch-all 없이는 거부·있으면 해시 읽기 0(E25 재현), 저장 정규식 평가 단위 테스트(ERE 동등성 확인 포함).
- [ ] `T-025` (`AC-013`) 비밀번호 생성·위생 검사 테스트: 생성 경로 64 hex, 31자·반복 문자·관리자 비밀번호 동일 값 기동 거부, 문서의 운영자 책임 문구 존재 확인, 신원 DN `reqResult=49` 반복 알림 계약(accesslog 질의 예·`promtool` 규칙) 검증.

## Synchronize durable truth

- [ ] `T-030` 규범 문서·운영 지침: `image/README.md`(env 표·복제 절 갱신, `:300-309`의 임시 slapd 서술 오류 수정, 위험 명시: 잠금 제외·cn=config 평문 잔존·TLS 필수), `charts/ldapium/README.md`, `docs/ha-profile.md`(contextCSN 알림의 한계, 점검 스크립트·로그·accesslog 신호, 주기 점검 계약과 **못 잡는 것** 목록), `docs/migration.md`(준비→G1→생성→G2→전환·롤백 절차와 전제), 운영 런북(회전 상태 기계).
- [ ] `T-031` ADR 작성(T-005 초안 확정): 단순 바인드+TLS 주 설계와 SASL EXTERNAL 대체안, 예약 DN·`prepare` 단계, 잠금 제외, fail-closed 부트스트랩, D43 게이트 결정.
- [ ] `T-032` 릴리스·마이그레이션·롤백·호환 노트: 신규 env/값(`LDAP_REPLICATION_IDENTITY`, `LDAP_REPLICATION_INIT_TOKEN_FILE`, `LDAP_REPLICATION_IDENTITY_UUID`), 이미지 롤아웃·`prepare` 완료 전 전환 금지, [generated-credentials](../generated-credentials/CHANGE.md)에 D43 후속(D56) 기록, `CHANGELOG*`.
- [ ] `T-033` 포트폴리오/다운스트림 영향 검토 및 `docs/IMPLEMENTATION-STATUS.md` 상태 게시. 기본값 전환과 SASL EXTERNAL은 각각 별도 이슈·패키지로 분리해 등록.

## Completion review

- [ ] Every requirement maps to an acceptance scenario and verification result.
- [ ] Material scope changes were reflected in the Change Package and re-reviewed.
- [ ] Expected evidence is attached or linked.
- [ ] Known incomplete work has an owner and tracking issue.
- [ ] The PR states the checks actually run and any important unverified path.
