# Tasks: syncrepl 전용 복제 신원(replicator)

설계: [CHANGE.md](CHANGE.md) (Status: `Proposed / awaiting review`). 모든 항목은 미착수이며 Class D 패키지 수용 전에는 `Implement`
이후 단계를 시작하지 않는다. **수용 표시는 유지보수자만 한다.** `image/entrypoint.sh`·ACL·복제를 건드리는 모든 작업은 먼저
`.agents/skills/ldapium-directory-change/SKILL.md`를 로드한다. 구현은 단계 병합이며 각 단위는 기본값(`LDAP_REPLICATION_IDENTITY=admin`)에서
기존 테스트가 통과하는 상태로 main에 들어간다. 라이브 LDAP 경로는 모킹하지 않는다.

## Inspect and establish evidence

- [ ] `T-001` (`REQ-001`, `REQ-003`) HEAD에서 소스 오브 트루스 재확인: `01-cn-config.ldif`의 `olcAccess {0}`이 `LDAP_ANONYMOUS_READ_BASE` 설정 여부와 무관하게 같은 위치(`{0}`)인지, `entrypoint.sh`에 부트스트랩 렌더 외 `olcAccess` 쓰기가 없는지, 베이스 DIT 템플릿(`03-base-structure.ldif`)에 신원 엔트리를 덧붙일 때 `#__PASSWORD_POLICY__` 앵커·`ou=policies` 존재 조건(`LDAP_PASSWORD_POLICY_ENABLED=false`)이 안전한지.
- [ ] `T-002` (`AC-007`) 사전 기준선 캡처: 현재 이미지로 `test-wiped-node-resync.sh`·`test-bootstrap-seed.sh`·`replication-chaos-e2e.yml` 결과와 렌더된 `olcSyncrepl` 줄(`-b olcDatabase={1}mdb,cn=config`)을 기록(전환 후 diff 기준).
- [ ] `T-003` 다운스트림·소비자 검토: `detect-config-drift.sh`·`export-incident-evidence.sh`의 `credentials` 마스킹 회귀, 백업/복원(`backup.sh`·`restore.sh`)이 신원 엔트리·해시를 어떻게 다루는지, UI/API 디렉터리 브라우저에서 신원 엔트리의 노출·삭제 가능성, `detect-entry-drift`·`migration-dryrun`·`docs/migration.md` 영향, 차트 `helm test`(`files/tests/directory-test.sh`) 확장 지점.
- [ ] `T-004` (`REQ-003`, `REQ-008`) CHANGE.md "검증하지 못한 주장" (a)–(c) 해소 시도: `credentials`의 파일/SASL 비밀 참조 지원 여부(slapd 2.6.15 소스·`man slapd-config`), `olcLimits time=unlimited` 필요성(긴 refreshAndPersist 세션이 `olcTimeLimit`에 걸리는지), 신원 잠금 상태에서 노드 1 wipe 시 베이스 DIT 재생성 여부. 결과를 CHANGE.md에 반영(재검토 필요 시 표시).
- [ ] `T-005` (`REQ-001`–`REQ-012`) 수용 선행: Owner 지정, OQ-1–OQ-3 결정 기록, ADR 초안(자격 증명 수용 경로·D43 변경·예약 DN), `security-reviewer` 검토 요청. **수용 표시는 유지보수자만 한다.**

## Implement

수용 이후에만 착수. 순서는 병합 단위(앞 단위는 뒤 단위 없이도 기본값에서 안전).

- [ ] `T-010` (`REQ-001`, `REQ-003`) 비활성 ACL·limits 설치(D51/D52): `01-cn-config.ldif`(신규 부트스트랩)와 부팅 시 오프라인 `slapmodify -n 0` 멱등 보정(기존 볼륨, `hd_clear` 패턴), 복제 활성 시에만. 신원 엔트리는 아직 없음 → 동작 불변. 검증: 신규/기존 볼륨 모두 부팅 후 `olcAccess {0}`·`olcLimits` 존재, 재부팅 멱등, 기존 e2e 통과.
- [ ] `T-011` (`REQ-007`, `REQ-008`) `scripts/check-replication-identity.sh`(D59): 피어별 신원 바인드, admin 엔트리 `userPassword` 읽기, `entryCSN/entryUUID` 읽기, `(objectClass=*)` 개수 신원 vs root, 잠금 속성, contextCSN 집합 비교. 종료코드 0/1/2, 비밀번호는 `-y` 파일, 출력에 비밀 없음. 순수 파싱/판정 함수는 fixture 단위 테스트. 전환 게이트(모든 프로바이더 ACL 보유 확인)로도 사용.
- [ ] `T-012` (`REQ-006`) `LDAP_REPLICATION_IDENTITY` 파싱·검증(`admin` 기본, `dedicated`), 잘못된 값 기동 실패. 기본값에서 olcSyncrepl 줄 바이트 단위 불변. 커스텀 `LDAP_REPLICATION_BIND_DN`(비관리자)은 동작 유지 + 경고 로그(D58).
- [ ] `T-013` (`REQ-001`, `REQ-002`, `REQ-004`) 전용 모드 베이스 DIT 확장(D53): 노드 1이 베이스를 만들 때 신원 엔트리(`slappasswd -T` 해시, `LDAP_PASSWORD_HASH` 준수)와 정책 엔트리(`LDAP_PASSWORD_POLICY_ENABLED`일 때)를 `slapadd -n 1`에 포함. 복제 비밀번호 미지정이면 기동 실패(관리자 비밀번호 폴백 금지), 최소 길이/엔트로피 검증, 개행 금지(`entrypoint.sh:581-583` 유지). 시드·마커·롤백 의미(`#203/#204`) 불변.
- [ ] `T-014` (`REQ-002`, `REQ-009`, `REQ-010`) 전용 모드 olcSyncrepl/탐지 분기: `..._BIND_DN` 기본값 `cn=replicator,<root>`, 첫 부팅 피어 탐지가 신원으로 바인드, D43 기동 실패를 전용 모드에서만 완화(복제 비밀번호 명시로 대체, D56). 부팅 끝 `unset`(`entrypoint.sh:1598-1603`)은 유지하고 신규 비밀번호 변수도 포함.
- [ ] `T-015` (`REQ-005`, `REQ-007`) `scripts/replication-identity.sh ensure|rotate|retire`(D54/D55): 온라인 복제 쓰기로 신원·정책 생성, 이중 값 추가→(롤링은 운영자/차트)→`replace`로 새 값만, 폐기. 비밀번호는 파일/stdin으로만 받고 argv에 두지 않는다(`#220` 관례). 기존 클러스터 전환 게이트로 T-011을 호출.
- [ ] `T-016` (`REQ-012`) 차트: `replication.identity`(기본 `admin`)·값 스키마, 복제 Secret(`existingSecret` 또는 lookup 기반 1회 생성 + `helm.sh/resource-policy: keep` + 오프라인 렌더 실패, D42 패턴), env 주입, 복제 Secret 변경 시 재시작 방법 문서화(자동 롤아웃 여부는 결정 후), `helm test`에 T-011 연동, `replication.bindDN` 주석의 죽은 `REPLICATION-CONTRACT.md` 참조 제거.
- [ ] `T-017` 문서 동기화 선행분: `image/README.md`의 env 표·복제 절 갱신(`:300-309`의 임시 slapd 서술 오류 수정 포함), 이 시점부터 사용자가 켤 수 있으므로 위험(잠금 제외, cn=config 평문 잔존) 명시.

## Verify

- [ ] `T-020` (`AC-001`–`AC-006`, `AC-008`, `AC-009`) 신규 `scripts/test/test-replication-identity.sh`(`test-wiped-node-resync.sh` 형식: 이미지 인자, `ldapium-*` 접두 리소스, 이름 있는 볼륨): 3노드 동시 콜드 스타트, 노드별 add/modify/pw/delete, 부정 테스트(쓰기·자기 비밀번호·cn=config·accesslog), ACL 누락·크기 제한·잘못된 비밀번호 주입 + 점검 스크립트 판정, sid 1·sid 2 wipe, 이중 값 회전+롤링, 노드별 다른 관리자 비밀번호, accesslog 바인드 레코드, `/proc/1/environ` 부재. CHANGE.md E1–E12를 각각 어느 단언이 대체하는지 표로 남긴다.
- [ ] `T-021` (`AC-006`, `AC-007`, `REQ-011`) 마이그레이션·혼합 모드·롤백 테스트(직전 릴리스 이미지 → 새 이미지)와 `e2e.yml` 연결(`test-wiped-node-resync` 옆, 기존 `.github/workflows/e2e.yml:107-110` 패턴), `replication-chaos-e2e.yml`에 전용 모드 시나리오(파드 삭제·파티션·확장 중 쓰기) 추가. 기존 테스트가 기본값에서 변경 없이 통과함을 함께 기록.
- [ ] `T-022` 실패·성공·환경·명령을 증거로 캡처(이미지 태그, OpenLDAP 버전, 명령, 출력). CHANGE.md의 일회용 실험 E1–E12를 위 테스트의 단언으로 재현 가능하게 이전.
- [ ] `T-023` 발견된 회귀 위험을 내구성 있는 검사로 전환: "contextCSN 동일 + 속성 누락"을 실패로 보는 단언을 점검 스크립트와 테스트에 고정, ACL 누락 노드를 게이트로 거부하는 단언 고정.

## Synchronize durable truth

- [ ] `T-030` 규범 문서·운영 지침: `docs/ha-profile.md`(contextCSN 알림의 한계, 점검 스크립트·로그·accesslog 신호 추가), `charts/ldapium/README.md`, `docs/migration.md`(전환·롤백 절차), 운영 런북(회전: 이중 값 → 롤링 재시작 → 정리).
- [ ] `T-031` ADR 작성(T-005 초안 확정): 단순 바인드 주 설계와 SASL EXTERNAL 대체안의 트레이드오프, 예약 DN, 잠금 제외 결정.
- [ ] `T-032` 릴리스·마이그레이션·롤백·호환 노트: cn=config에 비활성 ACL·limits 추가(D52), 신규 env/값, 이미지 롤아웃 완료 전 전환 금지, [generated-credentials](../generated-credentials/CHANGE.md)에 D43 후속(D56) 기록, `CHANGELOG*`.
- [ ] `T-033` 포트폴리오/다운스트림 영향 검토 및 `docs/IMPLEMENTATION-STATUS.md` 상태 게시. 기본값 전환(OQ-2)과 SASL EXTERNAL(OQ-3)은 각각 별도 이슈·패키지로 분리해 등록.

## Completion review

- [ ] Every requirement maps to an acceptance scenario and verification result.
- [ ] Material scope changes were reflected in the Change Package and re-reviewed.
- [ ] Expected evidence is attached or linked.
- [ ] Known incomplete work has an owner and tracking issue.
- [ ] The PR states the checks actually run and any important unverified path.
