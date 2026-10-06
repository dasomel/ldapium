# Tasks: syncrepl 전용 복제 신원(replicator)

설계: [CHANGE.md](CHANGE.md) (Status: `Proposed / awaiting review`, 개정 4 — 단순화). 모든 항목은 미착수이며 Class D 패키지 수용 전에는 `Implement`
이후 단계를 시작하지 않는다. **수용 표시는 유지보수자만 한다.** `image/entrypoint.sh`·ACL·복제를 건드리는 모든 작업은 먼저
`.agents/skills/ldapium-directory-change/SKILL.md`를 로드한다. 구현은 단계 병합이며 각 단위는 기본값(`LDAP_REPLICATION_IDENTITY=admin`)에서
cn=config·olcSyncrepl·기존 테스트가 그대로인 상태로 main에 들어간다. 매 단계 독립 검토를 받는다. 라이브 LDAP 경로는 모킹하지 않는다.

## Inspect and establish evidence

- [ ] `T-001` (`REQ-001`, `REQ-003`, `REQ-007`) HEAD에서 소스 오브 트루스 재확인: `01-cn-config.ldif`의 `olcAccess {0}` 위치(`LDAP_ANONYMOUS_READ_BASE` 유무와 무관), 렌더되는 catch-all의 `by self write`(`entrypoint.sh:794-815`), 부트스트랩 렌더 외 `olcAccess` 쓰기 부재, 소비자 전용 분기 조건(`entrypoint.sh:1111`)에 `dedicated`를 더했을 때 시드·마커·롤백(`#203/#204`) 경로가 sid≥2와 동일하게 동작하는지(E12 재확인).
- [ ] `T-002` (`AC-007`) 사전 기준선: 현재 이미지로 `test-wiped-node-resync.sh`·`test-bootstrap-seed.sh`·`replication-chaos-e2e.yml` 결과, **cn=config 전체 덤프**와 렌더된 `olcSyncrepl` 줄.
- [ ] `T-003` 다운스트림 검토: `detect-config-drift.sh`·`export-incident-evidence.sh`의 `credentials` 마스킹 회귀, `backup.sh`·`restore.sh`가 신원 엔트리·ACL(cn=config)을 어떻게 다루는지, UI/API 디렉터리 브라우저의 신원 엔트리 노출·삭제(rootDN 세션), `docs/migration.md`, 차트 `helm test`, `networkpolicy.yaml` 백업 CronJob 허용 규칙 패턴.
- [ ] `T-004` (`REQ-003`, `REQ-010`, `REQ-011`) 미검증 항목 해소: `credentials` 파일/SASL 비밀 참조 지원, `olcLimits time=unlimited` 필요성, **`restore.sh`로 복원한 노드가 `dedicated`로 기동되고 나머지가 복제로 채워지는지(전체 소실 절차 D63)**, ldapi peercred 신원이 authz 금지 조건과 무관한지, 점검의 노드 간 교차 비교·값 순서 정규화·대량 성능.
- [ ] `T-005` (`REQ-001`–`REQ-012`) 수용 선행: Owner 지정, ADR 초안(자격 증명 수용 경로·TLS 요구·mTLS 비공존·D43 게이트·운영자 명령으로만 생성), `security-reviewer` 검토 요청. **수용 표시는 유지보수자만 한다.**

## Implement

수용 이후에만 착수. 순서는 병합 단위(앞 단위는 뒤 단위 없이도 안전, 기본값에서 동작 불변).

- [ ] `T-010` (`REQ-006`, `REQ-009`) `LDAP_REPLICATION_IDENTITY`(`admin` 기본/`prepare`/`dedicated`) 파싱·검증(잘못된 값은 기동 실패). 복제 비밀번호 **위생 검사**(길이 ≥ 32, 서로 다른 문자 ≥ 10, 관리자 비밀번호와 불일치; 무작위성의 증거가 아님을 메시지에 명시). `admin`에서 cn=config·olcSyncrepl 바이트 단위 불변, 커스텀 비관리자 `LDAP_REPLICATION_BIND_DN`은 유지 + 경고.
- [ ] `T-011` (`REQ-001`, `REQ-003`) `prepare`: **로컬 예약 DN 엔트리가 없거나 ACL이 이미 저장돼 있을 때만** 명시적 첫 규칙 `{0}to * by dn.exact="<신원>" ssf=128 read by dn.exact="<신원>" none by * break` + `olcLimits` 설치(신규 부트스트랩=`01-cn-config.ldif`, 기존 볼륨=부팅 시 오프라인 `slapmodify -n 0`, `hd_clear` 패턴). 엔트리가 있고 ACL이 없으면 거부 메시지(먼저 `retire`). 복제 신원은 여전히 admin. 검증: 신규/기존 볼륨, 재부팅 멱등, wipe된 노드(빈 DB) 설치, 기존 엔트리 거부, `admin`에서 cn=config 불변.
- [ ] `T-012` (`REQ-007`, `REQ-008`, `REQ-011`) `dedicated`: **모든 노드(sid 1 포함) 소비자 전용**(`entrypoint.sh:1111` 조건), 엔트리 생성·피어 프로브·대기·토큰 없음, olcSyncrepl에 `tls_reqcert=demand`·`tls_cacert`(또는 `starttls=critical`)와 신원 바인드 DN. **기동 거부(고정 메시지, admin 폴백 없음)**: 복제 비밀번호 없음/위생 실패, TLS 미검증, `LDAP_TLS_MUTUAL_AUTH` 켬, `slapcat -n 0`에서 `olcTLSVerifyClient`가 `never` 외이거나 `olcAuthzRegexp`가 하나라도 있음(`service42` 매핑 fixture로 단위 테스트). 부팅 끝 `unset`(`entrypoint.sh:1598-1603`)과 `credentials` 마스킹 유지.
- [ ] `T-013` (`REQ-002`, `REQ-004`, `REQ-005`, `REQ-009`) `scripts/replication-identity.sh ensure|rotate|retire`: **`ensure`는 관리자 자격으로 라이브 클러스터에 1회**, 엔트리가 없을 때만 `cn=replication-policy,<root>`(`pwdLockout FALSE`, `pwdMaxAge 0`, `pwdAllowUserChange FALSE`)와 `cn=replicator,<root>`(명시 `pwdPolicySubentry`, OS CSPRNG 32바이트 비밀번호)를 온라인 복제 쓰기로 생성하고 자격 증명을 0600 파일/1회 출력으로 내준다(이미 있으면 거부). `rotate`는 상태를 디렉터리(값 개수)와 노드별 지문에서 유도하는 R0–R4(재실행으로 재개, 게이트가 닫히면 제거 거부, 롤백 안내), `retire`는 삭제. 비밀번호는 파일/stdin만(`#220` 관례).
- [ ] `T-014` (`REQ-010`) `scripts/check-replication-identity.sh`: `--local`(`slapcat`)/`--remote`(root·신원·`cn=admin,cn=config`), **열거 속성 집합만**(기본 `userPassword objectClass uid cn sn mail`, 확장 가능) 비교, `contextCSN`·동적 운영 속성 제외, `entryCSN` 안정성(R1/V/R2) 판정·같은 CSN 다른 내용 즉시 실패·≤5회 재시도·보류만 남으면 경고 통과, 노드 간 교차 비교, 소비자 `olcSyncrepl` 바인드 DN·자격 증명 지문, 카나리, **G1(생성 전 설정만) / G2(생성 후 권한·전파)**. 종료코드 0/1/2, 비밀번호는 `-y` 파일. 순수 판정 함수는 fixture 단위 테스트(경쟁·즉시 실패·보류).
- [ ] `T-015` (`REQ-006`) **게이트된 선택 단계 — T-020–T-022가 CI에서 녹색이기 전에는 시작하지 않는다.** `dedicated`에서만 D43 기동 실패(`entrypoint.sh:100-107`) 완화. `admin`·`prepare`는 D43 유지.
- [ ] `T-016` (`REQ-006`, `REQ-008`, `REQ-012`) 차트: `replication.identity`(기본 `admin`)·값 스키마, `replication.existingSecret` 사용(복제 Secret 자동 생성 없음), `dedicated`+`tls.enabled=false`·`dedicated`+mTLS 렌더 실패, `networkPolicy.ingressFrom` 기본값(`podSelector: {}`)에서 dedicated 렌더 경고, `replication.bindDN`의 죽은 `REPLICATION-CONTRACT.md` 참조 제거, 복제 Secret 변경 시 재시작 방법 문서화.
- [ ] `T-017` (`REQ-010`, `REQ-012`) 주기 점검(설계 구현): `replication.check.enabled`(기본 꺼짐) CronJob(`--remote`), `networkpolicy.yaml`에 점검 파드 허용 규칙, `kube_job_status_failed` 기반 PrometheusRule과 `promtool` 단위 테스트, 결과 노출 위치(Job 상태·로그)와 CronJob이 관리자 Secret을 가짐을 문서화.

## Verify

- [ ] `T-020` (`AC-001`, `AC-002`, `AC-003`, `AC-006`) 신규 `scripts/test/test-replication-identity.sh`(`test-wiped-node-resync.sh` 형식: 이미지 인자, `ldapium-*` 접두 리소스, 이름 있는 볼륨): `admin` 3노드(TLS) → `prepare` → `ensure` → 노드별 `dedicated` 전환과 양방향 쓰기·해시, 부정 테스트(자기 `description`/`pwd*`/비밀번호(정책 허용 상태 포함)/삭제/타 엔트리/cn=config/accesslog/평문 읽기, 일반 사용자 회귀), 잠금 매트릭스 5종 + 대조군, `prepare` 4케이스, 지속 쓰기 중 점검(대조: 단일 샷·전 속성 비교는 거짓 실패) + 결함 4종 주입, 혼합 모드·롤백.
- [ ] `T-021` (`AC-004`, `AC-005`, `AC-007`) wipe 복구(sid 1·sid 2, 틀린 비밀번호, 피어 부재 → 즉시 Ready·아무것도 만들지 않음·피어 데이터 불변, 현행 코드의 소실 E8을 회귀 대비로 기록), **전체 소실 절차(D63) 테스트**, 회전 5시나리오(무중단·중단·조기 제거+재연결·롤백·복구)와 지문 게이트, 기존 테스트 기본값 통과(`e2e.yml:107-110` 패턴 연결), `replication-chaos-e2e.yml`에 dedicated 시나리오.
- [ ] `T-022` (`AC-008`, `AC-009`) 안전하지 않은 설정 6종 거부 + TLS만 통과 + 주체=예약 DN 인증서 `-Y EXTERNAL` 실패(E13 재현), TLS E2E 매트릭스에 dedicated 추가, 차트 `helm template`·`verify-chart-schema.sh`.
- [ ] `T-023` 발견된 회귀 위험을 내구성 있는 검사로 고정: "contextCSN 동일 + 속성 누락"을 실패로 보는 단언, ACL 없는 프로바이더로의 전환 거부 단언, 전 속성 비교가 거짓 실패함을 보이는 대조 단언.
- [ ] `T-024` 환경·명령·출력을 증거로 캡처하고 CHANGE.md E1–E16을 각각 대체하는 단언 대응표를 남긴다.

## Synchronize durable truth

- [ ] `T-030` 규범 문서·운영 지침: `image/README.md`(env·모드·절차, `:300-309` 임시 slapd 서술 오류 수정, 위험: 잠금 제외·cn=config 평문 잔존·TLS 필수·mTLS 비공존), `charts/ldapium/README.md`, `docs/ha-profile.md`(contextCSN 알림 한계, 점검 계약과 **못 잡는 것**), `docs/migration.md`(prepare→G1→ensure→G2→dedicated·롤백·전체 소실 절차), 운영 런북(회전).
- [ ] `T-031` ADR 작성(T-005 초안 확정).
- [ ] `T-032` 릴리스·마이그레이션·롤백·호환 노트: 신규 env/값, 이미지 롤아웃·`prepare` 완료 전 전환 금지, [generated-credentials](../generated-credentials/CHANGE.md)에 D43 후속(D56), `CHANGELOG*`.
- [ ] `T-033` 포트폴리오/다운스트림 영향 검토 및 `docs/IMPLEMENTATION-STATUS.md`. 기본값 전환·SASL EXTERNAL·처음부터 dedicated인 신규 클러스터는 각각 별도 이슈로 등록.

## Completion review

- [ ] Every requirement maps to an acceptance scenario and verification result.
- [ ] Material scope changes were reflected in the Change Package and re-reviewed.
- [ ] Expected evidence is attached or linked.
- [ ] Known incomplete work has an owner and tracking issue.
- [ ] The PR states the checks actually run and any important unverified path.
