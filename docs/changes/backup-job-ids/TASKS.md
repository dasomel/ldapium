# Tasks: 백업 실행 job ID·상태·취소·복구

설계: [CHANGE.md](CHANGE.md) (Status: `Accepted 2026-10-06 — maintainer instruction to process #217 (open questions resolved as recorded below)`). T-010–T-018·T-020–T-025·T-030은 구현·검증됐다(증거: [EVIDENCE.md](EVIDENCE.md)). T-021의 라이브 경로 중 원격 대상 S3/FTP/SFTP 성공 경로, SIGKILL 유예 후 경로, deadline 경로는 #255에서 범위를 좁혀 검증됐다(`scripts/test/test-backup-jobs-remotes-live.py`, 증거와 미검증 범위: [EVIDENCE.md](EVIDENCE.md)). 원격 실패 주입, 실제 워커의 deadline 정리는 단위 테스트만(수용). 남은 항목: T-001–T-005(사전 확인·기준선·수용 표시는 유지보수자).
구현 순서: 워커 계약(T-015) → 컨트롤러·API·OpenAPI(T-010–T-014, T-016, T-017은 T-014와 같은 PR에서 함께 머지해 드리프트 테스트가 매 태스크 초록) → UI(T-018). **T-018(`cancelled`·`abandoned`·`interrupted` 라벨)은 T-014와 같은 릴리스**에 나가야 하며 그보다 늦게 릴리스하지 않는다.
테스트는 순수 함수 단위 + 실제 워커 라이브 검증이며 목 프레임워크를 도입하지 않는다(AGENTS.md). LDAP 와이어 경로 변경은 없다.

## Inspect and establish evidence

- [ ] `T-001` (`REQ-002`, `REQ-013`) 소스 오브 트루스 재확인: CHANGE.md가 인용한 줄 번호(`run.go`, `manager.go`, `backup_handlers.go`, `backup_worker.py`)가 구현 시점 main에서도 유효한지, `GET /api/v1/backups`·`states` 소비처(UI·e2e·`docs/api.md`·스크립트) 전수. **(Status after #255: live-verified: local checks in test-backup-jobs-live.py; via scripts/test/test-backup-jobs-remotes-live.py: success path to S3/FTP/SFTP (non-empty remote complete.json asserted), SIGKILL after the 10s grace (leftover staging asserted present and reported `pending` before the script removes it), and the 1m deadline path with a stand-in worker that creates and removes its own staging dir. Unit-test only, accepted: remote failure injection and the real backup_worker.py cleanup on deadline; see EVIDENCE.md.)**
- [x] `T-022` (`AC-010`, `AC-011`) UI: Playwright 모킹 스펙(실행 중→성공, 취소, 대상 부분 실패 렌더, 좁은 뷰포트), 기존 `@fixture` 백업 스펙 2건 무수정 통과 확인 및 job 목록 단언 추가(#227 CI 연결 기준). 프런트 `npm run build`.
- [x] `T-023` (`AC-007`, `AC-012`) `scripts/test/test_backup_worker.py` 확장: `--job-id`·매니페스트 호환, 대상 중간 실패 시 대상별 결과, 결과 파일 원자 기록(성공·실패), SIGTERM 정리, 종료 코드 75. 기존 4건 무회귀.
- [x] `T-024` 실패·성공·환경·명령을 `EVIDENCE.md`에 실제 출력으로 기록(검증 실패와 수정 포함).
- [x] `T-025` 발견된 회귀 위험을 지속 검사로 전환(센티널 테스트·복구 표·워커 계약 테스트를 CI 기존 잡에 편입하고 경로 필터를 걸지 않는다).

## Synchronize durable truth

- [x] `T-030` 규범 문서·운영 가이드: `docs/api.md`, `ui/README.md`, 차트 README, 운영 가이드(`abandoned` 해석, `worker_busy`, 고아 워커 확인, `backup-jobs.json` 삭제 안전성).
- [x] `T-031` #216(idempotency convention)·#218(envelope) 확정 시 D217-9·오류 코드 표기를 정합시키고 이 패키지에 변경 기록. #216 확정 후 멱등 키 가산 여부 결정(규약이 202+`Location` 재생·키 충돌·TTL·인가 결합·정책 리비전 결합을 제공해야 함, CHANGE.md D217-9). “Error codes introduced” 4개(`backup_busy`, `job_not_found`, `job_not_cancellable`, `persistence_unavailable`)를 #218 코드 표에 전달. **(CLOSE-OUT: NOT DONE: CHANGE.md D217-9 and Q2 still say keys are out of scope although #241 added keyed backup start; error codes are in the #218 table)** **(DOCS #255: CHANGE.md D217-9 and Q2 updated for the keyed backup start shipped by #241; the four error codes are in the #218 table.)**
- [x] `T-032` 릴리스·호환 노트: 신규 엔드포인트, `states[kind].status`의 `cancelled`, 409 본문 가산 필드, 시작 영속 실패 422→503 분리, `backup_started` 로그의 `actor`(DN)→`actor_fp` 변경, `<root>/.results/` 신규, 백업 대응 이미지 재빌드 필요. 롤백 시 구버전이 job 파일을 무시함을 명시. **(CLOSE-OUT: NOT DONE: CHANGELOG.md has no backup-job entry (422->503 split, actor_fp log change, .results/, image rebuild))** **(DOCS #255: CHANGELOG.md [Unreleased] has the backup-job entry: endpoints, `cancelled`, 409 body fields, 422 -> 503, `actor_fp`, `<root>/.results/`, image rebuild, rollback note.)**
- [x] `T-033` 포트폴리오/다운스트림 영향 검토 후 검증된 상태만 게시. #217 PR 본문은 모든 REQ가 덮일 때만 닫음 표기, 아니면 “Related to #217 (not closing yet)”와 후속 이슈 분리. **(CLOSE-OUT: NOT DONE: no portfolio review; PR #236 said Related to #217 (not closing yet))** **(DOCS #255: `docs/IMPLEMENTATION-STATUS.md` has an "External HTTP API" section limited to verified state, including the unit-only paths. PR #236 said "Related to #217 (not closing yet)".)**

## Completion review

- [ ] Every requirement maps to an acceptance scenario and verification result.
- [ ] Material scope changes were reflected in the Change Package and re-reviewed.
- [ ] Expected evidence is attached or linked.
- [ ] Known incomplete work has an owner and tracking issue.
- [ ] The PR states the checks actually run and any important unverified path.
