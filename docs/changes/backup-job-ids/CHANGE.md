# Change: 백업 실행에 내구성 있는 job ID·상태 조회·취소·복구 부여

- Change class: `B` — 공개 API 추가(기존 필드 유지), 워커 계약 확장, 영속 파일 추가. 인증·인가 경계, 의존성, 릴리스 계약은 바뀌지 않아 `D`로 승격하지 않는다(승격 조건: 아래 R3).
- Owner: 미지정 — 수용 전 지정
- Related issue: [#217](https://github.com/dasomel/ldapium/issues/217) — 출처 [api-integration PLAN P2](../api-integration/PLAN.md). #217은 이 패키지가 전부 닫는다(umbrella 아님): PR 본문은 구현이 모든 REQ를 덮을 때만 "Closes"를 쓴다.
- Status: `Accepted 2026-10-06 — maintainer instruction to process #217 (open questions resolved as recorded below)`
- Accepted by / date: 유지보수자 지시(#217 처리), 2026-10-06 — 열린 질문은 Review record에 결정으로 기록
- 작성일: 2026-10-06 (독립 비평 반영 개정: 고아 워커·취소 정리·영속 실패·로그 신원 규칙·오류 코드)

> 코드·OpenAPI·워커·UI는 변경하지 않았고 아래 동작은 구현·런타임 검증되지 않았다.
> “현재 동작” 서술의 줄 번호는 main `60dae0d`에서 다시 열어 확인했다(대상 파일은 `32263eb` 이후 변경 없음).
> 오류 본문은 **#218 envelope**(`{error, message, code, requestId, retryable}`)를 따르며 여기서 재정의하지 않는다. 이 패키지가 추가하는 코드는 “Error codes introduced” 절에 모았다.
> 멱등 키는 **#216 idempotency convention**으로 미룬다(D217-9). 필드 표기 규칙: 새 필드는 해당 엔드포인트 계열의 표기를 따른다 — 백업 계열 JSON은 snake_case, 오류 봉투는 #218의 `requestId` camelCase(D217-18).

## Problem

`POST /api/v1/backups/jobs/:kind`는 202와 `{"kind","status":"running"}`만 돌려주고 job 식별자가 없다
([backup_handlers.go:99](../../../ui/backend/internal/httpapi/backup_handlers.go)). 호출자는 자기 요청의 결과를 추적할 수 없다.

현재 동작(근거):

| 관찰 | 근거 |
|---|---|
| 실행 상태는 종류별 `State` 하나뿐이다(마지막 시도·성공·`run_id`). 이력이 없어 이전 실행 결과는 다음 실행이 덮어쓴다 | [model.go:26-35](../../../ui/backend/internal/backup/model.go), [run.go:76-89](../../../ui/backend/internal/backup/run.go) |
| 동시 실행은 `running` bool 하나(뮤텍스 보호, 메모리). 두 번째 요청은 `ErrBusy` → 409 `{"message":"backup already running"}`이며 무엇이 돌고 있는지 알려주지 않는다 | [manager.go:33](../../../ui/backend/internal/backup/manager.go), [run.go:20-22](../../../ui/backend/internal/backup/run.go), [backup_handlers.go:93-95](../../../ui/backend/internal/httpapi/backup_handlers.go) |
| 추적 수단은 `GET /api/v1/backups`의 `states[kind]`·`running` 폴링뿐(UI도 5초 폴링). 응답 유실 후 재시도하면 409를 받고, 그 409가 내 요청의 job 때문인지 다른 사람의 job 때문인지 구분할 수 없다 | [BackupsPage.tsx:24](../../../ui/frontend/src/pages/BackupsPage.tsx), OpenAPI `runBackup` 설명(“There is no job ID; poll …”) [openapi.json:4150](../../../ui/backend/internal/httpapi/openapi/openapi.json) |
| HTTP 취소 수단이 없다. 취소는 프로세스 종료 시 런타임 컨텍스트 취소뿐이며 워커 프로세스 그룹에 즉시 `SIGKILL`을 보낸다(정리 기회 없음) | [run.go:43-45](../../../ui/backend/internal/backup/run.go), [run.go:56-58](../../../ui/backend/internal/backup/run.go) |
| 최대 실행 시간은 2시간 하드코딩, 종류·환경별 설정 불가 | [run.go:50](../../../ui/backend/internal/backup/run.go) |
| 실행 중 프로세스가 죽으면 기동 시 `running` → `interrupted`로 바뀌지만 **디스크에 반영되지 않고**(메모리 값만 바꿈) 어떤 실행이었는지 기록이 없다. 또 `NextRun`이 실행 시작 시점에 `attempt+interval`로 이미 저장돼([run.go:35](../../../ui/backend/internal/backup/run.go), [run.go:38](../../../ui/backend/internal/backup/run.go)) 중단된 예약 실행은 한 주기(data 기본 24h) 동안 재시도되지 않는다 | [manager.go:108-113](../../../ui/backend/internal/backup/manager.go) |
| 대상별 결과가 없다. 워커 성공 응답의 `destinations`는 정책에 적힌 목록을 되돌릴 뿐 결과가 아니고, 실패 응답은 `local_verified`만 싣는다. 원격 전송은 첫 실패에서 중단된다(뒤 대상 미시도) | [backup_worker.py:249](../../../ui/backend/backup-tools/backup_worker.py), [backup_worker.py:250-253](../../../ui/backend/backup-tools/backup_worker.py), [backup_worker.py:229-248](../../../ui/backend/backup-tools/backup_worker.py) |
| 감사 줄에 요청 ID가 없고 시작/완료 줄을 잇는 키가 없다: `backup_started actor kind` / `backup_completed kind status policy_revision` | [backup_handlers.go:98](../../../ui/backend/internal/httpapi/backup_handlers.go), [run.go:93](../../../ui/backend/internal/backup/run.go) |

## Intent

백업 실행마다 불투명한 job ID를 발급해 영속 기록으로 남기고, 그 기록을 조회·취소할 수 있는 좁은 API를 둔다.
재시작·타임아웃·취소·대상 부분 실패가 모두 기록상 명확한 종료 상태로 끝나게 하고, 감사 로그를 job ID로 상관시킨다.
기존 `GET /api/v1/backups`, `states[kind]`, 202 본문의 기존 필드, UI 동작은 호환을 유지한다.

## Scope

- In scope: job ID·기록 모델·영속·보관 상한, 상태 조회(목록·단건), 취소, 종류별 최대 실행 시간, 기동 복구, 대상별 결과·산출물 참조,
  409 본문의 활성 job 노출, 감사 로그 상관, 워커 계약 확장(`--job-id`, 대상별 결과, SIGTERM 정리, 종료 코드 75), OpenAPI·`docs/api.md`, UI 작업 목록.
- Affected: `ui/backend/internal/backup`, `ui/backend/internal/httpapi`(핸들러·OpenAPI), `ui/backend/internal/config`,
  `ui/backend/backup-tools/backup_worker.py`, `ui/frontend`(BackupsPage·`lib/backups.ts`), `charts/ldapium/templates/ui-deployment.yaml`(타임아웃 env), `scripts/test/test_backup_worker.py`.
- 대상: 백업 관리자(UI·스크립트 호출자), 운영자.

## Non-goals

- 범용 jobs API·다른 비동기 작업(PLAN P2는 “backup run is not the same as a universal jobs API”). 경로는 `/api/v1/backups/` 아래에 한정한다.
- 대기열(queued)·병렬 실행: 단일 활성 job 유지. 두 번째 요청은 여전히 409.
- Idempotency-Key 처리(D217-9), 오류 envelope 정의(#218), cursor paging(PLAN P1), 머신 주체 접근([machine-principal-auth](../machine-principal-auth/CHANGE.md)는 백업을 명시 제외).
- 실패한 job의 자동 재시도, 완료 후 취소·롤백(산출물 삭제), 복원(restore) 흐름 변경.
- 정책·연결 저장 의미(ETag/If-Match, `PUT /policies`, `PUT /connections`)와 보관(keep-days/keep-count) 의미 변경.
- 워커 stderr·rclone 출력의 API 노출, 로그 수집 파이프라인.

## Requirements

- `REQ-001` — `POST /api/v1/backups/jobs/{kind}`는 202 + `Location` + 본문 `job_id`를 돌려주고 기존 본문 필드(`kind`,`status`)와 요청 게이트(same-origin·415·빈 본문)를 유지한다.
- `REQ-002` — 모든 실행(수동·예약)은 프로세스 재시작 후에도 유일한 불투명 job ID를 가진 영속 기록을 남긴다.
- `REQ-003` — 기록은 종료 상태 `succeeded|failed|cancelled|abandoned`와 비종료 `running`, 시각, 트리거, 정책 리비전, 오류 코드+고정 문구를 가진다. 비밀·원격 stderr·소유 루트 밖 경로·요청자 DN 원문을 담지 않는다(요청자는 지문만, D217-12).
- `REQ-004` — 기록은 원자적·비공개(0600/0700)로 쓰고, 개수·기간 상한으로 가지치기해 무한히 커지지 않는다. 가지치기는 산출물(아카이브)을 지우지 않는다.
- `REQ-005` — `GET /api/v1/backups/jobs`(목록)·`GET /api/v1/backups/jobs/{id}`(단건)로 기록을 조회한다. 백업 관리자 전용이며 `GET /api/v1/backups`가 보여주는 범위를 넘는 정보를 노출하지 않는다.
- `REQ-006` — `POST /api/v1/backups/jobs/{id}/cancel`로 실행 중 job을 취소한다. 워커 프로세스 그룹에 SIGTERM, 10초 유예 뒤 SIGKILL을 보낸다. job은 `cancelled`가 되고 확정된 로컬 사본은 보존된다. 스테이징 정리는 SIGTERM이 처리되면 즉시, SIGKILL이 필요했으면 다음 실행의 정리까지 지연되며 기록의 `staging_cleanup`(`done|pending|not_applicable`)이 이를 솔직히 보여준다.
- `REQ-007` — 종류별 최대 실행 시간을 설정할 수 있고(기본 2h = 현행 동작) 컨텍스트로 강제한다. 초과는 `failed` + `deadline_exceeded`.
- `REQ-008` — 기동 시 `running`으로 남은 기록은 먼저 워커 잠금을 탐지한다. 잠금이 잡혀 있으면(고아 워커) 기록은 `running`+`orphan_suspected`로 유지하고 만회·새 job을 보류한 채 잠금이 풀릴 때까지 백오프로 폴링한다. 풀린 뒤 워커가 남긴 결과 파일·매니페스트로 실제 결과(`succeeded`/`failed`)를 확정하고, 결과 없이 죽은 경우에만 `abandoned`(명확한 사유)로 확정한다. `State.Status`는 작업 기록에서 재동기화한다.
- `REQ-009` — 단일 활성 job을 유지한다. 409 본문이 활성 `job_id`·`kind`를 알려 응답을 잃은 호출자가 **조회**할 수 있게 한다. 이는 소유 증명이 아니며, job 종료 후의 재시도는 새 실행이다(멱등성은 #216 규약의 몫, D217-9).
- `REQ-010` — 기록에 대상별 결과(`succeeded|failed|skipped|unknown`)와 로컬 검증 결과, 산출물 매니페스트 참조(run ID·파일명·크기·sha256)를 담는다.
- `REQ-011` — 시작·완료·취소·복구 로그 줄에 `job_id`·`request_id`·actor를 싣는다(예약은 actor=`scheduler`).
- `REQ-012` — 오류 응답은 #218 envelope(`error`·`message` 같은 값 + `code`·`requestId`·`retryable`)를 따르고, 이 패키지가 추가하는 코드는 “Error codes introduced”에 나열한다(`backup_busy`, `job_not_found`, `job_not_cancellable`, `persistence_unavailable`).
- `REQ-013` — OpenAPI(드리프트 테스트 통과)·`docs/api.md`·UI 타입을 갱신하고, 기존 클라이언트(`states[kind]`, `running`, 현행 UI)는 코드 변경 없이 동작한다.
- `REQ-014` — UI는 작업 목록(진행·결과·대상별 결과)과 취소 버튼을 보여준다.
- `REQ-015` — job 기록·API·로그에 어떤 자격 증명·`userPassword`·원격 구성 값·요청자 DN 원문도 나타나지 않는다(테스트로 고정).
- `REQ-016` — 영속 전이(시작·취소 요청·종료·복구)마다 쓰기 순서와 실패 동작이 정해져 있다: 시작 기록을 쓸 수 없으면 워커를 시작하지 않고 503 `persistence_unavailable`(`retryable=true`)을 반환하며, 어떤 실패도 “시작되지 않은 job이 디스크에 `running`으로 남는” 결과를 만들지 않거나(보상) 기동 시 재조정으로 수렴한다.
- `REQ-017` — 새 실행은 워커 잠금이 잡혀 있으면 시작하지 않고(수동 409 `backup_busy`, 예약은 조용히 건너뜀) `worker_busy` 결과는 예약을 한 주기 뒤로 미루지 않고 곧(60초 기준) 재시도한다.

## Acceptance scenarios

### `AC-001` — 시작 응답이 job을 식별한다

- Covers: `REQ-001`, `REQ-002`, `REQ-011`
- Given 백업 관리자 세션, 유휴 상태
- When `POST /api/v1/backups/jobs/logs`(same-origin, `application/json`, 빈 본문)
- Then 202, `Location: /api/v1/backups/jobs/<job_id>`, 본문에 `job_id`·`kind:"logs"`·`status:"running"`, 감사 줄에 같은 `job_id`와 요청 ID가 남는다. 본문이 있거나 Origin/Content-Type이 어긋나면 현행대로 400/403/415.

### `AC-002` — 상태를 폴링해 성공까지 추적한다

- Covers: `REQ-003`, `REQ-005`, `REQ-010`
- Given AC-001의 job
- When `GET /api/v1/backups/jobs/{job_id}`를 폴링
- Then `running` → `succeeded`, `finished_at` 설정, `local.verified=true`, 대상별 `succeeded`, `artifact.run_id`가 `GET /api/v1/backups`의 `states.logs.run_id`와 같고 `files[].sha256`이 실제 `complete.json` 매니페스트와 일치한다.

### `AC-003` — 응답 유실 후 이어받기

- Covers: `REQ-009`
- Given job A가 실행 중이고 호출자가 202 응답을 받지 못함
- When 같은 종류로 재요청
- Then 409, 본문이 `error`·`message`(같은 값)·`code=backup_busy`·`requestId`·`retryable:true`와 `active_job_id=A`·`active_kind`를 포함한다. 호출자는 `GET .../jobs/A`로 **조회**할 수 있고 두 번째 실행은 만들어지지 않는다. 이 응답은 A가 내 요청의 job이라는 증명이 아니며, A가 끝난 뒤 같은 요청을 재시도하면 새 job이 시작된다(문서화·테스트 단언).

### `AC-004` — 취소

- Covers: `REQ-006`, `REQ-003`
- Given 오래 걸리는 워커로 실행 중인 job
- When `POST .../jobs/{id}/cancel`
- Then 202(`cancel_requested_at` 설정). 워커 프로세스 그룹이 SIGTERM에 종료하지 않으면 유예(10초) 후 SIGKILL, 손자 프로세스까지 종료. job은 `cancelled`, `State.Status=cancelled`. 스테이징 정리는 보장하지 않는다: SIGTERM이 처리되어 워커 `finally`가 돌았으면 `staging_cleanup=done`, SIGKILL이 필요했으면 `.pending-*`가 남을 수 있어 `staging_cleanup=pending`이며 다음 실행의 정리([backup_worker.py:171-176](../../../ui/backend/backup-tools/backup_worker.py))가 지운다(`pending`은 조회 시 `<root>/<kind>`에 `.pending-*`가 없으면 `done`으로 표시). 최종 이름으로 이미 확정된 로컬 사본이 있으면 보존되고 `local.verified=true`·산출물 참조가 기록된다. 같은 job을 다시 취소하면 200(변화 없음), 다른 종료 상태 job의 취소는 409 `job_not_cancellable`, 모르는 ID는 404 `job_not_found`.

### `AC-005` — 실행 시간 초과

- Covers: `REQ-007`
- Given `BACKUP_JOB_TIMEOUT_LOGS=2s`와 오래 걸리는 워커
- When job 실행
- Then 프로세스 그룹이 종료되고 job은 `failed`, `error.code=deadline_exceeded`. 범위 밖 설정(`<1m`·`>24h`·파싱 불가)은 기동 실패(테스트용 하한은 내부 시계 주입으로 우회하며 프로덕션 하한은 유지).

### `AC-006` — 백엔드가 작업 중 죽은 뒤 복구

- Covers: `REQ-002`, `REQ-008`
- Given `running` 기록이 있는 상태에서 컨트롤러 프로세스가 비정상 종료(SIGKILL)했고 **워커 잠금은 풀려 있으며 결과 파일이 없다**(워커도 죽음)
- When 재기동
- Then 해당 기록은 `abandoned`, `error.code=abandoned`, 고정 사유 문구, `finished_at`=복구 시각으로 **디스크에 확정**되고, 확정된 `complete.json`(소유 검사 통과, 같은 `job_id`)이 있으면 `artifact`·`local.verified=true`가 채워지며 대상은 `unknown`이다. `states[kind].status`는 `interrupted`로 디스크에서도 일치한다. 결과 파일이 있으면 그 내용대로 `succeeded`/`failed`로 확정한다(AC-013). 잠금이 잡혀 있으면 이 시나리오가 아니라 AC-013이다. 예약이 켜져 있고 해당 종류의 최근 3개가 전부 `abandoned`가 아니면 `next_run`이 복구 시각으로 설정돼 첫 틱에 한 번 만회 실행된다. 최근 3개가 모두 `abandoned`면 만회하지 않고 주기를 기다린다.

### `AC-007` — 대상 부분 실패

- Covers: `REQ-010`, `REQ-003`
- Given 대상 `local`, `remote-a`(전송 실패), `remote-b`
- When job 실행
- Then job은 `failed`, `local.verified=true`, 대상별 `local=succeeded`·`remote-a=failed(transfer_failed)`·`remote-b=skipped`, 로컬 사본 보존(현행 D30 유지), 응답 어디에도 rclone/네트워크 오류 원문이 없다.

### `AC-008` — 기록 보관 상한

- Covers: `REQ-004`
- Given 상한 초과 개수·기간의 기록
- When 새 job 종료 또는 기동
- Then 가장 오래된 종료 기록부터 제거되어 개수 ≤ 200·기간 ≤ 90일. 실행 중 job과 종류별 가장 최근 `succeeded` 기록은 상한과 무관하게 남는다. 아카이브 디렉터리는 하나도 지워지지 않는다. 파일은 0600, 쓰기는 임시 파일 + rename.

### `AC-009` — 비밀·경계 비노출

- Covers: `REQ-003`, `REQ-005`, `REQ-015`
- Given 관리형 연결에 비밀이 저장된 상태와 실패한 job
- When 목록·단건·409·로그·`backup-jobs.json`을 검사
- Then 비밀 값·`password_file` 경로·`rclone_config` 경로·요청자 DN 원문이 없고(job 로그 줄은 `actor_fp` 지문만, D217-12) 오류 본문은 #218 envelope(`error`·`message`·`code`·`requestId`·`retryable`)다. 비관리자 세션은 모든 job 엔드포인트에서 403, 백업 비활성은 404(현행 `requireBackupAdmin`).

### `AC-010` — 호환

- Covers: `REQ-001`, `REQ-013`
- Given 변경 전 클라이언트(현행 UI 번들, 폴링 스크립트)
- When 새 서버에 연결
- Then `GET /api/v1/backups`의 필드·ETag·`states[kind]` 값 어휘(`running|succeeded|failed|interrupted`에 `cancelled`만 추가)·`running`이 그대로이고, 기존 `@fixture` e2e 두 건이 변경 없이 통과한다. OpenAPI 드리프트 테스트 통과.

### `AC-011` — UI

- Covers: `REQ-014`
- Given 백업 페이지
- When 지금 백업 → 완료 / 실행 중 취소
- Then 작업 목록에 새 job이 `running`으로 나타나고 종료 상태·대상별 결과·산출물 크기가 표시되며, 실행 중에만 취소 버튼이 활성이다. 좁은 뷰포트에서 가로 스크롤이 없다.

### `AC-012` — 워커 계약

- Covers: `REQ-006`, `REQ-010`
- Given 워커 단위 테스트
- When `--job-id` 전달, 대상 중간 실패, SIGTERM, 잠금 경합
- Then 매니페스트에 `job_id`가 추가되되 기존 키·검증(`verify`, `prune`, 원격 `complete.json` 동등 비교)은 영향 없고, 실패 응답에 대상별 결과가 실리며, 종료 시(성공·실패 모두) 같은 내용의 결과 파일 `<root>/.results/<job_id>.json`(0600, 열거형 값만)이 원자적으로 쓰이고, SIGTERM 시 스테이징이 정리되며, 락 경합은 종료 코드 75로 끝난다.

### `AC-013` — 고아 워커가 살아 있는 동안의 재기동

- Covers: `REQ-008`, `REQ-017`
- Given `running` 기록이 있고 컨트롤러만 SIGKILL됐으며 워커는 계속 실행 중(잠금 보유)
- When 재기동
- Then 기록은 `running`+`orphan_suspected=true`로 유지되고(`abandoned` 아님), 메모리 `running`이 true라 새 수동 요청은 409 `backup_busy`(해당 `active_job_id`), 예약 틱은 건너뛰며 만회·`NextRun` 변경이 없다. 컨트롤러는 5초에서 시작해 30초까지 두 배로 백오프하며 잠금을 폴링한다. 워커가 끝나 잠금이 풀리면 결과 파일로 `succeeded`/`failed`와 실제 대상별 결과를 확정하고, 결과 파일이 없고 매니페스트만 있으면 `abandoned`(+`artifact`·`local.verified`), 둘 다 없으면 `abandoned`로 확정한다. 확정 뒤에만 만회 판단(D217-8)이 실행된다. `deadline_at`을 넘겨도 컨트롤러는 pid를 모르므로 죽이지 않고 경고 로그만 남긴다(운영 가이드).

### `AC-014` — 영속 실패

- Covers: `REQ-016`
- Given 주입된 실패 쓰기 함수(`Manager`의 writer 필드)
- When 시작 기록 쓰기 / 취소 요청 기록 쓰기 / 종료 기록 쓰기가 각각 실패
- Then 시작 실패는 503 `persistence_unavailable`(`retryable:true`)이고 워커가 시작되지 않으며 메모리·디스크의 job과 `State`가 변하지 않는다(예약은 건너뛰고 다음 틱에 재시도). 취소 요청 기록 실패는 503이고 신호를 보내지 않는다. 종료 기록 실패는 메모리에서는 종료로 확정하고 `dirty`로 두었다가 다음 쓰기·틱에서 재시도하며, 그 사이 죽으면 기동 시 결과 파일로 수렴한다. 어떤 경우에도 시작되지 않은 job이 `running`으로 남지 않는다.

### `AC-015` — `worker_busy` 재시도

- Covers: `REQ-017`
- Given 새 실행 직전 워커 잠금이 잡혀 있음 / 탐지와 시작 사이 경합으로 워커가 종료 코드 75
- When 수동 요청 / 예약 틱
- Then 사전 탐지에서 걸리면 기록 없이 수동은 409 `backup_busy`, 예약은 건너뜀. 경합으로 75가 나오면 job은 `failed`+`worker_busy`이고 `NextRun`은 60초 뒤(연속 10회 초과 시 정책 주기)이며 한 주기 뒤로 미뤄지지 않는다.

## Architecture and decisions

- Relevant ADR/design links: [backup-policies](../backup-policies/CHANGE.md)(D29–D38, 특히 D30 로컬 사본 보존·D37 비밀 파일), [api-integration PLAN P2](../api-integration/PLAN.md), [api.md](../../api.md), [openapi.json](../../../ui/backend/internal/httpapi/openapi/openapi.json), [ui/README.md](../../../ui/README.md)(백업 env).
- ADR threshold result: `not required` — 새 신뢰 경계·자격 증명 경로·저장소 의존성이 없고, 공개 계약 변화는 기존 엔드포인트에 대한 가산이다. 단 R3 조건이 발생하면 Class D·ADR로 재분류한다.

### 결정 기록

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D217-1 | job ID = `job-<UTC YYYYMMDDTHHMMSSZ>-<12 hex>`(crypto/rand 48비트), 정규식 `^job-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$`. 클라이언트에는 불투명 문자열로 문서화(≤64자). 생성 시 영속 이력과 충돌 검사. `instance_id`는 포함하지 않는다. 정책 리비전은 ID가 아니라 기록 필드 `policy_revision`으로 둔다([run.go:34](../../../ui/backend/internal/backup/run.go)와 동일 의미). 워커 `run_id`(`storage.go`의 `runName` 형식 [storage.go:10](../../../ui/backend/internal/backup/storage.go))와 접두사로 구분 | 시간순 정렬·재시작 간 유일성·`run_id`와 혼동 방지. `instance_id` 비포함은 운영자 식별자 불필요 노출 회피 | 이력 상한 200이라 충돌 확률은 무시 가능하나 검사 코드 필요 | 형식은 불투명 계약이므로 ULID 등으로 바꿔도 클라이언트 무영향 |
| D217-2 | 기록 모델(JSON, 기존 backups 도메인과 같은 snake_case): `job_id, kind, trigger(manual|schedule), status(running|succeeded|failed|cancelled|abandoned), requested_by{type:user|scheduler, fingerprint}, request_id, policy_revision, created_at, started_at, finished_at, deadline_at, cancel_requested_at, orphan_suspected, orphan_reason(worker_lock_held|lock_probe_error), staging_cleanup(done|pending|not_applicable), error{code,message}, local{verified}, destinations[{id,status,error_code}], artifact{run_id,files[{name,bytes,sha256}]}`. `queued`는 두지 않는다(대기열 없음, D217-8). 요청자는 DN 원문 대신 기존 `fingerprintIdentity`([audit_log.go:108](../../../ui/backend/internal/httpapi/audit_log.go)) 16hex, 예약은 `type:scheduler`. `error.message`는 코드별 고정 문구 카탈로그에서만 뽑고 워커 stderr·예외 문자열은 쓰지 않는다. 산출물은 성공/로컬확정 시 `<root>/<kind>/<run_id>/complete.json`을 소유 검사([storage.go:36-46](../../../ui/backend/internal/backup/storage.go))와 같은 규칙으로 읽어 파일명·크기·sha256만 담는다 | “GET /api/v1/backups가 보여주는 범위 이내” 요구: 파일에도 API에도 DN·경로·비밀이 없다. DN 원문은 기록·API·job 로그 어디에도 없고 지문으로 상관한다(D217-12). 매니페스트 이름·sha256은 이미 보관 디렉터리에 있는 값이며 소유 루트 밖 경로는 읽지 않는다 | 요청자 사람 식별은 로그와 대조해야 함. 산출물 읽기 코드 추가 | 필드는 모두 가산이므로 제거·추가가 호환적. DN 노출이 필요하면 별도 변경 |
| D217-3 | 영속 위치 = `BACKUP_POLICY_PATH`와 같은 디렉터리의 별도 파일 `backup-jobs.json`(`{"version":1,"jobs":[…]}`, 새 env 없음). 기존 `write()`([manager.go:129-154](../../../ui/backend/internal/backup/manager.go): 임시 파일 + fsync + rename, 디렉터리 0700, 파일 0600)를 재사용. **작업 파일이 권위**이고 `State`는 기동 시 최신 job으로 재동기화한다. 전이마다 쓴다: 시작(`running`) → 취소 요청 → 종료. 전이별 쓰기 순서·실패 동작·주입 방법은 D217-17 | 정책 파일에는 관리형 연결 비밀이 있다([manager.go:17-21](../../../ui/backend/internal/backup/manager.go), D37). job 전이마다 비밀 파일을 다시 쓰면 노출·손상 표면이 늘어난다. 별도 파일이면 job 파일에는 비밀이 구조적으로 들어갈 수 없다. 구버전은 모르는 파일을 무시해 롤백 안전(정책 파일 파싱은 `DisallowUnknownFields`를 쓰지 않음, [manager.go:79-82](../../../ui/backend/internal/backup/manager.go)) | 파일 둘 사이에 원자성이 없다 → 재동기화 규칙 필요. `write()`는 디렉터리 fsync를 하지 않아 전원 손실 시 마지막 rename이 사라질 수 있음(기록 1건 손실 허용, 복구는 결과 파일·`abandoned`로 수렴) | 단일 파일(`disk` 확장)로 합치려면 `disk`에 필드만 추가. jobs 디렉터리 방식은 이력 상한이 커질 때 |
| D217-4 | 경로: `GET /api/v1/backups/jobs`(목록, `kind`·`status`·`limit` 기본 20/최대 100, 최신순, 이력 ≤200이라 cursor 없음 — cursor는 PLAN P1 규약 도입 시 가산), `GET /api/v1/backups/jobs/{id}`, `POST /api/v1/backups/jobs/{id}/cancel`. 기존 `POST /api/v1/backups/jobs/{kind}`는 URL 불변. OpenAPI 3.1은 같은 계층의 서로 다른 템플릿 이름을 동일 경로로 금지하므로 `/jobs/{id}` **한 경로 항목**에 `post`(runBackup, `id`=`data`\|`logs`)와 `get`(getBackupJob, `id`=job ID)을 두고 오퍼레이션별 파라미터 설명을 분리한다. Echo 등록도 `:id`로 통일(드리프트 테스트는 echo 파라미터 이름을 그대로 비교, [api_contract_test.go:46-58](../../../ui/backend/internal/httpapi/api_contract_test.go)) | 요청된 URL 형태 유지 + 스펙 유효성. 와이어 계약은 변하지 않는다(경로 위치만 의미). `GET /jobs/data`처럼 job ID 형식이 아니면 404 | 한 파라미터가 오퍼레이션별로 다른 의미라 문서가 어색하다 | 항목 경로를 `/api/v1/backups/job-runs/{id}`로 이전(`Location` 헤더만 바뀜. 클라이언트는 URL을 조립하지 말고 `Location`을 따르도록 문서화) |
| D217-5 | 취소 = `POST …/{id}/cancel`(DELETE 아님). running → 202 + 현재 기록(`cancel_requested_at` 설정, 종료는 비동기), 이미 `cancelled` → 200(멱등), 그 외 종료 상태 → 409 `job_not_cancellable`, 모르는 ID → 404 `job_not_found`. 같은 게이트(same-origin·`application/json`·빈 본문)를 `requireProfileWrite`([app_profile_handlers.go:112-121](../../../ui/backend/internal/httpapi/app_profile_handlers.go))로 적용 | DELETE는 기록 삭제를 암시하는데 기록은 감사용으로 남는다. 동사형 하위 리소스가 비동기 상태 전이를 가장 정직하게 표현 | 별도 오퍼레이션 1개 | DELETE 별칭은 후속에 가산 가능 |
| D217-6 | 종료 의미: 취소·시간 초과 시 프로세스 그룹에 SIGTERM, 유예 10초(고정) 후 SIGKILL(현행은 즉시 SIGKILL, [run.go:57-58](../../../ui/backend/internal/backup/run.go)). 워커는 SIGTERM 핸들러로 `finally`를 타게 해 스테이징을 지운다([backup_worker.py:254-256](../../../ui/backend/backup-tools/backup_worker.py), 핸들러가 없으면 파이썬은 `finally` 없이 즉사). 디스크 규칙: ① 스테이징 정리는 **보장하지 않는다**: SIGTERM이 처리되면 `finally`가 지우고 기록은 `staging_cleanup=done`, SIGKILL이 필요했으면 `.pending-*`가 남을 수 있어 `pending`이며 다음 실행이 소유 마커 검사 후 정리한다([backup_worker.py:171-176](../../../ui/backend/backup-tools/backup_worker.py)). `pending`은 조회 시 `<root>/<kind>`에 `.pending-*`가 없으면 `done`으로 표시(읽기 전용 계산, 저장 안 함). 취소·`deadline_exceeded`에만 적용, 그 외 `not_applicable` ② 최종 이름으로 rename(226행)이 끝난 로컬 사본은 **보존**(D30)하고 job에 `local.verified=true` ③ 원격 부분 업로드는 `pending.json`만 있고 `complete.json`이 없어 다음 실행의 `cleanup_remote`가 정리([backup_worker.py:111-130](../../../ui/backend/backup-tools/backup_worker.py)) — 취소가 원격을 직접 지우지 않는다. 취소 상태는 `State.Status=cancelled`(UI 어휘 추가) | 데이터를 지우는 동작을 취소에 넣지 않는다(파괴적 동작은 설계 변경). 정리는 이미 소유 검사된 기존 경로 재사용. SIGKILL은 `finally`를 실행하지 않으므로 즉시 정리를 약속하지 않는다 | 취소 직후 `.pending-*`가 남을 수 있다(다음 실행까지 용량 점유). 취소된 job이 쓸 만한 로컬 사본을 남길 수 있다 → `local.verified`로 노출. 유예 10초만큼 취소 지연 | 유예를 설정화, 원격 즉시 정리는 별도 변경 |
| D217-7 | 기동 복구는 **잠금 탐지가 먼저**다(고아 워커 처리는 D217-16). 잠금이 풀려 있을 때만: 결과 파일 `<root>/.results/<job_id>.json`이 있으면 그 내용대로 `succeeded`/`failed`를 확정하고(대상별 실제 결과 포함), 없으면 `abandoned`(`error.code=abandoned`, 문구 “controller restarted while the job was running”, `finished_at`=복구 시각, 대상 `unknown`). 워커가 `--job-id`로 매니페스트에 `job_id`를 남기므로, 소유 검사를 통과한 `<root>/<kind>/*/complete.json`에 해당 `job_id`가 있으면 `artifact`·`local.verified=true`를 채운다(`abandoned` 한정). `running` bool은 메모리 값이라 기동 시 false([manager.go:77](../../../ui/backend/internal/backup/manager.go))이지만, 고아가 의심되면 true로 둔다(D217-16). `State.Status`는 `interrupted`(abandoned)·확정 결과로 **디스크에도** 반영 | 현재는 메모리만 바꿔 재기동이 한 번 더 있으면 흔적이 사라진다. 컨트롤러가 죽으면 워커 stdout 파이프도 사라져 실제 결과는 디스크 증거(결과 파일·매니페스트)로만 알 수 있다 | 워커 `--job-id`·매니페스트 `job_id` 필드(가산; `verify`/`prune`은 필요한 키만 읽고([backup_worker.py:58-63](../../../ui/backend/backup-tools/backup_worker.py), [73-74](../../../ui/backend/backup-tools/backup_worker.py)) 원격 `complete.json`은 같은 파일을 비교하므로([backup_worker.py:245](../../../ui/backend/backup-tools/backup_worker.py)) 영향 없음 — T-002에서 확인). `.results/` 파일 신규(0600, 열거형 값만, 기록 가지치기 시 함께 삭제) | 스캔·결과 파일 생략 시 `abandoned`로만 수렴(정보만 줄고 안전성 불변). **결과 파일은 신뢰하지 않는다**: 열린 비심볼릭 일반 파일·64 KiB 이하·`job_id`/`kind` 일치·열거형 값만 통과하며, 하나라도 어긋나면 `succeeded`/`failed`로 확정하지 않고 `abandoned`+`result_invalid`로 확정한다(매니페스트는 소유 검사·평탄 파일명·run 디렉터리 내부 일반 파일만 인정). 잠금 탐지 오류는 “잠금 해제”가 아니라 고아 의심(`orphan_reason=lock_probe_error`)으로 유지하고 백오프 재시도 |
| D217-8 | 만회·동시성: 단일 활성 job과 `ErrBusy`→409 유지. 대기열 없음. 409 본문은 #218 envelope(`error`=`message`, `code=backup_busy`, `requestId`, `retryable:true`)에 `active_job_id`·`active_kind`를 가산한다. **새 실행은 시작 전에 워커 잠금을 탐지**한다(잡혀 있으면 수동 409 `backup_busy`, 예약은 건너뜀·기록 없음). 탐지와 시작 사이 경합으로 워커가 종료 코드 75면 job `failed`+`worker_busy`이고, 완료 처리는 `NextRun`을 정책 주기가 아니라 **60초 뒤**로 둔다(현행은 모든 결과에 `now+interval`, [run.go:83](../../../ui/backend/internal/backup/run.go); 연속 10회 `worker_busy` 이후엔 주기로 복귀). 만회: **고아 확정(D217-16) 이후** 예약이 켜져 있으면 `State.NextRun=복구 시각`(현재는 시작 시점에 `attempt+interval`이 저장돼 중단 후 한 주기 공백, [run.go:35](../../../ui/backend/internal/backup/run.go)). **크래시 루프 가드**: 해당 종류의 최근 3개 job이 모두 `abandoned`면 만회 안 함(`NextRun=복구 시각+interval`). 틱은 활성이 있으면 건너뛴다([manager.go:222-226](../../../ui/backend/internal/backup/manager.go)) | 데이터 백업은 주기가 24h라 한 번 놓치면 하루 공백이다. `worker_busy`가 주기를 미루면 고아 워커 한 건이 하루치 백업을 삼킨다. 반복 크래시가 매 기동마다 무거운 백업을 재시작하는 폭주는 막아야 한다 | 가드 임계 3은 임의값. 만회 실행이 기동 직후 LDAP 부하를 만든다(10초 틱 뒤) | 임계·만회를 env로 설정화하거나 만회 비활성(현행 동작 복귀) |
| D217-9 | **Idempotency-Key는 이번 범위에서 제외**하고 “#216 idempotency convention”에 위임한다. 대신 응답 유실 시 활성 job은 409의 `active_job_id`·목록 `status=running`으로 **조회**할 수 있다(AC-003). 이것은 소유 증명이 아니다(다른 관리자의 job일 수 있음). job이 이미 끝난 뒤의 재시도는 **새 실행**이다. 기록에 키 필드를 미리 두지 않고, 정책 ETag를 job 상태 리비전으로 재사용하지 않는다. #216 규약이 제공해야 할 것: 202+`Location` 재생(같은 키 → 같은 job 응답), 키 충돌(같은 키·다른 kind/요청 → 오류), TTL(최소 job 이력 보관 이상), 인가 결합(키를 요청한 백업 관리자 지문에 묶음), 정책 리비전 결합(키 재생 시 `policy_revision` 불일치 처리) | #216이 키 형식·TTL·재생 응답·불일치 오류를 모든 POST에 대해 정할 예정이라, 여기서 먼저 만들면 규약이 둘로 갈라진다. 백업은 비파괴·단일 활성이라 키 없이도 중복 실행이 구조적으로 불가능하다 | 마지막 job이 이미 끝난 뒤의 재시도(응답 유실 + 짧은 job)는 새 job이 된다. 호출자가 `created_at`·`request_id`로 구분해야 한다 | #216 확정 후 기록에 해시 필드 가산 + 핸들러에서 조회(T-031) |
| D217-10 | 최대 실행 시간: env `BACKUP_JOB_TIMEOUT_DATA`·`BACKUP_JOB_TIMEOUT_LOGS`(Go duration), 기본 둘 다 `2h`(= [run.go:50](../../../ui/backend/internal/backup/run.go) 현행, 호환), 범위 `1m`~`24h`, 벗어나면 기동 실패([config.go:206-208](../../../ui/backend/internal/config/config.go) 패턴). `context.WithTimeout`으로 강제, 만료는 `failed`+`deadline_exceeded`. 요청 단위 deadline은 두지 않는다: POST는 비동기이고 본문 금지([backup_handlers.go:89](../../../ui/backend/internal/httpapi/backup_handlers.go)). GET/취소는 메모리 조회라 별도 deadline 불필요. 워커 내부 명령 타임아웃 1800초([backup_worker.py:23](../../../ui/backend/backup-tools/backup_worker.py))는 컨트롤러 상한 안에서 그대로 둔다 | “요청 deadline” 요구를 job 단위 상한으로 해석. 기본값 유지로 동작 변화 0 | env 2개와 차트 값 | 기본값만 바꿔 롤아웃, env 제거 시 2h로 복귀 |
| D217-11 | 대상별 결과·워커 계약: 워커 stdout 결과를 `{run_id, kind, verified, local_verified, job_id, destinations:[{id,status,error_code}]}`로 확장(기존 키 유지). 현행 의미 보존 — 원격 첫 실패에서 중단하고 나머지는 `skipped`(`previous_destination_failed`). `local`은 로컬 검증 결과에서 파생. `error_code`는 거친 열거형 `transfer_failed`(rclone 명령 실패)·`verify_failed`(체크섬 불일치)·`config_invalid`(`validate_remote` 거부)만. 같은 JSON을 종료 시 `<root>/.results/<job_id>.json`에도 원자적으로 쓴다(컨트롤러 사망 시 복구 증거, D217-7). 락 경합(`flock` LOCK_NB, [backup_worker.py:160](../../../ui/backend/backup-tools/backup_worker.py))은 종료 코드 75로 구분 → job `failed`+`worker_busy`(`retryable:true`, D217-8). 컨트롤러는 stderr를 기록하지 않고 오류 문구는 카탈로그만 사용([run.go:60](../../../ui/backend/internal/backup/run.go)의 `cmd.Output`이 stderr를 `ExitError`에 담지만 버린다) | “중단/계속” 의미를 바꾸면 D30·보관 정리 순서와 얽힌다 → 보고만 추가. 코드 열거형이라 비밀·경로가 새지 않는다 | 워커·Go 양쪽 계약 변경. 대상 하나가 실패해도 뒤 대상은 시도되지 않는 한계가 기록에 드러남 | 별도 변경으로 “실패해도 계속” 정책 도입 |
| D217-12 | 감사 상관: 로그 줄을 `backup_started job_id=… kind=… trigger=… actor_fp=… request_id=%q`, `backup_cancel_requested job_id=… actor_fp=… request_id=%q`, `backup_completed job_id=… kind=… status=… error_code=… policy_revision=…`, `backup_abandoned job_id=… kind=…`로 정리([backup_handlers.go:98](../../../ui/backend/internal/httpapi/backup_handlers.go), [run.go:93](../../../ui/backend/internal/backup/run.go) 대체; 기존 `request_id` 키 관례 [app_method_handlers.go:51](../../../ui/backend/internal/httpapi/app_method_handlers.go) 따름). `backup_abandoned`·고아 확정 줄에는 `orphan`·`result_source=file|manifest|none`을 추가한다. 요청 ID는 `requestIDOf`([audit_log.go:120-122](../../../ui/backend/internal/httpapi/audit_log.go))로 받아 기록에도 저장. 예약은 `actor_fp=scheduler`. **신원 규칙 하나: job 기록과 job 로그 줄은 요청자 지문(`fingerprintIdentity` 16hex)만 싣고 DN 원문은 어디에도 싣지 않는다.** 이는 현행 `backup_started actor=%q`(DN 원문, [backup_handlers.go:98](../../../ui/backend/internal/httpapi/backup_handlers.go))보다 **엄격**하며, `backup_started`의 `actor` 키는 `actor_fp`로 대체된다(로그 형식 변경, 릴리스 노트 T-032). 이번 범위 밖인 `backup_policy_saved`·`backup_connection_changed`([backup_handlers.go:79](../../../ui/backend/internal/httpapi/backup_handlers.go), [135](../../../ui/backend/internal/httpapi/backup_handlers.go))는 DN을 계속 기록하는 현행 관행이며 불일치로 문서화한다. 나머지 키(`kind`, `status`, `policy_revision`)는 유지 | 한 줄 grep으로 요청→실행→종료를 잇는다. 지문은 인증 이벤트와 같은 상관 수단이고 DN은 기록에 남지 않아 “GET /api/v1/backups 범위 이내”와 모순이 없다 | `actor` 키로 DN을 파싱하던 로그 소비자는 깨진다. 사람 식별은 지문을 알려진 DN과 대조해야 한다 | 정책·연결 로그도 같은 규칙으로 정렬하는 것은 후속 변경 |
| D217-13 | 인가·노출: 모든 신규 엔드포인트는 `requireBackupAdmin`([backup_handlers.go:34-49](../../../ui/backend/internal/httpapi/backup_handlers.go)) 하위, 읽기는 GET이라 Origin/415 게이트 불필요(`GET /api/v1/backups`와 동일), 변경(POST cancel)은 `requireProfileWrite`. 머신 주체는 비대상(machine-principal-auth Non-goals). 기록은 D217-2의 필드만 노출 | 기존 백업 관리자 경계를 그대로 재사용, 새 경계 없음 | — | — |
| D217-14 | 보관: 최대 200건·90일(상수, env 없음). 종료 기록만 대상, 실행 중 job과 종류별 가장 최근 `succeeded`는 항상 유지. 기동 시와 종료 시 적용. 기록 가지치기는 아카이브를 건드리지 않는다(아카이브 보관은 정책 `keep_days/keep_count`가 소유) | 파일 크기 상한(≈수백 KB)과 “마지막 성공” 가시성 동시 보장 | 90일 이전 실행은 조회 불가(아카이브·`states[kind]`는 남음) | 상수를 env로 승격 |
| D217-15 | 호환: `states[kind]`·`running`·`GET /api/v1/backups` 불변. `states[kind].status`에 `cancelled` 값 추가, `last_job_id`는 State에 가산하지 않는다(job 목록으로 충분). POST 202 본문은 `{"kind","status","job_id"}`. 현행 UI는 알 수 없는 상태를 “실행 기록 없음”으로 표시하므로([BackupsPage.tsx:82](../../../ui/frontend/src/pages/BackupsPage.tsx)) UI에 `cancelled`·`abandoned`(job 목록)·`interrupted` 라벨을 **같은 릴리스**에서 추가(UI 변경이 컨트롤러보다 늦게 나가지 않는다 — T-018을 T-014와 같은 릴리스로 묶음). 시작 시 영속 실패는 현행 422(`kind/source unavailable or status persistence failed`, [backup_handlers.go:96](../../../ui/backend/internal/httpapi/backup_handlers.go))에서 503 `persistence_unavailable`로 분리된다(422는 kind/source 오류만 유지). OpenAPI·드리프트 갱신은 컨트롤러/API 변경과 같은 태스크(T-014)에 포함 | 외부 클라이언트가 새 어휘를 만날 가능성을 문서에 명시(OpenAPI enum 갱신) | 엄격한 enum 검증 클라이언트는 `cancelled`에서 깨질 수 있다 | `cancelled`를 `failed`로 접는 모드는 두지 않는다(정보 손실). 필요 시 `states`는 `interrupted/failed`로 매핑 |
| D217-16 | 고아 워커: 기동 시 `running` 기록이 있으면 먼저 `<root>/.worker.lock`([backup_worker.py:159-160](../../../ui/backend/backup-tools/backup_worker.py)과 같은 파일)에 비차단 `flock` 탐지(`Manager.lockProbe` 필드, 기본 실제 flock). **잡혀 있으면** 기록을 `running`+`orphan_suspected=true`로 유지, 메모리 `running=true`(새 수동 요청 409, 정책/연결 저장도 현행처럼 `ErrBusy`), 예약 틱 건너뜀·만회 보류, 폴링은 5s→30s 백오프. **풀리면** D217-7 순서로 확정(결과 파일 → `succeeded`/`failed`, 매니페스트만 → `abandoned`+산출물, 없음 → `abandoned`) 후 `running=false`, 그 다음에만 만회 판단. pid는 저장·kill하지 않는다(pid 재사용 위험). `deadline_at` 초과 후에도 계속 대기하고 경고 로그만(어차피 새 워커도 `flock`으로 막히므로 대기가 손해를 늘리지 않는다) | 단순 `abandoned`+즉시 만회는 살아 있는 워커 앞에서 `worker_busy`로 한 주기를 날리고 고아의 성공 결과를 놓친다. 결과 판정은 워커가 쓴 증거에만 근거한다 | 고아가 멈춰 있으면 백업이 막힌 채 경고만 남는다(운영자 개입 필요, 운영 가이드). 결과 파일·폴링 코드 추가 | 폴링 상한 시간 후 `abandoned` 강제 확정하는 설정 가산 가능(기본은 대기) |
| D217-17 | 영속 전이 순서·실패 동작. 쓰기는 `Manager.writer func(path string, data any) error`(기본 `write`) 필드를 통해서만 하고 테스트는 실패 횟수를 세는 함수를 주입한다(목 프레임워크 불필요, 현재 `write` 직접 호출 지점: [manager.go:193](../../../ui/backend/internal/backup/manager.go), [run.go:38](../../../ui/backend/internal/backup/run.go), [run.go:90](../../../ui/backend/internal/backup/run.go), [connections.go:186](../../../ui/backend/internal/backup/connections.go), [connections.go:223](../../../ui/backend/internal/backup/connections.go)). **시작**: ① `backup-jobs.json`에 `running` 기록 쓰기 ② 성공해야 워커 시작. `State.Status=running`·`NextRun`은 메모리에만 반영하고 디스크 `State`는 종료 시에 쓴다(시작 시 이중 쓰기 제거: 현행은 시작 때 `State`를 쓰고 `NextRun=attempt+interval`을 저장, [run.go:35-41](../../../ui/backend/internal/backup/run.go)). ①이 실패하면 워커 미시작·메모리/디스크 불변, 호출자에 503 `persistence_unavailable`(`retryable:true`), 예약은 건너뛰고 다음 틱 재시도(로그는 분당 1회로 제한). **취소 요청**: `cancel_requested_at` 기록 쓰기 성공 후에만 신호 전송, 실패 시 503·신호 없음. **종료**: ① job 종료 기록 ② `State`·`NextRun`. ①이 실패하면 메모리에서 종료 확정+`dirty`, 다음 쓰기/틱에서 재시도(새 job 시작은 같은 파일 전체를 쓰므로 `dirty`를 함께 flush하며 실패 시 503), 그 전에 죽으면 기동 시 결과 파일로 수렴. ②만 실패하면 로그(`backup_state_persist_failed job_id=…`, 현행 [run.go:90-92](../../../ui/backend/internal/backup/run.go) 동작)만 남기고 기동 시 작업 파일에서 재동기화. **복구(abandon/확정)**: ① job 기록 ② `State`. 실패해도 기동은 계속하고(백업 가용성) 메모리 상태로 동작하며 `dirty`로 재시도. 보상: 시작은 ①만 쓰므로 “시작 안 된 job이 `running`” 상태가 생기지 않는다. 전원 손실로 ①만 디스크에 남고 워커가 못 떴으면 기동 시 잠금 없음·결과 없음 → `abandoned` | 이중 쓰기를 없애는 것이 보상 로직보다 단순하고 안전하다. 주입 가능한 writer로 모든 실패 분기를 순수 단위 테스트로 고정한다 | `State`의 디스크 `running`이 시작 직후에는 반영되지 않는다(기동 시 작업 파일에서 복원하므로 허용). `Manager` 필드 1개 | 실패 분기 증가 시 전이를 하나의 `commit(transition)` 함수로 묶는다 |
| D217-18 | 표기·봉투 규칙: 새 필드는 해당 엔드포인트 계열의 표기를 따른다. job 응답·기록·202 본문은 백업 계열과 같은 snake_case(`job_id`, `created_at`, …). 오류 본문은 #218 봉투 그대로이며 `requestId`만 camelCase다(오류 본문 확장 필드 `active_job_id`·`active_kind`는 백업 계열이라 snake_case). 로그 키는 로그 스키마의 `request_id`. 모든 오류 예시는 `error`와 `message`(같은 값)를 함께 싣는다 | 기존 백업 뷰(`last_attempt` 등)와 #218 `requestId`를 둘 다 깨지 않는다 | 한 응답 안에서 표기가 섞여 보인다(독립 비평 PASS) | #218이 표기 통일을 정하면 별칭 필드 가산 |

### 오류 예시 (#218 envelope)

```json
{
  "error": "backup already running",
  "message": "backup already running",
  "code": "backup_busy",
  "requestId": "5nQe3kXyZpLwTqA0vB9cJmRdUsHf2GoE",
  "retryable": true,
  "active_job_id": "job-20261006T031500Z-3fa9c1d27b40",
  "active_kind": "data"
}
```

```json
{
  "error": "backup state could not be saved; retry",
  "message": "backup state could not be saved; retry",
  "code": "persistence_unavailable",
  "requestId": "Zr8mPq0LkVt2aXw7cB1nUeHs4JdYgF3o",
  "retryable": true
}
```

### Error codes introduced

#218가 코드 표에 흡수할 목록(이름은 append-only 계약, HTTP 상태·`retryable`은 #218 D218-5 규칙을 따른다):

| code | 상태 | retryable | 발생 |
|---|---|---|---|
| `backup_busy` | 409 | true | 활성 job 존재(또는 워커 잠금 탐지). `active_job_id`·`active_kind` 가산 |
| `job_not_found` | 404 | false | 형식이 맞지 않거나 보관에 없는 job ID(조회·취소) |
| `job_not_cancellable` | 409 | false | `running`이 아닌 종료 job(이미 `cancelled`는 200 멱등) |
| `persistence_unavailable` | 503 | true | 시작·취소 요청 기록을 쓸 수 없음(워커 미시작·신호 미전송). 일시적 503 규칙에 따라 `Retry-After` |

기록 필드 `error.code`(HTTP 코드 아님, 고정 문구 카탈로그): `deadline_exceeded`, `abandoned`, `worker_failed`, `worker_busy`, `unverified_result`, `result_invalid`, `persistence_unavailable`. 대상별 `error_code`: `transfer_failed`, `verify_failed`, `config_invalid`, `previous_destination_failed`.

### 위험

- R1 워커가 컨트롤러 사망 후 고아로 남을 수 있다. 워커는 자체 프로세스 그룹(`Setpgid`, [run.go:57](../../../ui/backend/internal/backup/run.go))이라 컨트롤러가 SIGKILL돼도 살아남는다. `flock`([backup_worker.py:160](../../../ui/backend/backup-tools/backup_worker.py))은 **새** 워커만 거부할 뿐 고아의 결과를 알려주지 않는다. 그래서 기동 시 잠금을 먼저 탐지해 고아를 `running`+`orphan_suspected`로 유지하고 만회를 보류하며 결과 파일로 확정한다(D217-16, AC-013). `worker_busy`가 주기를 한 번 미루던 문제([run.go:83](../../../ui/backend/internal/backup/run.go))는 60초 재시도로 바꾼다(D217-8). 쿠버네티스 단일 컨테이너에서는 컨테이너 재시작이 워커도 함께 죽이므로 실제 빈도는 낮다고 **가정하지만 검증하지 않았다**(T-004·T-021 라이브 고아 시나리오). 잔여 위험: 멈춰버린 고아는 백업을 막고 경고만 남긴다.
- R2 job 파일·정책 파일 사이 비원자성. 시작은 job 파일 한 번만 쓰고 종료는 job→`State` 순서이며 작업 파일 권위 + 기동 재동기화 + 결과 파일로 수렴한다(D217-17, AC-006·AC-014).
- R3 승격 조건(Class D 재분류): 취소가 원격/로컬 아카이브를 삭제하게 되는 변경, job API에 머신 주체 접근 추가, 매니페스트 필드 변경이 `restore.sh`·`prune`·`verify`의 읽기 키에 영향, 새 env/Secret이 필요한 변경.
- R4 `write()`가 디렉터리 fsync를 하지 않는다(전원 손실 시 최근 전이 1건 유실 가능). 유실된 `running`은 존재하지 않는 job이 되고 `State`는 `interrupted` 규칙으로 수렴.
- R5 UI 5초 폴링은 job 목록 폴링을 포함하도록 확장되며 새 서버 부하는 메모리 조회 한 번이다.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | 신규 오퍼레이션 3개(`listBackupJobs`·`getBackupJob`·`cancelBackupJob`), `runBackup` 응답 가산, 409 본문 가산, `State.Status` 값 `cancelled` 추가. 공개 API 변경이므로 설계 변경(AGENTS.md) — 이 패키지가 검토 대상. `Manager.Run` 시그니처 변경(내부) |
| Dependencies / lockfiles | N/A — 표준 라이브러리만 사용(`crypto/rand`, `syscall`) |
| Runtime / toolchain | 워커 `--job-id` 인자·SIGTERM 핸들러·종료 코드 75·결과 JSON 확장. 파이썬 버전·rclone 요구 불변 |
| CI / CD | 새 워크플로 없음. 기존 `ui-e2e` 백업 스펙(`@fixture`, #227로 CI 연결)에 신규 단언 추가. Go·파이썬 테스트는 기존 잡에 편입 |
| Release / packaging | 이미지에 워커 파일이 포함되므로 백업 대응 이미지 재빌드. 호환 가산이라 릴리스 계약 불변. 릴리스 노트에 `cancelled` 상태 값과 신규 엔드포인트 명시 |
| Generated output | `openapi.json`·`llms.txt` 갱신, `docs/api.md` 표, `ui/frontend` 빌드 산출물 |
| Security / supply chain | 비밀 비노출 테스트(AC-009), 기록에 DN·경로 없음, 새 입력은 job ID(정규식 검증)뿐, 취소는 프로세스 그룹 신호만(경로·명령 입력 없음). 보안 리뷰어 검토 권장 |
| Offline / air-gap | N/A — 외부 호출 없음 |
| Documentation / operations | `docs/api.md`, `ui/README.md`(env 2개, 기록 파일 위치·보관), 운영 가이드(abandoned 해석, worker_busy, 고아 워커 확인법), `docs/changes/backup-policies/CHANGE.md`에 후속 참조 한 줄 |
| Portfolio / downstream repositories | N/A — 외부 소비자는 이 저장소의 OpenAPI뿐. 상태 문서 갱신은 PR 시점에 확인 |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 핸들러 단위(`backup_handlers_test.go` 확장, 202·`Location`·`job_id`, 400/403/415 유지) + 라이브 | `go test`; 실제 워커(로컬 transport) | 응답 헤더·본문 캡처, 로그 줄 |
| `AC-002` | 라이브: 실제 워커로 시작→폴링→성공→`complete.json` 대조 | 로컬 컨테이너·로그 소스(@fixture 환경) | 단건 JSON, 매니페스트 sha256 일치 |
| `AC-003` | 핸들러 단위(활성 중 재요청) + 라이브 | 단위 + 로컬 | 409 본문 `active_job_id`, 실행 1건 확인 |
| `AC-004` | 단위(`TestCancellationTerminatesWorkerAndChild` 확장: SIGTERM 무시 워커로 유예 후 SIGKILL, 손자 종료) + 라이브(긴 job 취소) + 워커 테스트(스테이징 정리) | 단위 + 로컬 | 종료 상태·`ps` 결과, `staging_cleanup`(SIGTERM 처리 시 `done`, SIGKILL 시 `pending`→다음 실행 후 정리) 디스크 목록 |
| `AC-005` | 단위(주입 가능한 타임아웃, 느린 워커) + env 범위 검사 단위 | 단위 | `deadline_exceeded` 기록, 설정 오류 테스트 |
| `AC-006` | 순수 전이/복구 단위(복구 함수가 기록 슬라이스를 받아 결과를 돌려주는 순수 함수로 분리) + 라이브(백엔드 SIGKILL 후 재기동) | 단위 + 로컬 | 재기동 후 `abandoned`·`interrupted` 디스크 확인, 만회/가드 표 |
| `AC-007` | 파이썬 워커 테스트(전송 실패 주입, 대상별 결과) + Go 결과 매핑 단위 | `python3 scripts/test/test_backup_worker.py`; 단위 | 대상별 결과 JSON, 로컬 사본 존재 |
| `AC-008` | 순수 가지치기 단위(개수·기간·최근 성공 유지·실행 중 유지) + 파일 모드/원자 쓰기 검사 | 단위 | 표 구동 테스트 결과 |
| `AC-009` | 비밀 비노출 테스트: 알려진 비밀·경로 센티널을 심고 모든 응답·`backup-jobs.json`·로그 캡처에 대해 부분 문자열 검색, 비관리자·비활성 상태 코드 표 | 단위(`go test`) + 라이브 grep | 센티널 0건 |
| `AC-010` | OpenAPI 드리프트(`TestOpenAPIMatchesRegisteredRoutes`)·완전성 테스트, 기존 `@fixture` e2e 2건 무수정 통과 | `go test`; Playwright ui-e2e | CI 결과 |
| `AC-011` | UI e2e: 모킹(상태 전이·취소·부분 실패 렌더) + 기존 `@fixture` 스펙에 job 목록 단언 추가 | Playwright(모킹), 로컬 fixture 환경 | 렌더 스냅샷, 좁은 뷰포트 확인 |
| `AC-012` | `scripts/test/test_backup_worker.py` 확장(`--job-id`, 매니페스트 호환, 결과 파일 원자 기록, SIGTERM, 종료 코드 75) | python3 | 테스트 통과, 기존 4건 무회귀 |
| `AC-013` | 순수 상태기계 단위: `reconcile(record, lockHeld, resultFile, manifest)` 표(잠금 유지→`running`+`orphan_suspected`·만회 없음 / 해제+결과 파일→실제 결과 / 해제+매니페스트만→`abandoned`+산출물 / 해제+없음→`abandoned`), 백오프 함수 표, 주입된 `lockProbe`. 라이브 고아 시나리오(T-004와 동일): 느린 워커 실행 중 백엔드만 SIGKILL → 재기동 → 409·`orphan_suspected` → 워커 종료 후 결과 확정 → 만회 1회 | 단위 + 로컬(실제 워커) | 재기동 직후 기록·409 본문, 확정 후 기록·로그 줄(`result_source`) |
| `AC-014` | 주입 writer 단위(시작·취소 요청·종료·복구 각 쓰기를 N번째에 실패): 503 `persistence_unavailable`·워커 미시작, 신호 미전송, `dirty` 재시도, 시작되지 않은 `running` 없음 | 단위 | 실패 분기 표 테스트 |
| `AC-015` | 순수 스케줄 함수 단위(`worker_busy`→`NextRun=now+60s`, 연속 10회 후 주기), 사전 잠금 탐지 핸들러/틱 단위 | 단위 | 표 구동 테스트 |

단위/정적(`go test -race ./...`, `go vet`, 파이썬 테스트, 프런트 빌드)과 런타임(실제 워커 라이브 시나리오, UI e2e)을 구분해 EVIDENCE에 기록한다. LDAP 와이어 코드는 단위 테스트 대상이 아니며 목 프레임워크를 도입하지 않는다(AGENTS.md Testing philosophy).

## Rollout, rollback and recovery

- Rollout sequence: ① 워커 계약(가산, 구 컨트롤러와 호환) → ② 컨트롤러 기록·복구·API(`backup-jobs.json` 최초 생성은 빈 이력) → ③ OpenAPI·문서 → ④ UI. 각 단계는 독립 머지 가능하며 ①②는 UI 없이도 동작한다. 기능 플래그 없음(가산 변경).
- Rollback trigger and procedure: 복구 오류·기록 손상·기존 e2e 회귀 시 이전 이미지로 되돌린다. 구버전은 `backup-jobs.json`을 읽지 않고 정책 파일의 모르는 필드를 무시한다. 워커 가산 필드는 구 컨트롤러가 무시한다([run.go:61-65](../../../ui/backend/internal/backup/run.go)는 필요한 키만 디코드).
- Data/configuration recovery: `backup-jobs.json`이 손상되면 컨트롤러는 파일을 `.corrupt-<ts>`로 옮기고 빈 이력으로 시작하며 로그를 남긴다(기동 실패로 백업이 멈추지 않게 — 정책 파일 손상이 기동 실패인 현행([manager.go:80-82](../../../ui/backend/internal/backup/manager.go))과 의도적으로 다르다: job 이력은 정책이 아니라 진단 정보). 파일은 삭제해도 안전하다(정책·`State`·아카이브는 그대로). `<root>/.results/`의 결과 파일은 기록 가지치기와 함께 삭제되며 `storage()`·복원·`prune`이 보는 `<root>/<kind>/` 밖이라 영향이 없다. 기록이 삭제된 상태에서 고아 워커의 결과 파일만 남으면 무시한다.
- Compatibility or migration obligations: 마이그레이션 없음. 기존 `State.Status=running`이 남은 상태의 최초 기동은 기록이 없으므로 합성 `abandoned` 기록을 만들지 않고 현행대로 `interrupted`만 적용한다. 기존 클라이언트 호환은 AC-010.

## Evidence and durable synchronization

- Evidence location/format: `docs/changes/backup-job-ids/EVIDENCE.md`(구현 시 생성) — 명령·환경·실제 출력, 실패와 수정 기록. 연구 증거 규약은 `research/README.md`를 따르되 개발을 막지 않는다.
- Tests or checks that become durable regression controls: 순수 전이·복구·가지치기 표 테스트, 비밀 센티널 테스트, 취소·타임아웃 프로세스 그룹 테스트, 워커 계약 테스트, OpenAPI 드리프트, UI e2e(모킹).
- Documentation to update: `docs/api.md`, `ui/README.md`, OpenAPI·`llms.txt`, 운영 가이드, `charts/ldapium/README.md`(타임아웃 값).
- ADR/evidence/portfolio records to update: ADR 불필요(위 판정). #216·#218 확정 시 D217-9·오류 코드 표기를 해당 규약에 맞춰 갱신하고 이 패키지에 변경 기록을 남긴다.

## Traceability matrix

| Requirement | Acceptance | Task | Evidence |
|---|---|---|---|
| `REQ-001` | AC-001, AC-010 | T-010, T-014, T-020, T-021 | 핸들러 단위, 응답 캡처 |
| `REQ-002` | AC-001, AC-006 | T-010, T-011, T-020, T-021 | 영속·재시작 시나리오 |
| `REQ-003` | AC-002, AC-004, AC-007, AC-009 | T-010, T-013, T-020 | 상태·오류 코드 표 |
| `REQ-004` | AC-008 | T-011, T-020 | 가지치기 표, 파일 모드 |
| `REQ-005` | AC-002, AC-009 | T-014, T-020, T-021 | GET 단위·라이브 |
| `REQ-006` | AC-004, AC-012 | T-013, T-015, T-020, T-021, T-023 | 프로세스 그룹 테스트, 라이브 취소 |
| `REQ-007` | AC-005 | T-013, T-016, T-020 | 타임아웃 단위 |
| `REQ-008` | AC-006, AC-013 | T-004, T-012, T-020, T-021 | 복구 순수 단위, 재기동·고아 라이브 |
| `REQ-009` | AC-003 | T-014, T-020, T-021 | 409 본문 |
| `REQ-010` | AC-002, AC-007, AC-012 | T-013, T-015, T-021, T-023 | 워커 테스트, 매니페스트 대조 |
| `REQ-011` | AC-001 | T-013, T-014, T-020 | 로그 줄 검사 |
| `REQ-012` | AC-003, AC-004 | T-014, T-017, T-031 | 코드 표, #218 정합 확인 |
| `REQ-013` | AC-010 | T-017, T-020, T-022 | 드리프트·기존 e2e |
| `REQ-014` | AC-011 | T-018, T-022 | UI e2e |
| `REQ-015` | AC-009 | T-020 | 센티널 테스트 |
| `REQ-016` | AC-014 | T-011, T-013, T-014, T-020 | 주입 writer 실패 분기 표 |
| `REQ-017` | AC-013, AC-015 | T-012, T-013, T-020 | 스케줄·잠금 탐지 표 |

## Review record

- Accepted scope/requirements: 유지보수자 지시(#217 처리)로 REQ-001..017 수용, 2026-10-06. 열린 질문은 아래와 같이 결정됨.
- Material changes after acceptance and re-review: 독립 비평(Codex, main `60dae0d` 기준) 반영 개정 — ① 고아 워커 대 만회(D217-16, AC-013, REQ-017) ② 취소 정리 약속 완화(`staging_cleanup`, D217-6) ③ 전이별 영속 순서·실패·writer 주입(D217-17, AC-014, REQ-016) ④ 신원 규칙 단일화(지문만, D217-12) ⑤ 오류 봉투·코드 표·표기 규칙·멱등 한계(D217-9, D217-18).
- Open questions or blockers: 없음 — 아래 결정으로 닫힘. 구현 중 뒤집으려면 이 패키지를 갱신하고 재검토한다.

| ID | 질문 | 결정 | 뒤집을 때 비용 |
|---|---|---|---|
| Q1 | job 항목 경로를 `/jobs/{id}`(OpenAPI상 `post`와 한 경로 항목)로 둘 것인가, `/job-runs/{id}`로 분리할 것인가 | `/jobs/{id}` 유지. Echo는 파라미터 이름을 메서드별로 저장하고 드리프트 테스트가 이를 수용함(독립 비평 PASS). 도구가 이중 의미를 문제 삼으면 분리 | `Location` 값과 문서만 변경 |
| Q2 | job ID 생성기와 Idempotency-Key | ID 생성기는 구현이 선택하되 **계약은 고정**: 불투명, URL-safe, 시간순 정렬 가능, 비밀 없음, ≤64자(D217-1의 형식은 권고 구현). Idempotency-Key는 #216 규약에 위임(D217-9) | 후속에 해시 필드·조회 가산 |
| Q3 | 만회 정책 | 고아 워커가 끝나 결과가 확정된 **뒤**에만 만회(D217-16 → D217-8), 크래시 루프 가드 유지(최근 3건 `abandoned`이면 중단) | env로 비활성화 가능하게 가산 |
