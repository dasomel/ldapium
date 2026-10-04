# Independent static review

Read-only ephemeral Codex review; no test execution by reviewer.

Final restore boundary review after fixes:

PASS — `scripts/restore.sh` 읽기 전용 검토에서 남은 critical/high 결함은 발견하지 못했습니다. 실행 검증은 수행하지 않았습니다.

Prior findings and fixes are recorded in EVIDENCE.md.

Final targeted review of partial-local success state and Base64 DN fix:

PASS

## UI settings extension review — 2026-10-03

- **HIGH — 운영자 remote 설정을 덮어써 백업을 다른 서버로 전송할 수 있음.** [backup_worker.py:289](/Users/m/Documents/IdeaProjects/20.dasomel/ldapium/ui/backend/backup-tools/backup_worker.py:289): managed ID `demo`는 기존 `[ldapium-managed-demo]` 섹션을 무조건 교체합니다. API는 destination ID 충돌만 검사하므로, 다른 ID의 운영자 destination이 이 remote를 참조하면 연결을 등록하는 것만으로 기존 정책의 LDAP 백업 전송 대상이 변경됩니다. 해당 managed 연결이 정책에서 선택되지 않아도 발생합니다. 메모리 재현에서 운영자 endpoint와 자격증명이 교체됨을 확인했습니다.

- **MEDIUM — 점이 포함된 S3 버킷은 저장되지만 백업 전송이 항상 실패함.** [backup_worker.py:279](/Users/m/Documents/IdeaProjects/20.dasomel/ldapium/ui/backend/backup-tools/backup_worker.py:279): bucket을 prefix에 합친 뒤 `validate_remote()`의 `[A-Za-z0-9_/-]+` 검사에 넘깁니다. API가 허용하는 `backup.example`은 worker에서 거부됩니다. 동일 정규식 재현 결과: API 검사 `True`, worker 검사 `False`.

읽기 전용 정적 검토와 메모리 재현만 수행했습니다. 파일 변경 및 실제 LDAP/rclone 전송 테스트는 수행하지 않았습니다.

Resolution: generate unused random remote section names and ignore unselected managed
entries; dotted bucket names accepted with path traversal segments still rejected.
Regression test added. Final targeted review:

PASS — 지정한 세 수정에서 남은 critical/high/medium 회귀는 발견하지 못했습니다.

메모리 기반 회귀 검사 통과: 섹션 충돌 시 이름 재생성, 미선택 연결 제외, dotted S3 버킷 허용, `.`/`..` 및 빈 경로 구간 거부. 실제 rclone 전송은 검증하지 않았습니다. 파일 수정 없음.
