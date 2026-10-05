PASS. 검증된 파일명의 프로필 ID로 정책 키를 분리하여 다른 프로필과 기존 정책을 보존합니다. `policy.default`와 `scopes` 충돌은 병합을 거부합니다.

`python3 -B scripts/test/test_merge_app_oidc.py MergeTests.test_argocd_preserves_other_policy_and_rejects_default_conflicts MergeTests.test_grafana_preserves_secret_and_other_sections_idempotently` → 2 tests, OK.

전체 테스트의 CLI 항목은 읽기 전용 환경에서 임시 디렉터리 생성이 차단되어 검증하지 못했습니다. 파일 수정 및 `.local` 접근 없음.