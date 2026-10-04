- **P2 — [merge-app-oidc.py:62](scripts/integration/merge-app-oidc.py:62)**: 기존 `policy.ldapium.csv`를 충돌 검사 없이 덮어씁니다. 다른 프로필의 export를 같은 ConfigMap에 병합하면 이전 그룹 매핑이 사라집니다. `/team-a → admin`이 `/team-b → readonly`로 대체되는 것을 재현했습니다. 기존 테스트는 이 충돌을 검사하지 않습니다.

기존 두 결함은 코드상 수정됐습니다. native exporter는 `/engineering/team`을 허용하면서 정책 구분자·개행을 거부합니다. tombstone은 파일에 저장되고 재시작 시 복원되며, 재생성 revision은 증가합니다. HTTP PUT과 Store.Put 모두 `deleted:true`를 거부합니다.

검증: `python3 -B` 병합 테스트 **2개 OK**. `go test ./internal/appprofile ./internal/httpapi`는 읽기 전용 환경의 임시 디렉터리 생성 제한으로 실행하지 못했습니다. 따라서 Go 동작 검증은 정적 검토에 한정됩니다.