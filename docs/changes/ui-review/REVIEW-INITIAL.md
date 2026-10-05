- **P2 — [export.go:18](/Users/m/Documents/IdeaProjects/20.dasomel/ldapium/ui/backend/internal/appprofile/export.go:18)**: Grafana·Argo CD exporter의 `policyWord`가 `/`를 거부합니다. 새 UI가 안내하는 `/engineering`이나 중첩 그룹 경로를 매핑하면 저장·미리보기는 성공하지만 내보내기는 422로 실패합니다. UI가 제시하는 그룹 경로 기반 연동을 완료할 수 없습니다.

- **P2 — [store.go:113](/Users/m/Documents/IdeaProjects/20.dasomel/ldapium/ui/backend/internal/appprofile/store.go:113)**: 프로파일 삭제 후 같은 ID를 재생성하면 revision이 다시 1이 됩니다. 이전 revision 1을 보유한 관리자 탭의 PUT 또는 DELETE가 재생성된 프로파일에 그대로 승인되어, 새 설정을 덮어쓰거나 삭제합니다. 삭제 이후에도 구분되는 세대 식별자나 revision이 필요합니다.

미추적 소스와 공유 UI 변경을 포함한 정적 검토입니다. 테스트·실제 LDAP/Keycloak·브라우저 검증은 실행하지 않았습니다.