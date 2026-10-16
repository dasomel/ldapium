# 보안 정책

ldapium은 OpenLDAP을 컨테이너와 Kubernetes 환경에서 패키징하는 프로젝트입니다. OpenLDAP 자체의 취약점은 가능한 경우 업스트림 OpenLDAP 프로젝트의 보안 절차를 사용하십시오.

English | **한국어**

## 취약점 신고

공개 GitHub issue에 보안 취약점을 올리지 마십시오. GitHub [private vulnerability reporting](https://github.com/dasomel/ldapium/security/advisories/new)(Security → Report a vulnerability)을 사용해 비공개로 신고하십시오. 논의와 최종 advisory를 한곳에 모을 수 있어 권장합니다.

신고에는 가능한 한 다음 정보를 포함해 주십시오.

- 영향을 받는 버전 또는 이미지 digest
- 재현 절차
- 예상 결과와 실제 결과
- 영향을 받는 구성(image, UI, Helm chart 등)
- 가능한 경우 최소 재현 환경

첫 회신은 일주일 이내를 예상하십시오. 유급 보안 팀이 없는 소규모 프로젝트이므로 이는 보장하는 목표가 아니라 현실적인 소요 시간입니다.

## 보안 설계 원칙

- 기본 관리자 비밀번호를 제공하지 않습니다.
- 샘플 사용자와 비밀번호를 이미지에 포함하지 않습니다.
- 이미지, Helm chart, Compose 모두 관리자 비밀번호 없이는 기동(렌더링)을 거부하므로 "기본 비밀번호가 약하다"는 신고는 해당되지 않습니다.
- UI는 서비스 계정 없이 로그인한 사용자로 bind하므로 세션이 읽고 쓸 수 있는 범위는 UI 코드가 아니라 디렉터리의 ACL이 결정합니다. 예외는 OIDC 토큰에 bind용 비밀번호가 없는 SSO 경로이며 `ui/README.md`에 문서화되어 있습니다.
- `cn=config`는 UI가 만들 수 있는 어떤 세션으로도 접근할 수 없습니다. 의도된 설계 제약입니다.
- 컨테이너는 최소 권한과 non-root 실행을 기본으로 합니다.
- TLS는 기본적으로 꺼져 있으며 플랫폼(Ingress/service mesh)에서 종료하거나 `tls.enabled`로 명시적으로 켜는 것을 전제로 합니다. 클러스터 내부 Service의 평문 LDAP은 문서화된 기본값이며, 그 경계 밖으로 인증 정보가 새는 경우는 신고해 주십시오. TLS를 켜면 `.github/workflows/e2e.yml`의 `TLS E2E` job이 모든 PR과 `main` push에서 LDAPS와, 복제 설치의 경우 엄격한 CA 검증을 거치는 `ldaps://` syncrepl을 검증합니다.

## 범위

이 프로젝트의 패키징, Helm chart, 관리 UI, CI/CD 및 공급망 구성에 대한 취약점은 프로젝트 범위에 포함됩니다. OpenLDAP 서버 자체의 구현 취약점은 [OpenLDAP 프로젝트](https://bugs.openldap.org/)에 신고하십시오. 이 저장소는 수정하지 않은 업스트림 소스를 컴파일하며 자체 패치가 없습니다. 업스트림 수정이 릴리스된 뒤 고정 버전을 올리는 일은 보안 신고가 아니라 일반 issue입니다.

## 지원 버전

최신 릴리스만 지원합니다(현재 0.2.x, `CHANGELOG.md` 참고). 0.x 단계이므로 백포트는 없고 수정은 이전 버전 패치가 아니라 다음 릴리스로 나갑니다.

두 이미지는 매주(`.github/workflows/weekly-rebuild.yml`) 다시 빌드되어 Debian 패키지 보안 업데이트가 릴리스를 기다리지 않고 `:main` 태그에 반영됩니다. 베이스 이미지는 digest로 고정되어 있어 `debian:trixie-slim` 갱신은 재빌드가 아니라 Dependabot PR로 들어오며(`docs/dependency-policy.md`), 릴리스된 태그는 불변이고 제자리에서 다시 빌드하지 않습니다.
