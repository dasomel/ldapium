# 변경 기록

이 문서는 ldapium의 주요 변경 사항을 한국어로 정리합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고 버전은 Semantic Versioning을 사용합니다.

English | **한국어**

하나의 Git tag `vX.Y.Z`가 Helm chart와 두 컨테이너 이미지를 같은 버전으로 배포합니다. `appVersion`은 빌드에 포함되는 OpenLDAP 버전을 의미합니다.

## [0.1.0] — 2026-08-18

첫 번째 프로토타입 릴리스입니다.

### 서버 이미지

- OpenLDAP 2.6.14 업스트림 소스를 직접 빌드
- `linux/amd64`, `linux/arm64` 지원
- 기본 샘플 데이터와 기본 관리자 비밀번호 없음
- `memberof`, `refint`, `ppolicy`, `unique`, `syncprov` 등의 overlay 지원
- N-way multi-provider replication 지원
- 대규모 디렉터리를 고려한 paging, size/time limit 및 file descriptor 설정

### 관리 UI

- Go backend + React frontend
- DIT 조회, 사용자/그룹 CRUD, 비밀번호 설정/변경, 계정 잠금 해제
- 로그인한 사용자의 LDAP identity 기반 동작
- 선택적인 Keycloak OIDC SSO + PKCE
- 한국어/영어 UI
- LDAP에서 백업 상태를 직접 조회하는 기능

### Helm chart

- StatefulSet + PVC + Headless Service
- `replicaCount > 1`에서 replication 자동 구성
- 선택적인 UI Deployment
- 디렉터리 백업 CronJob
- 설치 후 `helm test`를 통한 실제 LDAP 동작 검증

### 기타

- Docker Compose 기반 독립 실행
- Kubernetes/Compose 환경에서 credential 조회 스크립트
- 공급망 보안을 위한 provenance/SBOM 구조

### 알려진 제한 사항

- TLS end-to-end 검증이 아직 완료되지 않았습니다.
- 0.1.0은 첫 릴리스이므로 기존 버전에서의 upgrade path를 약속하지 않습니다.
- e2e workflow는 새로 구성되었으므로 독립 환경에서 지속적인 검증이 필요합니다.
