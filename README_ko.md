# ldapium

Kubernetes에서 사용할 수 있는 OpenLDAP 기반 디렉터리 스택입니다. OpenLDAP 2.6을 업스트림 소스에서 직접 빌드한 서버 이미지, 관리 UI, Helm chart를 하나의 프로젝트로 제공합니다.

English | **한국어**

[![CI](https://github.com/dasomel/ldapium/actions/workflows/ci.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.6.14-informational)](https://www.openldap.org/)

> **상태: prototype**. 초기부터 공개하여 패키징과 운영 방식을 실제 환경에서 검증하는 프로젝트입니다. 현재 릴리스 문서에 기술된 기능 중 일부는 아직 독립적인 환경에서 충분히 검증되지 않았으며, 특히 TLS 경로는 end-to-end 검증이 필요합니다.

## 프로젝트 목적

기존 OpenLDAP 컨테이너와 Kubernetes chart는 최신 OpenLDAP 버전, ARM64 지원, 지속적인 유지보수, 관리 UI, 재현 가능한 Helm 배포를 한 번에 제공하기 어려웠습니다.

ldapium은 이 문제를 다음 구성으로 해결합니다.

- 업스트림 OpenLDAP 소스 직접 빌드
- `linux/amd64` 및 `linux/arm64` 지원
- 기본 샘플 데이터 없음
- 기본 관리자 비밀번호 없음
- Kubernetes용 Helm chart
- 선택 가능한 관리 UI
- 단독 Docker Compose 실행
- 다중 제공자 replication
- 백업과 설치 검증용 `helm test`

## 구성 요소

| 경로 | 설명 |
|---|---|
| `image/` | OpenLDAP 2.6.14 서버 이미지 |
| `ui/` | DIT 브라우저, 사용자/그룹 관리, 비밀번호 관리 UI |
| `charts/ldapium/` | StatefulSet, replication, backup, UI 등을 제공하는 Helm chart |

## 설치

### Kubernetes

```bash
helm install directory oci://ghcr.io/dasomel/charts/ldapium \
  --version 0.1.0 \
  --namespace directory --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set ldap.rootDN='dc=example,dc=org'
```

관리자 비밀번호는 기본값이 없습니다. `auth.adminPassword` 또는 기존 Secret을 반드시 제공해야 합니다.

설치 후에는 다음 명령으로 실제 디렉터리 동작을 확인합니다.

```bash
helm test directory --namespace directory --logs
```

### 이미지

- `ghcr.io/dasomel/ldapium:0.1.0` — OpenLDAP 서버
- `ghcr.io/dasomel/ldapium-ui:0.1.0` — 관리 UI

두 이미지는 `linux/amd64`와 `linux/arm64`를 대상으로 설계되어 있습니다. 이미지와 Helm chart의 실제 registry 게시 여부는 해당 GitHub Release와 GHCR package 상태를 기준으로 확인해야 합니다.

### Docker Compose

Kubernetes 없이도 사용할 수 있습니다.

```bash
make local-up
make local-credentials
```

기본적으로 UI는 `http://localhost:8080`, LDAP는 `ldap://localhost:389`에서 사용할 수 있습니다.

## 주요 보안 원칙

- 기본 관리자 비밀번호를 제공하지 않습니다.
- 기본 샘플 사용자/그룹을 만들지 않습니다.
- UI는 기본적으로 로그인한 사용자의 LDAP identity로 bind합니다.
- Kubernetes에서는 non-root와 최소 권한 security context를 사용합니다.
- 이미지에는 provenance와 SBOM을 연결할 수 있도록 release workflow가 구성되어 있습니다.

## 개발

```bash
make help
make local-init
make local-up
make check
```

자세한 개발 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하십시오.

## 문서

- [영문 README](README.md)
- [한국어 README](README_ko.md)
- [한국어 기여 가이드](CONTRIBUTING_ko.md)
- [한국어 변경 기록](CHANGELOG_ko.md)
- [한국어 보안 정책](SECURITY_ko.md)
- [한국어 릴리스 가이드](RELEASING_ko.md)
- [한국어 법률/라이선스 안내](docs/legal_ko.md)

## 라이선스

프로젝트 자체의 원본 코드는 Apache-2.0입니다. 배포 이미지에는 OpenLDAP Public License 2.8로 제공되는 OpenLDAP 소프트웨어가 포함됩니다. 자세한 내용은 [NOTICE](NOTICE)와 [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)를 참고하십시오.
