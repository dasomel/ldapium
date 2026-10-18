# 라이선스 및 법률 안내

ldapium은 OpenLDAP을 공식 배포하는 프로젝트가 아니라 OpenLDAP 업스트림 소스를 컨테이너와 Kubernetes 환경에 맞게 패키징하는 프로젝트입니다.

English | **한국어**

## 프로젝트 라이선스

이 저장소에서 새로 작성한 원본 코드(UI의 Go/TypeScript, Helm chart, entrypoint와 스크립트, Dockerfile, 문서)는 Apache License 2.0([LICENSE](../LICENSE))으로 배포합니다. MIT 대신 Apache-2.0을 고른 이유는 명시적 특허 허여(§3)와 [NOTICE](../NOTICE)를 통한 attribution 때문입니다.

## OpenLDAP 라이선스

배포 이미지에는 OpenLDAP Software가 포함되며 OpenLDAP Public License 2.8의 적용을 받습니다. OpenLDAP 원본과 프로젝트에서 작성한 코드는 서로 다른 저작물이며 각각의 라이선스를 유지합니다.

자세한 내용은 다음 파일을 확인하십시오.

- `NOTICE`
- `docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt`
- `THIRD-PARTY-LICENSES.md`

## 배포 이미지에 포함되는 것

| 계층 | 내용 | 라이선스 | 수정 여부 |
|---|---|---|---|
| OpenLDAP | 업스트림 소스 릴리스를 `image/Dockerfile`에서 버전과 sha256으로 고정해 컴파일 | OpenLDAP Public License 2.8 | 예. syncrepl 패치 1건을 적용합니다(`image/patches/`, #432). 이미지의 `/usr/share/doc/openldap/patches/`에도 포함됩니다. |
| 베이스 OS | `debian:trixie-slim`과 빌드가 설치하는 패키지(OpenSSL, Cyrus SASL, libargon2 등) | 대부분 GPL/LGPL, 일부 BSD/Apache/CC0 | 아니오. 패키지 그대로 재배포합니다. |
| UI | 이 프로젝트의 Go 바이너리와 빌드된 frontend | Apache-2.0 | 해당 없음 |

베이스 이미지의 GPL 패키지는 OpenLDAP이 호출하거나 링크하는 **별도의 프로그램**이며(GPL이 말하는 단순 aggregation), 이 프로젝트의 바이너리는 GPL/LGPL을 링크하지 않습니다. Go 의존성은 MIT/Apache-2.0/BSD, npm 운영 의존성은 MIT/Apache-2.0/ISC/0BSD만 허용하며 CI가 이를 강제합니다(`scripts/licenses.sh`). 유일한 LGPL 구성요소는 OpenLDAP이 모듈 로딩을 위해 **동적으로** 링크하는 `libltdl`이며 수정하지 않았고 `NOTICE`에 기록되어 있습니다. unixODBC를 끌어오는 실험적 `back-sql`은 빌드하지 않습니다. 이미지에 패키지를 추가해 다시 빌드한다면 이 분석은 직접 다시 해야 하며 `make sbom`이 입력이 됩니다. 자세한 근거는 영문 [legal.md](legal.md)를 참고하십시오.

## SBOM

릴리스된 모든 이미지는 SBOM을 두 방식으로 제공합니다. registry에 서명된 attestation으로 이미지와 함께 붙어 있고, GitHub Release에는 SPDX 2.3(`ldapium.spdx.json`)과 CycloneDX(`ldapium.cdx.json`) 및 UI 이미지용 같은 쌍이 첨부됩니다. 직접 생성해 비교할 수 있습니다.

```sh
gh attestation verify oci://ghcr.io/dasomel/ldapium:0.3.0 --repo dasomel/ldapium
syft ghcr.io/dasomel/ldapium:0.3.0 -o spdx-json
```

빌드 provenance도 같은 방식으로 attest되므로 이미지를 만든 workflow run과 commit까지 추적할 수 있습니다.

## 상표

OpenLDAP은 OpenLDAP Foundation의 등록 상표입니다. ldapium은 OpenLDAP Foundation과 제휴, 보증 또는 지원 관계에 있지 않으며 여기서 빌드되는 이미지는 공식 OpenLDAP 릴리스가 아닙니다.

## 암호화와 수출

이미지에는 Debian의 OpenSSL과 Cyrus SASL, OpenLDAP에 컴파일된 TLS/SASL 지원, Argon2 비밀번호 해시 등 암호화 소프트웨어가 포함됩니다. 소스가 공개되어 있고(암호와 무관한 syncrepl 패치 1건 외에는) 수정하지 않았다는 점에서 미국 EAR의 TSU 예외(§740.13(e))가 상정하는 상황이며, 일반적인 Linux 컨테이너 이미지와 같은 입장입니다. 이는 법률 의견이 아니며 각 관할지의 암호화 수입 제한은 직접 확인해야 합니다.

## 의존성 라이선스

서드파티 의존성은 CI에서 라이선스를 검사하며 허용 목록 밖의 라이선스가 추가되거나 라이선스 목록이 실제 dependency tree와 일치하지 않으면 검사가 실패합니다.

공개 전에 수행한 점검(추적 파일에 자격 증명/키 없음, 기본 비밀번호 없음, 샘플/개인 데이터 없음, 문서에 내부 호스트명 없음, 허용 라이선스만 사용, Trivy 스캔)은 릴리스 전에도 반복할 가치가 있으며 명령은 영문 문서의 "What was checked before publication"에 있습니다. 라이선스나 attribution 문의는 issue로, 보안 취약점은 [SECURITY-ko.md](../SECURITY-ko.md)에 따라 비공개로 알려 주십시오.

이 문서는 법률 자문이 아니며 실제 배포 시에는 해당 라이선스의 원문과 조직의 법무 검토를 함께 확인해야 합니다.
