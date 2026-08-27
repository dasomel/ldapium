# 릴리스 가이드

ldapium은 하나의 Git tag `vX.Y.Z`를 기준으로 서버 이미지, UI 이미지, Helm chart를 같은 버전으로 배포합니다.

English | **한국어**

## 릴리스 준비

1. `CHANGELOG.md`에 해당 버전의 섹션을 작성합니다.
2. 이미지와 chart의 버전 일관성을 확인합니다.
3. `make check` 및 필요한 e2e 검증을 실행합니다.
4. 변경 사항이 실제 환경에서 검증되었는지 확인합니다.

## 태그 생성

```bash
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1
```

`release.yml`이 `v*` tag push를 감지하여 서버/UI multi-arch 이미지와 Helm chart를 GHCR에 게시하고 GitHub Release를 생성합니다.

## 이미지

다음 형식으로 게시됩니다.

```text
ghcr.io/dasomel/ldapium:<version>
ghcr.io/dasomel/ldapium-ui:<version>
```

`vX.Y.Z`의 안정 릴리스에서는 `latest`도 함께 업데이트됩니다.

## Helm chart

```text
oci://ghcr.io/dasomel/charts/ldapium
```

Chart version은 release tag에서 결정되고 `appVersion`은 빌드 대상 OpenLDAP 버전을 나타냅니다.

## 릴리스 검증

실제 게시가 완료된 뒤 registry에서 multi-arch manifest와 digest를 확인하고 필요하면 다음과 같이 provenance를 검증합니다.

```bash
gh attestation verify oci://ghcr.io/dasomel/ldapium:<version> --repo dasomel/ldapium
gh attestation verify oci://ghcr.io/dasomel/ldapium-ui:<version> --repo dasomel/ldapium
```

Helm chart도 실제 OCI registry에서 설치해 `helm lint`와 `helm test`까지 수행하는 것을 권장합니다.
