# 릴리스 가이드

ldapium은 하나의 Git tag `vX.Y.Z`를 기준으로 서버 이미지, UI 이미지, Helm chart를 같은 버전으로 배포합니다.

English | **한국어**

## 릴리스 준비

1. **버전을 정합니다.** 0.x 단계에서는 minor 올림이 호환성을 깨뜨릴 수 있으며, 그럴 때는 changelog에 명시합니다.
2. **버전이 들어가는 네 곳을 갱신한 뒤** 스크립트로 빠짐없이 바꿨는지 확인합니다.
   - `charts/ldapium/Chart.yaml`의 `version`
   - `docker-compose.yml`의 `OPENLDAP_IMAGE` / `UI_IMAGE` 기본 태그
   - `ui/frontend/package.json`의 `version`
   - `README.md`의 설치 예시

   ```bash
   ./scripts/check-versions.sh
   ```

   `appVersion`은 여기에 포함되지 않습니다. 이미지가 빌드하는 OpenLDAP 버전이므로 `image/Dockerfile`의 `OPENLDAP_VERSION`과 sha256이 바뀔 때만 바꿉니다.
3. **`CHANGELOG.md`에 `## [X.Y.Z] — YYYY-MM-DD` 섹션과 하단 링크를 작성합니다.** 릴리스 workflow가 이 섹션을 그대로 추출하며, 없으면 실패합니다.
4. `make check`로 CI와 같은 검사를 실행하고 필요한 e2e 검증을 확인합니다.
5. **`main`에 병합하고 CI가 모두 통과할 때까지 기다립니다.** 통과하기를 기대하는 커밋이 아니라 이미 통과한 커밋에서 태그를 만드십시오.

### Preflight 규칙

`release.yml`의 `preflight` job은 **태그된 SHA**를 기준으로 다음 중 하나라도 어긋나면 릴리스 전체를 실패시킵니다.

- 해당 SHA가 `main`의 조상일 것
- 그 SHA의 **모든** check run 결론이 `success`, `skipped`, `neutral` 중 하나일 것. 아직 `pending`인 것을 포함해 그 외 결론은 release-critical 목록과 무관하게 실패입니다.
- `main` 브랜치 보호가 요구하는 status check가 모두 성공했을 것
- 아래 release-critical job이 해당 SHA에서 성공했을 것

| Job | Workflow |
|---|---|
| `Go vulnerabilities (reachable)` | `security-scan.yml` |
| `rolling upgrade + rollback (standalone)` / `(replicated)` | `upgrade-e2e.yml` |
| `backup → verify → corrupt-check → restore` | `backup-restore.yml` |
| `3-node backup → bad delete → restore → resync` | `backup-restore.yml` |
| `machine bearer auth (real Keycloak)` | `machine-keycloak-e2e.yml` |
| `machine write (real Keycloak)` | `machine-write-e2e.yml` |
| `generated credentials + API edge codes (live)` | `api-credentials-e2e.yml` |

해당 workflow가 생기기 전의 `main` 커밋에는 이런 run이 없으므로 그 커밋에 태그를 달면 gate가 실패합니다. 그 SHA에서 workflow를 다시 실행하거나(예: `gh workflow run machine-keycloak-e2e.yml --ref <해당 SHA의 branch 또는 tag>`, 반드시 그 커밋에 대한 run이어야 함) 더 최신 커밋에 태그를 다십시오. skipped/cancelled run이나 다른 SHA의 success는 gate를 만족시키지 못합니다. `machine write (real Keycloak)` job은 v2b/v2c(`setPassword`) drill과 live proof도 함께 실행하므로 이 이름 하나가 모두를 gate합니다.

일시적 실패는 해당 job을 다시 실행해 해소할 수 있습니다. check-runs API는 가장 최근 시도를 보고하므로 성공한 재실행이 실패를 대체합니다. gate는 polling하지 않으므로 `main`의 check가 끝날 때까지 먼저 기다리십시오. upgrade/backup e2e는 10~20분이 걸립니다.

## 태그 생성

```bash
git tag -a v0.1.1 -m "ldapium 0.1.1"
git push origin v0.1.1
```

tag annotation에 `[skip ci]`를 넣지 마십시오. tag push가 릴리스를 시작시킵니다.

`release.yml`이 `v*` tag push를 감지하여 서버/UI multi-arch 이미지와 Helm chart를 GHCR에 게시하고 GitHub Release를 생성합니다.

tag push는 `Research evidence` workflow(`research-check`)도 시작하며, 이 workflow는 Release의 preflight가 check run을 읽기 전에 끝나야 합니다. 아직 pending일 때 preflight가 실행되면 `pending research-check`로 실패합니다(v0.2.0, v0.2.1에서 발생). `research-check`가 끝나기를 기다린 뒤 `gh run rerun <release-run-id>`로 다시 실행하십시오. **태그를 다시 만들지 않습니다.**

## 게시되는 산출물

```text
ghcr.io/dasomel/ldapium:<version>
ghcr.io/dasomel/ldapium-ui:<version>
oci://ghcr.io/dasomel/charts/ldapium
```

- 이미지에는 `<version>`, `<major>.<minor>`, `latest`, `sha-<sha>` 태그가 붙습니다. `:main`은 릴리스가 아니라 현재 소스를 매주 다시 빌드한 것입니다.
- GitHub Release에는 `CHANGELOG.md`의 노트와 chart tarball, SBOM 4개가 첨부됩니다.
- Chart version은 release tag에서 결정되고 `appVersion`은 빌드 대상 OpenLDAP 버전을 나타냅니다.
- 각 이미지에는 provenance와 SBOM attestation이 GitHub OIDC identity로 서명되어 registry에 함께 올라갑니다. 사람이 관리하는 별도 서명 키는 없습니다.

## 릴리스 검증

green check가 곧 성공이라고 가정하지 말고 게시된 결과를 확인합니다.

```bash
helm pull oci://ghcr.io/dasomel/charts/ldapium --version <version>
docker buildx imagetools inspect ghcr.io/dasomel/ldapium:<version>
gh attestation verify oci://ghcr.io/dasomel/ldapium:<version> --repo dasomel/ldapium
gh attestation verify oci://ghcr.io/dasomel/ldapium-ui:<version> --repo dasomel/ldapium
```

`imagetools inspect` 출력에는 `linux/amd64`와 `linux/arm64`가 모두 있어야 합니다.

게시된 chart를 실제로 설치해 `helm test`까지 수행합니다. 렌더링된 template이 곧 동작하는 릴리스는 아닙니다. `helm test`는 실행 중인 서버에 overlay가 실제로 로드되었는지 확인하는 검사이며, overlay가 빠져도 slapd는 기동합니다.

```bash
helm install smoke oci://ghcr.io/dasomel/charts/ldapium --version <version> \
  --namespace smoke --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)"
helm test smoke --namespace smoke --logs
helm uninstall smoke --namespace smoke && kubectl delete ns smoke
```

## OpenLDAP 버전 올리기

프로젝트 릴리스와는 별개이지만 보통 릴리스로 이어집니다. openldap.org에서 받은 tarball의 sha256을 `image/Dockerfile`의 `OPENLDAP_VERSION`/`OPENLDAP_SHA256`과 `charts/ldapium/Chart.yaml`의 `appVersion`에 반영하고(`check-versions.sh`가 둘의 일치를 확인), 이미지를 빌드해 **실제로 기동**한 뒤 overlay와 3-node replication 수렴을 확인합니다.

## 자동화되지 않는 것

- 백포트는 없습니다. 수정은 다음 릴리스로 나갑니다([SECURITY-ko.md](SECURITY-ko.md) 참고).
- 저장소 공개 전환 시의 설정(Actions 권한, secret scanning, branch protection, GHCR package 공개 등)은 저장소 파일로 지정할 수 없으므로 영문 [RELEASING.md](RELEASING.md)의 "Going public" 체크리스트를 따릅니다.
