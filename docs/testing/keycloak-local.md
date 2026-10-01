# 로컬 Keycloak LDAP 연동 검증

## 기동과 접속

LDAP가 실행 중인 상태에서 저장소 루트에서 실행합니다.

```sh
make keycloak-up
make keycloak-status
```

- 관리자 화면: <http://127.0.0.1:8180/admin/>
- 관리자: `admin` / `admin-local-only` (로컬 테스트 전용)
- 이미지: `quay.io/keycloak/keycloak:26.7.4`
- 테스트 Realm: `ldapium-local` (로그인 후 master에서 전환)
- LDAP 컨테이너: `ldapium-ldap-1`
- LDAP 서비스 DN: `cn=keycloak-svc,dc=example,dc=org`
- 사용자 검색: `ou=people,dc=example,dc=org` 하위
- 그룹 검색: `ou=groups,dc=example,dc=org` 하위
- 연동 모드: READ_ONLY, LDAP 페이징 사용

컨테이너 이름이나 포트를 바꾸려면 다음과 같이 실행합니다.

```sh
LDAP_CONTAINER=my-ldap KC_PORT=8280 make keycloak-up
```

스크립트는 LDAP의 실제 루트 DN을 읽습니다. 위 DN은 기본 로컬 환경의 예시입니다.
없는 `ou=people`, `ou=groups`, 서비스 계정만 생성하며 기존 계정은 수정하지 않습니다.
Keycloak은 루프백에만 공개되고, 서비스 계정은 일반 인증 사용자 ACL로 읽으며
`userPassword`를 읽거나 디렉터리를 관리할 권한을 받지 않습니다.

## 관리자 화면에서 확인

1. `ldapium-local` Realm의 `User federation → ldapium`을 엽니다.
2. `Test connection`, `Test authentication`으로 연결과 서비스 계정 인증을 확인합니다.
3. `Synchronize all users`로 사용자를 가져옵니다.
4. `Users`에서 LDAP 사용자 이름(uid)을 검색하고, 사용자 `Groups`에서 그룹을 확인합니다.
5. 그룹 Mapper는 `groupOfNames.member`를 읽어 Keycloak 그룹으로 연결합니다.

사용자는 `ou=people`에 `inetOrgPerson`, `uid`, `cn`, `sn`, 비밀번호를 갖고 있어야 합니다.
UI의 테스트 데이터는 `ou=ldapium-testdata` 아래에 있으므로 기본 연동 검색 범위에는
포함되지 않습니다. 해당 데이터를 검증하려면 LDAP Provider의 Users DN과 그룹
Mapper의 Groups DN을 각각 그 컨테이너 안의 `ou=people`, `ou=groups`로 변경하고
전체 동기화합니다. 기존 Realm이 있으면 `keycloak-up`은 설정을 덮어쓰지 않습니다.

## 자동 검증

```sh
make keycloak-test
KC_TEST_GROUPS='basic memberof changed-sync' make keycloak-test
KC_TEST_GROUPS=all make keycloak-test
```

기본 `basic` 검증은 별도 임시 LDAP와 Keycloak에서 사용자·그룹 동기화,
LDAP 비밀번호 로그인, 토큰의 그룹 claim을 확인합니다. 현재 디렉터리는
테스트 대상이 아니며, 테스트 컨테이너와 네트워크는 종료 시 정리합니다.
테스트에는 `ldapium:e2e` 이미지가 필요합니다.

```sh
docker build -t ldapium:e2e -f image/Dockerfile ./image
```

어제 수행한 전체 검증의 결과와 제약은
[검증 기록](../changes/keycloak-federation/CHANGE.md)에 있습니다.
그 기록은 당시 실행 결과이며 오늘 실행 결과와 구분합니다.

2026-10-01 최초 검증(26.0.7): `make keycloak-up`으로 로컬 Realm/LDAP Provider 생성 및
`make keycloak-status`에서 실행 상태 확인. `make keycloak-test`는
`DONE: 0 failure(s), 17s`로 종료했고, 사용자 동기화·그룹 멤버십 2건·정상
로그인(200)·오류 비밀번호(401)·토큰 그룹 claim의 6개 검사가 통과했습니다.
현재 로컬 `ou=people`에는 사용자가 없어 관리자 화면의 사용자 목록은 비어
있습니다. 이 자동 검증 결과는 격리한 테스트 LDAP의 Alice/Bob으로 확인한 것입니다.

## LDAP 사용자 로그인 직접 확인

```sh
read -r -p 'LDAP uid: ' KC_TEST_USER
read -r -s -p 'LDAP password: ' KC_TEST_PASSWORD; echo
curl --fail-with-body -sS \
  --data-urlencode client_id=ldapium-local \
  --data-urlencode grant_type=password \
  --data-urlencode scope=openid \
  --data-urlencode "username=$KC_TEST_USER" \
  --data-urlencode "password=$KC_TEST_PASSWORD" \
  http://127.0.0.1:8180/realms/ldapium-local/protocol/openid-connect/token
unset KC_TEST_PASSWORD
```

HTTP 200과 access token은 해당 사용자의 LDAP 인증 성공을 뜻합니다.
이 테스트 Realm/클라이언트는 로컬 검증 전용입니다. ldapium UI의 OIDC SSO는
별도 설정이며 이 명령으로 활성화되지 않습니다.

## 종료

```sh
make keycloak-down
```

Keycloak 컨테이너와 그 안의 Realm 상태는 삭제됩니다. LDAP 사용자·그룹과
서비스 계정은 유지됩니다. 다시 기동하면 Realm을 새로 구성합니다.

## 최신 버전 재검증 (2026-10-01)

공식 다운로드 페이지에서 26.7.4를 확인해 개발 기동 스크립트, 테스트
스크립트, federation CI 이미지 버전을 함께 올렸습니다. 이전 버전의
검증 기록은 당시 증거로 유지합니다.

- `make keycloak-up`: 26.7.4 실행, Realm/LDAP Provider/그룹 Mapper 자동 생성 확인.
- `make keycloak-test`: `DONE: 0 failure(s), 20s`, 기본 연동 검사 7개 통과.
- 최초 재검증 실패: 잘못된 비밀번호의 HTTP 응답이 401에서 400으로 변경됨.
  테스트에 `invalid_grant` 및 access token 미발급 검사를 추가한 뒤 통과.
- `shellcheck`, `git diff --check`: 통과.
- 로컬 actionlint는 기존 workflow의 `concurrency.queue`를 인식하지 못해
  실패했습니다. GitHub Actions 전체 실행과 나머지 테스트 그룹은 이번에
  실행하지 않았습니다.
