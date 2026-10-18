# Change: 다중 프로바이더 동일 엔트리 동시 쓰기 발산 완화 설계

- Change class: `D` — 복제 시맨틱·데이터 정합성·가용성 토폴로지 (AGENTS.md)
- Owner: dasomel
- Related issue: [#434](https://github.com/dasomel/ldapium/issues/434) (근본 원인 [#432](https://github.com/dasomel/ldapium/issues/432), 실측 기록 [#435](https://github.com/dasomel/ldapium/pull/435))
- Status: `Accepted (2026-10-17: D434-1, D434-2, D434-3 accepted by the maintainer; D434-4 stands as proposed deferral). 2026-10-18: D434-2 merged (#437); D434-3 patch proven on a branch (see "D434-3 실증 결과") and shipped by the maintainer's decision (#440)`
- Accepted by / date: dasomel, 2026-10-17 (D434-1~3), 2026-10-18 (D434-3 출하)

## Problem

N-way 다중 프로바이더 Active-Active(`olcMultiProvider: TRUE`) 환경에서 두 프로바이더에 수 밀리초 내로 동일 엔트리 수정이 동시에 도달할 경우, OpenLDAP 2.6.15 `syncrepl` 결함으로 인해 이전(earlier) CSN을 가진 노드에 잘못된 데이터가 남아 영구 발산하는 문제가 발생한다(#432).

- **관찰 증상**: 일반 속성 `replace` 경합 시 해당 속성이 완전히 삭제된다. RFC 3062 Password Modify 경합 시에는 자체 `userPassword`는 남으나 `entryCSN`, `modifiersName`, `modifyTimestamp` 등 운영 속성(opattrs)이 엔트리에서 영구 유실된다.
- **탐지 불가**: 양 노드의 접미사 `contextCSN`은 양쪽 쓰기를 모두 반영하여 동일하므로 `LDAPiumContextCSNDivergence` 경보가 발화하지 않는다. 다음 쓰기가 올 때까지 발산이 유지되며 재기동이나 대기(600초 이상)로도 복구되지 않는다.
- **실측치**: 로컬 Colima 환경 실측 결과 일반 속성 replace 약 0.9% (10/~1,170), Password Modify 약 0.3-0.4%에서 발산이 재현되었다(출처: docs/changes/machine-write-scope-v2/EVIDENCE.md §2r 및 PR #435).
- **원인 메커니즘** (2026-10-18 코드 확인 및 D434-3 패치로 실증): `servers/slapd/syncrepl.c:4708`의 ITS#10358 어서션 재시도(`goto retry_diff`)는 수신 `modlist`를 복원하지 않는다. 1차 `syncrepl_diff_entry()`에서 `attr_cmp`는 수신 modlist를 수신 엔트리 속성과 lock-step으로 걷으며 바뀐 속성의 mod만 떼어 `dni.mods`로 옮기고(이후 `be_modify`/`be_modrdn` 뒤 해제), 바뀌지 않은 속성의 mod는 남긴 채 꼬리를 자른다(`*ml = NULL`, line 5726). 수신 엔트리 속성에는 `SLAP_ATTR_IXADD`도 남는다. 2차 diff는 이 일부만 남은 목록으로 돌기 때문에 mod와 속성 짝이 어긋나 DELETE를 만들고 opattr mod를 잃는다. 이것으로 두 관찰 증상이 모두 설명되며, 재시도 전에 modlist를 다시 만드는 패치가 발산을 없앴다. slapd 로그에는 `be_modify <dn> (122)` 직후 `(0)`이 기록된다. master 브랜치도 `retry_diff` 리셋 로직은 동일하다(master는 실측하지 않음).
- **업스트림 현황**: bugs.openldap.org에서 관련 리포트인 ITS#10358(2.6.11 재시도 도입), ITS#10541(2.6.14)은 확인되었으나, 본 결함과 일치하는 보고는 없었다. 초안(`.omc/logs/agy-432-its-draft.md`)이 작성되어 있으나 외부 게시 승인 전이다.
- **노출 위험**: 단일 노드에 고정된 `W_cred`는 안전하나, UI(`LDAP_URL`이 로드밸런싱 Service를 향함) 및 머신 `W_data`/`W_lock`, 외부 LDAP 클라이언트는 두 노드에 동시 도달할 수 있어 위험에 노출된다.

## Intent

N-way 복제 토폴로지(D11)의 가용성을 유지하면서 동일 엔트리 동시 쓰기 시 발생하는 데이터 유실 결함을 완화하고, 업스트림 보고, 2단계 탐지 및 복구 런북을 수립하며, 소스 캐리 패치의 안전성을 실증 검증하여 영구 수정안을 도출한다.

## Scope

- In scope: 4개 대안 비교 및 권고안(D434-1~D434-4), 업스트림 ITS 보고 승인 절차, 2단계 탐지기(로그 감지 + 지연 교차 검증) 및 PrometheusRule 경보, 수동 복구 런북 수립, 브랜치 기반 캐리 패치 하네스 실증 검증 계획.
- Affected users/systems: `image/Dockerfile`, `image/entrypoint.sh`, `charts/ldapium/templates/prometheusrule.yaml`, `charts/ldapium/templates/replication-check-*`, `scripts/lib/replication_identity_check.py`, `docs/ha-profile.md`, `AGENTS.md`.

## Non-goals

- 단일 쓰기 프로바이더 전환 (D11 Active-Active 지원 정책 및 분산 펜싱 부재로 제외).
- 복제 인프라 전체의 delta-syncrepl 전면 마이그레이션 (Full-sync 폴백 시 결함 잔존 및 cn=config 마이그레이션 부담으로 제외).
- 검증되지 않은 캐리 패치의 메인 즉시 반영 (브랜치 실증 선행).

## Requirements

- `REQ-001` — 작성된 ITS 초안을 유지보수자 명시 승인 후 bugs.openldap.org에 공식 등록한다.
- `REQ-002` — 복제 로그의 어서션 재시도 패턴을 1단계로 감지하고, 유예 후 해당 DN의 교차 검증을 거쳐 실제 발산 시에만 경보를 발화하는 2단계 탐지기를 제공한다.
- `REQ-003` — 발산 발생 시 최신 CSN과 정상 opattrs를 보존한 노드에서 재기록하여 수렴시키는 운영 복구 런북을 제공한다.
- `REQ-004` — OpenLDAP 2.6.15 `syncrepl.c` 패치 이미지를 브랜치에서 빌드하고, 신규 구축 예정인 2,000회 경합 검증 하네스(저장소 외부에 아카이브된 #432 진단 하네스를 참고하여 인리포 스크립트 `scripts/test/test-machine-write-cred-multiprovider-live.py` 기반으로 구축 예정)를 통해 2,000회 이상 무발산 및 기존 E2E 무회귀를 입증한다.

## Acceptance scenarios

### `AC-001` — 2단계 복제 발산 감지 및 Prometheus 경보
- Covers: `REQ-002`
- Given: 복제 활성화 시 `image/entrypoint.sh:812-816`에 의해 slapd 로그 레벨에 `,sync`가 기본 추가되어 있다.
- When: 동일 엔트리 경합으로 `syncrepl_entry ... be_modify <dn> (122)` 후 `(0)`이 발생하고, 2~5초 지연 후 프로바이더 간 해당 DN 조회 시 속성 누락 또는 opattrs 결손이 확인된다.
- Then: 메트릭 `ldapium_syncrepl_retry_divergence_total`(제안)이 증가하고 `LDAPiumReplicationDivergence`(제안) 경보가 발생하며, `(122)` 재시도 뒤 정상 수렴한 충돌은 교차 조회 단계에서 거짓 양성으로 걸러진다.

### `AC-002` — 캐리 패치 무발산 실증 및 안전성 검증
- Covers: `REQ-004`
- Given: OpenLDAP 2.6.15 소스에 `syncrepl.c` 재시도 보정 패치를 적용하여 파생 이미지(`2.6.15-ldapium1`)를 빌드한다.
- When: 신규 구축 예정인 경합 검증 하네스(저장소 외부에 아카이브된 #432 진단 하네스를 참고하여 인리포 스크립트 `scripts/test/test-machine-write-cred-multiprovider-live.py` 기반으로 구축 예정)로 plain replace 및 Password Modify를 각 2,000회 이상 병행 인가한다.
- Then: `(122)` 후 `(0)`이 발생해도 엔트리 발산율 0건이 유지되어야 하며, `replication-chaos-e2e` 및 `upgrade-e2e`가 통과해야 한다.

## Architecture and decisions

- Relevant ADR/design links: [docs/ha-profile.md](../../ha-profile.md) D11, [docs/changes/replication-identity/](../replication-identity/), [docs/changes/machine-write-scope-v2/EVIDENCE.md](../machine-write-scope-v2/EVIDENCE.md) §2r
- ADR threshold result: `required` — 복제 시맨틱, 데이터 정합성 보장 메커니즘 및 소스 캐리 패치(D434-3) 도입 검토는 가용성 토폴로지(D11)와 직결되는 Class D 설계 변경에 해당함.
- Alternatives and important trade-offs: 아래 '대안 비교 (Options Comparison)' 참조.

### 대안 비교 (Options Comparison)

| 대안 | 결함 해결 여부 | 잔여 위험 노출 | 기존 결정 충돌 | 규모 | 리스크 | 필요 검증 |
|---|---|---|---|---|---|---|
| 1. 단일 쓰기 프로바이더 | 설계상 회피 (두 provider 동시 쓰기 자체를 없앰; 승격·재연결 구간은 별도 검증 필요) | 쓰기 노드 크래시 시 쓰기 가용성 전면 중단(SPOF), 펜싱 없는 승격 시 스플릿 브레인 | D11(N-way Active-Active 유일 지원) 정면 배치, RTO SLA 위반 | 대형 | 높음 | 무중단 장애 조치, 스플릿 브레인 방지 |
| 2. delta-syncrepl | 일반 쓰기 해결(미검증: delta 수정이 syncrepl_op_modify()를 경유한다는 ITS#10358 메인테이너 발언에 기반한 미검증 가설) | purge 초과·노드 초기화 시 Full-sync 폴백으로 #432 재노출 | 없음 (신규 구성) | 대형 | 높음 | 기존 볼륨 cn=config 마이그레이션, 디스크 I/O |
| 3. 캐리 패치 (Carry Patch) | 해결 (2026-10-18 브랜치 실증, "D434-3 실증 결과" 참조) | 업스트림 버전 업 시 리베이스 비용, C 코드 잠재적 코너케이스 | 없음 (패치 관리 허용) | 소형 | 중간 | 신규 하네스 구축 후 2,000회 무발산 실증, 카오스 E2E |
| 4. 탐지기 + 수용 (Accept+Detector) | 미해결 (사후 감지 및 수동 복구) | 발산 발생 시 복구 전까지 불일치 지속 (~0.9%) | 없음 (현행 정책 유지) | 소형 | 낮음 | 2단계 탐지 신뢰성, 거짓 양성 배제 |

- **대안 1 (단일 쓰기)**: `docs/ha-profile.md` D11과 정면 충돌한다. OpenLDAP 자체에는 분산 펜싱 메커니즘이 없어 펜싱 없는 자동 승격에는 스플릿 브레인으로 인한 데이터 손상 위험이 있다(D11 근거 참조). 또한 UI 백엔드는 인증 직후 비밀번호를 폐기하므로(`session/store.go:14-25`) 요청마다 쓰기 대상을 바꾸는 분기는 어렵다(추론).
- **대안 2 (delta-syncrepl)**: delta-syncrepl이 일반 쓰기 결함을 해결한다는 것은 delta 수정이 `syncrepl_op_modify()`를 경유한다는 ITS#10358 메인테이너 발언에만 기반한 **미검증** 가정이다. 또한 `cn=accesslog` 기반 델타 복제를 구성하더라도 changelog purge 기간 초과나 신규 노드 추가로 인한 전체 동기화(`refreshAndPersist`) 폴백 시 #432 취약 경로에 다시 노출된다(Full-refresh 폴백 한계). 또한 기존 볼륨(`$MARKER` 존재 시)의 `cn=config` 오프라인 마이그레이션과 디스크 부하가 크다.
- **대안 3 (캐리 패치)**: `syncrepl.c`의 `retry_diff:` 구간에서 `slap_entry2mods`로 `*modlist`를 재생성하여 결함을 해결한다. 제안 당시에는 미실증 가설이었으나 2026-10-18 브랜치 실증으로 확인됐다("D434-3 실증 결과" 참조). 아키텍처나 기존 결정을 훼손하지 않으며, 남은 비용은 업스트림 버전 업 때의 리베이스다.
- **대안 4 (탐지기 + 수용)**: 결함을 직접 막지는 못하나, 발생률(~0.9%)이 낮고 재기록으로 복구 가능한 점을 고려하여 프로덕션 위험을 관측 가능성 테두리 안에서 통제한다.

### 결정 (Decisions — D434-1~3 수용 2026-10-17)

- `D434-1`: 업스트림 ITS 버그 리포트 공식 등록
  - Reason: 근본 해결책은 OpenLDAP 공식 픽스이며 초안(`.omc/logs/agy-432-its-draft.md`)이 준비되어 있다.
  - Cost: 외부 공개 전 유지보수자의 명시적 승인 필요, 계정 제출 및 후속 응답 관리.
  - Escape hatch: 유지보수자 미승인 시 내부 로그로 보존하고 공식 제출을 보류한다.
- `D434-2`: 2단계 탐지기(Log Trigger + Cross-provider Verify) 및 복구 런북 도입
  - Reason: 캐리 패치 실증 전까지 프로덕션 안전망이 필요하다. `image/entrypoint.sh:812-816`으로 `,sync` 로그가 이미 남으므로 `(122)` 후 `(0)`을 트리거로 삼되, 2~5초 유예 후 해당 DN을 교차 조회하여, `(122)` 재시도 뒤 정상 수렴한 경우(#432 실측에서 다수 관찰, 비율은 미측정)의 거짓 양성을 제거한다.
  - Cost: 로그 파서 사이드카(Vector/Fluentbit) 또는 스크립트 확장, `image/ldifs/01-cn-config.ldif:78`에 `entryCSN eq`만 있어 부등호 윈도우 검색 부하 주의 필요.
  - Escape hatch: 실시간 로그 파싱 구현 부담 시 `replication.check` CronJob에서 의심 엔트리 주기적 샘플 검사로 대체.
- `D434-3`: 브랜치 기반 캐리 패치 실증 검증 선행
  - Reason: C 소스 패치는 검증 대상 가설(미실증, D434-3에서 증명)이므로 격리 브랜치에서 빌드 및 실측 검증(신규 구축 예정인 경합 하네스로 2,000회 이상 무발산 실증, chaos E2E 통과)을 완수한 후 메인 도입을 결정한다. 출하 시 수정판임을 표기한다(2026-10-18 정정: OpenLDAP PL 2.8은 바이너리 재배포 시 저작권 고지·조건·면책 문구(제2조)와 라이선스 사본(제3조)만 요구하며 수정판 재표기 의무는 없다. 그래도 NOTICE, `docs/legal*.md`, THIRD-PARTY-LICENSES, 이미지 label `io.ldapium.openldap.patches`, 이미지 내 `/usr/share/doc/openldap/patches/`로 자발적으로 표기한다).
  - Cost: 브랜치 빌드 파이프라인 및 장시간 하네스 실행 공수, 업스트림 버전 범프 시 리베이스 유지보수.
  - Escape hatch: 하네스 실측 중 예상치 못한 코너케이스나 사이드이펙트 발견 시 즉시 기각하고 D434-2 체제로 안착.
- `D434-4`: 단일 쓰기 프로바이더 및 delta-syncrepl 전환 보류
  - Reason: 단일 쓰기는 D11 정면 위배 및 가용성 후퇴이며, delta-syncrepl은 full-sync 폴백 한계와 마이그레이션 위험이 과도하다. D434-3 실증 성공 시 불필요하다.
  - Cost: 패치 도입 전까지 Active-Active 환경의 동시 쓰기 잠재 결함 존속.
  - Escape hatch: D434-3 실증이 실패하고 업스트림 해결이 장기화될 경우 재검토.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | N/A — 외부 API 및 CLI 명령 변경 없음 |
| Dependencies / lockfiles | N/A — Go/Python 의존성 락파일 변경 없음 |
| Runtime / toolchain | `image/Dockerfile`이 OpenLDAP 2.6.15 소스에 `image/patches/openldap-2.6.15-its-retry-diff.patch`를 `--fuzz=0`으로 적용해 컴파일한다(#440) |
| CI / CD | `.github/workflows/machine-write-e2e.yml` 측정 항목 유지, 캐리 패치 검증 워크플로 추가 |
| Release / packaging | `appVersion`은 `2.6.15` 유지(`check-versions.sh`가 Dockerfile tarball 버전과 일치를 요구하고 UI가 `OPENLDAP_VERSION`으로 표시). 패치 식별은 이미지 label `io.ldapium.openldap.patches`와 이미지 내 패치 사본으로 한다 |
| Generated output | N/A — 자동 생성 산출물 없음 |
| Security / supply chain | C 소스 패치 무결성 검증, Syft SBOM에 패치 버전 라벨 명시 |
| Offline / air-gap | N/A — 외부 네트워크 연결 불필요 (패치 파일은 저장소 내 번들링) |
| Documentation / operations | `docs/ha-profile.md` 장애 복구 런북(정상 노드 기준 재기록) 및 `AGENTS.md` 갱신 |
| Portfolio / downstream repositories | N/A — 다운스트림 저장소 영향 없음 |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 인위적 충돌 주입 후 2단계 탐지기 실행 및 메트릭/경보 확인 | 로컬 Docker 2노드 클러스터 | 발산 발생 시 메트릭 증가, `(122)` 재시도 후 정상 수렴한 경우 경보 0건 |
| `AC-002` | 패치 이미지 빌드 후 신규 구축 예정인 2,000회 경합 검증 하네스(저장소 외부에 아카이브된 #432 진단 하네스 'diag432'를 참고하여 인리포 스크립트 `scripts/test/test-machine-write-cred-multiprovider-live.py` 기반으로 구축 예정) 수행 | Colima (`ldapium` 프로파일) | plain replace 및 Password Modify 모두 발산율 0건, 카오스 E2E 통과 |

### D434-3 실증 결과 (2026-10-18)

패치: `syncrepl_entry()`의 `retry_diff:` 맨 앞에서, 2차 이후 패스에만(`diff_done`) 수신 엔트리 속성의 `SLAP_ATTR_IXADD`를 지우고 남은 `*modlist`를 해제한 뒤 `slap_entry2mods(entry, …)`로 다시 만든다. 1차 패스는 바뀌지 않는다. 남은 `*modlist`는 이미 해제된 mod와 연결이 끊겨 있어 double free가 없고, 다시 만든 목록은 호출자 `do_syncrep2`가 기존대로 해제한다(코드 확인).

| 시험 | 이미지 | round | 발산 | `be_modify (122)` |
|---|---|---|---|---|
| plain replace 경합 | 순정 2.6.15 | 8,400 | 9 | – |
| plain replace 경합 | 패치 | 12,600 | **0** | 1,161 |
| Password Modify 경합 (M5) | 순정 2.6.15 | 3,000 | 46 | 523 |
| Password Modify 경합 (M5) | 패치 | 3,000 | **0** | 512 |
| plain replace 경합 | 패치 + `-fsanitize=address` | 500 | 0 | 57 |
| Password Modify 경합 (M5) | 패치 + `-fsanitize=address` | 300 | 0 | 96 |
| modrdn 대 modify 경합 | 순정 / 패치 + ASAN | 300 / 300 | 0 / 0 | `be_modrdn (122)` 0 |

- 환경: Colima `ldapium` 프로파일, 두 provider, 공유 게이트에서 동시에 방출. Password Modify 경합은 순정 이미지의 양쪽 성공 round 1,194회 중 46회(약 3.9 %)가 발산했고, 같은 비율이라면 패치 이미지(양쪽 성공 1,132회)에서 약 44건이 나와야 한다.
- ASAN: 실행 중인 slapd에서 수집한 AddressSanitizer 오류 0건. LeakSanitizer 보고는 부트스트랩의 `slappasswd`·`slapadd` 1회성 할당뿐이다.
- 확인하지 못한 것: slapd 자체의 누수(하네스가 정상 종료 대신 강제 삭제), modrdn 재시도 경로(300 round에서 한 번도 도달하지 않음). modrdn 경로에는 업스트림 기존 결함(재시도 시 `orr_modlist`·RDN 누수, `dni.renamed` 미초기화)이 있으며 패치가 다루지 않는다.
- 전체 CI(`replication-chaos-e2e`, `upgrade-e2e` 포함)를 패치 이미지로 돌린 결과: draft PR [#438](https://github.com/dasomel/ldapium/pull/438)에서 40개 check 통과(3개 skip). `replication-chaos`와 `rolling upgrade + rollback`(replicated, standalone)도 통과했다. 첫 실행에서 `machine write measurements`의 E-22 timeout 측정이 한 번 실패했다(409 `idempotency_outcome_unknown`). E-22는 provider 하나로만 돌아 syncrepl 경로를 지나지 않고, 재실행에서 통과했다. 같은 job의 두 provider M5는 5 round 모두 수렴했다.
- 하네스(`exp434-race.py`, `exp434-modrdn-race.py`, M5 전용 `MP_ONLY_M5` 플래그, `Dockerfile.asan`)는 병합하지 않은 실험 브랜치에 있다. 패치를 출하할 때 회귀 시험으로 들일지 정한다.

## Rollout, rollback and recovery

- **Rollout sequence**:
  1. D434-1: 유지보수자 승인 후 업스트림 ITS 공식 제출.
  2. D434-2: 2단계 탐지 메트릭 및 PrometheusRule 경보를 차트에 배포.
  3. D434-3: 브랜치에서 신규 구축 하네스를 통한 캐리 패치 실증 테스트(2,000회 이상 무발산) 통과 후 유지보수자 결정으로 출하(#440). 다음 릴리스에 포함.
- **Rollback trigger and procedure**:
  - 패치 이미지 적용 후 예기치 않은 slapd 비정상 종료나 복제 스톨 발생 시 즉시 순정 2.6.15 이미지로 롤백하고 D434-2(사후 탐지 및 수동 복구) 체제로 전환한다.
- **Data/configuration recovery**:
  - 발산 탐지 시 복구 런북: 양 프로바이더에서 `ldapsearch -b <dn> -s base '*' '+'`를 수행하여 최신 `entryCSN`과 온전한 opattrs를 유지한 정상 프로바이더를 판별한다. 정상 프로바이더에서 해당 엔트리의 속성을 재기록(`ldapmodify`)하여 새로운 최신 CSN을 부여하면, syncrepl 전파를 통해 발산 노드의 엔트리가 즉시 정상 수렴된다.
- **Compatibility or migration obligations**:
  - 기존 볼륨과의 100% 바이너리 호환성 유지, DIT 스키마 변경 없음.

## Evidence and durable synchronization

- **Evidence location/format**:
  - `#432` 원인 분석 및 재현 로그 (`.omc/logs/agy-432-its-draft.md`, `.omc/logs/agy-434-*.md`).
  - `#435` PR 및 `docs/changes/machine-write-scope-v2/EVIDENCE.md` §2r 측정 결과: plain replace 약 0.9% (10/~1,170), Password Modify 약 0.3-0.4% 발산 실측 기록.
  - `docs/changes/machine-write-scope-v2/EVIDENCE.md` §2r 및 §3.
- **Tests or checks that become durable regression controls**:
  - `test-machine-write-cred-multiprovider-live.py`의 unpartitioned M5 측정 로직.
  - D434-3 캐리 패치 검증 시 도입될 장기 복제 경합 E2E 스크립트(저장소 외부에 아카이브된 #432 진단 하네스 대신 인리포 스크립트 `scripts/test/test-machine-write-cred-multiprovider-live.py`를 기반으로 신규 구축 예정).
- **Documentation to update**:
  - `docs/ha-profile.md`: 다중 프로바이더 동시 쓰기 결함 및 수동 복구 런북(행 추가 완료, D434-2 탐지 반영).
  - `AGENTS.md`: "Non-obvious OpenLDAP behavior" 섹션에 #432 원인 및 완화 방향 기록 유지.
- **ADR/evidence/portfolio records to update**:
  - D434 수용 및 D434-3 실증 결과에 따른 ADR 작성 검토, `docs/IMPLEMENTATION-STATUS.md` 갱신, `docs/changes/machine-write-scope-v2/EVIDENCE.md` §2r 및 #434/#435 기록 동기화.

## Review record

- **Accepted scope/requirements**: 2026-10-17 유지보수자가 D434-1(업스트림 ITS 게시), D434-2(2단계 탐지기 구현), D434-3(브랜치에서 패치 실증, 출하는 별도 결정)을 수용했다. D434-4(단일 쓰기·delta-syncrepl 보류)는 제안 그대로 유지한다. D434-2 구현은 Kubernetes에서 다른 컨테이너 stdout을 읽기 어려우므로 상태 기반(교차 provider 비교)을 1차로, 로그 트리거를 보조로 한다.
- **Material changes after acceptance and re-review**: N/A
- **Open questions or blockers**:
  1. **[PARTIAL 검증] `W_cred` 라우팅 일치 여부**: `docs/machine-write-account.md:329`에는 `W_cred`가 비밀번호 쓰기를 고정한 1개 노드에만 설치된다고 명시되어 있으나, UI 백엔드 설정상 머신 cred 쓰기를 특정 노드로 고정하는 구성이 발견되지 않았다(UI `LDAP_URL`은 로드밸런싱 Service를 향함). 비고정 노드로 라우팅될 때 fail-closed(50) 거부되는 현상이 의도된 것인지, 아니면 라우팅 고정 로직의 누락인지 검증이 필요하다.
  2. **[해결 2026-10-18] 캐리 패치 디프 스케치 및 `dni.mods==NULL` 주장**: `dni.mods==NULL` 주장은 틀렸다(2차 패스는 일부만 남은 modlist로 DELETE를 만들어 두 번째 `be_modify (0)`이 된다). `slap_entry2mods` 재생성 패치는 "D434-3 실증 결과"에서 실증됐다.
  4. **[해결 2026-10-18] 패치 출하**: 유지보수자가 main 반영과 다음 릴리스 포함을 결정했다(#440). CI의 비분할 M5는 다시 `diverged == 0` 검사가 되었고, 경합 하네스는 수동 실행용 `scripts/test/test-replication-write-race-live.py`로 들어갔다(CI 미편입, 실행 시간).
  3. **[외부 게시 승인] 업스트림 ITS 리포트 등록**: `.omc/logs/agy-432-its-draft.md`의 bugs.openldap.org 등록은 외부 게시이므로 유지보수자의 명시적 승인이 선행되어야 한다 (D434-1).
