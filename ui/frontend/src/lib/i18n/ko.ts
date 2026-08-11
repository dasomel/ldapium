import type { DictKey } from './en'

// Korean strings. Typed as Record<DictKey, string> against en.ts, so a
// missing or misspelled key fails the build instead of silently falling
// back to English at runtime. See en.ts for what does and doesn't belong
// in this file — the short version: our own UI text, not server error
// text or raw LDAP tokens.
const ko: Record<DictKey, string> = {
  'nav.tree': 'DIT 트리',
  'nav.users': '사용자',
  'nav.groups': '그룹',

  'common.boundAs': '바인딩 계정',
  'common.logOut': '로그아웃',
  'common.themeToLight': '라이트 모드',
  'common.themeToDark': '다크 모드',
  'common.logoutFailed': '로그아웃에 실패했습니다 — 다시 시도해 주세요.',

  'changePassword.title': '비밀번호 변경',
  'changePassword.currentPasswordLabel': '현재 비밀번호',
  'changePassword.newPasswordLabel': '새 비밀번호',
  'changePassword.confirmPasswordLabel': '새 비밀번호 확인',
  'changePassword.mismatchInline': '비밀번호가 일치하지 않습니다.',
  'changePassword.mismatchError': '새 비밀번호와 확인이 일치하지 않습니다.',
  'changePassword.disclaimer': '비밀번호 요구사항은 이 화면이 아니라 디렉터리 서버가 결정합니다.',
  'changePassword.submitBusy': '변경 중…',
  'changePassword.successToast': '비밀번호가 변경되었습니다. 다음 로그인부터 새 비밀번호를 사용하세요.',
  'changePassword.genericError': '비밀번호 변경에 실패했습니다.',
  'changePassword.ambiguousCurrentPassword':
    '현재 비밀번호가 올바르지 않을 수 있습니다 — 다시 한번 확인 후 시도해 주세요. (이 서버에서 현재 비밀번호 확인 기능이 꺼져 있는 경우에도 같은 메시지가 나타날 수 있습니다. 계속되면 관리자에게 문의하세요.)',
  'changePassword.requirementsHeading': '비밀번호 요구사항 (디렉터리 서버 기준)',
  'changePassword.reqMinLength': '최소 {n}자 이상',
  // Korean doesn't inflect for plural, so the "one"/"many" variants are
  // identical on purpose — the split still exists so this file's key set
  // matches en.ts exactly.
  'changePassword.reqHistory.one': '최근 사용한 비밀번호 {n}개는 재사용할 수 없음',
  'changePassword.reqHistory.many': '최근 사용한 비밀번호 {n}개는 재사용할 수 없음',
  'changePassword.neverExpires': '만료 없음',
  'changePassword.expiresAfter': '{duration} 후 만료',
  'changePassword.currentPasswordRequired': '변경 시 현재 비밀번호 입력 필요',
  'changePassword.currentPasswordNotRequired': '변경 시 현재 비밀번호 입력 불필요',
  'changePassword.qualityNote': '이 외에도 서버가 추가로 품질을 검사할 수 있습니다.',
  'changePassword.ambiguousPolicy':
    '이 서버에는 비밀번호 정책이 여러 개 설정되어 있어, 내 계정에 어떤 정책이 적용되는지 이 화면만으로는 알 수 없습니다. 정확한 요구사항은 관리자에게 문의하세요.',
  'changePassword.unit.day.one': '{n}일',
  'changePassword.unit.day.many': '{n}일',
  'changePassword.unit.hour.one': '{n}시간',
  'changePassword.unit.hour.many': '{n}시간',
  'changePassword.unit.minute.one': '{n}분',
  'changePassword.unit.minute.many': '{n}분',
  'changePassword.unit.second.one': '{n}초',
  'changePassword.unit.second.many': '{n}초',
}

export default ko
