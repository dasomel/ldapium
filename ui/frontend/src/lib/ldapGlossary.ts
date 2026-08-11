import type { Language } from '@/context/LanguageContext'

/**
 * One-line explanations for LDAP concepts that show up as raw attribute
 * names or objectClass values in this UI, in every language this app
 * supports. Keyed by the exact LDAP token, looked up case-insensitively
 * by GlossaryTerm.
 *
 * Only add an entry once it's been verified against this repo and/or the
 * actual running server — an unverified guess is worse than no tooltip at
 * all (a wrong explanation is more damaging than a missing one). Every
 * entry below was confirmed either against this repo's own schema/ACL
 * config or by inspecting the live server; the Korean text is a natural
 * rendering of the same fact, not a literal machine translation of the
 * English.
 *
 * The LDAP token itself (dn, objectClass, cn, ...) is never translated —
 * GlossaryTerm always looks it up by its one true spelling regardless of
 * UI language. Only the explanation changes. See lib/i18n/{en,ko}.ts for
 * this app's own UI text, which follows the same "never translate the
 * server's/LDAP's own vocabulary" rule.
 */
const en: Record<string, string> = {
  dn: "Distinguished Name — an entry's full address in the tree, e.g. uid=alice,ou=people,dc=example,dc=org. Read right to left: the rightmost part is the top of the tree, like a file path in reverse.",
  objectclass:
    'The entry\'s "type". It determines which attributes the entry can or must have, and an entry can carry more than one objectClass at once.',
  organizationalunit: 'A folder in the tree — a container for organizing entries. It has nothing to do with permissions.',
  inetorgperson: 'The standard type for a person entry. Carries attributes like uid, cn, sn, and mail.',
  organizationalrole:
    "A role entry. It has no uid attribute — this is why an account like this must log in with its full DN instead of a short username.",
  groupofnames: 'A group entry. Its member attribute lists the DNs of its members; the schema requires at least one.',
  member: 'Set on a group entry; lists the DNs of the entries that belong to it.',
  memberof: "The reverse of member, computed automatically on a person's entry by the server. It can't be edited directly.",
  cn: "Common name — the entry's display name.",
  sn: 'Surname — last name.',
  givenname: 'Given name — first name.',
  uid: 'Login ID (username).',
  dc: "Domain component — a piece of the tree's top, modeled after a domain name. dc=example,dc=org corresponds to example.org.",
  pwdpolicy: 'A password policy entry — configuration, not a user or group.',
}

const ko: Record<string, string> = {
  dn: '엔트리의 전체 주소입니다. 예: uid=alice,ou=people,dc=example,dc=org. 오른쪽이 상위이며, 파일 경로와 비슷하지만 순서가 반대입니다.',
  objectclass: '엔트리의 "종류"입니다. 이 값이 엔트리가 가질 수 있는/가져야 하는 속성을 결정하며, 여러 개를 겹쳐 쓸 수 있습니다.',
  organizationalunit: '트리의 폴더입니다. 엔트리를 담는 컨테이너일 뿐 권한과는 무관합니다.',
  inetorgperson: '사람 엔트리의 표준 종류입니다. uid, cn, sn, mail 등의 속성을 가집니다.',
  organizationalrole: '역할 엔트리입니다. uid 속성이 없어서, 이런 계정은 짧은 이름 대신 전체 DN으로 로그인해야 합니다.',
  groupofnames: '그룹 엔트리입니다. member 속성에 소속 엔트리의 DN을 나열하며, 스키마상 최소 한 명이 있어야 합니다.',
  member: '그룹 엔트리에 설정되며, 소속된 엔트리들의 DN을 나열합니다.',
  memberof: 'member의 반대 방향으로, 사람 쪽 엔트리에 서버가 자동으로 계산해 주는 값입니다. 직접 편집할 수 없습니다.',
  cn: 'Common name — 엔트리의 표시 이름입니다.',
  sn: 'Surname — 성(姓)입니다.',
  givenname: 'Given name — 이름입니다.',
  uid: '로그인 아이디입니다.',
  dc: 'Domain component — 트리 최상단을 도메인처럼 쪼갠 것입니다. dc=example,dc=org는 example.org에 해당합니다.',
  pwdpolicy: '비밀번호 정책 엔트리입니다. 사용자나 그룹이 아니라 설정입니다.',
}

export const LDAP_GLOSSARY: Record<Language, Record<string, string>> = { en, ko }
