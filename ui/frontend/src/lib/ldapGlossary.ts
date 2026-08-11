/**
 * One-line explanations for LDAP concepts that show up as raw attribute
 * names or objectClass values in this UI. Keyed by the exact LDAP token,
 * looked up case-insensitively by GlossaryTerm.
 *
 * Only add an entry here once it's been verified against this repo and/or
 * the actual running server — an unverified guess is worse than no
 * tooltip at all (a wrong explanation is more damaging than a missing
 * one). Every entry below was confirmed either against this repo's own
 * schema/ACL config or by inspecting the live server.
 */
export const LDAP_GLOSSARY: Record<string, string> = {
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
