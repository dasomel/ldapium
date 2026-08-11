// English strings — the canonical key set. ko.ts is typed against this
// file's keys (see DictKey below), so adding/removing/renaming a key here
// forces a matching update there; TypeScript won't compile otherwise.
//
// What belongs here: UI chrome we wrote (labels, buttons, our own
// messages) and translated *explanations* of LDAP concepts. What does
// NOT belong here: raw error text the directory server sends back
// (ppolicy/slapd diagnostic messages), or LDAP's own tokens — attribute
// names, objectClass values, DNs. Those are shown exactly as the server
// gives them, in every language, on purpose — see the callers of
// ApiError.message and lib/ldapGlossary.ts.
const en = {
  'nav.tree': 'DIT Tree',
  'nav.users': 'Users',
  'nav.groups': 'Groups',

  'common.boundAs': 'Bound as',
  'common.logOut': 'Log out',
  'common.themeToLight': 'Light mode',
  'common.themeToDark': 'Dark mode',
  'common.logoutFailed': 'Logout failed — try again.',

  'changePassword.title': 'Change password',
  'changePassword.currentPasswordLabel': 'Current password',
  'changePassword.newPasswordLabel': 'New password',
  'changePassword.confirmPasswordLabel': 'Confirm new password',
  'changePassword.mismatchInline': 'Passwords do not match.',
  'changePassword.mismatchError': 'New password and confirmation do not match.',
  'changePassword.disclaimer': 'Password requirements are enforced by the directory server, not this page.',
  'changePassword.submitBusy': 'Changing…',
  'changePassword.successToast': 'Password changed. Use your new password next time you sign in.',
  'changePassword.genericError': 'Failed to change password.',
  // The one case where the server's own diagnostic text is deliberately
  // replaced rather than shown as-is: result code 53 with this specific
  // message reads as "the server refused to check" when the actual cause
  // is usually "your current password was wrong" — see
  // ChangePasswordPage's describeSetPasswordError for why.
  'changePassword.ambiguousCurrentPassword':
    "Your current password may be incorrect — double check it and try again. (If current-password verification isn't enabled on this server, this message can also appear even when it was correct; ask an administrator if it persists.)",
  'changePassword.requirementsHeading': 'Password requirements (from the directory server)',
  'changePassword.reqMinLength': 'At least {n} characters',
  'changePassword.reqHistory.one': "Can't reuse your last {n} password",
  'changePassword.reqHistory.many': "Can't reuse your last {n} passwords",
  'changePassword.neverExpires': "Doesn't expire",
  'changePassword.expiresAfter': 'Expires after {duration}',
  'changePassword.currentPasswordRequired': 'Your current password is required to change it',
  'changePassword.currentPasswordNotRequired': 'Your current password is not required to change it',
  'changePassword.qualityNote': "The server may enforce additional quality checks beyond what's listed above.",
  'changePassword.ambiguousPolicy':
    "Multiple password policies are configured on this server, and it's not clear from here which one applies to your account. Ask an administrator if you're unsure of the requirements.",
  'changePassword.unit.day.one': '{n} day',
  'changePassword.unit.day.many': '{n} days',
  'changePassword.unit.hour.one': '{n} hour',
  'changePassword.unit.hour.many': '{n} hours',
  'changePassword.unit.minute.one': '{n} minute',
  'changePassword.unit.minute.many': '{n} minutes',
  'changePassword.unit.second.one': '{n} second',
  'changePassword.unit.second.many': '{n} seconds',
} satisfies Record<string, string>

export type DictKey = keyof typeof en

export default en
