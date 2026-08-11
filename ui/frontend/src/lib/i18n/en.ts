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
  'common.cancel': 'Cancel',
  'common.close': 'Close',
  'common.edit': 'Edit',
  'common.delete': 'Delete',
  'common.saving': 'Saving…',
  'common.working': 'Working…',
  'common.saveChanges': 'Save changes',
  'common.somethingWrong': 'Something went wrong',
  'common.retry': 'Retry',
  'common.noMatches': 'No matches',
  'common.noMatchesDescription': 'Nothing matches "{query}".',
  'common.description': 'Description',
  'common.members': 'Members',
  'common.actions': 'Actions',
  'common.thisEntry': 'this entry',
  'common.dismiss': 'Dismiss',
  'common.add': 'Add',
  'common.done': 'Done',
  'common.newPasswordLabel': 'New password',

  'changePassword.title': 'Change password',
  'changePassword.currentPasswordLabel': 'Current password',
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

  'login.subtitle': 'Sign in with your directory credentials',
  'login.identityLabelJoiner': ' or ',
  'login.passwordLabel': 'Password',
  'login.connectionError': 'Could not reach the server.',
  'login.bindingBusy': 'Binding…',
  'login.signInButton': 'Sign in',
  'login.footerNote': 'Authenticated by an LDAP bind. Your permissions are whatever your directory account allows.',

  'tree.browserTitle': 'DIT Browser',
  'tree.loadingBase': 'Loading base DN…',
  'tree.noEntriesTitle': 'No entries under the base DN',
  'tree.entryAttributesTitle': 'Entry attributes',
  'tree.selectEntryTitle': 'Select an entry',
  'tree.nothingSelectedTitle': 'Nothing selected',
  'tree.nothingSelectedDescription': 'Pick an entry from the tree on the left to inspect its attributes.',
  'tree.loadingEntry': 'Loading entry…',
  'tree.loadBaseFailed': 'Failed to load the base DN',
  'tree.loadEntryFailed': 'Failed to load entry',
  'tree.loadingChildren': 'Loading…',
  'tree.noEntriesShort': 'No entries',
  'tree.loadChildrenFailed': 'Failed to load children',

  'users.filterPlaceholder': 'Filter users…',
  'users.newUserButton': 'New user',
  'users.title': 'Users',
  'users.truncatedBanner':
    'Showing the first {n} users — the directory has more than fit in one response. Filter below to find a specific user.',
  'users.loading': 'Loading users…',
  'users.emptyTitle': 'No users yet',
  'users.emptyDescription': 'Create the first directory user to get started.',
  'users.colName': 'Name',
  'users.colMail': 'Mail',
  'users.colStatus': 'Status',
  'users.lockedBadge': 'Locked',
  'users.lockedSince': 'Locked since {date}',
  'users.unlockTitle': 'Unlock account',
  'users.updatedToast': 'Updated {name}',
  'users.createdToast': 'Created user {uid}',
  'users.passwordUpdatedToast': 'Password updated',
  'users.deletedToast': 'Deleted {uid}',
  'users.unlockedToast': 'Unlocked {uid}',
  'users.unlockFailedToast': 'Failed to unlock {uid}',
  'users.loadFailed': 'Failed to load users',
  'users.deleteTitle': 'Delete user',
  'users.deleteDescription': 'This permanently removes {dn} from the directory.',

  'groups.filterPlaceholder': 'Filter groups…',
  'groups.newGroupButton': 'New group',
  'groups.truncatedBanner':
    'Showing the first {n} groups — the directory has more than fit in one response. Filter below to find a specific group.',
  'groups.loading': 'Loading groups…',
  'groups.emptyTitle': 'No groups yet',
  'groups.emptyDescription': 'Create the first group to start organizing access.',
  'groups.manageMembersTitle': 'Manage members',
  'groups.updatedToast': 'Updated {cn}',
  'groups.createdToast': 'Created group {cn}',
  'groups.deletedToast': 'Deleted {cn}',
  'groups.loadFailed': 'Failed to load groups',
  'groups.deleteTitle': 'Delete group',
  'groups.deleteDescription': 'This permanently removes {dn} from the directory.',

  'userForm.editTitle': 'Edit user',
  'userForm.newTitle': 'New user',
  'userForm.givenNameLabel': 'Given name',
  'userForm.initialPasswordLabel': 'Initial password (optional)',
  'userForm.initialPasswordHint':
    'Set via the LDAP Password Modify operation (RFC 3062). Leave blank to set it later.',
  'userForm.genericError': 'Failed to save user',
  'userForm.createButton': 'Create user',

  'groupForm.editTitle': 'Edit group',
  'groupForm.newTitle': 'New group',
  'groupForm.genericError': 'Failed to save group',
  'groupForm.createButton': 'Create group',
  // Fragments around two inline GlossaryTerm elements (groupOfNames, then
  // member) — see GroupFormDialog. Both languages put groupOfNames first
  // and member second, so a fixed two-fragment split works for both.
  'groupForm.firstMemberNoteMiddle': ' requires at least one ',
  'groupForm.firstMemberNoteEnd':
    ', so the new group starts with you as its first member — add the real member(s) and remove yourself afterwards if needed.',

  'membersDialog.searchPlaceholder': 'Search by name, or paste a full DN',
  'membersDialog.pickListError': "Couldn't load a pick list ({error}) — paste a full DN above to add someone.",
  'membersDialog.loadCandidatesFailedGeneric': 'Failed to load users/groups',
  // The concrete example is deliberate, not decorative — this is the
  // single most useful sentence in the nested-group note, confirmed
  // against how memberOf actually behaves on this server.
  'membersDialog.nestedGroupsNote':
    "Groups can be members too, for nesting. OpenLDAP does not automatically expand nested groups: for example, if u0002 is a member of admins, and admins is a member of engineers, u0002's memberOf only shows admins — not engineers.",
  'membersDialog.removeMemberTitle': 'Remove member',
  'membersDialog.noMembers': 'No members',
  'membersDialog.addMemberFailed': 'Failed to add member',
  'membersDialog.removeMemberFailed': 'Failed to remove member',

  'memberOfDialog.title': 'Group membership',
  'memberOfDialog.noGroupMembership': 'No group membership',

  'setPasswordDialog.title': 'Set password',
  'setPasswordDialog.generatedLabel': 'Server-generated password',
  'setPasswordDialog.copyNowHint': "Copy this now — it won't be shown again.",
  'setPasswordDialog.blankHint': 'Leave blank to have the directory server generate one instead.',
  'setPasswordDialog.genericError': 'Failed to set password',
  'setPasswordDialog.settingBusy': 'Setting…',

  // Value comes first (as a styled chip in the JSX), explanation after —
  // reads naturally in both languages without needing per-language word
  // order for a single template. See ConfirmDialog.
  'confirmDialog.typeToConfirmSuffix': ' — type this to confirm',
} satisfies Record<string, string>

export type DictKey = keyof typeof en

export default en
