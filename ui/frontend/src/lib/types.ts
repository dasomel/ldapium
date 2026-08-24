export interface Me {
  dn: string
}

export type AuthMode = 'ldap' | 'sso'

export interface AuthConfig {
  mode: AuthMode
}

export interface LogoutResponse {
  redirectURL?: string
}

export interface ServerSettings {
  applicationVersion: string
  openLdapVersion: string
  ossVersions: OSSVersion[]
  passwordHash: string
  passwordPolicy: boolean
  uniqueAttributes: string[]
  loadedModules: string[]
  activeOverlays: string[]
  baseDn: string
  userSearchBase: string
  userCreateBase: string
  groupSearchBase: string
  groupCreateBase: string
  connectionSecurity: 'LDAP' | 'LDAPS' | 'StartTLS'
  tlsVerified: boolean
  sessionTtlSeconds: number
  cookieSecure: boolean
}

export interface OSSVersion {
  name: string
  version: string
}

export interface OperationCounter {
  name: string
  initiated: number
  completed: number
}

export interface MonitorStats {
  connectionsCurrent: number
  connectionsTotal: number
  connectionsMaxFds: number
  operations: OperationCounter[]
  bytesSent: number
  entriesSent: number
  threadsMax: number
  threadsMaxPending: number
  threadsActive: number
  databasePagesUsed: number
  databasePagesMax: number
  databasePagesFree: number
  databaseEntries: number
}

export interface TreeNode {
  dn: string
  rdn: string
  objectClasses: string[]
  hasChildren: boolean
}

export interface Entry {
  dn: string
  attributes: Record<string, string[]>
}

export interface User {
  dn: string
  uid: string
  cn: string
  sn: string
  givenName?: string
  mail?: string
  displayName?: string
  memberOf?: string[]
  /** True when the directory's password policy overlay has locked this
   * account (too many failed bind attempts). Clear it via api.unlockUser. */
  locked: boolean
  /** ISO 8601 timestamp of when the lock was applied, if known. Absent
   * both when the account isn't locked and when it's locked indefinitely
   * (no meaningful timestamp) — check `locked`, not this field. */
  lockedAt?: string
  /** departmentNumber — an organizational label, independent of where the
   * entry actually lives in the DIT. */
  department?: string
  /** o (organizationName). */
  organization?: string
  /** ou, as a plain attribute on the entry — a department/unit label, not
   * the entry's actual DIT location. */
  organizationalUnit?: string
}

export interface UserFormInput {
  dn?: string
  uid: string
  cn: string
  sn: string
  givenName?: string
  mail?: string
  password?: string
  department?: string
  organization?: string
  organizationalUnit?: string
}

export interface Group {
  dn: string
  cn: string
  description?: string
  members: string[]
}

export interface GroupFormInput {
  dn?: string
  cn: string
  description?: string
}

/** A pwdPolicy entry (draft-behera-ldap-password-policy, as implemented by
 * slapd's ppolicy overlay), exactly as the server stores it. Optional
 * fields are undefined when the attribute is absent from the entry —
 * distinct from being present and 0/false, both of which are meaningful
 * policy values (e.g. pwdMaxAge: 0 means "never expires"). Nothing here is
 * reinterpreted server-side; display formatting only happens in the UI. */
export interface PasswordPolicy {
  dn: string
  cn: string
  pwdAttribute: string
  pwdMinLength?: number
  pwdInHistory?: number
  pwdMaxAge?: number
  pwdCheckQuality?: number
  pwdLockout?: boolean
  pwdMaxFailure?: number
  pwdLockoutDuration?: number
  pwdSafeModify?: boolean
}

export interface ApiErrorBody {
  error?: string
  message?: string
}

/** Response shape for list endpoints that may cut results off at the
 * server's maxListResults cap. truncated is always explicit — never
 * inferred from the array length — so a cut-off list can't be mistaken for
 * a complete one. */
export interface ListResult<T> {
  truncated: boolean
  items: T[]
}
