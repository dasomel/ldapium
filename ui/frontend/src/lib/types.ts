export interface Me {
  dn: string
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
}

export interface UserFormInput {
  dn?: string
  uid: string
  cn: string
  sn: string
  givenName?: string
  mail?: string
  password?: string
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

export interface ApiErrorBody {
  error?: string
  message?: string
}
