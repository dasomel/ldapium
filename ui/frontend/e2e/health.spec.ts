import { test, expect } from '@playwright/test'

// This repo's first browser-driven test (#45) — run against a real chart
// install by .github/workflows/ui-e2e.yml, not a mocked backend, so a pass
// here means the actual login → API → LDAP round trip works end to end,
// not just that the frontend renders given canned JSON.
//
// E2E_ADMIN_DN/E2E_ADMIN_PASSWORD identify the account the workflow
// installed the chart with and (for the health assertions below) already
// granted cn=Monitor read access to — see that workflow for the exact
// ldapmodify. Required, not defaulted: a silently-skipped credential would
// make every assertion below meaningless rather than fail loudly.
const IDENTITY = requireEnv('E2E_ADMIN_DN')
const PASSWORD = requireEnv('E2E_ADMIN_PASSWORD')

function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value) {
    throw new Error(`${name} must be set to run this spec`)
  }
  return value
}

async function login(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.locator('#identity').fill(IDENTITY)
  await page.locator('#password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/tree$/, { timeout: 15_000 })
}

const CRUD_USER = {
  uid: 'e2e-ui-crud-user',
  cn: 'E2E UI CRUD User',
  sn: 'User',
  initialMail: 'e2e-ui-crud-initial@example.org',
  updatedMail: 'e2e-ui-crud-updated@example.org',
  initialPassword: 'UiE2EInitial-2026!',
  resetPassword: 'UiE2EReset-2026!',
}

function userRow(page: import('@playwright/test').Page, uid: string) {
  return page.getByRole('row').filter({ has: page.getByRole('cell', { name: uid, exact: true }) })
}

async function filterUsers(page: import('@playwright/test').Page, query: string) {
  await page.getByPlaceholder('Filter users…').fill(query)
}

async function deleteUserIfPresent(page: import('@playwright/test').Page, uid: string) {
  const row = userRow(page, uid)
  if ((await row.count()) === 0) return

  await row.getByRole('button', { name: 'Delete' }).click()
  const dialog = page.getByRole('dialog', { name: 'Delete user' })
  await dialog.locator('#confirm-text').fill(uid)
  await dialog.getByRole('button', { name: 'Delete' }).click()
  await expect(row).toHaveCount(0)
}

test('logs in and browses the DIT tree', async ({ page }) => {
  await login(page)
  // The base DN is always the tree's root node — confirms the backend
  // actually returned real LDAP data, not just that routing worked.
  await expect(page.getByText('dc=example,dc=org', { exact: false }).first()).toBeVisible()
})

test('health page shows live cn=Monitor data once granted', async ({ page }) => {
  await login(page)
  await page.locator('a[href="/health"]').click()
  await expect(page).toHaveURL(/\/health$/)

  // The workflow grants IDENTITY read access to cn=Monitor before this
  // spec runs, so this must be real data, not the permission-denied empty
  // state — asserting both catches either direction of regression: the
  // feature silently breaking, or the ACL grant step silently not taking
  // effect.
  await expect(page.getByText("Your account can't read cn=Monitor")).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Connections' })).toBeVisible()
  await expect(page.getByText('Current')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Operations' })).toBeVisible()
  // { exact: true }: a substring match on "Bind" also matches "Unbind" —
  // found by actually running this against a live server, not assumed.
  await expect(page.getByText('Bind', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Database' })).toBeVisible()
})

test('creates, edits, resets the password for, and deletes a user through the UI', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: 'Users' }).click()
  await expect(page).toHaveURL(/\/users$/)
  await expect(page.getByText(/^\d+ total$/)).toBeVisible()

  // A failed prior run can leave this dedicated account behind. Remove it
  // through the same confirmation UI before starting, keeping reruns
  // idempotent without bypassing the application or LDAP.
  await filterUsers(page, CRUD_USER.uid)
  await deleteUserIfPresent(page, CRUD_USER.uid)
  await filterUsers(page, '')

  // There are two "New user" buttons when the directory has no users: the
  // always-present one in the page toolbar and a second inside the empty-state
  // card. On a freshly seeded CI directory the empty state renders too, so an
  // unscoped name match is ambiguous — target the toolbar button, which comes
  // first in the DOM and is present regardless of how many users exist.
  await page.getByRole('button', { name: 'New user' }).first().click()
  const createDialog = page.getByRole('dialog', { name: 'New user' })
  await createDialog.locator('#uid').fill(CRUD_USER.uid)
  await createDialog.locator('#mail').fill(CRUD_USER.initialMail)
  await createDialog.locator('#sn').fill(CRUD_USER.sn)
  await createDialog.locator('#cn').fill(CRUD_USER.cn)
  await createDialog.locator('#password').fill(CRUD_USER.initialPassword)
  await createDialog.getByRole('button', { name: 'Create user' }).click()
  await expect(page.getByText(`Created user ${CRUD_USER.uid}`)).toBeVisible()

  await filterUsers(page, CRUD_USER.uid)
  const row = userRow(page, CRUD_USER.uid)
  await expect(row).toContainText(CRUD_USER.cn)
  await expect(row).toContainText(CRUD_USER.initialMail)

  await row.getByRole('button', { name: 'Edit' }).click()
  const editDialog = page.getByRole('dialog', { name: 'Edit user' })
  await editDialog.locator('#mail').fill(CRUD_USER.updatedMail)
  await editDialog.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText(`Updated ${CRUD_USER.uid}`)).toBeVisible()
  await expect(row).toContainText(CRUD_USER.updatedMail)

  await row.getByRole('button', { name: 'Set password' }).click()
  const passwordDialog = page.getByRole('dialog', { name: 'Set password' })
  await passwordDialog.locator('#new-password').fill(CRUD_USER.resetPassword)
  await passwordDialog.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByText('Password updated')).toBeVisible()
  await expect(passwordDialog).toHaveCount(0)

  await deleteUserIfPresent(page, CRUD_USER.uid)
  await expect(userRow(page, CRUD_USER.uid)).toHaveCount(0)
})

test('logs out and cannot reach an authed page without a session', async ({ page }) => {
  await login(page)
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page).toHaveURL(/\/login$/, { timeout: 15_000 })

  await page.goto('/health')
  await expect(page).toHaveURL(/\/login$/)
})

test('records operator action history for UI create and delete without leaking attribute values, and renders extended monitor stats', async ({ page }) => {
  const testUser = {
    uid: 'e2e-history-actor-check',
    cn: 'History Check User',
    sn: 'Check',
    mail: 'history-check@example.org',
    password: 'HistorySecret-2026!',
  }

  await login(page)
  await page.getByRole('link', { name: 'Users' }).click()
  await expect(page).toHaveURL(/\/users$/)

  // Cleanup if left from prior run
  await filterUsers(page, testUser.uid)
  await deleteUserIfPresent(page, testUser.uid)
  await filterUsers(page, '')

  // Create user via UI
  await page.getByRole('button', { name: 'New user' }).first().click()
  const createDialog = page.getByRole('dialog', { name: 'New user' })
  await createDialog.locator('#uid').fill(testUser.uid)
  await createDialog.locator('#mail').fill(testUser.mail)
  await createDialog.locator('#sn').fill(testUser.sn)
  await createDialog.locator('#cn').fill(testUser.cn)
  await createDialog.locator('#password').fill(testUser.password)
  await createDialog.getByRole('button', { name: 'Create user' }).click()
  await expect(page.getByText(`Created user ${testUser.uid}`)).toBeVisible()

  // Delete user via UI
  await filterUsers(page, testUser.uid)
  await deleteUserIfPresent(page, testUser.uid)
  await expect(userRow(page, testUser.uid)).toHaveCount(0)

  // Navigate to History page
  await page.locator('a[href="/history"]').click()
  await expect(page).toHaveURL(/\/history$/)
  await expect(page.getByText('Your account cannot view operator action history')).toHaveCount(0)

  // Verify rows are visible
  const targetDn = `uid=${testUser.uid},dc=example,dc=org`
  const historyRows = page.locator('[data-testid="history-row"]')
  await expect(historyRows.first()).toBeVisible({ timeout: 15_000 })

  const addRow = historyRows.filter({ hasText: 'add' }).filter({ hasText: targetDn })
  const delRow = historyRows.filter({ hasText: 'delete' }).filter({ hasText: targetDn })

  await expect(addRow).toHaveCount(1)
  await expect(delRow).toHaveCount(1)

  // Assert actor is present on both rows
  await expect(addRow.locator('[data-testid="history-actor"]')).toContainText(IDENTITY)
  await expect(delRow.locator('[data-testid="history-actor"]')).toContainText(IDENTITY)

  // Assert no attribute values (password, email, cn, sn) appear in changed attributes
  const addAttrs = addRow.locator('[data-testid="history-attrs"]')
  await expect(addAttrs).not.toContainText(testUser.password)
  await expect(addAttrs).not.toContainText(testUser.mail)
  await expect(addAttrs).not.toContainText(testUser.cn)
  await expect(addAttrs).not.toContainText(testUser.sn)

  // Open Monitor and assert counters render
  await page.locator('a[href="/health"]').click()
  await expect(page).toHaveURL(/\/health$/)
  await expect(page.getByText("Your account can't read cn=Monitor")).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Connections' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Operations' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Database' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Threads' })).toBeVisible()
  await expect(page.getByRole('heading', { name: /Uptime & Waiters/i })).toBeVisible()
  await expect(page.getByText('Read waiters', { exact: false })).toBeVisible()
  await expect(page.getByText('Write waiters', { exact: false })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Recent access logs' })).toBeVisible()
})

