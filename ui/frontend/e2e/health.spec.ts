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

test('logs out and cannot reach an authed page without a session', async ({ page }) => {
  await login(page)
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page).toHaveURL(/\/login$/, { timeout: 15_000 })

  await page.goto('/health')
  await expect(page).toHaveURL(/\/login$/)
})
