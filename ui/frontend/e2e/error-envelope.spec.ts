import { test, expect, type Page } from '@playwright/test'

// Mocked spec, no live backend or credentials: every /api call is answered by
// page.route, so this runs against `npx vite` alone. It proves the screens
// keep showing the server's `error` text now that every error also carries
// `message`, `code`, `requestId` and `retryable` (docs/changes/api-error-envelope,
// AC-002), including the screens that used to read only `message`.

function envelope(error: string, code: string, retryable = false, message = error) {
  return { error, message, code, requestId: 'req-e2e-1', retryable }
}

async function mockSession(page: Page) {
  // Anything not mocked below must not reach the vite proxy target.
  await page.route('**/api/**', (r) => r.fulfill({ status: 404, json: envelope('not found', 'not_found') }))
  await page.route('**/api/auth/config', (r) => r.fulfill({ json: { mode: 'ldap' } }))
  await page.route('**/api/me', (r) => r.fulfill({ json: { dn: 'cn=admin,dc=example,dc=org' } }))
}

test('login shows the 429 text and ignores the new keys', async ({ page }) => {
  await page.route('**/api/**', (r) => r.fulfill({ status: 404, json: envelope('not found', 'not_found') }))
  await page.route('**/api/auth/config', (r) => r.fulfill({ json: { mode: 'ldap' } }))
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: envelope('not logged in', 'unauthenticated') }))
  await page.route('**/api/login', (r) =>
    r.fulfill({
      status: 429,
      headers: { 'Retry-After': '42' },
      json: envelope('too many failed login attempts', 'login_rate_limited', true),
    }),
  )
  await page.goto('/login')
  await page.locator('#identity').fill('jdoe')
  await page.locator('#password').fill('wrong')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('too many failed login attempts', { exact: true })).toBeVisible()
})

test('user list failure shows the validation text', async ({ page }) => {
  await mockSession(page)
  await page.route('**/api/users', (r) =>
    r.fulfill({ status: 400, json: envelope('dn does not look like a distinguished name', 'invalid_request') }),
  )
  await page.goto('/users')
  await expect(page.getByText('dn does not look like a distinguished name')).toBeVisible()
})

test('password-policy refusal is shown as the server sent it', async ({ page }) => {
  await mockSession(page)
  await page.route('**/api/password-policies', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/users/password', (r) =>
    r.fulfill({
      status: 400,
      json: envelope('invalid input: Password does not pass required number of strength checks (1 of 3)', 'invalid_request'),
    }),
  )
  await page.goto('/change-password')
  await page.locator('#current-password').fill('Old-password-1!')
  await page.locator('#new-password').fill('aaaaaaaaaaaaaaaa')
  await page.locator('#confirm-password').fill('aaaaaaaaaaaaaaaa')
  await page.getByRole('button', { name: 'Change password', exact: true }).click()
  await expect(page.getByText('invalid input: Password does not pass required number of strength checks (1 of 3)')).toBeVisible()
})

// The application-profile and backup screens used to read only `message`.
// They read `error` first now; a body that carries only one of the two keys
// (an older server) still works.
test('application profile screen reads error first, message as a fallback', async ({ page }) => {
  await mockSession(page)
  await page.route('**/api/v1/applications/integration-methods', (r) => r.fulfill({ json: { methods: [] } }))
  await page.route('**/api/v1/applications', (r) =>
    r.fulfill({ status: 403, json: envelope('application profile administrator required', 'admin_required', false, 'ALIAS-TEXT') }),
  )
  await page.goto('/applications')
  await expect(page.getByRole('alert')).toContainText('application profile administrator required')
  await expect(page.getByRole('alert')).not.toContainText('ALIAS-TEXT')

  await page.unroute('**/api/v1/applications')
  await page.route('**/api/v1/applications', (r) => r.fulfill({ status: 403, json: { message: 'legacy message only' } }))
  await page.goto('/applications')
  await expect(page.getByRole('alert')).toContainText('legacy message only')
})

test('backup screen shows the 409 text', async ({ page }) => {
  await mockSession(page)
  await page.route('**/api/v1/backups', (r) => r.fulfill({ status: 409, json: envelope('backup already running', 'backup_busy', true) }))
  await page.goto('/backups')
  await expect(page.getByText('backup already running')).toBeVisible()
})
