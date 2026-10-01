import { test, expect } from '@playwright/test'
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('Disposable Keycloak integration credentials are required')

test('loads live Keycloak roles and creates/deletes a delegated role from the UI', async ({ page }) => {
  await page.goto('/login')
  await page.locator('#identity').fill(identity)
  await page.locator('#password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/tree$/)
  await page.getByRole('link', { name: 'App SSO permissions' }).click()
  await page.getByRole('button', { name: 'Custom', exact: false }).click()
  await page.getByRole('button', { name: 'Load Keycloak roles' }).click()
  await expect(page.getByText('Delegated editing enabled')).toBeVisible()
  await expect(page.getByRole('button', { name: 'operator', exact: true })).toBeVisible()
  page.on('dialog', (dialog) => dialog.accept())
  await page.getByLabel('Role name', { exact: true }).fill('browser-created')
  await page.getByRole('button', { name: 'Create role', exact: true }).click()
  await expect(page.getByRole('button', { name: 'browser-created', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Delete role', exact: true }).click()
  await expect(page.getByRole('button', { name: 'browser-created', exact: true })).toHaveCount(0)
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export configuration' }).click()
  expect((await download).suggestedFilename()).toBe('custom-oidc-contract.json')
  await expect(page.getByText('Apply through the application', { exact: false })).toBeVisible()
})
