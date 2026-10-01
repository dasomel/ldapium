import { test, expect } from '@playwright/test'

// This spec requires a real backend with APP_PROFILES_PATH and an allowed DN.
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('E2E_ADMIN_DN and E2E_ADMIN_PASSWORD are required')

test('persists a custom app profile through the UI without applying permissions', async ({ page }) => {
  await page.goto('/login')
  await page.locator('#identity').fill(identity)
  await page.locator('#password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/tree$/)
  await page.getByRole('link', { name: 'App SSO permissions' }).click()
  await expect(page.getByRole('heading', { name: 'Application SSO permissions' })).toBeVisible()
  const id = `custom-${Date.now()}`
  await page.getByLabel('Application ID', { exact: true }).fill(id)
  await page.getByLabel('Application name').fill('Custom example app')
  await page.getByLabel('Keycloak client ID').fill('custom-client')
  await page.getByLabel('OIDC issuer (HTTPS)').fill('https://sso.example/realms/company')
  await page.getByLabel('Role mappings').fill('app-admin = owner')
  await page.getByRole('button', { name: 'Save profile' }).click()
  await expect(page.getByRole('status')).toContainText('Application permissions have not been applied')
  await page.reload()
  await page.getByRole('button', { name: 'Custom example app' }).click()
  await expect(page.getByLabel('Application ID', { exact: true })).toHaveValue(id)
  await expect(page.getByLabel('Role mappings')).toHaveValue('app-admin = owner')
  await page.getByLabel('Enforcement', { exact: true }).selectOption('gateway_admission')
  await page.getByRole('button', { name: 'Save profile' }).click()
  await expect(page.getByRole('alert')).toContainText('gateway admission does not enforce native application roles')
})
