import { test, expect } from '@playwright/test'
const username = process.env.E2E_OIDC_USERNAME
const password = process.env.E2E_OIDC_PASSWORD
const base = process.env.E2E_GRAFANA_URL
if (!username || !password || !base) throw new Error('Disposable Grafana/OIDC fixture credentials required')

test('exported Grafana mapping grants Editor and rejects an unmapped identity', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  await page.goto(`${base}/login/generic_oauth`)
  await page.locator('#username').fill(username)
  await page.locator('#password').fill(password)
  await page.locator('#kc-login').click()
  await expect(page).toHaveURL(new RegExp(base.replaceAll('.', '\\.')), { timeout: 20000 })
  const user = await context.request.get(`${base}/api/user`)
  expect(user.status()).toBe(200)
  const organizations = await context.request.get(`${base}/api/user/orgs`)
  expect((await organizations.json())[0].role).toBe('Editor')
  const serverAdmin = await context.request.get(`${base}/api/admin/settings`)
  expect(serverAdmin.status()).toBe(403)
  await context.close()
  const denied = await browser.newContext()
  const deniedPage = await denied.newPage()
  await deniedPage.goto(`${base}/login/generic_oauth`)
  await deniedPage.locator('#username').fill('unmapped')
  await deniedPage.locator('#password').fill(password)
  await deniedPage.locator('#kc-login').click()
  await expect(deniedPage).toHaveURL(/\/login/, { timeout: 20000 })
  const noUser = await denied.request.get(`${base}/api/user`)
  expect(noUser.status()).toBe(401)
  await denied.close()
})
