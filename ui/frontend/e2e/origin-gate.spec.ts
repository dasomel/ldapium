import { test, expect } from '@playwright/test'

// Live spec (needs a real backend, like groups-pagination): the write Origin
// gate (docs/changes/api-error-envelope, D218-16) must never refuse the SPA's
// own same-origin writes. Browsers attach `Origin` to same-origin POST/DELETE,
// so this exercises the gate's accept path for the login form and for writes.
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('The origin gate spec requires administrator credentials')

test('same-origin login and writes pass the Origin gate', async ({ page }) => {
  const logins: { origin: string | undefined; status: number }[] = []
  page.on('response', async (res) => {
    if (res.url().endsWith('/api/login') && res.request().method() === 'POST') {
      // allHeaders() includes headers the browser adds itself, such as Origin.
      logins.push({ origin: (await res.request().allHeaders())['origin'], status: res.status() })
    }
  })
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  await expect.poll(() => logins.length).toBe(1)
  expect(logins[0].status).toBe(200)
  // The browser really did send an Origin; the gate accepted it.
  expect(logins[0].origin).toBe(new URL(page.url()).origin)

  const cn = `origin-gate-${Date.now()}`
  const result = await page.evaluate(async (name) => {
    const create = await fetch('/api/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cn: name }),
    })
    const created = create.status === 201 ? ((await create.json()) as { dn: string }) : null
    const del = created ? await fetch(`/api/groups?dn=${encodeURIComponent(created.dn)}`, { method: 'DELETE' }) : null
    return { create: create.status, del: del?.status ?? null }
  }, cn)
  expect(result).toEqual({ create: 201, del: 204 })
})
