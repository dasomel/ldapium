import { test, expect, type APIRequestContext } from '@playwright/test'

// Live spec (real backend, real slapd): the conditional-write UI against the
// actual 412 / Idempotency-Key behaviour (docs/changes/api-conditional-writes,
// AC-018). It does not care whether the deployment enabled Idempotency-Key
// (the stock CI install does not): it asserts whichever is true.
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('Conditional-write e2e requires administrator credentials')

const uid = `cw-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`

interface ListedUser {
  dn: string
  uid: string
  cn: string
  sn: string
  etag?: string
}

async function listed(request: APIRequestContext): Promise<ListedUser | undefined> {
  const res = await request.get('/api/users')
  const body = (await res.json()) as { users: ListedUser[] }
  return body.users.find((u) => u.uid === uid)
}

test('stale edit and stale delete are refused with the re-read notice; the retry then succeeds', async ({ page }) => {
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  const origin = new URL(page.url()).origin
  const write = { Origin: origin }
  // page.request shares the browser context's session cookie.
  const api = page.request
  const settings = (await (await api.get('/api/server-settings')).json()) as { idempotencyEnabled?: boolean }

  const writes: Array<Record<string, string>> = []
  page.on('request', (req) => {
    if (req.method() !== 'GET' && req.url().includes('/api/users')) writes.push(req.headers())
  })

  try {
    const created = await api.post('/api/users', { headers: write, data: { uid, cn: 'CW Original', sn: 'Writes' } })
    expect(created.status()).toBe(201)
    const { dn } = (await created.json()) as { dn: string }

    await page.goto('/users')
    await page.getByLabel('Filter users…', { exact: true }).fill(uid)
    const row = page.locator('tbody tr', { hasText: uid })
    await expect(row).toHaveCount(1)
    const etag = (await listed(api))?.etag
    expect(etag, 'the list item carries the entry etag').toMatch(/^"/)

    // Edit: someone else changes the entry after the dialog opened.
    await row.getByRole('button', { name: 'Edit', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.locator('#cn')).toHaveValue('CW Original')
    const other = await api.put('/api/users', {
      headers: write,
      data: { dn, uid, cn: 'CW Changed Elsewhere', sn: 'Writes' },
    })
    expect(other.status()).toBe(204)
    await dialog.locator('#cn').fill('CW My Edit')
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(dialog).toContainText('changed elsewhere')
    await expect(dialog.locator('#cn')).toHaveValue('CW Changed Elsewhere')
    expect((await listed(api))?.cn, 'the refused edit wrote nothing').toBe('CW Changed Elsewhere')

    // The retry runs from the re-read values and carries the new tag.
    await dialog.locator('#cn').fill('CW My Edit')
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText(`Updated ${uid}`)).toBeVisible()
    await expect.poll(async () => (await listed(api))?.cn).toBe('CW My Edit')
    const puts = writes.filter((h) => h['if-match'])
    expect(puts.length).toBeGreaterThanOrEqual(2)
    if (settings.idempotencyEnabled) expect(puts.every((h) => h['idempotency-key'])).toBe(true)
    else expect(writes.every((h) => !h['idempotency-key'])).toBe(true)

    // Delete: stale list item -> notice, nothing deleted, list re-read.
    await row.getByRole('button', { name: 'Delete', exact: true }).click()
    const bump = await api.put('/api/users', { headers: write, data: { dn, uid, cn: 'CW Bumped', sn: 'Writes' } })
    expect(bump.status()).toBe(204)
    await page.locator('#confirm-text').fill(uid)
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'changed elsewhere' })).toBeVisible()
    expect(await listed(api), 'the refused delete removed nothing').toBeTruthy()
    await expect(row).toContainText('CW Bumped')

    // A fresh attempt from the re-read list succeeds.
    await row.getByRole('button', { name: 'Delete', exact: true }).click()
    await page.locator('#confirm-text').fill(uid)
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByText(`Deleted ${uid}`)).toBeVisible()
    expect(await listed(api)).toBeUndefined()
  } finally {
    const left = await listed(api)
    if (left) await api.delete(`/api/users?dn=${encodeURIComponent(left.dn)}`, { headers: write })
  }
})

test('a keyed write is replayed once by the server when idempotency is on, refused when it is off', async ({ page }) => {
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  const write = { Origin: new URL(page.url()).origin }
  const api = page.request
  const settings = (await (await api.get('/api/server-settings')).json()) as { idempotencyEnabled?: boolean }
  const key = `ui-e2e-${uid}-replay`
  const user = { uid: `${uid}r`, cn: 'CW Replay', sn: 'Writes' }
  try {
    const first = await api.post('/api/users', { headers: { ...write, 'Idempotency-Key': key }, data: user })
    if (settings.idempotencyEnabled) {
      expect(first.status()).toBe(201)
      const again = await api.post('/api/users', { headers: { ...write, 'Idempotency-Key': key }, data: user })
      expect(again.status()).toBe(201)
      expect(again.headers()['idempotent-replayed']).toBe('true')
    } else {
      // This is what the UI's one-shot retry without the key relies on.
      expect(first.status()).toBe(422)
      expect(((await first.json()) as { code: string }).code).toBe('idempotency_unsupported')
    }
  } finally {
    const res = await api.get('/api/users')
    const found = ((await res.json()) as { users: ListedUser[] }).users.find((u) => u.uid === user.uid)
    if (found) await api.delete(`/api/users?dn=${encodeURIComponent(found.dn)}`, { headers: write })
  }
})
