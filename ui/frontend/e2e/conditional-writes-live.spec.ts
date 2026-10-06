import { randomBytes } from 'node:crypto'
import { test, expect, type Page } from '@playwright/test'

// Live spec (real backend, real slapd): the conditional-write UI against the
// actual 412 / Idempotency-Key behaviour (docs/changes/api-conditional-writes,
// AC-018). It does not care whether the deployment enabled Idempotency-Key
// (the stock CI install does not): it asserts whichever is true.
//
// Side calls go through the browser (page.evaluate + fetch), like
// origin-gate.spec.ts and health.spec.ts: the browser carries the session
// cookie and a real Origin. Node-side page.request does not send the Secure
// session cookie over plain http, which is how the CI chart install runs.
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('E2E_ADMIN_DN and E2E_ADMIN_PASSWORD must be set to run this spec')

const uid = `cw-${randomBytes(5).toString('hex')}`

interface ListedUser {
  dn: string
  uid: string
  cn: string
  sn: string
  etag?: string
}

interface ApiResult<T = unknown> {
  status: number
  headers: Record<string, string>
  body: T
}

async function api<T = unknown>(
  page: Page,
  method: string,
  path: string,
  opts: { data?: unknown; headers?: Record<string, string> } = {},
): Promise<ApiResult<T>> {
  return page.evaluate(
    async ({ method, path, data, headers }) => {
      const res = await fetch(path, {
        method,
        headers: { ...(data === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
        body: data === undefined ? undefined : JSON.stringify(data),
      })
      const text = await res.text()
      return {
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        body: text ? JSON.parse(text) : null,
      }
    },
    { method, path, data: opts.data, headers: opts.headers ?? {} },
  ) as Promise<ApiResult<T>>
}

async function listed(page: Page, wanted = uid): Promise<ListedUser | undefined> {
  const res = await api<{ users?: ListedUser[] }>(page, 'GET', '/api/users')
  if (res.status !== 200 || !res.body?.users) {
    throw new Error(`GET /api/users answered ${res.status}: ${JSON.stringify(res.body)}`)
  }
  return res.body.users.find((u) => u.uid === wanted)
}

async function login(page: Page) {
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
}

async function idempotencyEnabled(page: Page): Promise<boolean> {
  const res = await api<{ idempotencyEnabled?: boolean }>(page, 'GET', '/api/server-settings')
  expect(res.status).toBe(200)
  return res.body.idempotencyEnabled === true
}

test('stale edit and stale delete are refused with the re-read notice; the retry then succeeds', async ({ page }) => {
  await login(page)
  const enabled = await idempotencyEnabled(page)

  const writes: Array<Record<string, string>> = []
  page.on('request', (req) => {
    if (req.method() !== 'GET' && req.url().includes('/api/users')) writes.push(req.headers())
  })

  try {
    const created = await api<{ dn: string }>(page, 'POST', '/api/users', {
      data: { uid, cn: 'CW Original', sn: 'Writes' },
    })
    expect(created.status).toBe(201)
    const { dn } = created.body

    await page.goto('/users')
    await page.getByLabel('Filter users…', { exact: true }).fill(uid)
    const row = page.locator('tbody tr', { hasText: uid })
    await expect(row).toHaveCount(1)
    expect((await listed(page))?.etag, 'the list item carries the entry etag').toMatch(/^"/)

    // Edit: someone else changes the entry after the dialog opened.
    await row.getByRole('button', { name: 'Edit', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.locator('#cn')).toHaveValue('CW Original')
    const other = await api(page, 'PUT', '/api/users', {
      data: { dn, uid, cn: 'CW Changed Elsewhere', sn: 'Writes' },
    })
    expect(other.status).toBe(204)
    await dialog.locator('#cn').fill('CW My Edit')
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(dialog.getByRole('alert')).toContainText('changed elsewhere')
    await expect(dialog.getByRole('alert')).toContainText('cn: "CW My Edit"')
    await expect(dialog.locator('#cn')).toHaveValue('CW Changed Elsewhere')
    expect((await listed(page))?.cn, 'the refused edit wrote nothing').toBe('CW Changed Elsewhere')

    // The retry runs from the re-read values and carries the new tag.
    await dialog.locator('#cn').fill('CW My Edit')
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText(`Updated ${uid}`)).toBeVisible()
    await expect.poll(async () => (await listed(page))?.cn).toBe('CW My Edit')
    const puts = writes.filter((h) => h['if-match'])
    expect(puts.length).toBeGreaterThanOrEqual(2)
    if (enabled) expect(puts.every((h) => h['idempotency-key'])).toBe(true)
    else expect(writes.every((h) => !h['idempotency-key'])).toBe(true)

    // Delete: stale list item -> notice, nothing deleted, list re-read.
    await row.getByRole('button', { name: 'Delete', exact: true }).click()
    const bump = await api(page, 'PUT', '/api/users', { data: { dn, uid, cn: 'CW Bumped', sn: 'Writes' } })
    expect(bump.status).toBe(204)
    await page.locator('#confirm-text').fill(uid)
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'changed elsewhere' })).toBeVisible()
    expect(await listed(page), 'the refused delete removed nothing').toBeTruthy()
    await expect(row).toContainText('CW Bumped')

    // A fresh attempt from the re-read list succeeds.
    await row.getByRole('button', { name: 'Delete', exact: true }).click()
    await page.locator('#confirm-text').fill(uid)
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByText(`Deleted ${uid}`)).toBeVisible()
    expect(await listed(page)).toBeUndefined()
  } finally {
    const left = await listed(page).catch(() => undefined)
    if (left) await api(page, 'DELETE', `/api/users?dn=${encodeURIComponent(left.dn)}`)
  }
})

test('a keyed write is replayed once by the server when idempotency is on, refused when it is off', async ({ page }) => {
  await login(page)
  const enabled = await idempotencyEnabled(page)
  const key = `ui-e2e-${uid}-replay`
  const user = { uid: `${uid}r`, cn: 'CW Replay', sn: 'Writes' }
  const headers = { 'Idempotency-Key': key }
  try {
    const first = await api<{ code?: string }>(page, 'POST', '/api/users', { data: user, headers })
    if (enabled) {
      expect(first.status).toBe(201)
      const again = await api(page, 'POST', '/api/users', { data: user, headers })
      expect(again.status).toBe(201)
      expect(again.headers['idempotent-replayed']).toBe('true')
    } else {
      // This is what the UI's one-shot retry without the key relies on.
      expect(first.status).toBe(422)
      expect(first.body.code).toBe('idempotency_unsupported')
    }
  } finally {
    const found = await listed(page, user.uid).catch(() => undefined)
    if (found) await api(page, 'DELETE', `/api/users?dn=${encodeURIComponent(found.dn)}`)
  }
})
