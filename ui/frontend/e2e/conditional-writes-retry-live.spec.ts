import { randomBytes } from 'node:crypto'
import { test, expect, type Page, type Request } from '@playwright/test'

// Live spec (real backend, real slapd) for the keyed-retry half of the
// conditional-write UI (docs/changes/api-conditional-writes, AC-018, #268):
// the response to a write is lost after the server committed it, the operator
// submits again, and the UI must reuse the same Idempotency-Key so the server
// replays the first result instead of writing twice. Nothing is mocked: the
// browser's fetch is wrapped so the real response is read and then reported to
// the app as a network failure, i.e. a genuine dropped response.
//
// Like conditional-writes-live.spec.ts it asserts whichever is true for the
// deployment: the stock CI chart install leaves UI_IDEMPOTENCY_ENABLED off, the
// scripts/test/test-api-conditional-writes-local.py stack turns it on. Side
// calls go through the browser (cookie + Origin), see that spec for why.
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('E2E_ADMIN_DN and E2E_ADMIN_PASSWORD must be set to run this spec')

const uid = `cr-${randomBytes(5).toString('hex')}`

interface ApiResult<T = unknown> {
  status: number
  headers: Record<string, string>
  body: T
}

interface ListedUser {
  dn: string
  uid: string
  cn: string
}

async function api<T = unknown>(page: Page, method: string, path: string): Promise<ApiResult<T>> {
  return page.evaluate(
    async ({ method, path }) => {
      const res = await fetch(path, { method })
      const text = await res.text()
      return {
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        body: text ? JSON.parse(text) : null,
      }
    },
    { method, path },
  ) as Promise<ApiResult<T>>
}

async function listedByUid(page: Page, wanted: string): Promise<ListedUser[]> {
  const res = await api<{ users?: ListedUser[] }>(page, 'GET', '/api/users')
  if (res.status !== 200 || !res.body?.users) throw new Error(`GET /api/users answered ${res.status}`)
  return res.body.users.filter((u) => u.uid === wanted)
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

// The next /api/users write is performed for real and its response is read,
// then the app is told the request failed (a lost response). One shot.
async function dropNextUserWriteResponse(page: Page) {
  await page.evaluate(() => {
    const realFetch = window.fetch.bind(window)
    let armed = true
    window.fetch = async (input, init) => {
      const res = await realFetch(input, init)
      const method = (init?.method ?? 'GET').toUpperCase()
      if (armed && method !== 'GET' && String(input).includes('/api/users')) {
        armed = false
        throw new TypeError('Failed to fetch')
      }
      return res
    }
  })
}

interface Seen {
  method: string
  key?: string
  ifMatch?: string
  status?: number
  replayed?: string
}

// Collects every non-GET /api/users request with its real response.
function recordWrites(page: Page): Seen[] {
  const seen: Seen[] = []
  const byRequest = new Map<Request, Seen>()
  page.on('request', (req) => {
    if (req.method() === 'GET' || !req.url().includes('/api/users')) return
    const h = req.headers()
    const entry: Seen = { method: req.method(), key: h['idempotency-key'], ifMatch: h['if-match'] }
    byRequest.set(req, entry)
    seen.push(entry)
  })
  page.on('response', (res) => {
    const entry = byRequest.get(res.request())
    if (!entry) return
    entry.status = res.status()
    entry.replayed = res.headers()['idempotent-replayed']
  })
  return seen
}

test('a create whose response was lost is retried with the same key and leaves exactly one entry', async ({ page }) => {
  await login(page)
  const enabled = await idempotencyEnabled(page)
  const writes = recordWrites(page)
  try {
    await page.goto('/users')
    await page.getByRole('button', { name: 'New user' }).first().click()
    const dialog = page.getByRole('dialog')
    await dialog.locator('#uid').fill(uid)
    await dialog.locator('#sn').fill('Retry')
    await dialog.locator('#cn').fill('CR Created')
    await dropNextUserWriteResponse(page)
    await page.getByRole('button', { name: 'Create user' }).click()

    // The server committed it, but the screen never heard back.
    await expect(dialog).toBeVisible()
    await expect.poll(async () => (await listedByUid(page, uid)).length).toBe(1)

    await page.getByRole('button', { name: 'Create user' }).click()
    if (enabled) {
      await expect(page.getByText(`Created user ${uid}`)).toBeVisible()
      expect(writes).toHaveLength(2)
      expect(writes[0].key).toMatch(/^[A-Za-z0-9._~:-]{16,128}$/)
      expect(writes[1].key).toBe(writes[0].key)
      expect(writes[0].status).toBe(201)
      expect(writes[1].status).toBe(201)
      expect(writes[1].replayed).toBe('true')
    } else {
      // No key is ever sent, so the retry is a plain second create and the
      // directory refuses the duplicate.
      await expect(dialog.getByRole('alert')).toBeVisible()
      expect(writes.map((w) => w.key)).toEqual([undefined, undefined])
      expect(writes[1].status).toBe(409)
    }
    expect(await listedByUid(page, uid), 'no duplicate entry').toHaveLength(1)
  } finally {
    for (const u of await listedByUid(page, uid).catch(() => [])) {
      await api(page, 'DELETE', `/api/users?dn=${encodeURIComponent(u.dn)}`)
    }
  }
})

test('an edit whose response was lost is retried with the same key and is replayed, not refused as stale', async ({ page }) => {
  await login(page)
  const enabled = await idempotencyEnabled(page)
  const editUid = `${uid}e`
  try {
    const created = await page.evaluate(
      async ({ uid }) => {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ uid, cn: 'CR Original', sn: 'Retry' }),
        })
        return res.status
      },
      { uid: editUid },
    )
    expect(created).toBe(201)

    await page.goto('/users')
    await page.getByLabel('Filter users…', { exact: true }).fill(editUid)
    const row = page.locator('tbody tr', { hasText: editUid })
    await expect(row).toHaveCount(1)
    await row.getByRole('button', { name: 'Edit', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.locator('#cn')).toHaveValue('CR Original')

    const writes = recordWrites(page)
    await dialog.locator('#cn').fill('CR Edited')
    await dropNextUserWriteResponse(page)
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(dialog).toBeVisible()
    // The first PUT really landed, which moved the entry's etag under the form.
    await expect.poll(async () => (await listedByUid(page, editUid))[0]?.cn).toBe('CR Edited')

    await page.getByRole('button', { name: 'Save changes' }).click()
    expect(writes).toHaveLength(2)
    expect(writes[1].ifMatch, 'the retry still carries the etag the form was loaded with').toBe(writes[0].ifMatch)
    if (enabled) {
      await expect(page.getByText(`Updated ${editUid}`)).toBeVisible()
      expect(writes[1].key).toBe(writes[0].key)
      expect(writes[1].status).toBe(204)
      expect(writes[1].replayed).toBe('true')
    } else {
      // Without a key the retry's old etag is simply stale.
      await expect(dialog.getByRole('alert')).toContainText('changed elsewhere')
      expect(writes.map((w) => w.key)).toEqual([undefined, undefined])
      expect(writes[1].status).toBe(412)
    }
    expect((await listedByUid(page, editUid))[0]?.cn).toBe('CR Edited')
  } finally {
    for (const u of await listedByUid(page, editUid).catch(() => [])) {
      await api(page, 'DELETE', `/api/users?dn=${encodeURIComponent(u.dn)}`)
    }
  }
})
