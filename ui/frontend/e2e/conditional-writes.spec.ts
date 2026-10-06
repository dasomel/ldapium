import { test, expect, type Page, type Request, type Route } from '@playwright/test'

// Mocked spec, no live backend or credentials: every /api call is answered by
// page.route, so it runs against `npx vite` alone. It pins the UI half of the
// conditional-write contract (docs/changes/api-conditional-writes, T-018,
// AC-018): If-Match from the item's etag, one Idempotency-Key per attempt, the
// 412 re-read notice, the 422 idempotency_unsupported retry, and an older
// server (no etag, no setting) that must keep working unchanged.

const BASE = 'dc=example,dc=org'
const ADMIN = `cn=admin,${BASE}`
const jdoeDn = `uid=jdoe,ou=people,${BASE}`
const staffDn = `cn=staff,ou=groups,${BASE}`
const ETAG_1 = '"20261006100000.000000Z#000000#001#000000"'
const ETAG_2 = '"20261006110000.000000Z#000000#001#000000"'

function envelope(error: string, code: string, retryable = false) {
  return { error, message: error, code, requestId: 'req-e2e-1', retryable }
}

interface Mock {
  /** Every non-GET request the page made, in order. */
  writes: Request[]
  listGets: () => number
  setUser: (patch: Record<string, unknown>) => void
}

interface MockOptions {
  idempotencyEnabled?: boolean
  withEtag?: boolean
}

function userBody(cn: string, etag: string | undefined) {
  return { dn: jdoeDn, uid: 'jdoe', cn, sn: 'Doe', locked: false, ...(etag ? { etag } : {}) }
}

async function mockServer(page: Page, opts: MockOptions = {}): Promise<Mock> {
  const withEtag = opts.withEtag ?? true
  const writes: Request[] = []
  let userListGets = 0
  let user: Record<string, unknown> = userBody('John Doe', withEtag ? ETAG_1 : undefined)
  const group = {
    dn: staffDn,
    cn: 'staff',
    description: 'Staff',
    members: [jdoeDn],
    ...(withEtag ? { etag: ETAG_1 } : {}),
  }
  await page.route('**/api/**', (r) => r.fulfill({ status: 404, json: envelope('not found', 'not_found') }))
  await page.route('**/api/auth/config', (r) => r.fulfill({ json: { mode: 'ldap' } }))
  await page.route('**/api/me', (r) => r.fulfill({ json: { dn: ADMIN } }))
  await page.route('**/api/server-settings', (r) =>
    r.fulfill({
      json: {
        applicationVersion: 'test',
        baseDn: BASE,
        ...(opts.idempotencyEnabled === undefined ? {} : { idempotencyEnabled: opts.idempotencyEnabled }),
      },
    }),
  )
  await page.route('**/api/users', (r) => {
    if (r.request().method() === 'GET') {
      userListGets++
      return r.fulfill({ json: { users: [user], truncated: false } })
    }
    writes.push(r.request())
    return r.fulfill({ status: 204 })
  })
  await page.route('**/api/groups', (r) => {
    if (r.request().method() === 'GET') return r.fulfill({ json: { groups: [group], truncated: false } })
    writes.push(r.request())
    return r.fulfill({ status: 204 })
  })
  await page.route('**/api/groups/members**', (r) => {
    writes.push(r.request())
    return r.fulfill({ status: 204 })
  })
  await page.route('**/api/users?dn=**', (r) => {
    writes.push(r.request())
    return r.fulfill({ status: 204 })
  })
  await page.route('**/api/groups?dn=**', (r) => {
    writes.push(r.request())
    return r.fulfill({ status: 204 })
  })
  return { writes, listGets: () => userListGets, setUser: (patch) => (user = { ...user, ...patch }) }
}

async function openUserEdit(page: Page) {
  await page.goto('/users')
  await page.getByRole('button', { name: 'Edit', exact: true }).click()
  await expect(page.getByRole('dialog').locator('#cn')).toHaveValue('John Doe')
}

async function saveCn(page: Page, cn: string) {
  await page.getByRole('dialog').locator('#cn').fill(cn)
  await page.getByRole('button', { name: 'Save changes' }).click()
}

const header = (req: Request, name: string) => req.headers()[name.toLowerCase()]

test('user edit sends If-Match from the list etag and no key when the setting is off', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: false })
  await openUserEdit(page)
  await saveCn(page, 'Johnny Doe')
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  expect(mock.writes).toHaveLength(1)
  expect(mock.writes[0].method()).toBe('PUT')
  expect(header(mock.writes[0], 'If-Match')).toBe(ETAG_1)
  expect(header(mock.writes[0], 'Idempotency-Key')).toBeUndefined()
})

test('an older server (no etag, no setting) keeps working with no conditional headers', async ({ page }) => {
  const mock = await mockServer(page, { withEtag: false })
  await openUserEdit(page)
  await saveCn(page, 'Johnny Doe')
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  await page.getByRole('button', { name: 'Delete', exact: true }).first().click()
  await page.locator('#confirm-text').fill('jdoe')
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByText('Deleted jdoe')).toBeVisible()
  expect(mock.writes.map((w) => w.method())).toEqual(['PUT', 'DELETE'])
  for (const w of mock.writes) {
    expect(header(w, 'If-Match')).toBeUndefined()
    expect(header(w, 'Idempotency-Key')).toBeUndefined()
  }
})

test('a settings endpoint that fails does not block the write', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await page.route('**/api/server-settings', (r) => r.fulfill({ status: 500, json: envelope('boom', 'internal') }))
  await openUserEdit(page)
  await saveCn(page, 'Johnny Doe')
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  expect(header(mock.writes[0], 'Idempotency-Key')).toBeUndefined()
})

test('stale edit: 412 shows the re-read notice, refetches and re-seeds the form with the new etag', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 700 }) // the long notice must not break the narrow layout
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await openUserEdit(page)
  // Someone else changes the entry; the server now answers 412 for the old tag.
  mock.setUser({ cn: 'J. Doe (changed elsewhere)', etag: ETAG_2 })
  await page.unroute('**/api/users')
  let puts = 0
  await page.route('**/api/users', (r: Route) => {
    const req = r.request()
    if (req.method() === 'GET') return r.fulfill({ json: { users: [userBody('J. Doe (changed elsewhere)', ETAG_2)], truncated: false } })
    mock.writes.push(req)
    puts++
    if (header(req, 'If-Match') !== ETAG_2) {
      return r.fulfill({ status: 412, json: envelope('entry changed; reload before saving', 'revision_conflict') })
    }
    return r.fulfill({ status: 204 })
  })
  const getsBefore = mock.listGets()
  await saveCn(page, 'My edit')
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('changed elsewhere')
  await expect(dialog).toContainText('refreshed')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await expect(dialog.getByText('changed elsewhere')).toBeInViewport()
  // The form re-seeded from the re-read entry, so the next save carries the new tag.
  await expect(dialog.locator('#cn')).toHaveValue('J. Doe (changed elsewhere)')
  expect(mock.writes[0].headers()['if-match']).toBe(ETAG_1)
  expect(getsBefore).toBe(mock.listGets()) // the stale-tag GET mock above replaced the counted one
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  expect(puts).toBe(2)
  expect(header(mock.writes[1], 'If-Match')).toBe(ETAG_2)
  // 412 is never stored server-side and the user re-read: a fresh attempt, fresh key.
  expect(header(mock.writes[1], 'Idempotency-Key')).not.toBe(header(mock.writes[0], 'Idempotency-Key'))
})

test('stale delete: 412 closes the dialog with the notice and refetches the list', async ({ page }) => {
  const mock = await mockServer(page)
  await page.goto('/users')
  await page.unroute('**/api/users?dn=**')
  await page.route('**/api/users?dn=**', (r) => {
    mock.writes.push(r.request())
    return r.fulfill({ status: 412, json: envelope('entry changed; reload before saving', 'revision_conflict') })
  })
  const before = mock.listGets()
  await page.getByRole('button', { name: 'Delete', exact: true }).first().click()
  await page.locator('#confirm-text').fill('jdoe')
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'changed elsewhere' })).toBeVisible()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect(header(mock.writes[0], 'If-Match')).toBe(ETAG_1)
  await expect.poll(() => mock.listGets()).toBeGreaterThan(before)
})

test('a retried submit reuses one Idempotency-Key; the next change gets a new one', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await openUserEdit(page)
  await page.unroute('**/api/users')
  let calls = 0
  await page.route('**/api/users', (r) => {
    const req = r.request()
    if (req.method() === 'GET') return r.fulfill({ json: { users: [userBody('John Doe', ETAG_1)], truncated: false } })
    mock.writes.push(req)
    calls++
    // First attempt: the response is lost on the wire.
    return calls === 1 ? r.abort('connectionreset') : r.fulfill({ status: 204 })
  })
  await saveCn(page, 'Johnny Doe')
  await expect(page.getByRole('dialog')).toBeVisible() // still open, error shown
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  expect(mock.writes).toHaveLength(2)
  const key = header(mock.writes[0], 'Idempotency-Key')
  expect(key).toMatch(/^[A-Za-z0-9._~:-]{16,128}$/)
  expect(header(mock.writes[1], 'Idempotency-Key')).toBe(key)

  // After a success the next edit is a new attempt, even with identical content.
  await page.getByRole('button', { name: 'Edit', exact: true }).click()
  await saveCn(page, 'Johnny Doe')
  await expect(page.getByText('Updated jdoe')).toHaveCount(1)
  await expect.poll(() => mock.writes.length).toBe(3)
  expect(header(mock.writes[2], 'Idempotency-Key')).not.toBe(key)
})

test('editing the form after a failed attempt is a different request and gets a new key', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await openUserEdit(page)
  await page.unroute('**/api/users')
  let calls = 0
  await page.route('**/api/users', (r) => {
    const req = r.request()
    if (req.method() === 'GET') return r.fulfill({ json: { users: [userBody('John Doe', ETAG_1)], truncated: false } })
    mock.writes.push(req)
    calls++
    return calls === 1 ? r.abort('connectionreset') : r.fulfill({ status: 204 })
  })
  await saveCn(page, 'First')
  await expect(page.getByRole('dialog')).toBeVisible()
  await saveCn(page, 'Second')
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  expect(header(mock.writes[1], 'Idempotency-Key')).not.toBe(header(mock.writes[0], 'Idempotency-Key'))
})

test('422 idempotency_unsupported retries once without the key and stops asking', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await openUserEdit(page)
  await page.unroute('**/api/users')
  await page.route('**/api/users', (r) => {
    const req = r.request()
    if (req.method() === 'GET') return r.fulfill({ json: { users: [userBody('John Doe', ETAG_1)], truncated: false } })
    mock.writes.push(req)
    return header(req, 'Idempotency-Key')
      ? r.fulfill({ status: 422, json: envelope('Idempotency-Key is not enabled on this server', 'idempotency_unsupported') })
      : r.fulfill({ status: 204 })
  })
  await saveCn(page, 'Johnny Doe')
  await expect(page.getByText('Updated jdoe')).toBeVisible()
  expect(mock.writes).toHaveLength(2)
  expect(header(mock.writes[0], 'Idempotency-Key')).toBeTruthy()
  expect(header(mock.writes[1], 'Idempotency-Key')).toBeUndefined()
  expect(header(mock.writes[1], 'If-Match')).toBe(ETAG_1)
  // The server said no: later writes in this page session do not send a key at all.
  await page.getByRole('button', { name: 'Edit', exact: true }).click()
  await saveCn(page, 'Johnny Two')
  await expect.poll(() => mock.writes.length).toBe(3)
  expect(header(mock.writes[2], 'Idempotency-Key')).toBeUndefined()
})

test('idempotency error codes get understandable messages', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await openUserEdit(page)
  await page.unroute('**/api/users')
  const replies: Array<[number, string, string]> = [
    [409, 'idempotency_outcome_unknown', 'the outcome of this write is unknown'],
    [409, 'idempotency_key_conflict', 'still being processed'],
    [503, 'idempotency_capacity', 'record capacity reached'],
  ]
  let i = 0
  await page.route('**/api/users', (r) => {
    const req = r.request()
    if (req.method() === 'GET') return r.fulfill({ json: { users: [userBody('John Doe', ETAG_1)], truncated: false } })
    mock.writes.push(req)
    const [status, code, text] = replies[i++]
    return r.fulfill({ status, json: envelope(text, code, code !== 'idempotency_outcome_unknown') })
  })
  const dialog = page.getByRole('dialog')
  await saveCn(page, 'A')
  await expect(dialog).toContainText('could not confirm whether this change was applied')
  // The outcome is unknown: the user verifies, then a new submit is a new attempt.
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(dialog).toContainText('still being processed')
  expect(header(mock.writes[1], 'Idempotency-Key')).not.toBe(header(mock.writes[0], 'Idempotency-Key'))
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(dialog).toContainText('not accepting new changes')
  expect(header(mock.writes[2], 'Idempotency-Key')).toBe(header(mock.writes[1], 'Idempotency-Key'))
})

test('create sends a key but no If-Match', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: true })
  await page.goto('/users')
  await page.getByRole('button', { name: 'New user' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.locator('#uid').fill('newuser')
  await dialog.locator('#sn').fill('User')
  await dialog.locator('#cn').fill('New User')
  await page.getByRole('button', { name: 'Create user' }).click()
  await expect(page.getByText('Created user newuser')).toBeVisible()
  expect(mock.writes[0].method()).toBe('POST')
  expect(header(mock.writes[0], 'If-Match')).toBeUndefined()
  expect(header(mock.writes[0], 'Idempotency-Key')).toBeTruthy()
})

test('group edit and delete send If-Match; bulk member saves send none', async ({ page }) => {
  const mock = await mockServer(page, { idempotencyEnabled: false })
  await page.route('**/api/users', (r) =>
    r.request().method() === 'GET'
      ? r.fulfill({ json: { users: [userBody('John Doe', ETAG_1), { ...userBody('Jane Roe', ETAG_1), dn: `uid=jroe,ou=people,${BASE}`, uid: 'jroe' }], truncated: false } })
      : r.fulfill({ status: 204 }),
  )
  await page.goto('/groups')
  await page.getByRole('button', { name: 'Edit', exact: true }).click()
  await page.getByRole('dialog').locator('#group-description').fill('Staff 2')
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('Updated staff')).toBeVisible()
  expect(mock.writes[0].method()).toBe('PUT')
  expect(header(mock.writes[0], 'If-Match')).toBe(ETAG_1)

  await page.getByRole('button', { name: 'Delete', exact: true }).first().click()
  await page.locator('#confirm-text').fill('staff')
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByText('Deleted staff')).toBeVisible()
  expect(mock.writes[1].method()).toBe('DELETE')
  expect(header(mock.writes[1], 'If-Match')).toBe(ETAG_1)

  // Bulk member save: remove jdoe, add jroe, in parallel; neither may carry If-Match.
  const before = mock.writes.length
  await page.getByRole('button', { name: 'Manage members' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: /jdoe/ }).first().click()
  await dialog.getByRole('button', { name: 'Remove' }).click()
  await dialog.getByRole('button', { name: /jroe/ }).first().click()
  await dialog.getByRole('button', { name: 'Add' }).click()
  await dialog.getByRole('button', { name: /Save/ }).click()
  await expect.poll(() => mock.writes.length).toBeGreaterThanOrEqual(before + 2)
  for (const w of mock.writes.slice(before)) {
    expect(w.url()).toContain('/api/groups/members')
    expect(header(w, 'If-Match')).toBeUndefined()
  }
})
