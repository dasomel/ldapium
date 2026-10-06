import { test, expect, type Page } from '@playwright/test'

function envelope(error: string, code: string, retryable = false, message = error) {
  return { error, message, code, requestId: 'req-cursor-1', retryable }
}

async function mockSession(page: Page) {
  await page.route('**/api/auth/config', (r) => r.fulfill({ json: { mode: 'ldap' } }))
  await page.route('**/api/me', (r) => r.fulfill({ json: { dn: 'cn=admin,dc=example,dc=org' } }))
  await page.route('**/api/server-settings', (r) =>
    r.fulfill({ json: { applicationVersion: 'test', baseDn: 'dc=example,dc=org' } }),
  )
}

test.describe('Cursor pagination and error recovery', () => {
  test('navigates next and previous using cursor stack', async ({ page }) => {
    await mockSession(page)
    const calls: string[] = []

    await page.route('**/api/users*', (r) => {
      const url = new URL(r.request().url())
      const cursor = url.searchParams.get('cursor')
      calls.push(cursor ?? 'page1')

      if (!cursor) {
        return r.fulfill({
          json: {
            users: Array.from({ length: 10 }, (_, i) => ({
              dn: `uid=user-${i + 1},dc=example,dc=org`,
              uid: `user-${i + 1}`,
              cn: `User ${i + 1}`,
              sn: 'Test',
              locked: false,
            })),
            truncated: false,
            hasMore: true,
            nextCursor: 'cur-page-2',
          },
        })
      }
      if (cursor === 'cur-page-2') {
        return r.fulfill({
          json: {
            users: Array.from({ length: 5 }, (_, i) => ({
              dn: `uid=user-${i + 11},dc=example,dc=org`,
              uid: `user-${i + 11}`,
              cn: `User ${i + 11}`,
              sn: 'Test',
              locked: false,
            })),
            truncated: false,
            hasMore: false,
          },
        })
      }
      return r.fulfill({ status: 400, json: envelope('invalid cursor', 'cursor_invalid') })
    })

    await page.goto('/users')
    const rows = page.locator('tbody tr')
    const nav = page.getByRole('navigation', { name: 'User list pagination' })

    await expect(rows).toHaveCount(10)
    await expect(rows.first()).toContainText('user-1')
    await expect(nav.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled()
    await expect(nav.getByRole('button', { name: 'Next', exact: true })).toBeEnabled()
    await expect(nav.locator('[aria-current="page"]')).toHaveText('1')

    // Click Next to navigate to page 2
    await nav.getByRole('button', { name: 'Next', exact: true }).click()
    await expect(rows).toHaveCount(5)
    await expect(rows.first()).toContainText('user-11')
    await expect(nav.getByRole('button', { name: 'Previous', exact: true })).toBeEnabled()
    await expect(nav.getByRole('button', { name: 'Next', exact: true })).toBeDisabled()
    await expect(nav.locator('[aria-current="page"]')).toHaveText('2')

    // Click Previous to return to page 1 via cursor stack
    await nav.getByRole('button', { name: 'Previous', exact: true }).click()
    await expect(rows).toHaveCount(10)
    await expect(rows.first()).toContainText('user-1')
    await expect(nav.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled()
    await expect(nav.locator('[aria-current="page"]')).toHaveText('1')

    const uniqueCalls = calls.filter((c, i) => i === 0 || c !== calls[i - 1])
    expect(uniqueCalls).toEqual(['page1', 'cur-page-2', 'page1'])
  })

  test('search query q resets the cursor stack to page 1', async ({ page }) => {
    await mockSession(page)
    const queryCalls: Array<{ q: string; cursor: string | null }> = []

    await page.route('**/api/users*', (r) => {
      const url = new URL(r.request().url())
      const q = url.searchParams.get('q') ?? ''
      const cursor = url.searchParams.get('cursor')
      queryCalls.push({ q, cursor })

      if (q === 'alice') {
        return r.fulfill({
          json: {
            users: [
              {
                dn: 'uid=alice,dc=example,dc=org',
                uid: 'alice',
                cn: 'Alice Smith',
                sn: 'Smith',
                locked: false,
              },
            ],
            truncated: false,
            hasMore: false,
          },
        })
      }

      if (!cursor) {
        return r.fulfill({
          json: {
            users: [{ dn: 'uid=u1,dc=example,dc=org', uid: 'u1', cn: 'User 1', sn: 'Test', locked: false }],
            truncated: false,
            hasMore: true,
            nextCursor: 'cur-2',
          },
        })
      }
      return r.fulfill({
        json: {
          users: [{ dn: 'uid=u2,dc=example,dc=org', uid: 'u2', cn: 'User 2', sn: 'Test', locked: false }],
          truncated: false,
          hasMore: false,
        },
      })
    })

    await page.goto('/users')
    const nav = page.getByRole('navigation', { name: 'User list pagination' })
    await nav.getByRole('button', { name: 'Next', exact: true }).click()
    await expect(nav.locator('[aria-current="page"]')).toHaveText('2')

    // Filter resets cursor stack to page 1
    await page.getByLabel('Filter users…', { exact: true }).fill('alice')
    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText('alice')
    await expect(nav.locator('[aria-current="page"]')).toHaveText('1')
    await expect(nav.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled()

    const lastCall = queryCalls[queryCalls.length - 1]
    expect(lastCall.q).toBe('alice')
    expect(lastCall.cursor).toBeNull()
  })

  test('empty page with hasMore:true auto-advances to the next page', async ({ page }) => {
    await mockSession(page)
    const cursorCalls: Array<string | null> = []

    await page.route('**/api/users*', (r) => {
      const url = new URL(r.request().url())
      const cursor = url.searchParams.get('cursor')
      cursorCalls.push(cursor)

      // First call returns empty items with hasMore: true
      if (!cursor) {
        return r.fulfill({
          json: {
            users: [],
            truncated: false,
            hasMore: true,
            nextCursor: 'cur-auto-next',
          },
        })
      }
      // Auto-advanced call returns populated page
      return r.fulfill({
        json: {
          users: [
            {
              dn: 'uid=survivor,dc=example,dc=org',
              uid: 'survivor',
              cn: 'Survivor User',
              sn: 'Survivor',
              locked: false,
            },
          ],
          truncated: false,
          hasMore: false,
        },
      })
    })

    await page.goto('/users')
    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText('survivor')
    const uniqueCursorCalls = cursorCalls.filter((c, i) => i === 0 || c !== cursorCalls[i - 1])
    expect(uniqueCursorCalls).toEqual([null, 'cur-auto-next'])
  })

  test('400 cursor_invalid restarts from the first page', async ({ page }) => {
    await mockSession(page)
    let callCount = 0

    await page.route('**/api/users*', (r) => {
      const url = new URL(r.request().url())
      const cursor = url.searchParams.get('cursor')
      callCount++

      if (cursor === 'corrupted-cursor') {
        return r.fulfill({
          status: 400,
          json: envelope('invalid cursor', 'cursor_invalid'),
        })
      }

      return r.fulfill({
        json: {
          users: [
            {
              dn: `uid=page1-user,dc=example,dc=org`,
              uid: 'page1-user',
              cn: 'Page 1 User',
              sn: 'User',
              locked: false,
            },
          ],
          truncated: false,
          hasMore: true,
          nextCursor: 'corrupted-cursor',
        },
      })
    })

    await page.goto('/users')
    const rows = page.locator('tbody tr')
    const nav = page.getByRole('navigation', { name: 'User list pagination' })
    await expect(rows).toHaveCount(1)

    // Click Next, triggering 400 cursor_invalid on corrupted-cursor
    await nav.getByRole('button', { name: 'Next', exact: true }).click()

    // UI should restart from page 1
    await expect(rows.first()).toContainText('page1-user')
    await expect(nav.locator('[aria-current="page"]')).toHaveText('1')
    await expect(nav.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled()
    // initial page 1, corrupted page 2, restarted page 1
    await expect.poll(() => callCount).toBeGreaterThanOrEqual(3)
  })

  test('422 size_limit_exceeded displays narrow-your-search hint', async ({ page }) => {
    await mockSession(page)
    await page.route('**/api/users*', (r) =>
      r.fulfill({
        status: 422,
        json: envelope(
          'directory size limit reached; narrow with q, use an identity exempt from the limit, or ask the operator to set LDAP_PAGED_TOTAL_LIMIT',
          'size_limit_exceeded',
        ),
      }),
    )

    await page.goto('/users')
    await expect(page.getByRole('alert')).toBeVisible()
    await expect(page.getByText('directory size limit reached').first()).toBeVisible()
    await expect(page.getByText(/Narrow your search/i)).toBeVisible()
  })

  test('503 scan_timeout shows retry action and recovers upon retry', async ({ page }) => {
    await mockSession(page)
    let failing = true // dev StrictMode sends the first request twice, so gate on state, not a count

    await page.route('**/api/users*', (r) => {
      if (failing) {
        return r.fulfill({
          status: 503,
          headers: { 'Retry-After': '30' },
          json: envelope('scan timeout', 'scan_timeout', true),
        })
      }
      return r.fulfill({
        json: {
          users: [{ dn: 'uid=recovered,dc=example,dc=org', uid: 'recovered', cn: 'Recovered User', sn: 'User', locked: false }],
          truncated: false,
          hasMore: false,
        },
      })
    })

    await page.goto('/users')
    await expect(page.getByRole('alert')).toBeVisible()
    await expect(page.getByText('scan timeout')).toBeVisible()

    const retryBtn = page.getByRole('button', { name: 'Retry', exact: true })
    await expect(retryBtn).toBeVisible()
    failing = false
    await retryBtn.click()

    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText('recovered')
    await expect(page.getByRole('alert')).toHaveCount(0)
  })

  const user = (uid: string) => ({ dn: `uid=${uid},dc=example,dc=org`, uid, cn: uid, sn: 'T', locked: false })

  test('a slower older search response does not overwrite the newer rows', async ({ page }) => {
    await mockSession(page)
    const qs: string[] = []
    let releaseOld!: () => void
    const oldGate = new Promise<void>((res) => (releaseOld = res))
    let oldSent = false

    await page.route('**/api/users*', async (r) => {
      const q = new URL(r.request().url()).searchParams.get('q') ?? ''
      qs.push(q)
      if (q === 'old') {
        await oldGate
        await r.fulfill({ json: { users: [user('old-row')], truncated: false, hasMore: false } })
        oldSent = true
        return
      }
      await r.fulfill({ json: { users: [user(q ? 'new-row' : 'initial')], truncated: false, hasMore: false } })
    })

    await page.goto('/users')
    const filter = page.getByLabel('Filter users…', { exact: true })
    const rows = page.locator('tbody tr')
    await expect(rows.first()).toContainText('initial')

    await filter.fill('old')
    await expect.poll(() => qs.includes('old')).toBe(true)
    await filter.fill('new')
    await expect(rows.first()).toContainText('new-row')

    releaseOld()
    await expect.poll(() => oldSent).toBe(true)
    await page.waitForTimeout(300) // let the stale response reach the page
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText('new-row')
  })

  test('a stale error does not re-request with the old query', async ({ page }) => {
    await mockSession(page)
    const qs: string[] = []
    let releaseOld!: () => void
    const oldGate = new Promise<void>((res) => (releaseOld = res))
    let oldSent = false

    await page.route('**/api/users*', async (r) => {
      const q = new URL(r.request().url()).searchParams.get('q') ?? ''
      qs.push(q)
      if (q === 'old') {
        await oldGate
        await r.fulfill({ status: 400, json: envelope('invalid cursor', 'cursor_invalid') })
        oldSent = true
        return
      }
      await r.fulfill({ json: { users: [user(q ? 'new-row' : 'initial')], truncated: false, hasMore: false } })
    })

    await page.goto('/users')
    const filter = page.getByLabel('Filter users…', { exact: true })
    await expect(page.locator('tbody tr').first()).toContainText('initial')
    await filter.fill('old')
    await expect.poll(() => qs.includes('old')).toBe(true)
    await filter.fill('new')
    await expect(page.locator('tbody tr').first()).toContainText('new-row')
    const before = qs.length
    releaseOld()
    await expect.poll(() => oldSent).toBe(true)
    await page.waitForTimeout(300)
    expect(qs.length).toBe(before)
    await expect(page.locator('tbody tr').first()).toContainText('new-row')
  })

  test('leaving the page during an in-flight request stops auto-advance', async ({ page }) => {
    await mockSession(page)
    const cursorCalls: string[] = []
    let firstPageCalls = 0
    let releaseUsers!: () => void
    const gate = new Promise<void>((res) => (releaseUsers = res))
    let sent = 0

    await page.route('**/api/users*', async (r) => {
      const cursor = new URL(r.request().url()).searchParams.get('cursor')
      if (cursor) {
        cursorCalls.push(cursor)
        return r.fulfill({ json: { users: [user('late')], truncated: false, hasMore: false } })
      }
      firstPageCalls++
      await gate
      await r.fulfill({ json: { users: [], truncated: false, hasMore: true, nextCursor: 'cur-x' } })
      sent++
    })
    await page.route('**/api/groups*', (r) => r.fulfill({ json: { groups: [], truncated: false, hasMore: false } }))

    await page.goto('/users')
    await expect.poll(() => firstPageCalls).toBeGreaterThan(0)
    await page.getByRole('link', { name: 'Groups' }).first().click()
    await expect(page).toHaveURL(/\/groups/)

    releaseUsers()
    await expect.poll(() => sent).toBe(firstPageCalls)
    await page.waitForTimeout(300)
    expect(cursorCalls).toEqual([])
  })

  test('consecutive empty pages stop at the cap and show the narrow/retry hint', async ({ page }) => {
    await mockSession(page)
    let advances = 0
    await page.route('**/api/users*', (r) => {
      const hasCursor = new URL(r.request().url()).searchParams.has('cursor')
      if (hasCursor) advances++
      return r.fulfill({ json: { users: [], truncated: false, hasMore: true, nextCursor: `cur-${advances}` } })
    })

    await page.goto('/users')
    await expect(page.getByText(/narrow your search with a more specific filter/i)).toBeVisible()
    await page.waitForTimeout(300)
    expect(advances).toBe(20)
  })

  test('a failed next page is retried with the failed cursor, not the last good one', async ({ page }) => {
    await mockSession(page)
    const cursors: Array<string | null> = []
    let failed = false

    await page.route('**/api/users*', (r) => {
      const cursor = new URL(r.request().url()).searchParams.get('cursor')
      cursors.push(cursor)
      if (!cursor) {
        return r.fulfill({
          json: { users: [user('first-page')], truncated: false, hasMore: true, nextCursor: 'cur-2' },
        })
      }
      if (!failed) {
        failed = true
        return r.fulfill({
          status: 503,
          headers: { 'Retry-After': '30' },
          json: envelope('scan timeout', 'scan_timeout', true),
        })
      }
      return r.fulfill({ json: { users: [user('second-page')], truncated: false, hasMore: false } })
    })

    await page.goto('/users')
    const nav = page.getByRole('navigation', { name: 'User list pagination' })
    await expect(page.locator('tbody tr').first()).toContainText('first-page')
    await nav.getByRole('button', { name: 'Next', exact: true }).click()
    await expect(page.getByText('scan timeout')).toBeVisible()
    await page.getByRole('button', { name: 'Retry', exact: true }).click()

    await expect(page.locator('tbody tr').first()).toContainText('second-page')
    await expect(nav.locator('[aria-current="page"]')).toHaveText('2')
    expect(cursors.filter(Boolean)).toEqual(['cur-2', 'cur-2'])
  })

  test('a rejected group delete shows the error instead of failing silently', async ({ page }) => {
    await mockSession(page)
    const unhandled: string[] = []
    page.on('pageerror', (e) => unhandled.push(e.message))
    await page.route('**/api/groups*', (r) => {
      if (r.request().method() === 'DELETE') {
        return r.fulfill({ status: 500, json: envelope('delete exploded', 'internal') })
      }
      return r.fulfill({
        json: {
          groups: [{ dn: 'cn=devs,ou=groups,dc=example,dc=org', cn: 'devs', description: '', members: [] }],
          truncated: false,
          hasMore: false,
        },
      })
    })

    await page.goto('/groups')
    await page.getByRole('button', { name: 'Delete', exact: true }).first().click()
    await page.locator('#confirm-text').fill('devs')
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'delete exploded' })).toBeVisible()
    expect(unhandled).toEqual([])
  })

  test('renders narrow viewport at 390px without horizontal scroll and captures screenshot', async ({ page }) => {
    await mockSession(page)
    await page.route('**/api/groups*', (r) =>
      r.fulfill({
        json: {
          groups: [
            {
              dn: 'cn=developers,ou=groups,dc=example,dc=org',
              cn: 'developers',
              description: 'Software development engineering team',
              members: ['uid=alice,dc=example,dc=org'],
            },
            {
              dn: 'cn=operations,ou=groups,dc=example,dc=org',
              cn: 'operations',
              description: 'Site reliability and IT operations',
              members: [],
            },
          ],
          truncated: false,
          hasMore: true,
          nextCursor: 'cur-next',
        },
      }),
    )

    await page.setViewportSize({ width: 390, height: 700 })
    await page.goto('/groups')
    const nav = page.getByRole('navigation', { name: 'Group pagination' })
    await expect(nav).toBeVisible()

    // Verify layout does not overflow 390px horizontally
    const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)
    expect(noOverflow).toBe(true)

    // Capture screenshot of the narrow viewport
    await page.screenshot({ path: 'test-results/narrow-viewport.png', fullPage: true })
  })

  test('a write response that lands after a new search does not refresh with the old query', async ({ page }) => {
    await mockSession(page)
    const qs: string[] = []
    let releaseLock: () => void = () => undefined
    const lockGate = new Promise<void>((resolve) => (releaseLock = resolve))
    const user = (uid: string) => ({ dn: `uid=${uid},dc=example,dc=org`, uid, cn: uid, sn: 'T', locked: false })

    await page.route('**/api/users/lock', async (r) => {
      await lockGate
      await r.fulfill({ status: 204 })
    })
    await page.route('**/api/users?*', (r) => {
      const q = new URL(r.request().url()).searchParams.get('q') ?? ''
      qs.push(q)
      return r.fulfill({
        json: { users: [user(q === 'new' ? 'fresh-row' : 'initial-row')], truncated: false, hasMore: false },
      })
    })

    await page.goto('/users')
    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText('initial-row')

    await rows.first().getByRole('button', { name: 'Disable account' }).click()
    await page.getByPlaceholder('Filter users…').fill('new')
    await expect(rows.first()).toContainText('fresh-row')
    expect(qs.slice(qs.indexOf('new'))).toEqual(['new'])

    releaseLock()
    // Give the stale post-write refresh (if any) time to fire and settle.
    await page.waitForTimeout(500)
    await expect(rows.first()).toContainText('fresh-row')
    // Dev StrictMode may double the initial load; nothing may follow the 'new' search.
    expect(qs.slice(qs.indexOf('new'))).toEqual(['new'])
  })
})
