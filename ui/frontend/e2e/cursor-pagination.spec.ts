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
    expect(callCount).toBeGreaterThanOrEqual(3) // initial page 1, corrupted page 2, restarted page 1
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
    let tries = 0

    await page.route('**/api/users*', (r) => {
      tries++
      if (tries === 1) {
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
    await retryBtn.click()

    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText('recovered')
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
})
