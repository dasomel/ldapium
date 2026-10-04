import { test, expect } from '@playwright/test'
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('Group pagination requires administrator credentials')

test('paginates groups, resets search/size and edits the visible keyboard row', async ({ page }) => {
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  const mutations: string[] = []
  await page.route('**/api/groups', route => {
    if (route.request().method() !== 'GET') { mutations.push(route.request().method()); return route.abort() }
    return route.fulfill({ json: {
    groups: Array.from({ length: 23 }, (_, index) => ({ dn: `cn=group-${index + 1},ou=groups,dc=example,dc=org`,
      cn: `group-${index + 1}`, description: `Description ${index + 1}`, members: [] })), truncated: false,
  } }) })
  await page.goto('/groups')
  const rows = page.locator('tbody tr')
  const nav = page.getByRole('navigation', { name: 'Group pagination' })
  await expect(rows).toHaveCount(10)
  await expect(nav.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled()
  await nav.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(rows.first()).toContainText('group-11')
  await rows.first().focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByRole('dialog').locator('#group-cn')).toHaveValue('group-11')
  await page.keyboard.press('Escape')
  await nav.getByRole('button', { name: 'Last page', exact: true }).click()
  await expect(rows).toHaveCount(3)
  await expect(nav.getByRole('button', { name: 'Next', exact: true })).toBeDisabled()
  await page.getByLabel('Filter groups…', { exact: true }).fill('Description 2')
  await expect(rows).toHaveCount(5)
  await expect(nav.locator('[aria-current="page"]')).toHaveText('1')
  await page.getByLabel('Filter groups…', { exact: true }).fill('')
  await page.getByLabel('Rows per page', { exact: true }).selectOption('20')
  await expect(rows).toHaveCount(20)
  await nav.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(rows).toHaveCount(3)
  await page.getByLabel('Rows per page', { exact: true }).selectOption('50')
  await expect(rows).toHaveCount(23)
  await page.setViewportSize({ width: 390, height: 700 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.getByLabel('Filter groups…', { exact: true }).fill('does-not-exist')
  await expect(rows).toHaveCount(0)
  await expect(nav).toHaveCount(0)
  expect(mutations).toEqual([])
})
