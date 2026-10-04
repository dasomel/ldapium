import { test, expect } from '@playwright/test'
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('UI review requires local/disposable administrator credentials')

async function login(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
}

test('reviews named filters, selected navigation and mobile dialog focus without directory writes', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await login(page)
  await page.getByRole('link', { name: 'Users', exact: true }).click()
  await expect(page.getByRole('navigation', { name: 'Main navigation' }).locator('a[aria-current="page"]')).toHaveText('Users')
  await page.getByLabel('Filter users…', { exact: true }).fill('no-such-ui-review-user-938174')
  await page.getByRole('button', { name: 'Clear filter', exact: false }).click()
  await page.setViewportSize({ width: 390, height: 700 })
  await expect(page.locator('main')).toHaveJSProperty('clientWidth', 390)
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible()
  const newUser = page.getByRole('button', { name: 'New user', exact: true }).first()
  await newUser.click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  const box = await dialog.boundingBox()
  expect(box!.width).toBeLessThanOrEqual(390)
  expect(box!.height).toBeLessThanOrEqual(700)
  expect(box!.y).toBeGreaterThanOrEqual(0)
  await page.keyboard.press('Escape')
  await expect(dialog).toHaveCount(0)
  await expect(newUser).toBeFocused()
  await page.getByRole('button', { name: 'Open navigation' }).click()
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Groups', exact: true }).click()
  await expect(page).toHaveURL(/\/groups$/)
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByLabel('Filter groups…', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Open navigation' }).click()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused()
  expect(errors).toEqual([])
})

test('app integration tabs support keyboard navigation and explicit downstream save gates', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: 'App SSO permissions' }).click()
  const setup = page.getByRole('tab', { name: 'App and claims' })
  await expect(page.getByRole('tab', { name: 'Export and verify' })).toBeDisabled()
  await setup.focus()
  await page.keyboard.press('ArrowRight')
  await expect(setup).toBeFocused()
  await page.getByRole('button', { name: 'Add / manage methods' }).click()
  await expect(page.getByLabel('Method ID (custom- prefix)')).toBeFocused()
  await page.getByRole('button', { name: 'Close', exact: true }).click()
})
