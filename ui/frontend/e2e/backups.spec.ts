import { test, expect } from '@playwright/test'
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('Backup E2E requires administrator credentials')

test('saves separate backup policies and executes a real verified log backup', { tag: '@fixture' }, async ({ page }) => {
  test.setTimeout(120000)
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  await page.goto('/backups')
  await expect(page.getByRole('heading', { name: 'Backup management' })).toBeVisible()
  const data = page.getByRole('heading', { name: 'Data backup', exact: true }).locator('../..')
  const logs = page.getByRole('heading', { name: 'Log backup', exact: true }).locator('../..')
  const keep = logs.getByLabel('Retention (days)', { exact: true })
  const original = Number(await keep.inputValue())
  await keep.fill(String(original === 7 ? 6 : 7))
  await expect(logs.getByRole('button', { name: 'Back up now' })).toBeDisabled()
  await page.getByRole('button', { name: 'Save policies' }).click()
  await expect(page.getByText('Backup policies saved.', { exact: true })).toBeVisible()
  await page.reload()
  await expect(keep).toHaveValue(String(original === 7 ? 6 : 7))
  await expect(data.getByLabel('Retention (days)', { exact: true })).toHaveValue('30')
  await expect(logs.getByLabel('Scheduled backups', { exact: true })).not.toBeChecked()
  const before = await (await page.request.get('/api/v1/backups')).json()
  const previousRun = before.states.logs?.run_id
  const response = page.waitForResponse(res => res.url().endsWith('/api/v1/backups/jobs/logs') && res.request().method() === 'POST')
  await logs.getByRole('button', { name: 'Back up now' }).click()
  expect((await response).status()).toBe(202)
  await expect.poll(async () => {
    const current = await (await page.request.get('/api/v1/backups')).json()
    return current.states.logs?.status === 'succeeded' && current.states.logs.run_id !== previousRun
  }, { timeout: 60000 }).toBe(true)
  await expect(logs.getByText('Verified', { exact: true })).toBeVisible({ timeout: 10000 })
  await page.setViewportSize({ width: 390, height: 700 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('shows backup sizes and manages remote connection settings without returning secrets', { tag: '@fixture' }, async ({ page }) => {
  test.setTimeout(90000)
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  await page.goto('/backups')
  await expect(page.getByText('Local retained size', { exact: true })).toHaveCount(2)
  await expect(page.getByText('Latest retained copy size', { exact: true })).toHaveCount(2)
  const suffix = Date.now().toString()
  const created: string[] = []
  try {
    for (const type of ['s3', 'ftp', 'sftp']) {
      const id = `e2e-${type}-${suffix}`
      await page.getByRole('button', { name: 'Add destination', exact: true }).click()
      const form = page.locator('form')
      await form.getByLabel('Destination ID', { exact: true }).fill(id)
      await form.getByLabel('Display name', { exact: true }).fill(`E2E ${type}`)
      await form.getByLabel('Transport', { exact: true }).selectOption(type)
      if (type === 's3') {
        await form.getByLabel('Bucket', { exact: true }).fill('ldapium-e2e')
        await form.getByLabel('Access key', { exact: true }).fill('fake-access-key')
        await form.getByLabel('Secret key', { exact: true }).fill('fake-write-only-secret')
      } else {
        await form.getByLabel('Host', { exact: true }).fill('backup.example.invalid')
        await form.getByLabel('Username', { exact: true }).fill('backup')
        await form.getByLabel('Password', { exact: true }).fill('fake-write-only-secret')
        if (type === 'ftp') await form.getByLabel('Allow plaintext FTP (credentials and data are unencrypted)', { exact: true }).check()
        else await form.getByLabel('SSH server host keys (known_hosts)', { exact: true }).fill('backup.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyPublicKeyForUIFixtureOnly')
      }
      const saved = page.waitForResponse(r => r.url().endsWith('/backups/connections') && r.request().method() === 'PUT')
      await form.getByRole('button', { name: 'Save connection', exact: true }).click()
      const response = await saved
      expect(response.status()).toBe(200)
      const body = await response.text()
      expect(body).not.toContain('fake-write-only-secret')
      expect(body).not.toContain('fake-access-key')
      created.push(id)
      await expect(form).toHaveCount(0)
      const row = page.locator('strong', { hasText: `E2E ${type}` }).locator('../..')
      await expect(row.getByText('Credentials stored', { exact: true })).toBeVisible()
      await row.getByRole('button', { name: 'Edit', exact: true }).click()
      await expect(page.locator('form').getByLabel(type === 's3' ? 'Secret key' : 'Password', { exact: true })).toHaveValue('')
      await page.locator('form').getByRole('button', { name: 'Save connection', exact: true }).click()
      await expect(page.locator('form')).toHaveCount(0)
    }
    await page.reload()
    await expect(page.getByText('Credentials stored', { exact: true })).toHaveCount(3)
    await page.setViewportSize({ width: 390, height: 844 })
    await expect(page.getByRole('heading', { name: 'Remote destination settings' })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  } finally {
    for (const id of created) {
      const view = await (await page.request.get('/api/v1/backups')).json()
      const result = await page.request.delete(`/api/v1/backups/connections/${id}`, { headers: { 'Content-Type': 'application/json', 'Origin': new URL(page.url()).origin, 'If-Match': `"${view.policies.revision}"` } })
      expect(result.status()).toBe(200)
    }
  }
})
