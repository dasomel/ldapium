import { test, expect, type Page } from '@playwright/test'
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD
if (!identity || !password) throw new Error('Backup E2E requires administrator credentials')

// The backend is real (login, SPA); the backup endpoints are mocked so every job
// state can be rendered deterministically: running -> cancel, partial remote
// failure, abandoned/orphan.
const policy = { enabled: false, interval_minutes: 60, keep_days: 7, keep_count: 5, destinations: ['local'] }
const view = { connections: [], storage: {}, policies: { revision: 1, data: policy, logs: policy }, destinations: [{ id: 'local', name: 'Local', type: 'local' }], states: {}, running: false, logs_available: true }
const base = { kind: 'logs', trigger: 'manual', created_at: '2026-10-06T10:00:00Z', started_at: '2026-10-06T10:00:00Z' }

async function open(page: Page, jobs: unknown[]) {
  await page.route('**/api/v1/backups', route => route.fulfill({ json: view }))
  await page.route('**/api/v1/backups/jobs?*', route => route.fulfill({ json: { jobs } }))
  await page.goto('/login')
  await page.locator('#identity').fill(identity!)
  await page.locator('#password').fill(password!)
  await page.locator('#password').press('Enter')
  await expect(page).toHaveURL(/\/tree$/)
  await page.goto('/backups')
}

test('renders running, partially failed and abandoned jobs; only a running job can be cancelled', { tag: '@fixture' }, async ({ page }) => {
  const cancelled: string[] = []
  await page.route('**/api/v1/backups/jobs/*/cancel', route => { cancelled.push(route.request().url()); return route.fulfill({ status: 202, json: {} }) })
  await open(page, [
    { ...base, job_id: 'job-20261006T100000Z-aaaaaaaaaaaa', status: 'running' },
    { ...base, job_id: 'job-20261006T090000Z-bbbbbbbbbbbb', status: 'failed', finished_at: '2026-10-06T09:05:00Z', local: { verified: true },
      destinations: [{ id: 'local', status: 'succeeded' }, { id: 'remote-a', status: 'failed', error_code: 'transfer_failed' }, { id: 'remote-b', status: 'skipped', error_code: 'previous_destination_failed' }],
      artifact: { run_id: '20261006T090000Z-0123456789ab', files: [{ name: 'logs.tar.gz', bytes: 2048, sha256: 'x' }] } },
    { ...base, job_id: 'job-20261006T080000Z-cccccccccccc', status: 'abandoned', finished_at: '2026-10-06T08:30:00Z' },
  ])
  const list = page.getByRole('list', { name: 'Backup job list' })
  await expect(list.getByTestId('job-status')).toHaveText(['Running', 'Failed', 'Abandoned (restart)'])
  await expect(list.getByText('local: succeeded · remote-a: failed · remote-b: skipped')).toBeVisible()
  await expect(list.getByText('2.0 KiB')).toBeVisible()
  const buttons = list.getByRole('button', { name: 'Cancel' })
  await expect(buttons.nth(0)).toBeEnabled()
  await expect(buttons.nth(1)).toBeDisabled()
  await expect(buttons.nth(2)).toBeDisabled()
  await buttons.nth(0).click()
  await expect.poll(() => cancelled.length).toBe(1)
  expect(cancelled[0]).toContain('/jobs/job-20261006T100000Z-aaaaaaaaaaaa/cancel')
  await page.setViewportSize({ width: 390, height: 700 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('an orphan job after a restart cannot be cancelled and says why', { tag: '@fixture' }, async ({ page }) => {
  await open(page, [{ ...base, job_id: 'job-20261006T100000Z-dddddddddddd', status: 'running', orphan_suspected: true }])
  const list = page.getByRole('list', { name: 'Backup job list' })
  await expect(list.getByText('a worker from before the restart may still be running')).toBeVisible()
  await expect(list.getByRole('button', { name: 'Cancel' })).toBeDisabled()
})
