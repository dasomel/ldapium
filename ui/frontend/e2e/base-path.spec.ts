import { test, expect } from '@playwright/test'

// Change ui-base-path (D3, D4, D5): browser verification under a context path.
// Runs only when E2E_BASE_PATH is configured (e.g. E2E_BASE_PATH=/ldapium
// against a deployment with UI_BASE_PATH=/ldapium). At root or when unset,
// this spec is skipped so normal runs against root deployments stay green.
const rawBasePath = process.env.E2E_BASE_PATH
const basePath = rawBasePath ? rawBasePath.replace(/\/+$/, '') : ''
const identity = process.env.E2E_ADMIN_DN
const password = process.env.E2E_ADMIN_PASSWORD

test.describe('base path deployment', () => {
  test.skip(!basePath, 'E2E_BASE_PATH must be set to run base-path spec')

  test('renders login, scopes all network requests under base path, supports deep-link reload, and sets scoped session cookie', async ({ page, context }) => {
    if (!identity || !password) {
      throw new Error('Base path spec requires administrator credentials (E2E_ADMIN_DN, E2E_ADMIN_PASSWORD)')
    }

    const requests: string[] = []
    page.on('request', (req) => {
      requests.push(req.url())
    })

    // Relative navigation to 'login' using baseURL from playwright.config
    await page.goto('login')

    // Login page renders
    await expect(page.locator('#identity')).toBeVisible()
    await expect(page.locator('#password')).toBeVisible()
    const signInButton = page.getByRole('button', { name: 'Sign in' })
    await expect(signInButton).toBeVisible()

    // Log in
    await page.locator('#identity').fill(identity)
    await page.locator('#password').fill(password)
    await signInButton.click()
    await expect(page).toHaveURL(new RegExp(`${basePath}/tree$`), { timeout: 15_000 })

    // Deep link reload of a console route renders
    await page.getByRole('link', { name: 'Users', exact: true }).click()
    await expect(page).toHaveURL(new RegExp(`${basePath}/users$`))
    await expect(page.getByLabel('Filter users…', { exact: true })).toBeVisible()

    await page.reload()
    await expect(page).toHaveURL(new RegExp(`${basePath}/users$`))
    await expect(page.getByLabel('Filter users…', { exact: true })).toBeVisible()
    await expect(page.getByRole('navigation', { name: 'Main navigation' }).locator('a[aria-current="page"]')).toHaveText('Users')

    // Session cookie path equals E2E_BASE_PATH + '/'
    const cookies = await context.cookies()
    const sessionCookie = cookies.find((c) => c.name === 'ldapium_session')
    expect(sessionCookie).toBeDefined()
    expect(sessionCookie?.path).toBe(`${basePath}/`)

    // API docs (D7): curl examples carry the prefix; the Origin header stays scheme://host
    const origin = new URL(page.url()).origin
    await page.goto('api-docs')
    await expect(page.getByText(`curl -c cookies.txt -X POST '${origin}${basePath}/api/login'`)).toBeVisible()
    await page.getByRole('button', { name: /\/users/ }).first().click()
    await expect(page.getByText(new RegExp(`'${origin}${basePath}/api/`)).first()).toBeVisible()
    await expect(page.getByText(`Origin: ${origin}${basePath}`)).toHaveCount(0)

    // Every request the page makes stays under E2E_BASE_PATH (none at origin root)
    expect(requests.length).toBeGreaterThan(0)
    const rootOrOffBaseRequests = requests.filter((r) => {
      const u = new URL(r)
      if (u.origin !== origin) return false
      return !u.pathname.startsWith(`${basePath}/`) && u.pathname !== basePath
    })
    expect(rootOrOffBaseRequests).toEqual([])
  })
})
