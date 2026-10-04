import { test, expect } from '@playwright/test'

// Mocked spec, no live backend or login: /api-docs is a public route, so this
// also proves the page renders for a logged-out visitor.
const SPEC = {
  openapi: '3.1.0',
  info: { title: 'Mock API', version: '9.9.9' },
  servers: [{ url: '/api' }],
  tags: [{ name: 'auth', description: 'Session' }, { name: 'users' }],
  paths: {
    '/login': {
      post: {
        tags: ['auth'], summary: 'Sign in', security: [],
        requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Login' } } } },
        responses: { '200': { description: 'ok' }, '401': { description: 'bad credentials' } },
      },
    },
    '/users': {
      get: {
        tags: ['users'], summary: 'List users',
        parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'ok' } },
      },
    },
  },
  components: { schemas: { Login: { type: 'object', required: ['identity'], properties: { identity: { type: 'string' }, password: { type: 'string' }, self: { $ref: '#/components/schemas/Login' } } } } },
}

test('api docs renders groups, filters, and builds curl', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'unauthenticated' } }))
  await page.route('**/api/v1/openapi.json', (r) => r.fulfill({ json: SPEC }))
  await page.goto('/api-docs')

  await expect(page.getByRole('heading', { name: 'Mock API' })).toBeVisible()
  await expect(page.getByRole('heading', { name: /^auth/ })).toBeVisible()
  await expect(page.getByRole('heading', { name: /^users/ })).toBeVisible()

  await page.getByLabel('Search endpoints').fill('list users')
  await expect(page.getByRole('heading', { name: /^auth/ })).toHaveCount(0)
  await page.getByLabel('Search endpoints').fill('')

  await page.getByRole('button', { name: /\/users/ }).click()
  await expect(page.getByRole('button', { name: /\/users/ })).toHaveAttribute('aria-expanded', 'true')
  await page.getByRole('button', { name: 'Copy' }).last().click()
  const copied = await page.evaluate(() => navigator.clipboard.readText())
  expect(copied).toContain("curl -g -X GET")
  expect(copied).toContain('/api/users?q=string')
  expect(copied).toContain('-b cookies.txt')
})

test('api docs curl for a write op keeps path placeholder, required headers, and body', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  const spec = {
    ...SPEC,
    paths: {
      '/applications/{id}/profile': {
        put: {
          tags: ['users'], summary: 'Save profile',
          parameters: [
            { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
            { name: 'Origin', in: 'header', required: true, schema: { type: 'string' } },
            { name: 'If-Match', in: 'header', required: true, schema: { type: 'string' } },
          ],
          requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Login' } } } },
          responses: { '200': { description: 'ok' } },
        },
      },
    },
  }
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'unauthenticated' } }))
  await page.route('**/api/v1/openapi.json', (r) => r.fulfill({ json: spec }))
  await page.goto('/api-docs')

  await page.getByRole('button', { name: /\/applications/ }).click()
  await page.getByRole('button', { name: 'Copy' }).last().click()
  const copied = await page.evaluate(() => navigator.clipboard.readText())
  const origin = new URL(page.url()).origin
  expect(copied).toContain('curl -g -X PUT')
  expect(copied).toContain(`'${origin}/api/applications/<id>/profile'`)
  expect(copied).toContain(`-H 'Origin: ${origin}'`)
  expect(copied).toContain(`-H 'If-Match: "<etag>"'`)
  expect(copied).toContain("-H 'Content-Type: application/json'")
  expect(copied).toContain('-d ')
})

test('api docs shows an error state when the spec is missing', async ({ page }) => {
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'x' } }))
  await page.route('**/api/v1/openapi.json', (r) => r.fulfill({ status: 404, body: 'nope' }))
  await page.goto('/api-docs')
  await expect(page.getByText('API specification is not available')).toBeVisible()
})
