import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test, expect } from '@playwright/test'
import { buildCurl, collectEndpoints, operationMachineScope, type OpenApiDoc } from '../src/lib/api-docs'

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

// --- shell-quoting of the generated curl (issue #224) ----------------------
// Real shell semantics, not string matching: the generated command line runs
// through /bin/sh with `curl` swapped for a printf that emits argv NUL-separated
// (NUL cannot occur in an argument, so embedded newlines stay unambiguous).
// A canary scratch dir proves no injected command ran, and a poisoned env var
// proves nothing was expanded.
const CANARY_ENV = 'LDAPIUM_CANARY_VAR'

function runAsArgv(cmd: string, cwd: string): string[] {
  expect(cmd.startsWith('curl ')).toBe(true)
  const out = execFileSync('/bin/sh', ['-c', cmd.replace(/^curl/, "printf '%s\\0'")], {
    cwd, env: { PATH: process.env.PATH ?? '/usr/bin:/bin', [CANARY_ENV]: 'EXPANDED' },
  })
  const parts = out.toString('utf8').split('\0')
  expect(parts.pop()).toBe('') // trailing terminator
  return parts
}

function withScratchDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'ldapium-shq-'))
  try {
    const result = fn(dir)
    // Any `touch`/redirect that escaped quoting would have left a file behind.
    expect(readdirSync(dir)).toEqual([])
    return result
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// Hostile in every position buildCurl interpolates: path placeholder, query
// example, header name (and thus value), JSON body, origin.
const hostile = (dir: string) => ({
  quote: "it's",
  cmdsub: `$(touch ${dir}/sub)`,
  backtick: `\`touch ${dir}/tick\``,
  chain: `x; touch ${dir}/semi & touch ${dir}/amp | touch ${dir}/pipe`,
  env: `$${CANARY_ENV} \${${CANARY_ENV}}`,
  mixed: `a b\nc\t"d" é 한글 \\ *`,
})

function hostileDoc(dir: string): { doc: OpenApiDoc; body: unknown } {
  const h = hostile(dir)
  const body = { ...h, nested: { list: [h.quote, h.cmdsub, h.backtick] } }
  const doc: OpenApiDoc = {
    openapi: '3.1.0',
    servers: [{ url: '/api' }],
    paths: {
      [`/things/{${h.cmdsub}}/{${h.quote}}`]: {
        put: {
          parameters: [
            { name: 'q', in: 'query', required: true, schema: { type: 'string', example: "it's (x) $HOME" } },
            { name: `X-A b'c$${CANARY_ENV}\`id\``, in: 'header', required: true, schema: { type: 'string' } },
            { name: `X-${h.chain}`, in: 'header', required: true, schema: { type: 'string' } },
            { name: 'X-한글 é', in: 'header', required: true, schema: { type: 'string' } },
            { name: 'Origin', in: 'header', required: true, schema: { type: 'string' } },
          ],
          requestBody: { content: { 'application/json': { schema: { type: 'object' }, example: body } } },
        },
      },
    },
  }
  return { doc, body }
}

test('generated curl keeps hostile values as single argv items under /bin/sh', () => {
  withScratchDir((dir) => {
    const h = hostile(dir)
    const { doc, body } = hostileDoc(dir)
    const [endpoint] = collectEndpoints(doc)
    const origin = `http://evil'host${h.cmdsub}`
    const argv = runAsArgv(buildCurl(doc, endpoint, origin), dir)

    // The whole argv, exactly: one item per value, nothing split, merged or expanded.
    expect(argv).toEqual([
      '-g', '-X', 'PUT',
      `${origin}/api/things/<${h.cmdsub}>/<${h.quote}>?q=it's%20(x)%20%24HOME`,
      '-b', 'cookies.txt',
      '-H', 'Content-Type: application/json',
      '-H', `X-A b'c$${CANARY_ENV}\`id\`: <X-A b'c$${CANARY_ENV}\`id\`>`,
      '-H', `X-${h.chain}: <X-${h.chain}>`,
      '-H', 'X-한글 é: <X-한글 é>',
      '-H', `Origin: ${origin}`,
      '-d', JSON.stringify(body),
    ])
    // The -d payload is intact JSON carrying every hostile string verbatim.
    const sent = JSON.parse(argv[argv.indexOf('-d') + 1]) as Record<string, unknown>
    expect(sent).toEqual(JSON.parse(JSON.stringify(body)))
    expect(sent.mixed).toBe(h.mixed)
    expect(argv.join('\0')).not.toContain('EXPANDED')
  })
})

test('api docs page copies a curl that survives /bin/sh with hostile spec values', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'unauthenticated' } }))
  await withScratchDirAsync(async (dir) => {
    const { doc, body } = hostileDoc(dir)
    await page.route('**/api/v1/openapi.json', (r) => r.fulfill({ json: doc }))
    await page.goto('/api-docs')
    await page.getByRole('button', { name: /\/things\// }).click()
    await page.getByRole('button', { name: 'Copy' }).last().click()
    const copied = await page.evaluate(() => navigator.clipboard.readText())
    const argv = runAsArgv(copied, dir)
    expect(argv[argv.indexOf('-d') + 1]).toBe(JSON.stringify(body))
    expect(argv.filter((a) => a === '-H')).toHaveLength(5)
    expect(argv.join('\0')).not.toContain('EXPANDED')
    expect(argv[3]).toContain("?q=it's%20(x)%20%24HOME")
  })
})

async function withScratchDirAsync(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'ldapium-shq-'))
  try {
    await fn(dir)
    expect(readdirSync(dir)).toEqual([])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// --- description toggle and Korean counts (issue #224) ---------------------
const longDescription = Array.from({ length: 40 }, (_, i) => `Line ${i + 1} of a long API description.`).join('\n')

test('description toggle appears only when clamped, with aria-controls', async ({ page }) => {
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'x' } }))
  const serve = (description: string) => page.route('**/api/v1/openapi.json', (r) => r.fulfill({ json: { ...SPEC, info: { ...SPEC.info, description } } }))

  await serve('One short line.')
  await page.goto('/api-docs')
  await expect(page.getByRole('heading', { name: 'Mock API' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Show more' })).toHaveCount(0)

  await page.unroute('**/api/v1/openapi.json')
  await serve(longDescription)
  await page.goto('/api-docs')
  const toggle = page.getByRole('button', { name: 'Show more' })
  await expect(toggle).toBeVisible()
  await expect(toggle).toHaveAttribute('aria-expanded', 'false')
  const controls = await toggle.getAttribute('aria-controls')
  expect(controls).toBeTruthy()
  const target = page.locator(`#${controls}`)
  await expect(target).toContainText('Line 40') // full text stays in the DOM while clamped
  const height = async () => (await target.boundingBox())!.height

  const collapsed = await height()
  await toggle.focus()
  await page.keyboard.press('Enter') // native button: keyboard operable
  await expect(page.getByRole('button', { name: 'Show less' })).toHaveAttribute('aria-expanded', 'true')
  expect(await height()).toBeGreaterThan(collapsed)
  await page.keyboard.press('Enter')
  await expect(page.getByRole('button', { name: 'Show more' })).toHaveAttribute('aria-expanded', 'false')
})

test('endpoint counts read naturally in Korean', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('language', 'ko'))
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'x' } }))
  await page.route('**/api/v1/openapi.json', (r) => r.fulfill({ json: SPEC }))
  await page.goto('/api-docs')
  await expect(page.getByRole('heading', { name: /^users/ })).toContainText('1개 엔드포인트')
  await expect(page.getByRole('heading', { name: /^users/ })).not.toContainText('1 개')
})

// The served spec is embedded from the backend; the machine-callable set is
// derived from it (security lists machineBearer), never hard-coded here.
const SERVED = JSON.parse(readFileSync(join(process.cwd(), '../backend/internal/httpapi/openapi/openapi.json'), 'utf8')) as OpenApiDoc

test('machine badge maps exactly the machineBearer operations, with their x-machine-scope', () => {
  const eps = collectEndpoints(SERVED)
  const expected = eps.filter((e) => e.op.security?.some((s) => 'machineBearer' in s))
  expect(expected).toHaveLength(8)
  expect(eps.filter((e) => e.machineScope).map((e) => e.id).sort()).toEqual(expected.map((e) => e.id).sort())
  for (const e of expected) {
    expect(e.op['x-machine-scope'], e.id).toBeTruthy()
    expect(e.machineScope, e.id).toBe(e.op['x-machine-scope'])
    expect(operationMachineScope(e.op)).toBe(e.machineScope)
  }
  expect(eps.filter((e) => !e.machineScope && e.op.security?.length !== 0)).not.toHaveLength(0)
})

test('api docs page shows the machine badge only on machineBearer ops and states default-off', async ({ page }) => {
  await page.route('**/api/me', (r) => r.fulfill({ status: 401, json: { error: 'x' } }))
  await page.route('**/api/v1/openapi.json', (r) => r.fulfill({ json: SERVED }))
  await page.goto('/api-docs')
  await expect(page.getByText(/when the server enables machine auth \(off by default\)/).first()).toBeVisible()
  const expected = collectEndpoints(SERVED).filter((e) => e.machineScope)
  await expect(page.getByRole('button').getByText(/^Machine-callable: /)).toHaveCount(expected.length)
  for (const e of expected) {
    const row = page.getByRole('button', { name: new RegExp(`${e.path.replace(/[/{}]/g, '\\$&')}.*Machine-callable: ${e.machineScope!.replace(/\./g, '\\.')}`) })
    await expect(row.first()).toBeVisible()
  }
})
