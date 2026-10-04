// Pure helpers for the /api-docs page. The backend serves a public OpenAPI
// 3.1 document at /api/v1/openapi.json; nothing here talks to the network
// except fetchOpenApi, so everything else is unit-testable in isolation.

export const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const
export type Method = (typeof METHODS)[number]
export type AuthKind = 'public' | 'session' | 'admin'

export interface Schema {
  $ref?: string
  type?: string | string[]
  format?: string
  description?: string
  enum?: unknown[]
  example?: unknown
  default?: unknown
  properties?: Record<string, Schema>
  required?: string[]
  items?: Schema
  allOf?: Schema[]
  oneOf?: Schema[]
  anyOf?: Schema[]
  additionalProperties?: boolean | Schema
}

export interface Parameter {
  name: string
  in: 'path' | 'query' | 'header' | 'cookie'
  required?: boolean
  description?: string
  schema?: Schema
  $ref?: string
}

export interface MediaType { schema?: Schema; example?: unknown }
export interface RequestBody { description?: string; required?: boolean; content?: Record<string, MediaType> }
export interface Response { description?: string; content?: Record<string, MediaType> }

export interface Operation {
  tags?: string[]
  summary?: string
  description?: string
  operationId?: string
  parameters?: Parameter[]
  requestBody?: RequestBody
  responses?: Record<string, Response>
  security?: Record<string, string[]>[]
  [ext: `x-${string}`]: unknown
}

export interface OpenApiDoc {
  openapi?: string
  info?: { title?: string; version?: string; description?: string }
  servers?: { url: string; description?: string }[]
  tags?: { name: string; description?: string }[]
  paths?: Record<string, Record<string, unknown>>
  components?: { schemas?: Record<string, Schema>; parameters?: Record<string, Parameter> }
}

export interface Endpoint {
  id: string
  method: Method
  path: string
  op: Operation
  tag: string
  auth: AuthKind
}

export interface EndpointGroup { tag: string; description?: string; endpoints: Endpoint[] }

export const UNTAGGED = 'other'

export async function fetchOpenApi(signal?: AbortSignal): Promise<OpenApiDoc> {
  const res = await fetch('/api/v1/openapi.json', { credentials: 'same-origin', signal })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const doc = (await res.json()) as OpenApiDoc
  if (!doc || typeof doc !== 'object' || !doc.paths) throw new Error('not an OpenAPI document')
  return doc
}

/** Resolves a local "#/a/b/c" JSON pointer; undefined when it does not exist. */
export function resolveRef<T>(doc: OpenApiDoc, ref: string): T | undefined {
  if (!ref.startsWith('#/')) return undefined
  let cur: unknown = doc
  for (const part of ref.slice(2).split('/')) {
    if (cur === null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[part.replace(/~1/g, '/').replace(/~0/g, '~')]
  }
  return cur as T | undefined
}

/**
 * Follows $ref chains and merges allOf. `seen` is the cycle guard: a ref
 * already on the current resolution path is returned as a stub carrying only
 * its name, so recursive schemas terminate.
 */
export function resolveSchema(doc: OpenApiDoc, schema: Schema | undefined, seen: string[] = []): Schema {
  if (!schema) return {}
  if (schema.$ref) {
    const name = schema.$ref.split('/').pop() ?? schema.$ref
    if (seen.includes(schema.$ref)) return { description: `(recursive: ${name})`, type: 'object' }
    const target = resolveRef<Schema>(doc, schema.$ref)
    if (!target) return { description: `(unresolved: ${schema.$ref})` }
    return { ...resolveSchema(doc, target, [...seen, schema.$ref]), ...(schema.description ? { description: schema.description } : {}) }
  }
  if (schema.allOf?.length) {
    const merged: Schema = { ...schema, allOf: undefined }
    for (const part of schema.allOf) {
      const r = resolveSchema(doc, part, seen)
      merged.properties = { ...merged.properties, ...r.properties }
      merged.required = [...(merged.required ?? []), ...(r.required ?? [])]
      merged.type = merged.type ?? r.type
    }
    return merged
  }
  return schema
}

export function schemaTypeLabel(s: Schema): string {
  const t = Array.isArray(s.type) ? s.type.join(' | ') : s.type
  if (t === 'array') return `array<${s.items ? schemaTypeLabel(s.items.$ref ? { type: s.items.$ref.split('/').pop() } : s.items) : 'any'}>`
  if (s.enum) return `${t ?? 'enum'} (${s.enum.map(String).join(' | ')})`
  return [t ?? (s.properties ? 'object' : 'any'), s.format].filter(Boolean).join(':')
}

/** Builds a representative JSON value from a schema (examples win over synthesis). */
export function exampleFromSchema(doc: OpenApiDoc, schema: Schema | undefined, seen: string[] = [], depth = 0): unknown {
  const s = resolveSchema(doc, schema, seen)
  if (s.example !== undefined) return s.example
  if (s.default !== undefined) return s.default
  if (s.enum?.length) return s.enum[0]
  if (depth > 6) return null
  const type = Array.isArray(s.type) ? s.type.find((x) => x !== 'null') : s.type
  if (s.properties || type === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(s.properties ?? {})) {
      out[k] = exampleFromSchema(doc, v, v.$ref ? [...seen, v.$ref] : seen, depth + 1)
    }
    return out
  }
  if (type === 'array') return s.items ? [exampleFromSchema(doc, s.items, s.items.$ref ? [...seen, s.items.$ref] : seen, depth + 1)] : []
  if (type === 'integer' || type === 'number') return 0
  if (type === 'boolean') return false
  if (type === 'string') return s.format === 'email' ? 'user@example.com' : 'string'
  return null
}

export function operationAuth(op: Operation): AuthKind {
  if (Array.isArray(op.security) && op.security.length === 0) return 'public'
  const role = op['x-required-role'] ?? op['x-admin']
  if (role === 'admin' || role === true) return 'admin'
  return 'session'
}

export function collectEndpoints(doc: OpenApiDoc): Endpoint[] {
  const out: Endpoint[] = []
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    for (const method of METHODS) {
      const op = item[method] as Operation | undefined
      if (!op) continue
      out.push({ id: `${method} ${path}`, method, path, op, tag: op.tags?.[0] ?? UNTAGGED, auth: operationAuth(op) })
    }
  }
  return out
}

/** Groups by first tag, ordered by doc.tags first, then alphabetically. */
export function groupByTag(doc: OpenApiDoc, endpoints: Endpoint[]): EndpointGroup[] {
  const map = new Map<string, Endpoint[]>()
  for (const e of endpoints) map.set(e.tag, [...(map.get(e.tag) ?? []), e])
  const declared = doc.tags?.map((t) => t.name) ?? []
  const rank = (tag: string) => { const i = declared.indexOf(tag); return i < 0 ? declared.length : i }
  return [...map.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([tag, eps]) => ({ tag, description: doc.tags?.find((t) => t.name === tag)?.description, endpoints: eps }))
}

export function filterEndpoints(endpoints: Endpoint[], query: string, methods: ReadonlySet<Method>): Endpoint[] {
  const q = query.trim().toLowerCase()
  return endpoints.filter((e) => {
    if (methods.size > 0 && !methods.has(e.method)) return false
    if (!q) return true
    return [e.path, e.method, e.tag, e.op.summary, e.op.description, e.op.operationId].some((f) => f?.toLowerCase().includes(q))
  })
}

export function endpointParams(doc: OpenApiDoc, item: Operation, pathItem?: unknown): Parameter[] {
  const raw = [...(((pathItem as { parameters?: Parameter[] } | undefined)?.parameters) ?? []), ...(item.parameters ?? [])]
  return raw.map((p) => (p.$ref ? resolveRef<Parameter>(doc, p.$ref) : p)).filter((p): p is Parameter => !!p)
}

export function jsonBody(doc: OpenApiDoc, op: Operation): { schema: Schema; example: unknown } | undefined {
  const mt = op.requestBody?.content?.['application/json']
  if (!mt) return undefined
  return { schema: resolveSchema(doc, mt.schema), example: mt.example ?? exampleFromSchema(doc, mt.schema) }
}

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`

export function buildCurl(doc: OpenApiDoc, e: Endpoint, origin: string): string {
  // servers[0].url may be relative ("/api/v1") — resolve it against the page origin.
  const server = doc.servers?.[0]?.url ?? ''
  const base = (/^https?:\/\//.test(server) ? server : `${origin}${server}`).replace(/\/$/, '')
  const params = endpointParams(doc, e.op, doc.paths?.[e.path])
  const query = params.filter((p) => p.in === 'query' && p.required).map((p) => `${encodeURIComponent(p.name)}=${encodeURIComponent(String(exampleFromSchema(doc, p.schema)))}`)
  // {id} -> <id>: obviously a placeholder, and nothing curl or the shell would expand.
  const path = e.path.replace(/\{([^}]+)\}/g, '<$1>')
  const url = `${base}${path}${query.length ? `?${query.join('&')}` : ''}`
  // -g (--globoff) stops curl treating any remaining {} / [] in the URL as a glob.
  const lines = [`curl -g -X ${e.method.toUpperCase()} ${shq(url)}`]
  if (e.auth !== 'public') lines.push('  -b cookies.txt')
  // Writes need a JSON Content-Type even without a body: the backend answers 415 otherwise.
  const body = jsonBody(doc, e.op)
  if (body || e.method !== 'get') lines.push("  -H 'Content-Type: application/json'")
  for (const h of params.filter((p) => p.in === 'header' && p.required)) {
    const key = h.name.toLowerCase()
    if (key === 'content-type') continue
    const value = key === 'origin' ? origin : key === 'if-match' ? '"<etag>"' : `<${h.name}>`
    lines.push(`  -H ${shq(`${h.name}: ${value}`)}`)
  }
  if (body) lines.push(`  -d ${shq(JSON.stringify(body.example))}`)
  return lines.join(' \\\n')
}

export function buildLoginCurl(origin: string): string {
  return [
    `curl -c cookies.txt -X POST '${origin}/api/login'`,
    "  -H 'Content-Type: application/json'",
    `  -d '{"identity":"cn=admin,dc=example,dc=org","password":"..."}'`,
  ].join(' \\\n')
}
