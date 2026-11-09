let cachedBasePath: string | null = null

/**
 * Returns the configured base path for the UI.
 * Reads the `<meta name="ldapium-base-path" content="<prefix>">` tag once,
 * validates that it starts with "/" or is "", else falls back to "".
 * In `npm run dev` (no meta tag) or at root, returns "".
 */
export function basePath(): string {
  if (cachedBasePath !== null) {
    return cachedBasePath
  }
  if (typeof document === 'undefined') {
    cachedBasePath = ''
    return cachedBasePath
  }
  const meta = document.querySelector('meta[name="ldapium-base-path"]')
  const content = meta?.getAttribute('content')?.trim() ?? ''
  if (content === '' || !content.startsWith('/')) {
    cachedBasePath = ''
    return cachedBasePath
  }
  cachedBasePath = content.replace(/\/+$/, '')
  return cachedBasePath
}

/**
 * Prepends the base path to a root-absolute path (e.g. "/api/...").
 * If no base path is configured, returns the path as-is.
 */
export function withBase(path: string): string {
  const base = basePath()
  if (!base) {
    return path
  }
  if (path.startsWith('/')) {
    return `${base}${path}`
  }
  return `${base}/${path}`
}

