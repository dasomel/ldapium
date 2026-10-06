import { useRef } from 'react'
import { api, ApiError, type WriteOptions } from '@/lib/api'
import { useT } from '@/context/LanguageContext'

// Conditional writes and idempotent retries for the core user/group screens
// (docs/changes/api-conditional-writes, T-018 / REQ-013 / AC-018). Everything
// here is feature-detected and optional: an older server (no `etag` on items,
// no `idempotencyEnabled` setting) gets exactly the request it always got.

// Whether the server honours Idempotency-Key, read once from
// /api/server-settings. Only a successful read is remembered, so a transient
// failure is retried on the next write; a failed or old-server read means
// "off" (never send a key we cannot prove is understood).
let idempotencySetting: Promise<boolean> | null = null

function idempotencyEnabled(): Promise<boolean> {
  idempotencySetting ??= api
    .serverSettings()
    .then((s) => s.idempotencyEnabled === true)
    .catch(() => {
      idempotencySetting = null
      return false
    })
  return idempotencySetting
}

// 128-bit random key in the server's alphabet ([A-Za-z0-9._~:-], 16-128).
// getRandomValues rather than randomUUID: the latter is secure-context only
// and the UI is also served over plain http.
function newKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return 'ui-' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export interface WriteRun {
  /** Identifies the logical request (operation, target and body). The same
   * fingerprint is the same attempt and reuses its key; a different one (the
   * operator changed the form) is a different request and gets a new key,
   * since the server answers a reused key with a different body 422. */
  fingerprint: unknown
  /** The listed item's etag; omitted for creates and for older servers. */
  etag?: string
  /** Called for outcomes after which the operator must look at fresh data
   * (412, outcome unknown): re-read the list here. Failures are ignored. */
  onStale?: () => Promise<unknown>
}

/**
 * Runs one user-initiated write. One Idempotency-Key is generated per attempt
 * and reused when the operator submits the same request again after a
 * failure; it is dropped after success and after outcomes that end the
 * attempt. A 422 idempotency_unsupported (the switch is off on this server)
 * is retried once without the key and remembered for the session. Server
 * errors that need an explanation are rethrown with a localized message.
 */
export function useWriteAttempt() {
  const t = useT()
  const attempt = useRef<{ fingerprint: string; key: string } | null>(null)

  return async function run<T>(opts: WriteRun, call: (write: WriteOptions) => Promise<T>): Promise<T> {
    const fingerprint = JSON.stringify(opts.fingerprint)
    let key: string | undefined
    if (await idempotencyEnabled()) {
      if (attempt.current?.fingerprint !== fingerprint) attempt.current = { fingerprint, key: newKey() }
      key = attempt.current.key
    }
    const write = (idempotencyKey?: string): WriteOptions => ({ ifMatch: opts.etag, idempotencyKey })

    try {
      try {
        const result = await call(write(key))
        attempt.current = null
        return result
      } catch (err) {
        if (!key || !(err instanceof ApiError) || err.code !== 'idempotency_unsupported') throw err
        idempotencySetting = Promise.resolve(false)
        attempt.current = null
        const result = await call(write())
        return result
      }
    } catch (err) {
      if (!(err instanceof ApiError)) throw err
      switch (err.code) {
        case 'revision_conflict':
        case 'idempotency_outcome_unknown':
          // 412 stores nothing; an unknown outcome replays forever under its
          // key. Either way the operator re-reads, then starts a new attempt.
          attempt.current = null
          await opts.onStale?.().catch(() => undefined)
          throw new ApiError(
            err.status,
            t(err.code === 'revision_conflict' ? 'writes.revisionConflict' : 'writes.outcomeUnknown'),
            err.code,
          )
        case 'idempotency_key_conflict':
          throw new ApiError(err.status, t('writes.inProgress'), err.code)
        case 'idempotency_key_reused':
          attempt.current = null
          throw new ApiError(err.status, t('writes.keyReused'), err.code)
        case 'idempotency_capacity':
          throw new ApiError(err.status, t('writes.capacity'), err.code)
        default:
          throw err
      }
    }
  }
}
