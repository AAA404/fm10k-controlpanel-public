let csrf = ''
let sessionGeneration = 0
let sessionChange: Promise<void>|null = null
export const setCsrf = (value: string) => {
  if (csrf !== value) { csrf = value; ++sessionGeneration }
}
export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string) { super(message) }
}

export async function api<T = any>(path: string, body?: unknown, method?: string): Promise<T> {
  // Start new requests only after an in-flight credential change completes.
  // This also serializes login/logout without ever retrying an account write.
  while (sessionChange) await sessionChange
  const rotatesSession = ['/auth/administrator','/auth/login','/auth/setup','/auth/logout'].includes(path)
  let release: (() => void)|undefined
  const transition = rotatesSession ? new Promise<void>(resolve => { release = resolve }) : null
  if (transition) sessionChange = transition
  const generation = sessionGeneration
  try {
    const response = await fetch(`/api/v1${path}`, {
      method: method ?? (body === undefined ? 'GET' : 'POST'),
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    let value: any
    try { value = await response.json() } catch { throw new Error(`服务返回 ${response.status}`) }
    if (!response.ok) {
      if (response.status === 401) {
        // A polling request sent with the old cookie may finish either before
        // or after the account response. It cannot expire the replacement.
        if (!rotatesSession) while (sessionChange) await sessionChange
        if (generation !== sessionGeneration)
          throw new ApiError('登录状态已更新，请重试刚才的操作。',401,'superseded_session')
        if (!['/auth/login','/auth/setup'].includes(path) && typeof window !== 'undefined')
          window.dispatchEvent(new Event('fm10k-session-expired'))
      }
      throw new ApiError(typeof value.detail === 'string' ? value.detail : JSON.stringify(value.detail), response.status, value.code)
    }
    // Rotate before resolving the request, so queued operations use the new
    // CSRF token along with the browser's replacement HttpOnly cookie.
    if (rotatesSession && typeof value.csrf === 'string') setCsrf(value.csrf)
    else if (path === '/auth/logout') setCsrf('')
    return value as T
  } finally {
    if (transition && sessionChange === transition) sessionChange = null
    release?.()
  }
}
