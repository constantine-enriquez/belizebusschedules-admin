/**
 * Shared helpers for Pages admin API routes.
 * Env (set in Cloudflare Pages → Settings → Variables):
 *   SUPABASE_URL, SUPABASE_SERVICE_KEY
 * Optional: CORS_ORIGINS (comma-separated) for local dev origins
 */

export const CF_ACCESS_TEAM_DOMAIN = 'belizebusschedules.cloudflareaccess.com'

function base64UrlToBytes(segment) {
  const pad = '='.repeat((4 - (segment.length % 4)) % 4)
  const b64 = (segment + pad).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

export async function verifyAccessJWT(request, teamDomain) {
  if (!teamDomain) return { ok: false }

  const token = request.headers.get('Cf-Access-Jwt-Assertion')
  if (!token) return { ok: false }

  try {
    const certsUrl = `https://${teamDomain}/cdn-cgi/access/certs`
    const certsRes = await fetch(certsUrl)
    const { keys } = await certsRes.json()

    const parts = token.split('.')
    if (parts.length !== 3) return { ok: false }
    const [headerB64, payloadB64, sigB64] = parts
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`)

    let payload
    try {
      payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)))
    } catch {
      return { ok: false }
    }

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { ok: false }
    }

    const sig = base64UrlToBytes(sigB64)

    for (const jwk of keys || []) {
      try {
        const key = await crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['verify']
        )
        const valid = await crypto.subtle.verify(
          'RSASSA-PKCS1-v1_5',
          key,
          sig,
          data
        )
        if (valid) return { ok: true, payload }
      } catch {
        // try next key
      }
    }
    return { ok: false }
  } catch {
    return { ok: false }
  }
}

export function buildCorsHeaders(request, env) {
  const origin = request.headers.get('Origin') || ''
  const list = (env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  const base = {
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, Cf-Access-Jwt-Assertion',
    'Access-Control-Max-Age': '86400',
  }

  if (list.length && origin && list.includes(origin)) {
    return {
      ...base,
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
    }
  }

  if (list.length && !origin) {
    return {
      ...base,
      'Access-Control-Allow-Origin': list[0],
    }
  }

  if (origin) {
    return {
      ...base,
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
    }
  }

  return {
    ...base,
    'Access-Control-Allow-Origin': '*',
  }
}

export function jsonResponse(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  })
}

export function supabaseErrorMessage(body) {
  if (!body || typeof body !== 'object') return 'Supabase error'
  return (
    body.msg ||
    body.message ||
    body.error_description ||
    body.hint ||
    (typeof body.error === 'string' ? body.error : null) ||
    'Supabase error'
  )
}

export function adminUserIdFromCreateResponse(authJson) {
  if (authJson.user && authJson.user.id) return authJson.user.id
  if (authJson.id) return authJson.id
  return null
}

/**
 * @returns {Promise<Response | null>} Response if auth failed, null if OK
 */
export async function requireAccess(request, env, cors) {
  const access = await verifyAccessJWT(request, CF_ACCESS_TEAM_DOMAIN)
  if (!access.ok) {
    return jsonResponse(
      { error: 'Unauthorized — Cloudflare Access JWT missing or invalid' },
      401,
      cors
    )
  }
  return null
}
