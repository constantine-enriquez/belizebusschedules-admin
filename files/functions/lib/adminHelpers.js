/**
 * Shared helpers for Pages admin API routes.
 * Env (Cloudflare Pages → Settings):
 *   Variables: DRIVER_API_BASE_URL, ADMIN_API_SECRET
 *   Optional: CORS_ORIGINS (comma-separated), IMAGES_PUBLIC_BASE (e.g. https://images.belizebusschedules.com, no trailing slash)
 *   Functions → R2: bind bucket as BUS_IMAGES (bus photos; keys like {company-slug}/{vehicle-id}.jpg)
 *
 * Driver users are created/deleted via the driver Worker Better Auth endpoints
 * (see cloudflare-worker/AUTH_SETUP.md). Cloudflare Access still protects this admin UI.
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

/**
 * The admin UI calls this API from its own origin, which needs no CORS headers.
 * Other origins get access only when listed in CORS_ORIGINS — never by reflection,
 * since requests carry the admin's Cloudflare Access cookie.
 */
export function buildCorsHeaders(request, env) {
  const origin = request.headers.get('Origin') || ''
  const list = (env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  if (!origin || !list.includes(origin)) return {}

  return {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cf-Access-Jwt-Assertion',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  }
}

export function jsonResponse(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  })
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
