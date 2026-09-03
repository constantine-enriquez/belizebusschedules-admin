import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'

function driverApiBase(env) {
  const raw = (env.DRIVER_API_BASE_URL || '').trim().replace(/\/+$/, '')
  if (!raw) {
    throw new Error('DRIVER_API_BASE_URL is not configured on Pages')
  }
  return raw
}

function adminSecret(env) {
  const s = (env.ADMIN_API_SECRET || '').trim()
  if (!s) {
    throw new Error('ADMIN_API_SECRET is not configured on Pages')
  }
  return s
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM profiles ORDER BY created_at DESC'
    ).all()
    return jsonResponse({ users: results }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestPost({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    const { email, password, display_name, user_type, bus_company } =
      await request.json()

    if (!email || !password) {
      return jsonResponse({ error: 'Email and password required' }, 400, cors)
    }

    const base = driverApiBase(env)
    const secret = adminSecret(env)
    const authRes = await fetch(`${base}/api/internal/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Secret': secret,
      },
      body: JSON.stringify({
        email,
        password,
        display_name,
        user_type,
        bus_company,
      }),
    })

    const authData = await authRes.json().catch(() => ({}))
    if (!authRes.ok) {
      return jsonResponse(
        { error: authData.error || authData.message || 'Failed to create user' },
        authRes.status >= 400 ? authRes.status : 400,
        cors
      )
    }

    return jsonResponse(
      { success: true, id: authData.id || null },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
