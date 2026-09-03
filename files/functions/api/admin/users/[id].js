import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'

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

export async function onRequestPatch(context) {
  const { request, env, params } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const userId =
    params?.id ||
    new URL(request.url).pathname.split('/').filter(Boolean).pop()
  if (!userId) {
    return jsonResponse({ error: 'Missing user id' }, 400, cors)
  }

  try {
    const { display_name, user_type, bus_company } = await request.json()

    const base = driverApiBase(env)
    const secret = adminSecret(env)
    const res = await fetch(`${base}/api/internal/users/${userId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Secret': secret,
      },
      body: JSON.stringify({ display_name, user_type, bus_company }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      return jsonResponse(
        { error: data.error || data.message || 'Update failed' },
        res.status >= 400 ? res.status : 400,
        cors
      )
    }

    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestDelete(context) {
  const { request, env, params } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const userId =
    params?.id ||
    new URL(request.url).pathname.split('/').filter(Boolean).pop()
  if (!userId) {
    return jsonResponse({ error: 'Missing user id' }, 400, cors)
  }

  try {
    const base = driverApiBase(env)
    const secret = adminSecret(env)
    const authRes = await fetch(`${base}/api/internal/users/${userId}`, {
      method: 'DELETE',
      headers: {
        'X-Admin-Secret': secret,
      },
    })

    const errBody = await authRes.json().catch(() => ({}))
    if (!authRes.ok) {
      return jsonResponse(
        { error: errBody.error || errBody.message || 'Delete failed' },
        authRes.status >= 400 ? authRes.status : 400,
        cors
      )
    }

    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
