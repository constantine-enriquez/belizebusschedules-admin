import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'

function sessionIdFromContext(context) {
  const { params, request } = context
  if (params?.id) return params.id
  const parts = new URL(request.url).pathname.split('/').filter(Boolean)
  const idx = parts.indexOf('sessions')
  if (idx >= 0 && parts[idx + 1]) return parts[idx + 1]
  return null
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

/**
 * PATCH — end an active session (set ended_at, end_reason).
 * Body: { "end_reason": "manual_end" } optional; defaults to manual_end.
 */
export async function onRequestPatch(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = sessionIdFromContext(context)
  if (!id) {
    return jsonResponse({ error: 'Missing session id' }, 400, cors)
  }

  try {
    const body = await request.json().catch(() => ({}))
    const endReason = String(body.end_reason || 'manual_end').trim()
    const allowed = new Set(['manual_end', 'switch_vehicle'])
    const reason = allowed.has(endReason) ? endReason : 'manual_end'

    const row = await env.DB.prepare(
      'SELECT id, ended_at FROM driver_vehicle_sessions WHERE id = ? LIMIT 1'
    )
      .bind(id)
      .first()

    if (!row) {
      return jsonResponse({ error: 'Session not found' }, 404, cors)
    }
    if (row.ended_at) {
      return jsonResponse({ error: 'Session already ended' }, 409, cors)
    }

    const now = new Date().toISOString()
    await env.DB.prepare(
      `
      UPDATE driver_vehicle_sessions
      SET ended_at = ?, end_reason = ?, updated_at = ?
      WHERE id = ? AND ended_at IS NULL
    `
    )
      .bind(now, reason, now, id)
      .run()

    return jsonResponse(
      { success: true, ended_at: now, end_reason: reason },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
