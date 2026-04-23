import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'

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
      'SELECT DISTINCT company FROM bus_schedule_v2 WHERE company IS NOT NULL ORDER BY company ASC'
    ).all()
    return jsonResponse(
      { companies: results.map((r) => r.company) },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
