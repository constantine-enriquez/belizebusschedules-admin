import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

/**
 * GET ?company= — rows from bus_schedule_v2 for route pickers (BID, origin, destination, time).
 */
export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const url = new URL(request.url)
  const company = (url.searchParams.get('company') || '').trim()
  if (!company) {
    return jsonResponse({ error: 'company query parameter is required' }, 400, cors)
  }

  try {
    const { results } = await env.DB.prepare(
      `
      SELECT BID, company, origin, destination, departure_time
      FROM bus_schedule_v2
      WHERE company = ?
      ORDER BY departure_time ASC, BID ASC
    `
    )
      .bind(company)
      .all()
    return jsonResponse({ schedules: results || [] }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
