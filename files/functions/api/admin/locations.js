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
 * GET — distinct schedule places for ad route targeting.
 *   (no params)     → { origins: string[] }
 *   ?origin=Belize  → { destinations: string[] } for that origin only
 */
export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const url = new URL(request.url)
  const origin = (url.searchParams.get('origin') || '').trim()

  try {
    if (origin) {
      const { results } = await env.DB.prepare(
        `
        SELECT DISTINCT destination AS place
        FROM bus_schedule_v2
        WHERE origin = ?
          AND destination IS NOT NULL
          AND TRIM(destination) != ''
        ORDER BY destination ASC
      `
      )
        .bind(origin)
        .all()
      return jsonResponse(
        { destinations: (results || []).map((r) => r.place) },
        200,
        cors
      )
    }

    const { results } = await env.DB.prepare(
      `
      SELECT DISTINCT origin AS place
      FROM bus_schedule_v2
      WHERE origin IS NOT NULL
        AND TRIM(origin) != ''
      ORDER BY origin ASC
    `
    ).all()
    return jsonResponse(
      { origins: (results || []).map((r) => r.place) },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
