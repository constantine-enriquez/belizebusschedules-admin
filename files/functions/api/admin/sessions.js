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
 * GET — driver_vehicle_sessions with vehicle plate, driver profile, schedule route.
 * Query (all optional except sensible combos for route filter use company):
 *   company          — s.company_name
 *   schedule_id      — BID / schedule_id on session
 *   driver_user_id   — exact profile id
 *   driver_email     — substring match on profile email (case-insensitive)
 *   origin           — bus_schedule_v2.origin (requires join; use with company recommended)
 *   destination      — bus_schedule_v2.destination
 *   active_only=1   — only ended_at IS NULL
 *   limit            — default 200, max 1000
 */
export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const url = new URL(request.url)
  const company = (url.searchParams.get('company') || '').trim()
  const scheduleIdRaw = url.searchParams.get('schedule_id')
  const driverUserId = (url.searchParams.get('driver_user_id') || '').trim()
  const driverEmail = (url.searchParams.get('driver_email') || '').trim()
  const origin = (url.searchParams.get('origin') || '').trim()
  const destination = (url.searchParams.get('destination') || '').trim()
  const activeOnly = url.searchParams.get('active_only') === '1'
  let limit = parseInt(url.searchParams.get('limit') || '200', 10)
  if (!Number.isFinite(limit) || limit < 1) limit = 200
  if (limit > 1000) limit = 1000

  let scheduleId = null
  if (scheduleIdRaw != null && scheduleIdRaw !== '') {
    scheduleId = parseInt(scheduleIdRaw, 10)
    if (!Number.isFinite(scheduleId) || scheduleId <= 0) {
      return jsonResponse({ error: 'schedule_id must be a positive integer' }, 400, cors)
    }
  }

  const useRouteJoin = !!(origin || destination)
  const binds = []

  let sql = `
    SELECT
      s.id,
      s.driver_user_id,
      s.vehicle_id,
      s.company_name,
      s.schedule_id,
      s.link_method,
      s.started_at,
      s.ended_at,
      s.end_reason,
      s.created_at,
      s.updated_at,
      v.plate AS vehicle_plate,
      p.email AS driver_email,
      p.display_name AS driver_display_name,
      sch.origin AS route_origin,
      sch.destination AS route_destination,
      sch.departure_time AS route_departure_time
    FROM driver_vehicle_sessions s
    LEFT JOIN vehicles v ON v.id = s.vehicle_id
    LEFT JOIN profiles p ON p.id = s.driver_user_id
  `

  if (useRouteJoin) {
    sql += `
    INNER JOIN bus_schedule_v2 sch
      ON sch.company = s.company_name AND sch.BID = s.schedule_id
    `
  } else {
    sql += `
    LEFT JOIN bus_schedule_v2 sch
      ON sch.company = s.company_name AND sch.BID = s.schedule_id
    `
  }

  sql += ` WHERE 1=1`

  if (company) {
    sql += ` AND s.company_name = ?`
    binds.push(company)
  }
  if (scheduleId != null) {
    sql += ` AND s.schedule_id = ?`
    binds.push(scheduleId)
  }
  if (driverUserId) {
    sql += ` AND s.driver_user_id = ?`
    binds.push(driverUserId)
  }
  if (driverEmail) {
    sql += ` AND LOWER(COALESCE(p.email, '')) LIKE ?`
    binds.push(`%${driverEmail.toLowerCase()}%`)
  }
  if (activeOnly) {
    sql += ` AND s.ended_at IS NULL`
  }
  if (origin) {
    sql += ` AND sch.origin = ?`
    binds.push(origin)
  }
  if (destination) {
    sql += ` AND sch.destination = ?`
    binds.push(destination)
  }

  sql += ` ORDER BY s.started_at DESC LIMIT ?`
  binds.push(limit)

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all()
    return jsonResponse({ sessions: results || [] }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
