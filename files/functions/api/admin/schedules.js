import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'
import {
  EDITABLE_COLUMNS,
  actorFromRequest,
  changeLogStatement,
  ensureScheduleChangesTable,
  findDuplicate,
  normalizeSchedulePayload,
  rowToSchedule,
} from '../../lib/scheduleHelpers.js'

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

async function loadMeta(env, company) {
  const [days, services, places, phone] = await env.DB.batch([
    env.DB.prepare(`
      SELECT days_of_operation AS v, COUNT(*) AS n FROM bus_schedule_v2
      WHERE days_of_operation IS NOT NULL AND TRIM(days_of_operation) != ''
      GROUP BY days_of_operation ORDER BY n DESC
    `),
    env.DB.prepare(`
      SELECT service_type AS v, COUNT(*) AS n FROM bus_schedule_v2
      WHERE service_type IS NOT NULL AND TRIM(service_type) != ''
      GROUP BY service_type ORDER BY n DESC
    `),
    env.DB.prepare(`
      SELECT origin AS place FROM bus_schedule_v2 WHERE origin IS NOT NULL
      UNION
      SELECT destination FROM bus_schedule_v2 WHERE destination IS NOT NULL
      UNION
      SELECT json_extract(j.value, '$.location')
      FROM bus_schedule_v2,
        json_each(
          CASE WHEN json_valid(bus_schedule_v2.stops_data)
            AND json_type(bus_schedule_v2.stops_data) = 'array'
          THEN bus_schedule_v2.stops_data ELSE '[]' END
        ) AS j
    `),
    env.DB.prepare(`
      SELECT phone_number AS v, COUNT(*) AS n FROM bus_schedule_v2
      WHERE company = ? AND phone_number IS NOT NULL AND TRIM(phone_number) != ''
      GROUP BY phone_number ORDER BY n DESC LIMIT 1
    `).bind(company),
  ])
  return {
    days: (days.results || []).map((r) => r.v),
    service_types: (services.results || []).map((r) => r.v),
    places: (places.results || [])
      .map((r) => r.place)
      .filter((p) => p && String(p).trim())
      .sort((a, b) => String(a).localeCompare(String(b))),
    phone_number: phone.results?.[0]?.v || null,
  }
}

/**
 * GET ?company= — rows from bus_schedule_v2 for route pickers (BID, origin, destination, time).
 * GET ?company=&full=1 — every column plus parsed stops and editor suggestions (meta).
 */
export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const url = new URL(request.url)
  const company = (url.searchParams.get('company') || '').trim()
  const full = url.searchParams.get('full') === '1'
  if (!company) {
    return jsonResponse({ error: 'company query parameter is required' }, 400, cors)
  }

  try {
    if (full) {
      const { results } = await env.DB.prepare(
        `SELECT * FROM bus_schedule_v2 WHERE company = ? ORDER BY BID ASC`
      )
        .bind(company)
        .all()
      const meta = await loadMeta(env, company)
      return jsonResponse(
        { schedules: (results || []).map(rowToSchedule), meta },
        200,
        cors
      )
    }

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

/** POST — create one trip. Body: editable columns + `stops` array. */
export async function onRequestPost({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  let body
  try {
    body = await request.json()
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400, cors)
  }

  const { row, errors, warnings } = normalizeSchedulePayload(body || {})
  if (errors.length) {
    return jsonResponse({ error: errors[0], errors }, 400, cors)
  }

  try {
    await ensureScheduleChangesTable(env)
    const dup = await findDuplicate(env, row)
    if (dup) warnings.push(`Looks like a duplicate of BID ${dup}`)

    const created = await env.DB.prepare(
      `
      INSERT INTO bus_schedule_v2 (${EDITABLE_COLUMNS.join(', ')})
      VALUES (${EDITABLE_COLUMNS.map(() => '?').join(', ')})
      RETURNING *
    `
    )
      .bind(...EDITABLE_COLUMNS.map((c) => row[c]))
      .first()

    try {
      await changeLogStatement(env, {
        bid: created.BID,
        company: created.company,
        action: 'create',
        before: null,
        after: created,
        actor: actorFromRequest(request),
      }).run()
    } catch {
      warnings.push('Trip saved, but it could not be added to change history')
    }

    return jsonResponse({ schedule: rowToSchedule(created), warnings }, 201, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
