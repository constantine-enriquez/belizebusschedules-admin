import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'
import {
  EDITABLE_COLUMNS,
  actorFromRequest,
  changeLogStatement,
  ensureScheduleChangesTable,
  findDuplicate,
  normalizeSchedulePayload,
  rowToSchedule,
} from '../../../lib/scheduleHelpers.js'

function bidFromContext(context) {
  const { params, request } = context
  let raw = params?.id
  if (!raw) {
    const parts = new URL(request.url).pathname.split('/').filter(Boolean)
    const idx = parts.indexOf('schedules')
    if (idx >= 0) raw = parts[idx + 1]
  }
  const bid = Number(raw)
  return Number.isInteger(bid) && bid > 0 ? bid : null
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

/** PATCH — update one trip. Omitted keys keep their current values. */
export async function onRequestPatch(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const bid = bidFromContext(context)
  if (!bid) return jsonResponse({ error: 'Invalid schedule id' }, 400, cors)

  let body
  try {
    body = await request.json()
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400, cors)
  }

  try {
    const existing = await env.DB.prepare('SELECT * FROM bus_schedule_v2 WHERE BID = ? LIMIT 1')
      .bind(bid)
      .first()
    if (!existing) return jsonResponse({ error: 'Trip not found' }, 404, cors)

    const { row, errors, warnings } = normalizeSchedulePayload(body || {}, existing)
    if (errors.length) {
      return jsonResponse({ error: errors[0], errors }, 400, cors)
    }

    await ensureScheduleChangesTable(env)
    const dup = await findDuplicate(env, row, bid)
    if (dup) warnings.push(`Looks like a duplicate of BID ${dup}`)

    const updated = { BID: bid, ...row }
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE bus_schedule_v2 SET ${EDITABLE_COLUMNS.map((c) => `${c} = ?`).join(', ')} WHERE BID = ?`
      ).bind(...EDITABLE_COLUMNS.map((c) => row[c]), bid),
      changeLogStatement(env, {
        bid,
        company: row.company,
        action: 'update',
        before: existing,
        after: updated,
        actor: actorFromRequest(request),
      }),
    ])

    return jsonResponse({ schedule: rowToSchedule(updated), warnings }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestDelete(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const bid = bidFromContext(context)
  if (!bid) return jsonResponse({ error: 'Invalid schedule id' }, 400, cors)

  try {
    const existing = await env.DB.prepare('SELECT * FROM bus_schedule_v2 WHERE BID = ? LIMIT 1')
      .bind(bid)
      .first()
    if (!existing) return jsonResponse({ error: 'Trip not found' }, 404, cors)

    await ensureScheduleChangesTable(env)
    await env.DB.batch([
      env.DB.prepare('DELETE FROM bus_schedule_v2 WHERE BID = ?').bind(bid),
      changeLogStatement(env, {
        bid,
        company: existing.company,
        action: 'delete',
        before: existing,
        after: null,
        actor: actorFromRequest(request),
      }),
    ])
    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
