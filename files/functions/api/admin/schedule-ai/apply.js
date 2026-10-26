import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'
import {
  actorFromRequest,
  changeLogStatement,
  companyPhone,
  createdRowLogStatement,
  ensureScheduleChangesTable,
  insertScheduleStatement,
  newBatchId,
  normalizeSchedulePayload,
  planReplace,
  updateScheduleStatement,
} from '../../../lib/scheduleHelpers.js'

const MAX_TRIPS = 400

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

function tripSummary(row, activeSessions) {
  return {
    bid: row.BID,
    origin: row.origin,
    destination: row.destination,
    departure_time: row.departure_time,
    days_of_operation: row.days_of_operation,
    service_type: row.service_type,
    active_sessions: activeSessions.get(row.BID) || 0,
  }
}

/** Active driver sessions per BID, so removals that strand a driver can be flagged. */
async function activeSessionCounts(env, company, bids) {
  const counts = new Map()
  try {
    for (let i = 0; i < bids.length; i += 90) {
      const chunk = bids.slice(i, i + 90)
      const { results } = await env.DB.prepare(
        `SELECT schedule_id, COUNT(*) AS n FROM driver_vehicle_sessions
         WHERE ended_at IS NULL AND company_name = ? AND schedule_id IN (${chunk.map(() => '?').join(', ')})
         GROUP BY schedule_id`
      )
        .bind(company, ...chunk)
        .all()
      for (const r of results || []) counts.set(Number(r.schedule_id), r.n)
    }
  } catch {
    // Sessions table missing (e.g. a fresh database) — nothing to flag.
  }
  return counts
}

/**
 * POST { company, trips: [...], remove_missing = true, dry_run = false }
 * Replaces a company's schedule with the reviewed trips in one D1 transaction:
 * matching trips are updated in place (BID kept), new ones inserted, and — when
 * remove_missing — trips not in the list deleted. Every change shares one batch_id
 * so the whole import can be undone from Recent changes.
 */
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

  const company = String(body?.company || '').trim()
  const trips = Array.isArray(body?.trips) ? body.trips : null
  const removeMissing = body?.remove_missing !== false
  const dryRun = !!body?.dry_run
  if (!company) return jsonResponse({ error: 'company is required' }, 400, cors)
  if (!trips || !trips.length) {
    return jsonResponse({ error: 'Include at least one trip' }, 400, cors)
  }
  if (trips.length > MAX_TRIPS) {
    return jsonResponse({ error: `Too many trips (max ${MAX_TRIPS})` }, 400, cors)
  }

  try {
    const phone = await companyPhone(env, company)
    const rows = []
    const errorsByTrip = []
    trips.forEach((t, index) => {
      const { row, errors } = normalizeSchedulePayload({
        ...t,
        company,
        phone_number: t?.phone_number || phone,
      })
      if (errors.length) errorsByTrip.push({ index, errors })
      rows.push(row)
    })
    if (errorsByTrip.length) {
      return jsonResponse(
        {
          error: `${errorsByTrip.length} trip${errorsByTrip.length === 1 ? ' needs' : 's need'} fixing before import`,
          errors_by_trip: errorsByTrip,
        },
        400,
        cors
      )
    }

    const { results: existing } = await env.DB.prepare(
      'SELECT * FROM bus_schedule_v2 WHERE company = ? ORDER BY BID ASC'
    )
      .bind(company)
      .all()
    const plan = planReplace(existing || [], rows)
    const removing = removeMissing ? plan.remove : []
    const activeSessions = dryRun
      ? await activeSessionCounts(env, company, plan.remove.map((r) => r.BID))
      : new Map()

    const response = {
      counts: {
        add: plan.add.length,
        update: plan.update.length,
        same: plan.same.length,
        remove: removing.length,
        kept_missing: removeMissing ? 0 : plan.remove.length,
        current: (existing || []).length,
      },
      plan: {
        add: plan.add.map(({ index }) => ({ index })),
        update: plan.update.map(({ index, bid, changed }) => ({ index, bid, changed })),
        same: plan.same.map(({ index, bid }) => ({ index, bid })),
        remove: plan.remove.map((r) => tripSummary(r, activeSessions)),
      },
    }
    if (dryRun) return jsonResponse(response, 200, cors)

    await ensureScheduleChangesTable(env)
    const batchId = newBatchId('ai')
    const actor = actorFromRequest(request)
    const statements = []

    for (const u of plan.update) {
      const row = rows[u.index]
      statements.push(
        updateScheduleStatement(env, u.bid, row),
        changeLogStatement(env, {
          bid: u.bid,
          company,
          action: 'update',
          before: u.before,
          after: { BID: u.bid, ...row },
          actor,
          batchId,
        })
      )
    }
    for (const a of plan.add) {
      const row = rows[a.index]
      statements.push(
        insertScheduleStatement(env, row),
        createdRowLogStatement(env, { company, row, actor, batchId })
      )
    }
    for (const r of removing) {
      statements.push(
        env.DB.prepare('DELETE FROM bus_schedule_v2 WHERE BID = ?').bind(r.BID),
        changeLogStatement(env, {
          bid: r.BID,
          company,
          action: 'delete',
          before: r,
          after: null,
          actor,
          batchId,
        })
      )
    }

    if (!statements.length) {
      return jsonResponse({ ...response, applied: true, unchanged: true, batch_id: null }, 200, cors)
    }
    await env.DB.batch(statements)
    return jsonResponse({ ...response, applied: true, batch_id: batchId }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
