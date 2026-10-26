import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'
import {
  ROW_COLUMNS,
  actorFromRequest,
  changeLogStatement,
  ensureScheduleChangesTable,
  newBatchId,
  sameRow,
  updateScheduleStatement,
} from '../../lib/scheduleHelpers.js'

function parseJson(raw) {
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

/**
 * GET ?company=&limit= — newest schedule edits for one company.
 * Single edits come back as kind "change"; AI imports and batch undos are
 * collapsed into one kind "batch" entry with per-action counts.
 */
export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const url = new URL(request.url)
  const company = (url.searchParams.get('company') || '').trim()
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 25, 1), 100)
  if (!company) {
    return jsonResponse({ error: 'company query parameter is required' }, 400, cors)
  }

  try {
    await ensureScheduleChangesTable(env)
    const [singles, batches] = await env.DB.batch([
      env.DB.prepare(
        `
        SELECT * FROM schedule_changes
        WHERE company = ? AND batch_id IS NULL
        ORDER BY id DESC
        LIMIT ?
      `
      ).bind(company, limit),
      env.DB.prepare(
        `
        SELECT batch_id, MAX(id) AS id, MAX(created_at) AS created_at, MAX(actor) AS actor,
          SUM(action = 'create') AS creates,
          SUM(action = 'update') AS updates,
          SUM(action = 'delete') AS deletes,
          SUM(action = 'restore') AS restores,
          COUNT(*) AS total
        FROM schedule_changes
        WHERE company = ? AND batch_id IS NOT NULL
        GROUP BY batch_id
        ORDER BY id DESC
        LIMIT ?
      `
      ).bind(company, limit),
    ])

    const changes = [
      ...(singles.results || []).map((c) => ({
        kind: 'change',
        id: c.id,
        bid: c.bid,
        company: c.company,
        action: c.action,
        actor: c.actor,
        created_at: c.created_at,
        before: parseJson(c.before_json),
        after: parseJson(c.after_json),
      })),
      ...(batches.results || []).map((b) => ({
        kind: 'batch',
        id: b.id,
        batch_id: b.batch_id,
        batch_type: String(b.batch_id).startsWith('undo-') ? 'undo' : 'ai',
        actor: b.actor,
        created_at: b.created_at,
        counts: {
          create: b.creates,
          update: b.updates,
          delete: b.deletes,
          restore: b.restores,
          total: b.total,
        },
      })),
    ]
      .sort((a, b) => b.id - a.id)
      .slice(0, limit)

    return jsonResponse({ changes }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

/** Statements that put one trip back to `target` (null = trip should not exist). */
function restoreStatements(env, bid, target, current) {
  if (!target) {
    return current ? [env.DB.prepare('DELETE FROM bus_schedule_v2 WHERE BID = ?').bind(bid)] : []
  }
  if (current) return [updateScheduleStatement(env, bid, target)]
  return [
    env.DB.prepare(
      `INSERT INTO bus_schedule_v2 (${ROW_COLUMNS.join(', ')}) VALUES (${ROW_COLUMNS.map(() => '?').join(', ')})`
    ).bind(...ROW_COLUMNS.map((c) => (c === 'BID' ? bid : target[c] ?? null))),
  ]
}

async function currentRows(env, bids) {
  const map = new Map()
  for (let i = 0; i < bids.length; i += 90) {
    const chunk = bids.slice(i, i + 90)
    const { results } = await env.DB.prepare(
      `SELECT * FROM bus_schedule_v2 WHERE BID IN (${chunk.map(() => '?').join(', ')})`
    )
      .bind(...chunk)
      .all()
    for (const r of results || []) map.set(r.BID, r)
  }
  return map
}

/**
 * POST { id, force? } — undo one change.
 * POST { batch_id, force? } — undo every change from one AI import (or batch undo).
 * Each trip goes back to its `before` state. Returns 409 when a trip was edited
 * again since, unless `force` is true.
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

  try {
    await ensureScheduleChangesTable(env)

    let changes
    if (body?.batch_id) {
      const { results } = await env.DB.prepare(
        'SELECT * FROM schedule_changes WHERE batch_id = ? ORDER BY id DESC'
      )
        .bind(String(body.batch_id))
        .all()
      changes = results || []
    } else {
      const changeId = Number(body?.id)
      if (!Number.isInteger(changeId) || changeId < 1) {
        return jsonResponse({ error: 'Invalid change id' }, 400, cors)
      }
      const one = await env.DB.prepare('SELECT * FROM schedule_changes WHERE id = ? LIMIT 1')
        .bind(changeId)
        .first()
      changes = one ? [one] : []
    }
    if (!changes.length) return jsonResponse({ error: 'Change not found' }, 404, cors)

    const current = await currentRows(env, [...new Set(changes.map((c) => c.bid))])
    const conflicts = changes.filter((c) => !sameRow(current.get(c.bid) || null, parseJson(c.after_json)))
    if (conflicts.length && !body.force) {
      const many = changes.length > 1
      return jsonResponse(
        {
          error: many
            ? `${conflicts.length} of these trips changed since the import. Undo anyway?`
            : 'This trip has changed since that edit. Undo anyway?',
          conflict: true,
        },
        409,
        cors
      )
    }

    const batchId = body?.batch_id ? newBatchId('undo') : null
    const actor = actorFromRequest(request)
    const statements = []
    for (const c of changes) {
      const target = parseJson(c.before_json)
      const now = current.get(c.bid) || null
      if (sameRow(now, target)) continue
      const restore = restoreStatements(env, c.bid, target, now)
      if (!restore.length) continue
      statements.push(
        ...restore,
        changeLogStatement(env, {
          bid: c.bid,
          company: target?.company || now?.company || c.company,
          action: 'restore',
          before: now,
          after: target ? { ...target, BID: c.bid } : null,
          actor,
          batchId,
        })
      )
    }

    if (!statements.length) {
      return jsonResponse({ success: true, unchanged: true }, 200, cors)
    }
    await env.DB.batch(statements)
    return jsonResponse({ success: true, batch_id: batchId }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
