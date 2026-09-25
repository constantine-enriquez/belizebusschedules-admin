import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'
import {
  ensureAdsTable,
  findOverlaps,
  normalizeAdPayload,
  rowToAd,
  scheduleLabel,
  assertKnownRoute,
} from '../../lib/adsHelpers.js'

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

/**
 * GET ?placement=strip|card — list ads (newest first)
 */
export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    await ensureAdsTable(env)
    const url = new URL(request.url)
    const placement = (url.searchParams.get('placement') || '').trim().toLowerCase()

    let sql = 'SELECT * FROM ads'
    const binds = []
    if (placement === 'strip' || placement === 'card') {
      sql += ' WHERE placement = ?'
      binds.push(placement)
    }
    sql += ' ORDER BY updated_at DESC'

    const q = env.DB.prepare(sql)
    const { results } =
      binds.length > 0 ? await q.bind(...binds).all() : await q.all()

    const ads = (results || []).map((row) => ({
      ...rowToAd(row),
      schedule_label: scheduleLabel(row),
    }))
    return jsonResponse({ ads }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

/**
 * POST — create ad. Body matches ads table fields + ctas[].
 * Query force=1 skips overlap block (still returns warning).
 */
export async function onRequestPost({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    await ensureAdsTable(env)
    const body = await request.json()
    const normalized = normalizeAdPayload(body)
    if (normalized.error) {
      return jsonResponse({ error: normalized.error }, 400, cors)
    }

    const ad = normalized.ad
    const routeCheck = await assertKnownRoute(env, ad.origin, ad.destination)
    if (routeCheck.error) {
      return jsonResponse({ error: routeCheck.error }, 400, cors)
    }

    const url = new URL(request.url)
    const force = url.searchParams.get('force') === '1'

    let overlaps = []
    if (ad.status === 'active') {
      overlaps = await findOverlaps(env, {
        placement: ad.placement,
        origin: ad.origin,
        destination: ad.destination,
        starts_at: ad.starts_at,
        ends_at: ad.ends_at,
      })
      if (overlaps.length && !force) {
        return jsonResponse(
          {
            error:
              'Another active ad overlaps this route and schedule for the same placement',
            overlaps,
            code: 'OVERLAP',
          },
          409,
          cors
        )
      }
    }

    const id = crypto.randomUUID()
    const now = new Date().toISOString()

    await env.DB.prepare(
      `
      INSERT INTO ads (
        id, placement, origin, destination, starts_at, ends_at, status,
        category_kind, eyebrow, title, subtitle, body, support,
        discount_teaser, discount_code, discount_summary, discount_valid_until,
        ctas_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    )
      .bind(
        id,
        ad.placement,
        ad.origin,
        ad.destination,
        ad.starts_at,
        ad.ends_at,
        ad.status,
        ad.category_kind,
        ad.eyebrow,
        ad.title,
        ad.subtitle,
        ad.body,
        ad.support,
        ad.discount_teaser,
        ad.discount_code,
        ad.discount_summary,
        ad.discount_valid_until,
        ad.ctas_json,
        now,
        now
      )
      .run()

    const row = await env.DB.prepare('SELECT * FROM ads WHERE id = ?')
      .bind(id)
      .first()

    return jsonResponse(
      {
        success: true,
        ad: { ...rowToAd(row), schedule_label: scheduleLabel(row) },
        overlaps: overlaps.length ? overlaps : undefined,
      },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
