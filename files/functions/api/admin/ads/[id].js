import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'
import {
  ensureAdsTable,
  findOverlaps,
  normalizeAdPayload,
  rowToAd,
  scheduleLabel,
  assertKnownRoute,
} from '../../../lib/adsHelpers.js'

function adIdFromContext(context) {
  const { params, request } = context
  if (params?.id) return params.id
  const parts = new URL(request.url).pathname.split('/').filter(Boolean)
  const idx = parts.indexOf('ads')
  if (idx >= 0 && parts[idx + 1]) return parts[idx + 1]
  return null
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

export async function onRequestGet(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = adIdFromContext(context)
  if (!id) return jsonResponse({ error: 'Missing ad id' }, 400, cors)

  try {
    await ensureAdsTable(env)
    const row = await env.DB.prepare('SELECT * FROM ads WHERE id = ? LIMIT 1')
      .bind(id)
      .first()
    if (!row) return jsonResponse({ error: 'Ad not found' }, 404, cors)
    return jsonResponse(
      { ad: { ...rowToAd(row), schedule_label: scheduleLabel(row) } },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestPatch(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = adIdFromContext(context)
  if (!id) return jsonResponse({ error: 'Missing ad id' }, 400, cors)

  try {
    await ensureAdsTable(env)
    const existing = await env.DB.prepare(
      'SELECT * FROM ads WHERE id = ? LIMIT 1'
    )
      .bind(id)
      .first()
    if (!existing) return jsonResponse({ error: 'Ad not found' }, 404, cors)

    const body = await request.json()
    const normalized = normalizeAdPayload(body, { existing })
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
        excludeId: id,
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

    const now = new Date().toISOString()
    await env.DB.prepare(
      `
      UPDATE ads SET
        placement = ?, origin = ?, destination = ?, starts_at = ?, ends_at = ?,
        status = ?, category_kind = ?, eyebrow = ?, title = ?, subtitle = ?,
        body = ?, support = ?, discount_teaser = ?, discount_code = ?,
        discount_summary = ?, discount_valid_until = ?, ctas_json = ?,
        updated_at = ?
      WHERE id = ?
    `
    )
      .bind(
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
        id
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

export async function onRequestDelete(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = adIdFromContext(context)
  if (!id) return jsonResponse({ error: 'Missing ad id' }, 400, cors)

  try {
    await ensureAdsTable(env)
    const existing = await env.DB.prepare(
      'SELECT id FROM ads WHERE id = ? LIMIT 1'
    )
      .bind(id)
      .first()
    if (!existing) return jsonResponse({ error: 'Ad not found' }, 404, cors)

    await env.DB.prepare('DELETE FROM ads WHERE id = ?').bind(id).run()
    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
