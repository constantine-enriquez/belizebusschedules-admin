/**
 * Ads validation + D1 helpers for admin ad routes.
 * Public passenger serve lives on api.belizebusschedules.com (Flutter worker.js).
 */

export const PLACEMENTS = new Set(['strip', 'card'])
export const STATUSES = new Set(['draft', 'active', 'paused'])
export const CATEGORIES = new Set([
  'restaurant',
  'hotel',
  'shop',
  'taxi',
  'tour',
  'pharmacy',
  'car_rental',
  'other',
])
export const CTA_TYPES = new Set(['whatsapp', 'call', 'directions', 'website', 'custom'])
export const CTA_STYLES = new Set(['primary', 'secondary'])

const ADS_CATEGORY_CHECK = `category_kind IN (
      'restaurant', 'hotel', 'shop', 'taxi',
      'tour', 'pharmacy', 'car_rental', 'other'
    )`

/** Keep creatives compact so passenger UI stays readable. */
export const FIELD_LIMITS = {
  eyebrow: 28,
  title: 36,
  support: 42,
  subtitle: 48,
  body: 90,
  discount_teaser: 36,
  discount_code: 16,
  discount_summary: 48,
  cta_label: 14,
}

function clip(value, max) {
  if (value == null) return value
  const s = String(value)
  return s.length > max ? s.slice(0, max) : s
}

export async function ensureAdsTable(env) {
  await env.DB.prepare(
    `
    CREATE TABLE IF NOT EXISTS ads (
      id TEXT PRIMARY KEY,
      placement TEXT NOT NULL CHECK (placement IN ('strip', 'card')),
      origin TEXT NOT NULL,
      destination TEXT NOT NULL,
      starts_at TEXT NOT NULL,
      ends_at TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'paused')),
      category_kind TEXT NOT NULL CHECK (
        ${ADS_CATEGORY_CHECK}
      ),
      eyebrow TEXT,
      title TEXT NOT NULL,
      subtitle TEXT,
      body TEXT,
      support TEXT,
      discount_teaser TEXT,
      discount_code TEXT,
      discount_summary TEXT,
      discount_valid_until TEXT,
      ctas_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `
  ).run()

  // Existing D1 tables keep the old CHECK; rebuild when new categories are missing.
  const meta = await env.DB.prepare(
    `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ads'`
  ).first()
  const ddl = String(meta?.sql || '')
  if (ddl && !ddl.includes("'tour'")) {
    await env.DB.batch([
      env.DB.prepare(
        `
        CREATE TABLE ads__cat_mig (
          id TEXT PRIMARY KEY,
          placement TEXT NOT NULL CHECK (placement IN ('strip', 'card')),
          origin TEXT NOT NULL,
          destination TEXT NOT NULL,
          starts_at TEXT NOT NULL,
          ends_at TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'paused')),
          category_kind TEXT NOT NULL CHECK (
            ${ADS_CATEGORY_CHECK}
          ),
          eyebrow TEXT,
          title TEXT NOT NULL,
          subtitle TEXT,
          body TEXT,
          support TEXT,
          discount_teaser TEXT,
          discount_code TEXT,
          discount_summary TEXT,
          discount_valid_until TEXT,
          ctas_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `
      ),
      env.DB.prepare(
        `
        INSERT INTO ads__cat_mig
        SELECT
          id, placement, origin, destination, starts_at, ends_at, status,
          category_kind, eyebrow, title, subtitle, body, support,
          discount_teaser, discount_code, discount_summary, discount_valid_until,
          ctas_json, created_at, updated_at
        FROM ads
      `
      ),
      env.DB.prepare(`DROP TABLE ads`),
      env.DB.prepare(`ALTER TABLE ads__cat_mig RENAME TO ads`),
      env.DB.prepare(
        `
        CREATE INDEX IF NOT EXISTS idx_ads_route_placement
          ON ads(origin, destination, placement, status)
      `
      ),
    ])
  } else {
    await env.DB.prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_ads_route_placement
        ON ads(origin, destination, placement, status)
    `
    ).run()
  }
}

export function parseCtas(raw) {
  if (Array.isArray(raw)) return raw
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw)
      return Array.isArray(parsed) ? parsed : null
    } catch {
      return null
    }
  }
  return null
}

const PHONE_RE = /^\+?[\d\s\-().]{7,20}$/

/**
 * Fixes common shorthand (bare phone numbers, domains without https://) and rejects
 * links that don't fit the CTA type — passenger apps open these hrefs directly.
 * @returns {{ href: string } | { error: string }}
 */
export function normalizeCtaHref(type, href) {
  const h = String(href || '').trim()
  if (type === 'call') {
    if (/^tel:\+?[\d\-().]{3,20}$/i.test(h.replace(/\s/g, ''))) return { href: h.replace(/\s/g, '') }
    if (PHONE_RE.test(h)) return { href: `tel:${h.replace(/[^\d+]/g, '')}` }
    return { error: 'Call actions need a phone number, e.g. tel:+5016159303' }
  }
  if (type === 'whatsapp') {
    if (/^https:\/\/(wa\.me|api\.whatsapp\.com)\//i.test(h)) return { href: h }
    if (PHONE_RE.test(h)) return { href: `https://wa.me/${h.replace(/\D/g, '')}` }
    return { error: 'WhatsApp actions need a wa.me link or phone number, e.g. https://wa.me/5016159303' }
  }
  if (/^https?:\/\/[^\s]+\.[^\s]+/i.test(h)) return { href: h }
  if (type === 'custom' && /^mailto:[^\s@]+@[^\s@]+$/i.test(h)) return { href: h }
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/[^\s]*)?$/i.test(h)) return { href: `https://${h}` }
  return { error: 'Links must be a web address starting with https://' }
}

export function normalizeCtas(ctas, placement) {
  if (!Array.isArray(ctas)) {
    return { error: 'ctas must be an array' }
  }
  const max = placement === 'strip' ? 1 : 3
  const min = 1
  if (ctas.length < min || ctas.length > max) {
    return {
      error:
        placement === 'strip'
          ? 'Strip ads need exactly 1 CTA'
          : 'Card ads need 1–3 CTAs',
    }
  }

  let primaryCount = 0
  const out = []
  for (const c of ctas) {
    const type = String(c?.type || '').trim()
    const label = String(c?.label || '').trim()
    const href = String(c?.href || '').trim()
    const style = String(c?.style || 'secondary').trim() || 'secondary'
    if (!CTA_TYPES.has(type)) {
      return { error: `Invalid CTA type: ${type || '(empty)'}` }
    }
    if (!CTA_STYLES.has(style)) {
      return { error: `Invalid CTA style: ${style}` }
    }
    if (!label) return { error: 'Each CTA needs a label' }
    if (!href) return { error: 'Each CTA needs an href' }
    if (label.length > FIELD_LIMITS.cta_label) {
      return {
        error: `CTA label max ${FIELD_LIMITS.cta_label} characters`,
      }
    }
    const link = normalizeCtaHref(type, href)
    if (link.error) return { error: `“${label}”: ${link.error}` }
    if (style === 'primary') primaryCount += 1
    out.push({ type, label: clip(label, FIELD_LIMITS.cta_label), href: link.href, style })
  }
  if (placement === 'card' && primaryCount > 1) {
    return { error: 'Card ads can have at most one primary CTA' }
  }
  return { ctas: out }
}

function nullIfEmpty(v) {
  if (v == null) return null
  const s = String(v).trim()
  return s ? s : null
}

/**
 * Validate create/update body. For PATCH, pass existing row and only send changed fields.
 */
export function normalizeAdPayload(body, { existing = null } = {}) {
  const placement = String(
    body.placement != null ? body.placement : existing?.placement || ''
  )
    .trim()
    .toLowerCase()
  if (!PLACEMENTS.has(placement)) {
    return { error: 'placement must be strip or card' }
  }

  const origin = String(
    body.origin != null ? body.origin : existing?.origin || ''
  ).trim()
  const destination = String(
    body.destination != null ? body.destination : existing?.destination || ''
  ).trim()
  if (!origin || !destination) {
    return { error: 'origin and destination are required' }
  }

  const startsAt = String(
    body.starts_at != null ? body.starts_at : existing?.starts_at || ''
  ).trim()
  const endsAt = String(
    body.ends_at != null ? body.ends_at : existing?.ends_at || ''
  ).trim()
  if (!startsAt || !endsAt) {
    return { error: 'starts_at and ends_at are required' }
  }
  if (new Date(startsAt).toString() === 'Invalid Date') {
    return { error: 'starts_at must be a valid ISO date' }
  }
  if (new Date(endsAt).toString() === 'Invalid Date') {
    return { error: 'ends_at must be a valid ISO date' }
  }
  if (new Date(endsAt) <= new Date(startsAt)) {
    return { error: 'ends_at must be after starts_at' }
  }

  const status = String(
    body.status != null ? body.status : existing?.status || 'draft'
  )
    .trim()
    .toLowerCase()
  if (!STATUSES.has(status)) {
    return { error: 'status must be draft, active, or paused' }
  }

  const categoryKind = String(
    body.category_kind != null
      ? body.category_kind
      : existing?.category_kind || ''
  )
    .trim()
    .toLowerCase()
  if (!CATEGORIES.has(categoryKind)) {
    return { error: 'Invalid category_kind' }
  }

  const titleRaw = String(
    body.title != null ? body.title : existing?.title || ''
  ).trim()
  if (!titleRaw) return { error: 'title is required' }
  if (titleRaw.length > FIELD_LIMITS.title) {
    return { error: `title max ${FIELD_LIMITS.title} characters` }
  }
  const title = clip(titleRaw, FIELD_LIMITS.title)

  function takeLimited(field, key, max) {
    const raw =
      body[field] !== undefined
        ? nullIfEmpty(body[field])
        : existing
          ? existing[key]
          : null
    if (raw && String(raw).length > max) {
      return { error: `${field} max ${max} characters` }
    }
    return { value: raw ? clip(raw, max) : raw }
  }

  const eyebrowRes = takeLimited('eyebrow', 'eyebrow', FIELD_LIMITS.eyebrow)
  if (eyebrowRes.error) return eyebrowRes
  const subtitleRes = takeLimited('subtitle', 'subtitle', FIELD_LIMITS.subtitle)
  if (subtitleRes.error) return subtitleRes
  const bodyRes = takeLimited('body', 'body', FIELD_LIMITS.body)
  if (bodyRes.error) return bodyRes
  const supportRes = takeLimited('support', 'support', FIELD_LIMITS.support)
  if (supportRes.error) return supportRes

  const eyebrow = eyebrowRes.value
  const subtitle = subtitleRes.value
  const bodyText = bodyRes.value
  const support = supportRes.value

  let discountTeaserRes = takeLimited(
    'discount_teaser',
    'discount_teaser',
    FIELD_LIMITS.discount_teaser
  )
  if (discountTeaserRes.error) return discountTeaserRes
  let discountCodeRes = takeLimited(
    'discount_code',
    'discount_code',
    FIELD_LIMITS.discount_code
  )
  if (discountCodeRes.error) return discountCodeRes
  let discountSummaryRes = takeLimited(
    'discount_summary',
    'discount_summary',
    FIELD_LIMITS.discount_summary
  )
  if (discountSummaryRes.error) return discountSummaryRes

  let discountTeaser = discountTeaserRes.value
  let discountCode = discountCodeRes.value
  let discountSummary = discountSummaryRes.value
  let discountValidUntil =
    body.discount_valid_until !== undefined
      ? nullIfEmpty(body.discount_valid_until)
      : existing
        ? existing.discount_valid_until
        : null

  if (placement === 'strip') {
    discountTeaser = null
    discountCode = null
    discountSummary = null
    discountValidUntil = null
  }

  let ctasRaw =
    body.ctas !== undefined
      ? body.ctas
      : body.ctas_json !== undefined
        ? parseCtas(body.ctas_json)
        : existing
          ? parseCtas(existing.ctas_json)
          : null

  const ctaResult = normalizeCtas(ctasRaw || [], placement)
  if (ctaResult.error) return { error: ctaResult.error }

  return {
    ad: {
      placement,
      origin,
      destination,
      starts_at: startsAt,
      ends_at: endsAt,
      status,
      category_kind: categoryKind,
      eyebrow,
      title,
      subtitle: placement === 'card' ? subtitle : null,
      body: placement === 'card' ? bodyText : null,
      support: placement === 'strip' ? support : null,
      discount_teaser: discountTeaser,
      discount_code: discountCode,
      discount_summary: discountSummary,
      discount_valid_until: discountValidUntil,
      ctas_json: JSON.stringify(ctaResult.ctas),
    },
  }
}

export function rowToAd(row) {
  if (!row) return null
  return {
    ...row,
    ctas: parseCtas(row.ctas_json) || [],
  }
}

export function emptyAdStats() {
  return {
    impressions: 0,
    clicks: 0,
    discount_opens: 0,
    code_copies: 0,
    ctr: 0,
    by_cta: {},
  }
}

/**
 * Aggregate event counts for many ads (list view).
 * @returns {Promise<Record<string, ReturnType<typeof emptyAdStats>>>}
 */
export async function getAdStatsMap(env, adIds) {
  const map = {}
  if (!adIds?.length) return map
  for (const id of adIds) map[id] = emptyAdStats()

  try {
    const placeholders = adIds.map(() => '?').join(',')
    const { results } = await env.DB.prepare(
      `
      SELECT
        ad_id,
        event,
        cta_type,
        COUNT(*) AS n
      FROM ad_events
      WHERE ad_id IN (${placeholders})
      GROUP BY ad_id, event, cta_type
    `
    )
      .bind(...adIds)
      .all()

    for (const row of results || []) {
      const stats = map[row.ad_id] || emptyAdStats()
      const n = Number(row.n) || 0
      if (row.event === 'impression') stats.impressions += n
      else if (row.event === 'cta_click') {
        stats.clicks += n
        const key = row.cta_type || 'other'
        stats.by_cta[key] = (stats.by_cta[key] || 0) + n
      } else if (row.event === 'discount_open') stats.discount_opens += n
      else if (row.event === 'code_copy') stats.code_copies += n
      map[row.ad_id] = stats
    }

    for (const id of Object.keys(map)) {
      const s = map[id]
      s.ctr =
        s.impressions > 0
          ? Math.round((s.clicks / s.impressions) * 1000) / 10
          : 0
    }
  } catch {
    // ad_events table may be missing — leave zeros
  }
  return map
}

/** Full stats for one ad (report modal). */
export async function getAdStatsDetail(env, adId) {
  const map = await getAdStatsMap(env, [adId])
  return map[adId] || emptyAdStats()
}

/**
 * Find overlapping active ads for same placement + route.
 * Overlap if date ranges intersect (starts_at < other.ends AND ends_at > other.starts).
 */
export async function findOverlaps(env, { placement, origin, destination, starts_at, ends_at, excludeId = null }) {
  const { results } = await env.DB.prepare(
    `
    SELECT id, title, starts_at, ends_at, status
    FROM ads
    WHERE placement = ?
      AND origin = ?
      AND destination = ?
      AND status = 'active'
      AND starts_at < ?
      AND ends_at > ?
      ${excludeId ? 'AND id != ?' : ''}
  `
  )
    .bind(
      ...(excludeId
        ? [placement, origin, destination, ends_at, starts_at, excludeId]
        : [placement, origin, destination, ends_at, starts_at])
    )
    .all()
  return results || []
}

/** Pause active overlapping ads. Returns the rows that were paused. */
export async function pauseOverlappingAds(env, overlaps) {
  if (!overlaps?.length) return []
  const now = new Date().toISOString()
  const paused = []
  for (const row of overlaps) {
    await env.DB.prepare(
      `UPDATE ads SET status = 'paused', updated_at = ? WHERE id = ? AND status = 'active'`
    )
      .bind(now, row.id)
      .run()
    paused.push({ ...row, status: 'paused' })
  }
  return paused
}

export function scheduleLabel(row) {
  const now = Date.now()
  const start = new Date(row.starts_at).getTime()
  const end = new Date(row.ends_at).getTime()
  if (row.status === 'paused') return 'Paused'
  if (row.status === 'draft') return 'Draft'
  if (row.status === 'active') {
    if (now < start) return 'Scheduled'
    if (now >= end) return 'Ended'
    return 'Live'
  }
  return row.status
}

/** Ensure origin→destination exists in the live schedule table (exact search match). */
export async function assertKnownRoute(env, origin, destination) {
  const row = await env.DB.prepare(
    `
    SELECT 1 AS ok
    FROM bus_schedule_v2
    WHERE origin = ? AND destination = ?
    LIMIT 1
  `
  )
    .bind(origin, destination)
    .first()
  if (!row) {
    return {
      error:
        'From/To must match an existing schedule route exactly (pick from the dropdowns)',
    }
  }
  return { ok: true }
}
