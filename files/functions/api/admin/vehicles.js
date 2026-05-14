import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../lib/adminHelpers.js'

function normalizePlate(input) {
  if (typeof input !== 'string') return ''
  return input
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .substring(0, 24)
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const url = new URL(request.url)
  const company = (url.searchParams.get('company') || '').trim()

  try {
    let stmt = `
      SELECT id, company_name, plate, plate_normalized, vin, features, status, notes,
             COALESCE(photo_url, '') AS photo_url, created_at, updated_at
      FROM vehicles
    `
    const binds = []
    if (company) {
      stmt += ' WHERE company_name = ?'
      binds.push(company)
    }
    stmt += ' ORDER BY company_name ASC, plate_normalized ASC'

    const q = env.DB.prepare(stmt)
    const { results } =
      binds.length > 0 ? await q.bind(...binds).all() : await q.all()

    return jsonResponse({ vehicles: results || [] }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestPost({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    const body = await request.json()
    const companyName = String(body.company_name || '').trim()
    const plateRaw = String(body.plate || '').trim()
    if (!companyName || !plateRaw) {
      return jsonResponse(
        { error: 'company_name and plate are required' },
        400,
        cors
      )
    }

    const plateNormalized = normalizePlate(plateRaw)
    if (!plateNormalized) {
      return jsonResponse({ error: 'Invalid plate' }, 400, cors)
    }

    let features = '{}'
    if (body.features != null) {
      if (typeof body.features === 'string') {
        try {
          JSON.parse(body.features)
          features = body.features
        } catch {
          return jsonResponse({ error: 'features must be valid JSON' }, 400, cors)
        }
      } else if (typeof body.features === 'object') {
        features = JSON.stringify(body.features)
      }
    }

    const vin = body.vin != null ? String(body.vin).trim() || null : null
    const status = String(body.status || 'active').trim() || 'active'
    const notes = body.notes != null ? String(body.notes).trim() || null : null
    const photoUrl =
      body.photo_url != null ? String(body.photo_url).trim() || null : null

    const id = crypto.randomUUID()
    const now = new Date().toISOString()

    await env.DB.prepare(
      `
      INSERT INTO vehicles (
        id, company_name, plate, plate_normalized, vin, features, status, notes, photo_url, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    )
      .bind(
        id,
        companyName,
        plateRaw,
        plateNormalized,
        vin,
        features,
        status,
        notes,
        photoUrl,
        now,
        now
      )
      .run()

    return jsonResponse({ success: true, id }, 200, cors)
  } catch (e) {
    if (String(e.message || '').includes('UNIQUE')) {
      return jsonResponse(
        { error: 'A vehicle with this company and plate already exists' },
        409,
        cors
      )
    }
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
