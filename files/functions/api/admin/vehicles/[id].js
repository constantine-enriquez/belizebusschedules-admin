import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'

function normalizePlate(input) {
  if (typeof input !== 'string') return ''
  return input
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .substring(0, 24)
}

function vehicleIdFromContext(context) {
  const { params, request } = context
  if (params?.id) return params.id
  const parts = new URL(request.url).pathname.split('/').filter(Boolean)
  const idx = parts.indexOf('vehicles')
  if (idx >= 0 && parts[idx + 1]) return parts[idx + 1]
  return null
}

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

export async function onRequestPatch(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = vehicleIdFromContext(context)
  if (!id) {
    return jsonResponse({ error: 'Missing vehicle id' }, 400, cors)
  }

  try {
    const body = await request.json()
    const row = await env.DB.prepare(
      'SELECT * FROM vehicles WHERE id = ? LIMIT 1'
    )
      .bind(id)
      .first()
    if (!row) {
      return jsonResponse({ error: 'Vehicle not found' }, 404, cors)
    }

    const companyName =
      body.company_name != null
        ? String(body.company_name).trim()
        : row.company_name
    const plate = body.plate != null ? String(body.plate).trim() : row.plate
    const plateNormalized =
      body.plate != null ? normalizePlate(plate) : row.plate_normalized
    if (body.plate != null && !plateNormalized) {
      return jsonResponse({ error: 'Invalid plate' }, 400, cors)
    }

    const vin =
      body.vin !== undefined ? String(body.vin || '').trim() || null : row.vin

    let features = row.features
    if (body.features !== undefined) {
      if (typeof body.features === 'string') {
        try {
          JSON.parse(body.features)
          features = body.features
        } catch {
          return jsonResponse({ error: 'features must be valid JSON' }, 400, cors)
        }
      } else if (typeof body.features === 'object' && body.features !== null) {
        features = JSON.stringify(body.features)
      }
    }

    const status =
      body.status != null ? String(body.status).trim() : row.status
    const notes =
      body.notes !== undefined ? String(body.notes || '').trim() || null : row.notes
    const photoUrl =
      body.photo_url !== undefined
        ? String(body.photo_url || '').trim() || null
        : row.photo_url

    const now = new Date().toISOString()

    await env.DB.prepare(
      `
      UPDATE vehicles SET
        company_name = ?, plate = ?, plate_normalized = ?, vin = ?, features = ?,
        status = ?, notes = ?, photo_url = ?, updated_at = ?
      WHERE id = ?
    `
    )
      .bind(
        companyName,
        plate,
        plateNormalized,
        vin,
        features,
        status,
        notes,
        photoUrl,
        now,
        id
      )
      .run()

    return jsonResponse({ success: true }, 200, cors)
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

export async function onRequestDelete(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = vehicleIdFromContext(context)
  if (!id) {
    return jsonResponse({ error: 'Missing vehicle id' }, 400, cors)
  }

  try {
    await env.DB.prepare('DELETE FROM vehicles WHERE id = ?').bind(id).run()
    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
