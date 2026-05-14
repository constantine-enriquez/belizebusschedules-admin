/**
 * POST multipart/form-data with field "file" (image/jpeg, image/png, image/webp).
 * Stores object at {companySlug}/{vehicleId}.{ext} in R2 and updates vehicles.photo_url.
 *
 * Pages: bind R2 bucket as BUS_IMAGES (same bucket as images.belizebusschedules.com).
 * Env: IMAGES_PUBLIC_BASE = https://images.belizebusschedules.com (no trailing slash)
 */

import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../../lib/adminHelpers.js'

const MAX_BYTES = 5 * 1024 * 1024

const MIME_EXT = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
}

function companyFolderSlug(name) {
  const s = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
  return s || 'unknown'
}

function publicBase(env) {
  const b = String(env.IMAGES_PUBLIC_BASE || '').trim()
  if (b) return b.replace(/\/+$/, '')
  return 'https://images.belizebusschedules.com'
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

export async function onRequestPost(context) {
  const { request, env } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const id = vehicleIdFromContext(context)
  if (!id) {
    return jsonResponse({ error: 'Missing vehicle id' }, 400, cors)
  }

  if (!env.BUS_IMAGES) {
    return jsonResponse(
      {
        error:
          'R2 binding BUS_IMAGES is not configured. Add it under Pages → Settings → Functions → R2 bucket bindings.',
      },
      503,
      cors
    )
  }

  try {
    const row = await env.DB.prepare(
      'SELECT id, company_name FROM vehicles WHERE id = ? LIMIT 1'
    )
      .bind(id)
      .first()

    if (!row) {
      return jsonResponse({ error: 'Vehicle not found' }, 404, cors)
    }

    const ct = request.headers.get('Content-Type') || ''
    if (!ct.includes('multipart/form-data')) {
      return jsonResponse(
        { error: 'Expected multipart/form-data with field "file"' },
        400,
        cors
      )
    }

    const form = await request.formData()
    const file = form.get('file')
    if (!file || typeof file.arrayBuffer !== 'function') {
      return jsonResponse({ error: 'Missing file field' }, 400, cors)
    }

    const mime = (file.type || '').toLowerCase()
    const ext = MIME_EXT[mime]
    if (!ext) {
      return jsonResponse(
        { error: 'Only JPEG, PNG, or WebP images are allowed' },
        400,
        cors
      )
    }

    const buf = await file.arrayBuffer()
    if (buf.byteLength > MAX_BYTES) {
      return jsonResponse(
        { error: `Image too large (max ${MAX_BYTES / 1024 / 1024} MB)` },
        400,
        cors
      )
    }

    const slug = companyFolderSlug(row.company_name)
    const key = `${slug}/${id}.${ext}`
    const base = publicBase(env)
    const photoUrl = `${base}/${key}`

    await env.BUS_IMAGES.put(key, buf, {
      httpMetadata: { contentType: mime },
    })

    const now = new Date().toISOString()
    await env.DB.prepare(
      'UPDATE vehicles SET photo_url = ?, updated_at = ? WHERE id = ?'
    )
      .bind(photoUrl, now, id)
      .run()

    return jsonResponse({ success: true, photo_url: photoUrl, key }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message || 'Upload failed' }, 500, cors)
  }
}
