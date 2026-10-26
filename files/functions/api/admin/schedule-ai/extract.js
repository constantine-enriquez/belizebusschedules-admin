import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'
import { bytesToBase64, extractTrips, getAiSettings } from '../../../lib/geminiExtract.js'
import { companyPhone, normalizeSchedulePayload } from '../../../lib/scheduleHelpers.js'

const MAX_IMAGE_BYTES = 14 * 1024 * 1024
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif']

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

async function companyContext(env, company) {
  const [places, days, services, routes] = await env.DB.batch([
    env.DB.prepare(`
      SELECT place, COUNT(*) AS n FROM (
        SELECT origin AS place FROM bus_schedule_v2
        UNION ALL SELECT destination FROM bus_schedule_v2
        UNION ALL
        SELECT json_extract(j.value, '$.location')
        FROM bus_schedule_v2,
          json_each(
            CASE WHEN json_valid(bus_schedule_v2.stops_data)
              AND json_type(bus_schedule_v2.stops_data) = 'array'
            THEN bus_schedule_v2.stops_data ELSE '[]' END
          ) AS j
      )
      WHERE place IS NOT NULL AND TRIM(place) != ''
      GROUP BY place ORDER BY n DESC LIMIT 250
    `),
    env.DB.prepare(`
      SELECT days_of_operation AS v FROM bus_schedule_v2
      WHERE days_of_operation IS NOT NULL AND TRIM(days_of_operation) != ''
      GROUP BY days_of_operation ORDER BY COUNT(*) DESC LIMIT 30
    `),
    env.DB.prepare(`
      SELECT service_type AS v FROM bus_schedule_v2
      WHERE service_type IS NOT NULL AND TRIM(service_type) != ''
      GROUP BY service_type ORDER BY COUNT(*) DESC LIMIT 30
    `),
    env.DB.prepare(`
      SELECT route AS v, COUNT(*) AS n FROM bus_schedule_v2
      WHERE company = ? AND route IS NOT NULL
      GROUP BY route ORDER BY n DESC LIMIT 40
    `).bind(company),
  ])
  const list = (r, key = 'v') => (r.results || []).map((x) => x[key])
  return {
    places: list(places, 'place'),
    days: list(days),
    services: list(services),
    routes: list(routes),
  }
}

/**
 * POST multipart/form-data { company, image, note? }
 * → { trips: [{ trip, errors, warnings, confidence, unreadable_fields }], photo_notes, current_count, model }
 * Nothing is written to bus_schedule_v2 here; see /api/admin/schedule-ai/apply.
 */
export async function onRequestPost({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  let form
  try {
    form = await request.formData()
  } catch {
    return jsonResponse({ error: 'Expected multipart form data' }, 400, cors)
  }

  const company = String(form.get('company') || '').trim()
  const note = String(form.get('note') || '').trim().slice(0, 1000)
  const image = form.get('image')
  if (!company) return jsonResponse({ error: 'Pick a company first' }, 400, cors)
  if (!image || typeof image === 'string') {
    return jsonResponse({ error: 'Attach a schedule photo' }, 400, cors)
  }
  const mimeType = (image.type || '').toLowerCase()
  if (!ALLOWED_TYPES.includes(mimeType)) {
    return jsonResponse({ error: 'Photo must be JPEG, PNG, WebP, or HEIC' }, 400, cors)
  }
  if (image.size > MAX_IMAGE_BYTES) {
    return jsonResponse({ error: 'Photo is too large (max 14 MB)' }, 400, cors)
  }

  try {
    const [settings, ctx, phone, countRow] = await Promise.all([
      getAiSettings(env),
      companyContext(env, company),
      companyPhone(env, company),
      env.DB.prepare('SELECT COUNT(*) AS n FROM bus_schedule_v2 WHERE company = ?').bind(company).first(),
    ])

    const userText = [
      `Company: ${company}`,
      ctx.routes.length ? `This company's current route names: ${ctx.routes.join('; ')}` : null,
      `Known place spellings: ${ctx.places.join('; ')}`,
      `Known days_of_operation values: ${ctx.days.join('; ')}`,
      `Known service_type values: ${ctx.services.join('; ')}`,
      note ? `Extra instructions for this photo: ${note}` : null,
      'Extract every trip shown in the attached photo.',
    ]
      .filter(Boolean)
      .join('\n\n')

    const bytes = new Uint8Array(await image.arrayBuffer())
    const result = await extractTrips(env, {
      imageBase64: bytesToBase64(bytes),
      mimeType,
      systemPrompt: settings.system_prompt,
      model: settings.model,
      userText,
    })

    const trips = result.trips.map((raw) => {
      const { row, stops, errors, warnings } = normalizeSchedulePayload({
        ...raw,
        company,
        phone_number: phone,
        stops: Array.isArray(raw?.stops) ? raw.stops : [],
      })
      const { stops_data: _stopsData, ...fields } = row
      return {
        trip: { ...fields, stops },
        errors,
        warnings,
        confidence: typeof raw?.confidence === 'number' ? raw.confidence : null,
        unreadable_fields: Array.isArray(raw?.unreadable_fields) ? raw.unreadable_fields : [],
      }
    })

    return jsonResponse(
      {
        trips,
        photo_notes: result.photo_notes,
        current_count: countRow?.n ?? 0,
        model: result.model,
        usage: result.usage,
      },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, e.status || 500, cors)
  }
}
