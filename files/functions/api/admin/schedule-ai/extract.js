import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'
import { bytesToBase64, extractTrips, getAiSettings } from '../../../lib/geminiExtract.js'
import { companyPhone, normalizeSchedulePayload, rowToSchedule } from '../../../lib/scheduleHelpers.js'

const MAX_IMAGE_BYTES = 14 * 1024 * 1024
const MAX_PHOTOS = 6
// Gemini caps inline request data at ~20 MB, and base64 adds a third on top of the raw bytes.
const MAX_TOTAL_BYTES = 14 * 1024 * 1024
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

/** One saved trip in the response format, so the model copies this company's naming and stop style. */
async function exampleTrip(env, company) {
  const stopCount = `CASE WHEN json_valid(stops_data) THEN
      CASE WHEN json_type(stops_data) = 'array' THEN json_array_length(stops_data) ELSE 0 END
    ELSE 0 END`
  const row = await env.DB.prepare(
    `SELECT * FROM bus_schedule_v2
     WHERE company = ? AND ${stopCount} >= 2
     ORDER BY ${stopCount} DESC, BID ASC LIMIT 1`
  )
    .bind(company)
    .first()
    .catch(() => null)
  if (!row) return null
  const s = rowToSchedule(row)
  if (s.stops_invalid) return null
  return {
    route: s.route,
    origin: s.origin,
    destination: s.destination,
    departure_time: s.departure_time,
    arrival_time: s.arrival_time,
    days_of_operation: s.days_of_operation,
    service_type: s.service_type,
    notes: s.notes,
    stops: s.stops,
  }
}

/**
 * POST multipart/form-data { company, image (1–6, repeated field), note? }
 * All photos go to Gemini in one request so trips spread across them come back as one list.
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
  const photos = form.getAll('image').filter((f) => f && typeof f !== 'string')
  if (!company) return jsonResponse({ error: 'Pick a company first' }, 400, cors)
  if (!photos.length) return jsonResponse({ error: 'Attach a schedule photo' }, 400, cors)
  if (photos.length > MAX_PHOTOS) {
    return jsonResponse({ error: `Attach at most ${MAX_PHOTOS} photos at a time` }, 400, cors)
  }
  for (const photo of photos) {
    if (!ALLOWED_TYPES.includes((photo.type || '').toLowerCase())) {
      return jsonResponse({ error: `${photo.name || 'A photo'} must be JPEG, PNG, WebP, or HEIC` }, 400, cors)
    }
    if (photo.size > MAX_IMAGE_BYTES) {
      return jsonResponse({ error: `${photo.name || 'A photo'} is too large (max 14 MB)` }, 400, cors)
    }
  }
  if (photos.reduce((sum, p) => sum + p.size, 0) > MAX_TOTAL_BYTES) {
    return jsonResponse({ error: 'Photos are too large together (max 14 MB total) — try fewer at a time' }, 400, cors)
  }

  try {
    const [settings, ctx, phone, countRow, example] = await Promise.all([
      getAiSettings(env),
      companyContext(env, company),
      companyPhone(env, company),
      env.DB.prepare('SELECT COUNT(*) AS n FROM bus_schedule_v2 WHERE company = ?').bind(company).first(),
      exampleTrip(env, company),
    ])

    const many = photos.length > 1
    const userText = [
      `Company: ${company}`,
      ctx.routes.length ? `This company's current route names: ${ctx.routes.join('; ')}` : null,
      `Known place spellings: ${ctx.places.join('; ')}`,
      `Known days_of_operation values: ${ctx.days.join('; ')}`,
      `Known service_type values: ${ctx.services.join('; ')}`,
      example
        ? `Example of one trip already saved for ${company}, in the exact output format. Match its place names, route naming, and stop style. Only return it if it actually appears in the ${many ? 'photos' : 'photo'}:\n${JSON.stringify(example)}`
        : null,
      many
        ? `There are ${photos.length} photos, all part of ${company}'s timetable (for example different directions, days, or pages). Combine them into one list. If the same trip appears in more than one photo, return it once. In photo_notes, refer to photos by number.`
        : null,
      note ? `Extra instructions: ${note}` : null,
      many ? 'Extract every trip shown across all the attached photos.' : 'Extract every trip shown in the attached photo.',
    ]
      .filter(Boolean)
      .join('\n\n')

    const images = await Promise.all(
      photos.map(async (p) => ({
        mimeType: p.type.toLowerCase(),
        data: bytesToBase64(new Uint8Array(await p.arrayBuffer())),
      }))
    )
    const result = await extractTrips(env, {
      images,
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
        fell_back_from: result.fell_back_from,
        usage: result.usage,
      },
      200,
      cors
    )
  } catch (e) {
    return jsonResponse({ error: e.message }, e.status || 500, cors)
  }
}
