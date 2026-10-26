/**
 * Schedule photo → trips via the Gemini API.
 * Env (Cloudflare Pages → Settings → Variables and secrets):
 *   GEMINI_API_KEY (secret, required) — from https://aistudio.google.com/apikey
 *   GEMINI_MODEL (optional) — fallback when no model is saved in AI settings
 *
 * extractTrips() is the only provider-specific call; swap it to change AI vendors.
 */

// Free-tier models as of Oct 2026 (ai.google.dev/gemini-api/docs/pricing). Pro models are
// paid-only, and the 2.5 family is limited to accounts that already used it.
export const DEFAULT_MODEL = 'gemini-3.8-flash'
export const FALLBACK_MODEL = 'gemini-3.6-flash'

/** Saved 2.5 names from earlier deploys — remap so uploads don't waste a request on a locked model. */
const LEGACY_MODELS = new Set([
  'gemini-2.5-pro',
  'gemini-2.5-flash',
  'gemini-2.5-flash-lite',
  'gemini-2.0-flash',
  'gemini-2.0-flash-lite',
])

export function resolveModel(model, env) {
  const raw = String(model || '').trim()
  if (!raw || LEGACY_MODELS.has(raw)) return env?.GEMINI_MODEL || DEFAULT_MODEL
  return raw
}

export const DEFAULT_SYSTEM_PROMPT = `You read photos of bus timetables for Belize Bus Schedules and return every trip as structured data.

A trip is one bus run from its first stop to its last stop. Return one trip per run — never merge runs and never invent runs that are not printed.

How timetables are laid out:
- Grid timetables usually make each COLUMN (sometimes each ROW) one trip, with the stop names along the side. Read each trip's times along its column/row.
- Lists usually show one trip per line: departure time, route, and sometimes arrival time.
- If the photo has separate tables (e.g. weekdays vs Sundays, or each direction), extract all of them and set days_of_operation per table.

Field rules:
- Times are always "h:mm AM" or "h:mm PM" with no leading zero, e.g. "6:15 AM", "12:00 PM", "9:05 PM". Convert 24-hour times.
- origin = first stop, destination = last stop. Use the short town name for origin/destination (e.g. "Benque Viejo", "Belize City") and prefer the known place spellings provided.
- route = "<Origin> to <Destination>" using the names as printed (e.g. "Belize City to Benque Viejo Town").
- departure_time = first stop's depart time. arrival_time = last stop's arrive time, or null when not shown.
- stops lists every stop in travel order as { location, arrive, depart }.
  - First stop: depart = departure_time; arrive = 15 minutes before depart unless a different time is printed.
  - Middle stops: use printed times. When only one time is printed, use it for both arrive and depart.
  - Last stop: arrive = arrival time (or null), depart = null.
- days_of_operation: reuse one of the known values when it fits (e.g. "Monday to Sunday", "Monday to Saturday", "Monday to Friday"); otherwise copy what is printed.
- service_type: reuse a known value when it fits (e.g. "Regular", "Express"); otherwise copy what is printed, or null.
- notes: short operator notes that apply to the trip (e.g. "No 5:15AM Express on Sundays"), else null.

Accuracy:
- Never guess. If a value is unreadable, use null and add the field name to unreadable_fields (e.g. "arrival_time", "stops[2].depart").
- confidence is 0 to 1 for how sure you are that the whole trip is read correctly.
- Put anything the reviewer should know about the photo as a whole (cropped edges, glare, conflicting tables) in photo_notes.`

const STOP_SCHEMA = {
  type: 'OBJECT',
  properties: {
    location: { type: 'STRING' },
    arrive: { type: 'STRING', nullable: true },
    depart: { type: 'STRING', nullable: true },
  },
  required: ['location', 'arrive', 'depart'],
}

const RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    trips: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          route: { type: 'STRING', nullable: true },
          origin: { type: 'STRING' },
          destination: { type: 'STRING' },
          departure_time: { type: 'STRING' },
          arrival_time: { type: 'STRING', nullable: true },
          days_of_operation: { type: 'STRING' },
          service_type: { type: 'STRING', nullable: true },
          notes: { type: 'STRING', nullable: true },
          stops: { type: 'ARRAY', items: STOP_SCHEMA },
          confidence: { type: 'NUMBER' },
          unreadable_fields: { type: 'ARRAY', items: { type: 'STRING' } },
        },
        required: ['origin', 'destination', 'departure_time', 'days_of_operation', 'stops', 'confidence'],
      },
    },
    photo_notes: { type: 'STRING', nullable: true },
  },
  required: ['trips'],
}

let settingsTableReady = false

export async function ensureAiSettingsTable(env) {
  if (settingsTableReady) return
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS ai_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT NOT NULL
    )
  `).run()
  settingsTableReady = true
}

export async function getAiSettings(env) {
  await ensureAiSettingsTable(env)
  const { results } = await env.DB.prepare(
    `SELECT key, value FROM ai_settings WHERE key IN ('system_prompt', 'model')`
  ).all()
  const saved = Object.fromEntries((results || []).map((r) => [r.key, r.value]))
  return {
    system_prompt: saved.system_prompt || DEFAULT_SYSTEM_PROMPT,
    model: resolveModel(saved.model, env),
    is_default_prompt: !saved.system_prompt,
  }
}

/** Empty values reset that setting to its default. Legacy 2.5 model names clear to the new default. */
export async function saveAiSettings(env, { system_prompt, model }) {
  await ensureAiSettingsTable(env)
  const now = new Date().toISOString()
  const statements = []
  for (const [key, value] of [
    ['system_prompt', system_prompt],
    ['model', model],
  ]) {
    if (value === undefined) continue
    let v = String(value ?? '').trim()
    if (key === 'model') {
      if (!v || LEGACY_MODELS.has(v) || v === DEFAULT_MODEL) v = ''
    }
    statements.push(
      v
        ? env.DB.prepare(
            `INSERT INTO ai_settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
          ).bind(key, v, now)
        : env.DB.prepare(`DELETE FROM ai_settings WHERE key = ?`).bind(key)
    )
  }
  if (statements.length) await env.DB.batch(statements)
}

/** Chunked so large photos don't overflow the call stack in String.fromCharCode. */
export function bytesToBase64(bytes) {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

function httpError(message, status) {
  const err = new Error(message)
  err.status = status
  return err
}

/** Errors where another model may still work: unknown/unavailable model or exhausted quota. */
function isModelUnavailable(err) {
  if ([403, 404, 429].includes(err.geminiStatus)) return true
  return err.geminiStatus === 400 && /model|not (available|supported|found)|access/i.test(err.message)
}

/**
 * Tries `model`, then FALLBACK_MODEL if that model is unavailable or out of quota.
 * @returns {Promise<{ trips: object[], photo_notes: string | null, model: string, fell_back_from: string | null, usage: object | null }>}
 */
export async function extractTrips(env, opts) {
  if (!env.GEMINI_API_KEY) {
    throw httpError(
      'GEMINI_API_KEY is not set. Add it in Cloudflare Pages → Settings → Variables and secrets, then redeploy.',
      400
    )
  }

  const model = resolveModel(opts.model, env)
  const request = { ...opts, model }
  try {
    return { ...(await callGemini(env, request)), fell_back_from: null }
  } catch (err) {
    if (model === FALLBACK_MODEL || !isModelUnavailable(err)) throw err
    const result = await callGemini(env, { ...request, model: FALLBACK_MODEL })
    return { ...result, fell_back_from: model }
  }
}

/** Labels each photo so the model (and its photo_notes) can refer to "Photo 2". */
function imageParts(images) {
  if (images.length === 1) return [{ inlineData: { mimeType: images[0].mimeType, data: images[0].data } }]
  return images.flatMap((img, i) => [
    { text: `Photo ${i + 1}:` },
    { inlineData: { mimeType: img.mimeType, data: img.data } },
  ])
}

async function callGemini(env, { images, systemPrompt, model, userText }) {
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [
          {
            role: 'user',
            parts: [{ text: userText }, ...imageParts(images)],
          },
        ],
        generationConfig: {
          responseMimeType: 'application/json',
          responseSchema: RESPONSE_SCHEMA,
          // Timetable grids need fine print; HIGH keeps stop names/times readable.
          mediaResolution: 'MEDIA_RESOLUTION_HIGH',
          // Uploads are rare and accuracy matters more than latency; 3.x Flash defaults to medium.
          thinkingConfig: { thinkingLevel: 'HIGH' },
        },
      }),
    }
  )

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = data?.error?.message || `Gemini request failed (${res.status})`
    let err
    if (res.status === 429) {
      err = httpError(
        `Gemini free-tier limit reached for ${model}. Wait a minute (daily limits reset at midnight Pacific) and try again. (${msg})`,
        429
      )
    } else if (res.status === 404 || res.status === 403) {
      err = httpError(`Gemini model "${model}" isn't available to this API key. Change the model in AI settings. (${msg})`, 400)
    } else {
      err = httpError(`Gemini: ${msg}`, res.status >= 500 ? 502 : 400)
    }
    err.geminiStatus = res.status
    throw err
  }

  const candidate = data?.candidates?.[0]
  const text = (candidate?.content?.parts || [])
    .filter((p) => !p.thought && typeof p.text === 'string')
    .map((p) => p.text)
    .join('')
    .trim()
  if (!text) {
    const reason = candidate?.finishReason || data?.promptFeedback?.blockReason || 'no output'
    throw httpError(`Gemini returned no trips (${reason}). Try a clearer photo.`, 502)
  }

  let parsed
  try {
    parsed = JSON.parse(text.replace(/^```(?:json)?\s*|\s*```$/g, ''))
  } catch {
    throw httpError('Gemini returned data that could not be read. Try again.', 502)
  }

  return {
    trips: Array.isArray(parsed?.trips) ? parsed.trips : [],
    photo_notes: parsed?.photo_notes || null,
    model,
    usage: data?.usageMetadata || null,
  }
}
