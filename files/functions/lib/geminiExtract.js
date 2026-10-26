/**
 * Schedule photo → trips via the Gemini API.
 * Env (Cloudflare Pages → Settings → Variables and secrets):
 *   GEMINI_API_KEY (secret, required) — from https://aistudio.google.com/apikey
 *   GEMINI_MODEL (optional) — fallback when no model is saved in AI settings
 *
 * extractTrips() is the only provider-specific call; swap it to change AI vendors.
 */

export const DEFAULT_MODEL = 'gemini-2.5-pro'

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
    model: saved.model || env.GEMINI_MODEL || DEFAULT_MODEL,
    is_default_prompt: !saved.system_prompt,
  }
}

/** Empty values reset that setting to its default. */
export async function saveAiSettings(env, { system_prompt, model }) {
  await ensureAiSettingsTable(env)
  const now = new Date().toISOString()
  const statements = []
  for (const [key, value] of [
    ['system_prompt', system_prompt],
    ['model', model],
  ]) {
    if (value === undefined) continue
    const v = String(value ?? '').trim()
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

/**
 * @returns {Promise<{ trips: object[], photo_notes: string | null, model: string, usage: object | null }>}
 */
export async function extractTrips(env, { imageBase64, mimeType, systemPrompt, model, userText }) {
  if (!env.GEMINI_API_KEY) {
    throw httpError(
      'GEMINI_API_KEY is not set. Add it in Cloudflare Pages → Settings → Variables and secrets, then redeploy.',
      400
    )
  }

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
            parts: [{ text: userText }, { inlineData: { mimeType, data: imageBase64 } }],
          },
        ],
        generationConfig: {
          responseMimeType: 'application/json',
          responseSchema: RESPONSE_SCHEMA,
          temperature: 0,
        },
      }),
    }
  )

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = data?.error?.message || `Gemini request failed (${res.status})`
    if (res.status === 429) {
      throw httpError(
        `Gemini rate limit reached for ${model}. Wait a minute and try again, or switch to a Flash model in AI settings. (${msg})`,
        429
      )
    }
    if (res.status === 404) {
      throw httpError(`Gemini model "${model}" was not found. Change the model in AI settings. (${msg})`, 400)
    }
    throw httpError(`Gemini: ${msg}`, res.status >= 500 ? 502 : 400)
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
