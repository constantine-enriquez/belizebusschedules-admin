/**
 * Schedule photo → trips via Claude (default) or Gemini.
 * Env (Cloudflare Pages → Settings → Variables and secrets):
 *   ANTHROPIC_API_KEY (secret) — prepaid credits from https://platform.claude.com
 *   GEMINI_API_KEY (secret, optional) — free tier from https://aistudio.google.com/apikey; also the fallback
 */
import { callClaude, callGemini, claudeImageProblem, httpError } from './aiProviders.js'

export { httpError }

/** Shown in the AI settings dropdown, in this order. Prices are USD per million tokens. */
export const MODELS = [
  { id: 'claude-opus-5-5', provider: 'claude', label: 'Claude Opus 5.5', note: 'Most accurate. Paid from your Claude credits.', price: { input: 4, output: 20 } },
  { id: 'claude-sonnet-5-5', provider: 'claude', label: 'Claude Sonnet 5.5', note: 'About half the cost of Opus. Paid.', price: { input: 2, output: 10 } },
  { id: 'claude-haiku-5-5', provider: 'claude', label: 'Claude Haiku 5.5', note: 'Cheapest Claude model, less accurate on dense grids. Paid.', price: { input: 0.1, output: 0.5 } },
  { id: 'gemini-3.8-flash', provider: 'gemini', label: 'Gemini 3.8 Flash', note: 'Free tier. Can be slow or busy at peak times.', price: null },
  { id: 'gemini-3.6-flash', provider: 'gemini', label: 'Gemini 3.6 Flash', note: 'Free tier. Nearly as accurate as 3.8 and faster.', price: null },
  { id: 'gemini-3.5-flash-lite', provider: 'gemini', label: 'Gemini 3.5 Flash-Lite', note: 'Free tier. Fastest, least accurate.', price: null },
]
export const DEFAULT_MODEL = 'claude-opus-5-5'
// Fallbacks are always free, so a busy or unfunded model never silently switches you to a paid one.
const FREE_FALLBACKS = ['gemini-3.8-flash', 'gemini-3.6-flash']

const PROVIDER_KEYS = { claude: 'ANTHROPIC_API_KEY', gemini: 'GEMINI_API_KEY' }

export function modelInfo(id) {
  return MODELS.find((m) => m.id === id) || null
}

export function providerKeys(env) {
  return { claude: !!env.ANTHROPIC_API_KEY, gemini: !!env.GEMINI_API_KEY }
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

// Gemini's schema dialect; toJsonSchema() derives the standard JSON Schema Claude needs.
const STOP_SCHEMA = {
  type: 'OBJECT',
  properties: {
    location: { type: 'STRING' },
    arrive: { type: 'STRING', nullable: true },
    depart: { type: 'STRING', nullable: true },
  },
  required: ['location', 'arrive', 'depart'],
}

const GEMINI_SCHEMA = {
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

function toJsonSchema(s) {
  const type = s.type.toLowerCase()
  let out
  if (type === 'object') {
    out = {
      type,
      properties: Object.fromEntries(Object.entries(s.properties).map(([k, v]) => [k, toJsonSchema(v)])),
      additionalProperties: false,
    }
    if (s.required) out.required = s.required
  } else if (type === 'array') {
    out = { type, items: toJsonSchema(s.items) }
  } else {
    out = { type }
  }
  return s.nullable ? { anyOf: [out, { type: 'null' }] } : out
}

const CLAUDE_SCHEMA = toJsonSchema(GEMINI_SCHEMA)

const PROVIDERS = {
  claude: (env, opts) => callClaude(env, { ...opts, schema: CLAUDE_SCHEMA }),
  gemini: (env, opts) => callGemini(env, { ...opts, schema: GEMINI_SCHEMA }),
}

// ── Settings (D1) ───────────────────────────────────────────

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

/** Unknown saved models (e.g. retired Gemini 2.5 names) fall back to the default. */
export function resolveModel(model) {
  return modelInfo(String(model || '').trim()) ? String(model).trim() : DEFAULT_MODEL
}

export async function getAiSettings(env) {
  await ensureAiSettingsTable(env)
  const { results } = await env.DB.prepare(
    `SELECT key, value FROM ai_settings WHERE key IN ('system_prompt', 'model')`
  ).all()
  const saved = Object.fromEntries((results || []).map((r) => [r.key, r.value]))
  return {
    system_prompt: saved.system_prompt || DEFAULT_SYSTEM_PROMPT,
    model: resolveModel(saved.model),
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
    let v = String(value ?? '').trim()
    if (key === 'model' && v === DEFAULT_MODEL) v = ''
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

// ── Extraction ──────────────────────────────────────────────

/** Chunked so large photos don't overflow the call stack in String.fromCharCode. */
export function bytesToBase64(bytes) {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

function costOf(model, usage) {
  if (!model.price || usage?.input_tokens == null || usage?.output_tokens == null) return null
  return (usage.input_tokens * model.price.input + usage.output_tokens * model.price.output) / 1e6
}

function skipReason(env, model, images) {
  if (!env[PROVIDER_KEYS[model.provider]]) return `${PROVIDER_KEYS[model.provider]} isn't set.`
  if (model.provider === 'claude') return claudeImageProblem(images)
  return null
}

/**
 * Tries the chosen model, then the free Gemini fallbacks when it is busy, out of quota/credit, or not set up.
 * @param {{ model: string, images: { mimeType: string, data: string }[], systemPrompt: string, userText: string }} opts
 * @returns {Promise<{ trips: object[], photo_notes: string | null, model: string, model_label: string,
 *   fell_back_from: string | null, fallback_reason: string | null, usage: object | null, cost_usd: number | null }>}
 */
export async function extractTrips(env, opts) {
  const selected = modelInfo(resolveModel(opts.model))
  const chain = [selected, ...FREE_FALLBACKS.filter((id) => id !== selected.id).map(modelInfo)]
  const failures = []

  for (const model of chain) {
    const skip = skipReason(env, model, opts.images)
    if (skip) {
      failures.push({ model, message: skip, status: 400 })
      continue
    }
    try {
      const result = await PROVIDERS[model.provider](env, { ...opts, model: model.id })
      return {
        ...result,
        model: model.id,
        model_label: model.label,
        cost_usd: costOf(model, result.usage),
        fell_back_from: failures.length ? failures[0].model.label : null,
        fallback_reason: failures.length ? failures.map((f) => `${f.model.label}: ${f.message}`).join(' ') : null,
      }
    } catch (err) {
      if (!err.retryable) throw err
      failures.push({ model, message: err.message, status: err.status })
    }
  }

  const summary = failures.map((f) => `${f.model.label}: ${f.message}`).join(' ')
  throw httpError(summary, failures.some((f) => f.status >= 500) ? 502 : 400)
}
