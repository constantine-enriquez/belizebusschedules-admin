/**
 * Shared helpers for manual schedule management (bus_schedule_v2).
 * Passenger apps pull bus_schedule_v2 through /api/syncDatabase, so saved
 * edits reach riders on their next sync.
 */

export const ROW_COLUMNS = [
  'BID',
  'company',
  'route',
  'origin',
  'destination',
  'departure_time',
  'arrival_time',
  'days_of_operation',
  'service_type',
  'stops_data',
  'notes',
  'phone_number',
]

export const EDITABLE_COLUMNS = ROW_COLUMNS.filter((c) => c !== 'BID')

const MAX_STOPS = 40

let changesTableReady = false

export async function ensureScheduleChangesTable(env) {
  if (changesTableReady) return
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS schedule_changes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      bid INTEGER,
      company TEXT,
      action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'restore')),
      before_json TEXT,
      after_json TEXT,
      actor TEXT,
      created_at TEXT NOT NULL,
      batch_id TEXT
    )
  `).run()

  // Tables created before AI import existed lack batch_id.
  const { results: cols } = await env.DB.prepare(`PRAGMA table_info(schedule_changes)`).all()
  if (!(cols || []).some((c) => c.name === 'batch_id')) {
    await env.DB.prepare(`ALTER TABLE schedule_changes ADD COLUMN batch_id TEXT`).run()
  }

  await env.DB.batch([
    env.DB.prepare(`
      CREATE INDEX IF NOT EXISTS idx_schedule_changes_company
        ON schedule_changes(company, created_at)
    `),
    env.DB.prepare(`
      CREATE INDEX IF NOT EXISTS idx_schedule_changes_batch
        ON schedule_changes(batch_id)
    `),
  ])
  changesTableReady = true
}

export function newBatchId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

export function actorFromRequest(request) {
  return request.headers.get('Cf-Access-Authenticated-User-Email') || null
}

/**
 * Accepts "6:15 AM", "6:15am", "3: 45 PM", "06:15 PM", or 24h "18:15".
 * @returns {{ value: string | null, error?: string }}
 */
export function normalizeTime(input) {
  if (input == null) return { value: null }
  const raw = String(input).trim()
  if (!raw || raw.toLowerCase() === 'null') return { value: null }

  const compact = raw.replace(/\s+/g, '').replace(/\./g, '').toUpperCase()
  let m = compact.match(/^(\d{1,2}):?(\d{2})(AM|PM)$/)
  if (m) {
    const h = Number(m[1])
    const min = Number(m[2])
    if (h >= 1 && h <= 12 && min <= 59) {
      return { value: `${h}:${String(min).padStart(2, '0')} ${m[3]}` }
    }
  }

  m = compact.match(/^(\d{1,2}):(\d{2})$/)
  if (m) {
    const h = Number(m[1])
    const min = Number(m[2])
    if (h <= 23 && min <= 59) {
      const suffix = h >= 12 ? 'PM' : 'AM'
      return { value: `${h % 12 || 12}:${String(min).padStart(2, '0')} ${suffix}` }
    }
  }

  return { value: null, error: `"${raw}" is not a valid time (use h:mm AM/PM)` }
}

export function timeToMinutes(value) {
  const m = String(value || '').match(/^(\d{1,2}):(\d{2}) (AM|PM)$/)
  if (!m) return null
  return ((Number(m[1]) % 12) + (m[3] === 'PM' ? 12 : 0)) * 60 + Number(m[2])
}

/** Tolerates invalid JSON and string "null" times found in older rows. */
export function parseStops(raw) {
  if (raw == null || raw === '') return { stops: [], invalid: false }
  let parsed
  try {
    parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
  } catch {
    return { stops: [], invalid: true }
  }
  if (!Array.isArray(parsed)) return { stops: [], invalid: true }
  const clean = (t) => (t == null || String(t).trim().toLowerCase() === 'null' ? null : String(t))
  return {
    stops: parsed.map((s) => ({
      arrive: clean(s?.arrive),
      depart: clean(s?.depart),
      location: String(s?.location ?? ''),
    })),
    invalid: false,
  }
}

export function rowToSchedule(row) {
  const { stops, invalid } = parseStops(row.stops_data)
  return { ...row, stops, stops_invalid: invalid }
}

function placeMatches(a, b) {
  const x = String(a || '').trim().toLowerCase()
  const y = String(b || '').trim().toLowerCase()
  if (!x || !y) return true
  return x === y || x.startsWith(y) || y.startsWith(x)
}

export function scheduleWarnings(row, stops) {
  const warnings = []
  const dep = timeToMinutes(row.departure_time)
  const arr = timeToMinutes(row.arrival_time)

  if (!row.arrival_time) warnings.push('No arrival time set')
  else if (dep != null && arr != null && arr <= dep) {
    warnings.push('Arrival is not after departure (fine only for overnight trips)')
  }

  if (stops.length < 2) {
    warnings.push('Trips usually list at least the origin and destination as stops')
    return warnings
  }

  const first = stops[0]
  const last = stops[stops.length - 1]
  if (!placeMatches(first.location, row.origin)) {
    warnings.push(`First stop "${first.location}" doesn't match origin "${row.origin}"`)
  }
  if (!placeMatches(last.location, row.destination)) {
    warnings.push(`Last stop "${last.location}" doesn't match destination "${row.destination}"`)
  }
  if (first.depart && row.departure_time && first.depart !== row.departure_time) {
    warnings.push(`First stop departs ${first.depart} but trip departure is ${row.departure_time}`)
  }
  if (last.arrive && row.arrival_time && last.arrive !== row.arrival_time) {
    warnings.push(`Last stop arrives ${last.arrive} but trip arrival is ${row.arrival_time}`)
  }
  if (last.depart) warnings.push('Last stop usually has no depart time')

  let prev = null
  for (let i = 0; i < stops.length; i++) {
    for (const key of ['arrive', 'depart']) {
      const t = timeToMinutes(stops[i][key])
      if (t == null) continue
      if (prev != null && t < prev) {
        warnings.push(`Stop ${i + 1} (${stops[i].location}) ${key} time goes backwards`)
        return warnings
      }
      prev = t
    }
  }
  return warnings
}

/**
 * Validates a create/update payload. Keys missing from `body` fall back to `existing`.
 * @returns {{ row: object, stops: object[], errors: string[], warnings: string[] }}
 */
export function normalizeSchedulePayload(body, existing = null) {
  const errors = []
  const pick = (key) => (body[key] !== undefined ? body[key] : existing?.[key])
  const text = (key, max = 200) => {
    const v = pick(key)
    if (v == null) return null
    const s = String(v).trim().slice(0, max)
    return s || null
  }

  const company = text('company', 120)
  const origin = text('origin', 120)
  const destination = text('destination', 120)
  if (!company) errors.push('Company is required')
  if (!origin) errors.push('Origin is required')
  if (!destination) errors.push('Destination is required')

  const dep = normalizeTime(pick('departure_time'))
  if (dep.error) errors.push(`Departure: ${dep.error}`)
  else if (!dep.value) errors.push('Departure time is required')

  const arr = normalizeTime(pick('arrival_time'))
  if (arr.error) errors.push(`Arrival: ${arr.error}`)

  const days = text('days_of_operation', 80)
  if (!days) errors.push('Days of operation is required')

  let route = text('route', 200)
  if (!route && origin && destination) route = `${origin} to ${destination}`

  const existingStops = parseStops(existing?.stops_data)
  const keepRawStops = body.stops === undefined && existingStops.invalid
  let stopsInput = body.stops !== undefined ? body.stops : existingStops.stops
  if (!Array.isArray(stopsInput)) {
    errors.push('Stops must be a list')
    stopsInput = []
  }
  if (stopsInput.length > MAX_STOPS) errors.push(`Too many stops (max ${MAX_STOPS})`)

  const stops = stopsInput.slice(0, MAX_STOPS).map((s, i) => {
    const location = String(s?.location ?? '').trim().slice(0, 120)
    if (!location) errors.push(`Stop ${i + 1}: location is required`)
    const a = normalizeTime(s?.arrive)
    const d = normalizeTime(s?.depart)
    if (a.error) errors.push(`Stop ${i + 1} arrive: ${a.error}`)
    if (d.error) errors.push(`Stop ${i + 1} depart: ${d.error}`)
    return { arrive: a.value, depart: d.value, location }
  })

  const row = {
    company,
    route,
    origin,
    destination,
    departure_time: dep.value,
    arrival_time: arr.value,
    days_of_operation: days,
    service_type: text('service_type', 80),
    stops_data: keepRawStops ? existing.stops_data : JSON.stringify(stops),
    notes: text('notes', 500),
    phone_number: text('phone_number', 40),
  }

  const warnings = errors.length ? [] : scheduleWarnings(row, stops)
  return { row, stops, errors, warnings }
}

export async function findDuplicate(env, row, excludeBid = null) {
  const hit = await env.DB.prepare(
    `
    SELECT BID FROM bus_schedule_v2
    WHERE company = ? AND origin = ? AND destination = ? AND departure_time = ?
      AND IFNULL(days_of_operation, '') = IFNULL(?, '')
      AND BID != ?
    LIMIT 1
  `
  )
    .bind(
      row.company,
      row.origin,
      row.destination,
      row.departure_time,
      row.days_of_operation,
      excludeBid ?? -1
    )
    .first()
  return hit ? hit.BID : null
}

export function pickRow(row) {
  if (!row) return null
  const out = {}
  for (const c of ROW_COLUMNS) out[c] = row[c] ?? null
  return out
}

export function sameRow(a, b) {
  if (!a || !b) return !a && !b
  return ROW_COLUMNS.every((c) => String(a[c] ?? '') === String(b[c] ?? ''))
}

export function changeLogStatement(env, { bid, company, action, before, after, actor, batchId = null }) {
  return env.DB.prepare(
    `
    INSERT INTO schedule_changes (bid, company, action, before_json, after_json, actor, created_at, batch_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).bind(
    bid,
    company,
    action,
    before ? JSON.stringify(pickRow(before)) : null,
    after ? JSON.stringify(pickRow(after)) : null,
    actor,
    new Date().toISOString(),
    batchId
  )
}

/**
 * Logs the row inserted by the immediately preceding statement in the same D1 batch.
 * last_insert_rowid() is evaluated in VALUES before this log row is inserted.
 */
export function createdRowLogStatement(env, { company, row, actor, batchId }) {
  return env.DB.prepare(
    `
    INSERT INTO schedule_changes (bid, company, action, before_json, after_json, actor, created_at, batch_id)
    VALUES (last_insert_rowid(), ?, 'create', NULL, json_set(?, '$.BID', last_insert_rowid()), ?, ?, ?)
  `
  ).bind(company, JSON.stringify(pickRow({ ...row, BID: null })), actor, new Date().toISOString(), batchId)
}

export function insertScheduleStatement(env, row) {
  return env.DB.prepare(
    `INSERT INTO bus_schedule_v2 (${EDITABLE_COLUMNS.join(', ')}) VALUES (${EDITABLE_COLUMNS.map(() => '?').join(', ')})`
  ).bind(...EDITABLE_COLUMNS.map((c) => row[c] ?? null))
}

export function updateScheduleStatement(env, bid, row) {
  return env.DB.prepare(
    `UPDATE bus_schedule_v2 SET ${EDITABLE_COLUMNS.map((c) => `${c} = ?`).join(', ')} WHERE BID = ?`
  ).bind(...EDITABLE_COLUMNS.map((c) => row[c] ?? null), bid)
}

export async function companyPhone(env, company) {
  const hit = await env.DB.prepare(
    `
    SELECT phone_number AS v, COUNT(*) AS n FROM bus_schedule_v2
    WHERE company = ? AND phone_number IS NOT NULL AND TRIM(phone_number) != ''
    GROUP BY phone_number ORDER BY n DESC LIMIT 1
  `
  )
    .bind(company)
    .first()
  return hit?.v || null
}

function comparableValue(row, col) {
  if (col === 'stops_data') {
    const { stops, invalid } = parseStops(row.stops_data)
    return invalid ? String(row.stops_data ?? '') : JSON.stringify(stops)
  }
  return String(row[col] ?? '')
}

export function changedColumns(before, after) {
  return EDITABLE_COLUMNS.filter((c) => comparableValue(before, c) !== comparableValue(after, c))
}

function tripKey(row, withDays) {
  const lc = (v) => String(v ?? '').trim().toLowerCase()
  return [
    lc(row.origin),
    lc(row.destination),
    normalizeTime(row.departure_time).value || lc(row.departure_time),
    withDays ? lc(row.days_of_operation) : '',
  ].join('|')
}

/**
 * Matches proposed trips to a company's existing rows so unchanged trips keep their BID.
 * Pass 1 matches origin + destination + departure + days; pass 2 drops days when that
 * leaves exactly one candidate (e.g. the photo relabels "Daily" as "Monday to Sunday").
 */
export function planReplace(existing, proposed) {
  const used = new Set()
  const matches = new Array(proposed.length).fill(null)

  for (const withDays of [true, false]) {
    proposed.forEach((p, i) => {
      if (matches[i]) return
      const key = tripKey(p, withDays)
      const candidates = existing.filter((e) => !used.has(e.BID) && tripKey(e, withDays) === key)
      if (candidates.length === 1 || (withDays && candidates.length)) {
        matches[i] = candidates[0]
        used.add(candidates[0].BID)
      }
    })
  }

  const add = []
  const update = []
  const same = []
  proposed.forEach((p, index) => {
    const m = matches[index]
    if (!m) return add.push({ index })
    const changed = changedColumns(m, p)
    ;(changed.length ? update : same).push({ index, bid: m.BID, changed, before: m })
  })
  const remove = existing.filter((e) => !used.has(e.BID))
  return { add, update, same, remove }
}
