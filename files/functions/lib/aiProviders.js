/**
 * Raw calls to each AI provider. Both return { trips, photo_notes, usage: { input_tokens, output_tokens } }
 * and throw errors with `.status` (HTTP status for our response) and `.retryable` (another model may work).
 */

export function httpError(message, status, retryable = false) {
  const err = new Error(message)
  err.status = status
  err.retryable = retryable
  return err
}

function parseTripsJson(text, provider) {
  try {
    const parsed = JSON.parse(text.replace(/^```(?:json)?\s*|\s*```$/g, ''))
    return {
      trips: Array.isArray(parsed?.trips) ? parsed.trips : [],
      photo_notes: parsed?.photo_notes || null,
    }
  } catch {
    throw httpError(`${provider} returned data that could not be read. Try again.`, 502)
  }
}

/** Network failures (DNS, reset connections) are worth retrying on another provider. */
async function post(url, init, provider) {
  try {
    return await fetch(url, init)
  } catch (e) {
    throw httpError(`${provider} could not be reached (${e.message})`, 502, true)
  }
}

// ── Claude (Anthropic Messages API) ─────────────────────────

const CLAUDE_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp'])
// Anthropic rejects any single image over 10 MB once base64-encoded.
const CLAUDE_MAX_IMAGE_B64 = 10 * 1024 * 1024
const CLAUDE_RETRYABLE = new Set([401, 403, 404, 408, 413, 429, 500, 502, 503, 504, 529])

/** Why Claude can't take these photos, or null when it can. */
export function claudeImageProblem(images) {
  if (images.some((img) => !CLAUDE_IMAGE_TYPES.has(img.mimeType))) {
    return "Claude can't read HEIC photos. Convert them to JPEG (Safari and most phones can export JPEG)."
  }
  if (images.some((img) => img.data.length > CLAUDE_MAX_IMAGE_B64)) {
    return 'A photo is too large for Claude (max 10 MB each).'
  }
  return null
}

export async function callClaude(env, { model, images, systemPrompt, userText, schema }) {
  const content = []
  images.forEach((img, i) => {
    if (images.length > 1) content.push({ type: 'text', text: `Photo ${i + 1}:` })
    content.push({ type: 'image', source: { type: 'base64', media_type: img.mimeType, data: img.data } })
  })
  content.push({ type: 'text', text: userText })

  const res = await post(
    'https://api.anthropic.com/v1/messages',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        // Hard cap on thinking + JSON; a big multi-photo timetable can run past 15k output tokens.
        max_tokens: 32000,
        system: systemPrompt,
        messages: [{ role: 'user', content }],
        output_config: {
          // Opus 5.5 / Haiku 5.5 default to medium; dense timetables are worth the extra reasoning.
          effort: 'high',
          format: { type: 'json_schema', schema },
        },
      }),
    },
    'Claude'
  )

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = data?.error?.message || `request failed (${res.status})`
    const noCredit = /credit balance|billing/i.test(msg)
    let text
    if (res.status === 401) text = 'ANTHROPIC_API_KEY was rejected. Check the secret in Cloudflare Pages.'
    else if (noCredit) text = 'Claude credit balance is too low. Add credits at platform.claude.com.'
    else if (res.status === 429) text = 'Claude rate limit reached. Wait a minute and try again.'
    else if (res.status === 529 || res.status >= 500) text = 'Claude is overloaded right now.'
    else text = `Claude: ${msg}`
    throw httpError(text, res.status >= 500 ? 502 : 400, CLAUDE_RETRYABLE.has(res.status) || noCredit)
  }

  if (data.stop_reason === 'max_tokens') {
    throw httpError('Claude ran out of room before finishing. Try fewer photos at a time.', 502)
  }
  if (data.stop_reason === 'refusal') {
    throw httpError('Claude declined to read these photos.', 502)
  }
  const text = (data.content || [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('')
    .trim()
  if (!text) throw httpError('Claude returned no trips. Try a clearer photo.', 502)

  return {
    ...parseTripsJson(text, 'Claude'),
    usage: { input_tokens: data.usage?.input_tokens ?? null, output_tokens: data.usage?.output_tokens ?? null },
  }
}

// ── Gemini (generateContent) ────────────────────────────────

const GEMINI_RETRYABLE = new Set([403, 404, 408, 429, 500, 502, 503, 504])

export async function callGemini(env, { model, images, systemPrompt, userText, schema }) {
  const parts = [{ text: userText }]
  images.forEach((img, i) => {
    if (images.length > 1) parts.push({ text: `Photo ${i + 1}:` })
    parts.push({ inlineData: { mimeType: img.mimeType, data: img.data } })
  })

  const res = await post(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts }],
        generationConfig: {
          responseMimeType: 'application/json',
          responseSchema: schema,
          mediaResolution: 'MEDIA_RESOLUTION_HIGH',
          // 3.x Flash defaults to medium; accuracy matters more than latency here.
          thinkingConfig: { thinkingLevel: 'HIGH' },
        },
      }),
    },
    'Gemini'
  )

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = data?.error?.message || `request failed (${res.status})`
    let text
    if (res.status === 429) text = `Gemini free-tier limit reached for ${model}. Daily limits reset at midnight Pacific.`
    else if (res.status === 404 || res.status === 403) text = `Gemini model "${model}" isn't available to this API key.`
    else if (res.status >= 500) text = 'Gemini is overloaded right now.'
    else text = `Gemini: ${msg}`
    const modelProblem = res.status === 400 && /model|not (available|supported|found)|access/i.test(msg)
    throw httpError(text, res.status >= 500 ? 502 : 400, GEMINI_RETRYABLE.has(res.status) || modelProblem)
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

  const u = data?.usageMetadata || {}
  return {
    ...parseTripsJson(text, 'Gemini'),
    usage: {
      input_tokens: u.promptTokenCount ?? null,
      output_tokens: (u.candidatesTokenCount ?? 0) + (u.thoughtsTokenCount ?? 0) || null,
    },
  }
}
