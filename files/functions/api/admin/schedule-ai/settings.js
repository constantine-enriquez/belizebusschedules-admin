import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
} from '../../../lib/adminHelpers.js'
import {
  DEFAULT_MODEL,
  DEFAULT_SYSTEM_PROMPT,
  MODELS,
  getAiSettings,
  modelInfo,
  providerKeys,
  saveAiSettings,
} from '../../../lib/aiExtract.js'

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

async function settingsResponse(env, cors) {
  const settings = await getAiSettings(env)
  const keys = providerKeys(env)
  return jsonResponse(
    {
      ...settings,
      default_system_prompt: DEFAULT_SYSTEM_PROMPT,
      default_model: DEFAULT_MODEL,
      models: MODELS.map(({ id, provider, label, note }) => ({ id, provider, label, note, has_key: keys[provider] })),
      keys,
    },
    200,
    cors
  )
}

export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied
  try {
    return await settingsResponse(env, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

/** PUT { system_prompt?, model? } — empty string resets that setting to its default. */
export async function onRequestPut({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  let body
  try {
    body = await request.json()
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400, cors)
  }
  if (body.system_prompt != null && String(body.system_prompt).length > 20000) {
    return jsonResponse({ error: 'System prompt is too long (max 20,000 characters)' }, 400, cors)
  }
  const model = body.model == null ? undefined : String(body.model).trim()
  if (model && !modelInfo(model)) {
    return jsonResponse({ error: 'Pick a model from the list' }, 400, cors)
  }

  try {
    await saveAiSettings(env, { system_prompt: body.system_prompt, model })
    return await settingsResponse(env, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
