import {
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
  supabaseErrorMessage,
} from '../../../lib/adminHelpers.js'

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

export async function onRequestPatch(context) {
  const { request, env, params } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const userId =
    params?.id ||
    new URL(request.url).pathname.split('/').filter(Boolean).pop()
  if (!userId) {
    return jsonResponse({ error: 'Missing user id' }, 400, cors)
  }

  try {
    const { display_name, user_type, bus_company } = await request.json()

    await env.DB.prepare(
      `
      UPDATE profiles
      SET display_name = ?, user_type = ?, bus_company = ?
      WHERE id = ?
    `
    )
      .bind(
        display_name || null,
        user_type || null,
        bus_company || null,
        userId
      )
      .run()

    await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        apikey: env.SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_KEY}`,
      },
      body: JSON.stringify({
        app_metadata: { user_type: user_type || null },
      }),
    })

    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestDelete(context) {
  const { request, env, params } = context
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  const userId =
    params?.id ||
    new URL(request.url).pathname.split('/').filter(Boolean).pop()
  if (!userId) {
    return jsonResponse({ error: 'Missing user id' }, 400, cors)
  }

  try {
    const authRes = await fetch(
      `${env.SUPABASE_URL}/auth/v1/admin/users/${userId}`,
      {
        method: 'DELETE',
        headers: {
          apikey: env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${env.SUPABASE_SERVICE_KEY}`,
        },
      }
    )

    if (!authRes.ok) {
      const err = await authRes.json()
      return jsonResponse({ error: supabaseErrorMessage(err) }, 400, cors)
    }

    await env.DB.prepare('DELETE FROM profiles WHERE id = ?')
      .bind(userId)
      .run()

    return jsonResponse({ success: true }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
