import {
  adminUserIdFromCreateResponse,
  buildCorsHeaders,
  jsonResponse,
  requireAccess,
  supabaseErrorMessage,
} from '../../lib/adminHelpers.js'

export async function onRequestOptions({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  return new Response(null, { status: 204, headers: cors })
}

export async function onRequestGet({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM profiles ORDER BY created_at DESC'
    ).all()
    return jsonResponse({ users: results }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}

export async function onRequestPost({ request, env }) {
  const cors = buildCorsHeaders(request, env)
  const denied = await requireAccess(request, env, cors)
  if (denied) return denied

  try {
    const { email, password, display_name, user_type, bus_company } =
      await request.json()

    if (!email || !password) {
      return jsonResponse({ error: 'Email and password required' }, 400, cors)
    }

    const authRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: env.SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_KEY}`,
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        app_metadata: { user_type: user_type || null },
      }),
    })

    const authData = await authRes.json()
    if (!authRes.ok) {
      return jsonResponse({ error: supabaseErrorMessage(authData) }, 400, cors)
    }

    const userId = adminUserIdFromCreateResponse(authData)
    if (!userId) {
      return jsonResponse({ error: 'Supabase returned no user id' }, 500, cors)
    }

    await env.DB.prepare(
      `
      INSERT INTO profiles (id, email, display_name, user_type, bus_company)
      VALUES (?, ?, ?, ?, ?)
    `
    )
      .bind(
        userId,
        email,
        display_name || null,
        user_type || null,
        bus_company || null
      )
      .run()

    return jsonResponse({ success: true, id: userId }, 200, cors)
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors)
  }
}
