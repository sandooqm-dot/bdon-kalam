export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(),
  });
}

export async function onRequestGet(context) {
  try {
    const { request, env } = context;

    if (!env.DB) {
      return json(
        { ok: false, message: "قاعدة البيانات غير مربوطة." },
        500
      );
    }

    const token = getBearerToken(request);
    if (!token) {
      return json(
        { ok: false, message: "الجلسة غير موجودة." },
        401
      );
    }

    const row = await env.DB.prepare(`
      SELECT
        sessions.token AS token,
        sessions.email AS session_email,
        sessions.created_at AS session_created_at,
        users.email AS email,
        users.activated AS activated,
        users.created_at AS user_created_at
      FROM sessions
      INNER JOIN users ON users.email = sessions.email
      WHERE sessions.token = ?
      LIMIT 1
    `)
      .bind(token)
      .first();

    if (!row) {
      return json(
        { ok: false, message: "الجلسة غير صالحة أو منتهية." },
        401
      );
    }

    return json({
      ok: true,
      email: row.email,
      activated: !!row.activated,
      token: row.token,
      user: {
        email: row.email,
        activated: !!row.activated,
        created_at: row.user_created_at,
      },
      session: {
        email: row.session_email,
        created_at: row.session_created_at,
      },
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: "حدث خطأ أثناء قراءة حالة المستخدم.",
        error: String(error && error.message ? error.message : error),
      },
      500
    );
  }
}

function getBearerToken(request) {
  const auth =
    request.headers.get("Authorization") ||
    request.headers.get("authorization") ||
    "";

  const prefix = "Bearer ";
  if (!auth.startsWith(prefix)) return "";
  return auth.slice(prefix.length).trim();
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(),
  });
}
