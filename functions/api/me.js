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
        users.activated AS user_activated,
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

    const email = normalizeEmail(row.email);
    const deviceKey = normalizeDeviceKey(getDeviceKey(request));

    let currentDeviceActivation = null;
    let currentDeviceCode = null;

    if (deviceKey) {
      currentDeviceActivation = await env.DB.prepare(`
        SELECT code, device_key, activated_at
        FROM activations
        WHERE email = ? AND device_key = ?
        ORDER BY id DESC
        LIMIT 1
      `)
        .bind(email, deviceKey)
        .first();

      if (!currentDeviceActivation) {
        currentDeviceCode = await env.DB.prepare(`
          SELECT code, device_key, activated_at
          FROM codes
          WHERE email = ? AND device_key = ? AND status = 'USED'
          ORDER BY activated_at DESC
          LIMIT 1
        `)
          .bind(email, deviceKey)
          .first();
      }
    }

    const anyActivation = await env.DB.prepare(`
      SELECT code, device_key, activated_at
      FROM activations
      WHERE email = ?
      ORDER BY id DESC
      LIMIT 1
    `)
      .bind(email)
      .first();

    const anyCode = await env.DB.prepare(`
      SELECT code, device_key, activated_at
      FROM codes
      WHERE email = ? AND status = 'USED'
      ORDER BY activated_at DESC
      LIMIT 1
    `)
      .bind(email)
      .first();

    const matchedRecord = currentDeviceActivation || currentDeviceCode || null;
    const latestRecord = anyActivation || anyCode || null;

    const accountHasActivation =
      !!latestRecord || !!row.user_activated;

    const deviceActivated = !!matchedRecord;
    const deviceLocked = !!accountHasActivation && !deviceActivated;
    const needsActivation = !deviceActivated;
    const activated = deviceActivated;

    const activationCode = String(
      (matchedRecord && matchedRecord.code) ||
      (latestRecord && latestRecord.code) ||
      ""
    ).trim();

    const activationDeviceKey = normalizeDeviceKey(
      (matchedRecord && matchedRecord.device_key) ||
      (latestRecord && latestRecord.device_key) ||
      ""
    );

    const activationActivatedAt = String(
      (matchedRecord && matchedRecord.activated_at) ||
      (latestRecord && latestRecord.activated_at) ||
      ""
    ).trim();

    return json({
      ok: true,
      email,
      token: row.token,

      activated,
      needs_activation: needsActivation,
      device_locked: deviceLocked,
      account_has_activation: accountHasActivation,

      user: {
        email,
        activated,
        created_at: row.user_created_at,
      },

      session: {
        email: row.session_email,
        created_at: row.session_created_at,
      },

      activation: {
        code: activationCode || null,
        device_key: activationDeviceKey || null,
        activated_at: activationActivatedAt || null,
        same_device: deviceActivated,
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

function getDeviceKey(request) {
  return String(
    request.headers.get("X-Device-Id") ||
    request.headers.get("x-device-id") ||
    ""
  ).trim();
}

function normalizeDeviceKey(value) {
  return String(value || "").trim();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
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
