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

    const email = normalizeEmail(row.email);
    const deviceKey = normalizeDeviceKey(getDeviceKey(request));

    let boundCode = "";
    let boundDeviceKey = "";
    let boundActivatedAt = "";

    const activationRow = await env.DB.prepare(`
      SELECT id, code, device_key, activated_at
      FROM activations
      WHERE email = ?
      ORDER BY id DESC
      LIMIT 1
    `)
      .bind(email)
      .first();

    let activationId = null;

    if (activationRow) {
      activationId = activationRow.id;
      boundCode = String(activationRow.code || "").trim();
      boundDeviceKey = normalizeDeviceKey(activationRow.device_key);
      boundActivatedAt = String(activationRow.activated_at || "");
    }

    if (!boundDeviceKey) {
      const codeRow = await env.DB.prepare(`
        SELECT code, device_key, activated_at
        FROM codes
        WHERE email = ? AND status = 'USED'
        ORDER BY activated_at DESC
        LIMIT 1
      `)
        .bind(email)
        .first();

      if (codeRow) {
        boundCode = boundCode || String(codeRow.code || "").trim();
        boundDeviceKey = normalizeDeviceKey(codeRow.device_key);
        boundActivatedAt = boundActivatedAt || String(codeRow.activated_at || "");
      }
    }

    const accountActivated = !!row.activated;

    let sameDevice =
      !!accountActivated &&
      !!deviceKey &&
      !!boundDeviceKey &&
      deviceKey === boundDeviceKey;

    const canMigrateLegacyDeviceKey =
      !!accountActivated &&
      !!deviceKey &&
      isStableDeviceKey(deviceKey) &&
      (
        !boundDeviceKey ||
        !isStableDeviceKey(boundDeviceKey)
      );

    if (!sameDevice && canMigrateLegacyDeviceKey) {
      if (activationId) {
        await env.DB.prepare(`
          UPDATE activations
          SET device_key = ?
          WHERE id = ?
        `)
          .bind(deviceKey, activationId)
          .run();
      } else {
        const existingActivation = await env.DB.prepare(`
          SELECT id
          FROM activations
          WHERE email = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        if (existingActivation) {
          await env.DB.prepare(`
            UPDATE activations
            SET device_key = ?
            WHERE id = ?
          `)
            .bind(deviceKey, existingActivation.id)
            .run();
        }
      }

      await env.DB.prepare(`
        UPDATE codes
        SET device_key = ?
        WHERE email = ? AND status = 'USED'
      `)
        .bind(deviceKey, email)
        .run();

      boundDeviceKey = deviceKey;
      sameDevice = true;
    }

    // التفعيل الآن يعتمد على الحساب نفسه، وليس على تطابق deviceKey
    const activated = accountActivated;
    const deviceLocked = false;
    const needsActivation = !accountActivated;

    return json({
      ok: true,
      email,
      activated,
      token: row.token,
      device_locked: deviceLocked,
      needs_activation: needsActivation,
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
        code: boundCode || null,
        device_key: boundDeviceKey || null,
        activated_at: boundActivatedAt || null,
        same_device: sameDevice,
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

function isStableDeviceKey(value) {
  const v = normalizeDeviceKey(value);
  return /^bdk_/i.test(v);
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
