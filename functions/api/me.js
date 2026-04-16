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
        SELECT id, code, email, device_key, activated_at
        FROM activations
        WHERE email = ? AND device_key = ?
        ORDER BY activated_at DESC, id DESC
        LIMIT 1
      `)
        .bind(email, deviceKey)
        .first();

      if (!currentDeviceActivation) {
        currentDeviceCode = await env.DB.prepare(`
          SELECT id, code, email, device_key, activated_at
          FROM codes
          WHERE email = ? AND device_key = ? AND status = 'USED'
          ORDER BY activated_at DESC, id DESC
          LIMIT 1
        `)
          .bind(email, deviceKey)
          .first();
      }
    }

    let latestActivation = await env.DB.prepare(`
      SELECT id, code, email, device_key, activated_at
      FROM activations
      WHERE email = ?
      ORDER BY activated_at DESC, id DESC
      LIMIT 1
    `)
      .bind(email)
      .first();

    let latestCode = await env.DB.prepare(`
      SELECT id, code, email, device_key, activated_at
      FROM codes
      WHERE email = ? AND status = 'USED'
      ORDER BY activated_at DESC, id DESC
      LIMIT 1
    `)
      .bind(email)
      .first();

    let matchedRecord = currentDeviceActivation || currentDeviceCode || null;
    let latestRecord = pickLatestRecord(latestActivation, latestCode);

    let migratedLegacyDevice = false;
    const latestBoundDeviceKey = normalizeDeviceKey(latestRecord?.device_key);

    const canMigrateLegacyDevice =
      !matchedRecord &&
      !!deviceKey &&
      isStableDeviceKey(deviceKey) &&
      isLegacyRandomDeviceKey(latestBoundDeviceKey);

    if (canMigrateLegacyDevice) {
      await env.DB.prepare(`
        UPDATE activations
        SET device_key = ?
        WHERE email = ? AND device_key = ?
      `)
        .bind(deviceKey, email, latestBoundDeviceKey)
        .run();

      await env.DB.prepare(`
        UPDATE codes
        SET device_key = ?
        WHERE email = ? AND device_key = ? AND status = 'USED'
      `)
        .bind(deviceKey, email, latestBoundDeviceKey)
        .run();

      migratedLegacyDevice = true;

      currentDeviceActivation = await env.DB.prepare(`
        SELECT id, code, email, device_key, activated_at
        FROM activations
        WHERE email = ? AND device_key = ?
        ORDER BY activated_at DESC, id DESC
        LIMIT 1
      `)
        .bind(email, deviceKey)
        .first();

      if (!currentDeviceActivation) {
        currentDeviceCode = await env.DB.prepare(`
          SELECT id, code, email, device_key, activated_at
          FROM codes
          WHERE email = ? AND device_key = ? AND status = 'USED'
          ORDER BY activated_at DESC, id DESC
          LIMIT 1
        `)
          .bind(email, deviceKey)
          .first();
      } else {
        currentDeviceCode = null;
      }

      latestActivation = await env.DB.prepare(`
        SELECT id, code, email, device_key, activated_at
        FROM activations
        WHERE email = ?
        ORDER BY activated_at DESC, id DESC
        LIMIT 1
      `)
        .bind(email)
        .first();

      latestCode = await env.DB.prepare(`
        SELECT id, code, email, device_key, activated_at
        FROM codes
        WHERE email = ? AND status = 'USED'
        ORDER BY activated_at DESC, id DESC
        LIMIT 1
      `)
        .bind(email)
        .first();

      matchedRecord = currentDeviceActivation || currentDeviceCode || null;
      latestRecord = pickLatestRecord(latestActivation, latestCode);
    }

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
      migrated_legacy_device: migratedLegacyDevice,

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

function pickLatestRecord(a, b) {
  if (a && b) {
    const aTime = toMs(a.activated_at);
    const bTime = toMs(b.activated_at);
    return aTime >= bTime ? a : b;
  }
  return a || b || null;
}

function toMs(value) {
  const ms = Date.parse(String(value || "").trim());
  return Number.isFinite(ms) ? ms : 0;
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

function isLegacyRandomDeviceKey(value) {
  return /^bdk_rand_/i.test(normalizeDeviceKey(value));
}

function isStableDeviceKey(value) {
  const v = normalizeDeviceKey(value);
  return /^bdk_/i.test(v) && !/^bdk_rand_/i.test(v);
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
