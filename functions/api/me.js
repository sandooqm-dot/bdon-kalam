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

    const sessionUser = await getSessionUser(env.DB, token);
    if (!sessionUser) {
      return json(
        { ok: false, message: "الجلسة غير صالحة أو منتهية." },
        401
      );
    }

    const email = normalizeEmail(sessionUser.email);
    const deviceId = normalizeDeviceId(getDeviceId(request));

    let currentDeviceActivation = await findActivationByDevice(env.DB, email, deviceId);
    let currentDeviceCode = null;

    if (!currentDeviceActivation) {
      currentDeviceCode = await findCodeByDevice(env.DB, email, deviceId);
    }

    let latestActivation = await findLatestActivation(env.DB, email);
    let latestCode = await findLatestCode(env.DB, email);

    let latestRecord = latestActivation || latestCode || null;
    let matchedRecord = currentDeviceActivation || currentDeviceCode || null;

    const accountHasActivation =
      !!latestRecord || !!sessionUser.userActivated;

    const canMigrateLegacyDevice =
      !matchedRecord &&
      !!accountHasActivation &&
      !!deviceId &&
      isStableDeviceId(deviceId) &&
      (
        !latestRecord ||
        !isStableDeviceId(normalizeDeviceId(latestRecord.device_id))
      );

    if (canMigrateLegacyDevice) {
      await migrateLegacyDeviceId(env.DB, email, deviceId);

      currentDeviceActivation = await findActivationByDevice(env.DB, email, deviceId);
      if (!currentDeviceActivation) {
        currentDeviceCode = await findCodeByDevice(env.DB, email, deviceId);
      }

      latestActivation = await findLatestActivation(env.DB, email);
      latestCode = await findLatestCode(env.DB, email);

      latestRecord = latestActivation || latestCode || latestRecord || null;
      matchedRecord = currentDeviceActivation || currentDeviceCode || null;
    }

    const deviceActivated = !!matchedRecord;
    const deviceLocked = !!accountHasActivation && !deviceActivated;
    const needsActivation = !deviceActivated;
    const activated = deviceActivated;

    const activationCode = String(
      (matchedRecord && matchedRecord.code) ||
      (latestRecord && latestRecord.code) ||
      ""
    ).trim();

    const activationDeviceId = normalizeDeviceId(
      (matchedRecord && matchedRecord.device_id) ||
      (latestRecord && latestRecord.device_id) ||
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
      token: sessionUser.token,

      activated,
      needs_activation: needsActivation,
      device_locked: deviceLocked,
      account_has_activation: accountHasActivation,

      user: {
        email,
        activated,
        created_at: sessionUser.userCreatedAt,
      },

      session: {
        email: sessionUser.sessionEmail,
        created_at: sessionUser.sessionCreatedAt,
      },

      activation: {
        code: activationCode || null,
        device_id: activationDeviceId || null,
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

async function getSessionUser(DB, token) {
  const sessionCols = await getTableColumns(DB, "sessions");
  const userCols = await getTableColumns(DB, "users");

  if (!sessionCols.length || !userCols.length) return null;

  const sessionTokenCol = pickColumn(sessionCols, ["token"]);
  const sessionEmailCol = pickColumn(sessionCols, ["email", "user_email"]);
  const sessionCreatedAtCol = pickColumn(sessionCols, ["created_at"]);

  const userEmailCol = pickColumn(userCols, ["email"]);
  const userActivatedCol = pickColumn(userCols, ["activated", "user_activated", "is_activated"]);
  const userCreatedAtCol = pickColumn(userCols, ["created_at"]);

  if (!sessionTokenCol || !sessionEmailCol || !userEmailCol) return null;

  const sql = `
    SELECT
      sessions.${sessionTokenCol} AS token,
      sessions.${sessionEmailCol} AS session_email,
      ${sessionCreatedAtCol ? `sessions.${sessionCreatedAtCol}` : "NULL"} AS session_created_at,
      users.${userEmailCol} AS email,
      ${userActivatedCol ? `users.${userActivatedCol}` : "0"} AS user_activated,
      ${userCreatedAtCol ? `users.${userCreatedAtCol}` : "NULL"} AS user_created_at
    FROM sessions
    INNER JOIN users
      ON lower(trim(users.${userEmailCol})) = lower(trim(sessions.${sessionEmailCol}))
    WHERE sessions.${sessionTokenCol} = ?
    LIMIT 1
  `;

  return await DB.prepare(sql).bind(token).first();
}

async function findActivationByDevice(DB, email, deviceId) {
  if (!deviceId) return null;

  const cols = await getTableColumns(DB, "activations");
  if (!cols.length) return null;

  const emailCol = pickColumn(cols, ["email", "user_email", "used_by_email", "bound_email", "owner_email"]);
  const codeCol = pickColumn(cols, ["code", "activation_code"]);
  const deviceCol = pickColumn(cols, ["device_id", "device_key"]);
  const activatedAtCol = pickColumn(cols, ["activated_at", "used_at", "created_at"]);
  const orderCol = pickColumn(cols, ["id", "rowid", "activated_at", "created_at"]);

  if (!emailCol || !codeCol || !deviceCol) return null;

  const sql = `
    SELECT
      ${codeCol} AS code,
      ${deviceCol} AS device_id,
      ${activatedAtCol ? activatedAtCol : "NULL"} AS activated_at
    FROM activations
    WHERE lower(trim(${emailCol})) = ?
      AND ${deviceCol} = ?
    ORDER BY ${orderCol || activatedAtCol || codeCol} DESC
    LIMIT 1
  `;

  return await DB.prepare(sql).bind(email, deviceId).first();
}

async function findCodeByDevice(DB, email, deviceId) {
  if (!deviceId) return null;

  const cols = await getTableColumns(DB, "codes");
  if (!cols.length) return null;

  const emailCol = pickColumn(cols, ["email", "user_email", "used_by_email", "bound_email", "owner_email"]);
  const codeCol = pickColumn(cols, ["code", "activation_code"]);
  const deviceCol = pickColumn(cols, ["device_id", "device_key"]);
  const activatedAtCol = pickColumn(cols, ["activated_at", "used_at", "created_at"]);
  const statusCol = pickColumn(cols, ["status"]);
  const orderCol = pickColumn(cols, ["id", "rowid", "activated_at", "created_at"]);

  if (!emailCol || !codeCol || !deviceCol) return null;

  const whereStatus = statusCol
    ? ` AND upper(trim(${statusCol})) = 'USED' `
    : "";

  const sql = `
    SELECT
      ${codeCol} AS code,
      ${deviceCol} AS device_id,
      ${activatedAtCol ? activatedAtCol : "NULL"} AS activated_at
    FROM codes
    WHERE lower(trim(${emailCol})) = ?
      AND ${deviceCol} = ?
      ${whereStatus}
    ORDER BY ${orderCol || activatedAtCol || codeCol} DESC
    LIMIT 1
  `;

  return await DB.prepare(sql).bind(email, deviceId).first();
}

async function findLatestActivation(DB, email) {
  const cols = await getTableColumns(DB, "activations");
  if (!cols.length) return null;

  const emailCol = pickColumn(cols, ["email", "user_email", "used_by_email", "bound_email", "owner_email"]);
  const codeCol = pickColumn(cols, ["code", "activation_code"]);
  const deviceCol = pickColumn(cols, ["device_id", "device_key"]);
  const activatedAtCol = pickColumn(cols, ["activated_at", "used_at", "created_at"]);
  const orderCol = pickColumn(cols, ["id", "rowid", "activated_at", "created_at"]);

  if (!emailCol || !codeCol) return null;

  const sql = `
    SELECT
      ${codeCol} AS code,
      ${deviceCol ? deviceCol : "NULL"} AS device_id,
      ${activatedAtCol ? activatedAtCol : "NULL"} AS activated_at
    FROM activations
    WHERE lower(trim(${emailCol})) = ?
    ORDER BY ${orderCol || activatedAtCol || codeCol} DESC
    LIMIT 1
  `;

  return await DB.prepare(sql).bind(email).first();
}

async function findLatestCode(DB, email) {
  const cols = await getTableColumns(DB, "codes");
  if (!cols.length) return null;

  const emailCol = pickColumn(cols, ["email", "user_email", "used_by_email", "bound_email", "owner_email"]);
  const codeCol = pickColumn(cols, ["code", "activation_code"]);
  const deviceCol = pickColumn(cols, ["device_id", "device_key"]);
  const activatedAtCol = pickColumn(cols, ["activated_at", "used_at", "created_at"]);
  const statusCol = pickColumn(cols, ["status"]);
  const orderCol = pickColumn(cols, ["id", "rowid", "activated_at", "created_at"]);

  if (!emailCol || !codeCol) return null;

  const whereStatus = statusCol
    ? ` AND upper(trim(${statusCol})) = 'USED' `
    : "";

  const sql = `
    SELECT
      ${codeCol} AS code,
      ${deviceCol ? deviceCol : "NULL"} AS device_id,
      ${activatedAtCol ? activatedAtCol : "NULL"} AS activated_at
    FROM codes
    WHERE lower(trim(${emailCol})) = ?
      ${whereStatus}
    ORDER BY ${orderCol || activatedAtCol || codeCol} DESC
    LIMIT 1
  `;

  return await DB.prepare(sql).bind(email).first();
}

async function migrateLegacyDeviceId(DB, email, newDeviceId) {
  const activationCols = await getTableColumns(DB, "activations");
  if (activationCols.length) {
    const emailCol = pickColumn(activationCols, ["email", "user_email", "used_by_email", "bound_email", "owner_email"]);
    const deviceCol = pickColumn(activationCols, ["device_id", "device_key"]);

    if (emailCol && deviceCol) {
      const sql = `
        UPDATE activations
        SET ${deviceCol} = ?
        WHERE lower(trim(${emailCol})) = ?
          AND (
            ${deviceCol} IS NULL
            OR trim(${deviceCol}) = ''
            OR ${deviceCol} NOT LIKE 'bdk_%'
          )
      `;
      await DB.prepare(sql).bind(newDeviceId, email).run();
    }
  }

  const codeCols = await getTableColumns(DB, "codes");
  if (codeCols.length) {
    const emailCol = pickColumn(codeCols, ["email", "user_email", "used_by_email", "bound_email", "owner_email"]);
    const deviceCol = pickColumn(codeCols, ["device_id", "device_key"]);
    const statusCol = pickColumn(codeCols, ["status"]);

    if (emailCol && deviceCol) {
      const sql = `
        UPDATE codes
        SET ${deviceCol} = ?
        WHERE lower(trim(${emailCol})) = ?
          ${statusCol ? `AND upper(trim(${statusCol})) = 'USED'` : ""}
          AND (
            ${deviceCol} IS NULL
            OR trim(${deviceCol}) = ''
            OR ${deviceCol} NOT LIKE 'bdk_%'
          )
      `;
      await DB.prepare(sql).bind(newDeviceId, email).run();
    }
  }
}

async function getTableColumns(DB, tableName) {
  try {
    const safe = safeIdent(tableName);
    if (!safe) return [];
    const rows = await DB.prepare(`PRAGMA table_info(${safe})`).all();
    return Array.isArray(rows?.results)
      ? rows.results.map((r) => String(r.name || "").trim()).filter(Boolean)
      : [];
  } catch (_) {
    return [];
  }
}

function pickColumn(cols, candidates) {
  for (const name of candidates) {
    if (cols.includes(name)) return name;
  }
  return "";
}

function safeIdent(value) {
  const s = String(value || "").trim();
  if (!/^[A-Za-z0-9_]+$/.test(s)) return "";
  return s;
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

function getDeviceId(request) {
  return String(
    request.headers.get("X-Device-Id") ||
    request.headers.get("x-device-id") ||
    ""
  ).trim();
}

function normalizeDeviceId(value) {
  return String(value || "").trim();
}

function isStableDeviceId(value) {
  return /^bdk_/i.test(normalizeDeviceId(value));
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
