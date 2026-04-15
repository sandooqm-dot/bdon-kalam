export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(),
  });
}

export async function onRequestPost(context) {
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
        { ok: false, message: "يجب تسجيل الدخول أولًا." },
        401
      );
    }

    const session = await env.DB.prepare(`
      SELECT
        sessions.email AS email,
        users.activated AS activated
      FROM sessions
      INNER JOIN users ON users.email = sessions.email
      WHERE sessions.token = ?
      LIMIT 1
    `)
      .bind(token)
      .first();

    if (!session) {
      return json(
        { ok: false, message: "الجلسة غير صالحة أو منتهية." },
        401
      );
    }

    const body = await readJson(request);
    const code = normalizeCode(body.code);
    const bodyEmail = normalizeEmail(body.email);
    const sessionEmail = normalizeEmail(session.email);
    const deviceKey = normalizeDeviceKey(getDeviceKey(request));
    const nowIso = new Date().toISOString();

    if (!code) {
      return json(
        { ok: false, message: "أدخل كود اللعبة أولًا." },
        400
      );
    }

    if (bodyEmail && bodyEmail !== sessionEmail) {
      return json(
        { ok: false, message: "الإيميل لا يطابق الحساب الحالي." },
        403
      );
    }

    const codeRow = await env.DB.prepare(`
      SELECT code, status, email, device_key, activated_at
      FROM codes
      WHERE code = ?
      LIMIT 1
    `)
      .bind(code)
      .first();

    if (!codeRow) {
      return json(
        { ok: false, message: "الكود غير موجود." },
        404
      );
    }

    const codeStatus = String(codeRow.status || "").toUpperCase();
    const usedBy = normalizeEmail(codeRow.email);
    const codeDeviceKey = normalizeDeviceKey(codeRow.device_key);
    const activatedAt = String(codeRow.activated_at || nowIso);

    if (codeStatus === "USED") {
      if (usedBy === sessionEmail) {
        await markUserActivated(env.DB, sessionEmail);

        await ensureActivationRecord(env.DB, {
          code,
          email: sessionEmail,
          deviceKey: deviceKey || codeDeviceKey,
          activatedAt,
        });

        const sheetSync = await syncCodeToSheet({
          code,
          status: "USED",
          email: sessionEmail,
          deviceKey: deviceKey || codeDeviceKey || "",
          activatedAt,
        });

        return json({
          ok: true,
          message: "هذا الكود مرتبط بهذا الحساب مسبقًا وتم استعادة التفعيل بنجاح.",
          email: sessionEmail,
          activated: true,
          needs_activation: false,
          code,
          sheet_sync_ok: sheetSync.ok,
          sheet_sync_message: sheetSync.message,
        });
      }

      return json(
        { ok: false, message: "هذا الكود مستخدم بالفعل." },
        409
      );
    }

    const updateResult = await env.DB.prepare(`
      UPDATE codes
      SET
        status = 'USED',
        email = ?,
        device_key = ?,
        activated_at = ?
      WHERE code = ? AND status = 'NEW'
    `)
      .bind(sessionEmail, deviceKey || "", nowIso, code)
      .run();

    const changes =
      updateResult &&
      updateResult.meta &&
      typeof updateResult.meta.changes === "number"
        ? updateResult.meta.changes
        : 0;

    if (changes < 1) {
      const retryRow = await env.DB.prepare(`
        SELECT status, email, device_key, activated_at
        FROM codes
        WHERE code = ?
        LIMIT 1
      `)
        .bind(code)
        .first();

      const retryStatus = String(retryRow?.status || "").toUpperCase();
      const retryEmail = normalizeEmail(retryRow?.email);
      const retryDeviceKey = normalizeDeviceKey(retryRow?.device_key);
      const retryActivatedAt = String(retryRow?.activated_at || nowIso);

      if (retryStatus === "USED" && retryEmail === sessionEmail) {
        await markUserActivated(env.DB, sessionEmail);

        await ensureActivationRecord(env.DB, {
          code,
          email: sessionEmail,
          deviceKey: deviceKey || retryDeviceKey,
          activatedAt: retryActivatedAt,
        });

        const sheetSync = await syncCodeToSheet({
          code,
          status: "USED",
          email: sessionEmail,
          deviceKey: deviceKey || retryDeviceKey || "",
          activatedAt: retryActivatedAt,
        });

        return json({
          ok: true,
          message: "تم تفعيل الحساب بنجاح.",
          email: sessionEmail,
          activated: true,
          needs_activation: false,
          code,
          sheet_sync_ok: sheetSync.ok,
          sheet_sync_message: sheetSync.message,
        });
      }

      return json(
        { ok: false, message: "تعذر تفعيل الكود، حاول مرة أخرى." },
        409
      );
    }

    await markUserActivated(env.DB, sessionEmail);

    await ensureActivationRecord(env.DB, {
      code,
      email: sessionEmail,
      deviceKey,
      activatedAt: nowIso,
    });

    const sheetSync = await syncCodeToSheet({
      code,
      status: "USED",
      email: sessionEmail,
      deviceKey: deviceKey || "",
      activatedAt: nowIso,
    });

    return json({
      ok: true,
      message: "تم تفعيل اللعبة بنجاح.",
      email: sessionEmail,
      activated: true,
      needs_activation: false,
      code,
      sheet_sync_ok: sheetSync.ok,
      sheet_sync_message: sheetSync.message,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: "حدث خطأ أثناء تفعيل الكود.",
        error: String(error && error.message ? error.message : error),
      },
      500
    );
  }
}

async function markUserActivated(db, email) {
  await db.prepare(`
    UPDATE users
    SET activated = 1
    WHERE email = ?
  `)
    .bind(email)
    .run();
}

async function ensureActivationRecord(db, { code, email, deviceKey, activatedAt }) {
  const cleanDeviceKey = normalizeDeviceKey(deviceKey);

  if (cleanDeviceKey) {
    const existingSameDevice = await db.prepare(`
      SELECT id
      FROM activations
      WHERE code = ? AND email = ? AND device_key = ?
      LIMIT 1
    `)
      .bind(code, email, cleanDeviceKey)
      .first();

    if (existingSameDevice) return;

    await db.prepare(`
      INSERT INTO activations (code, email, device_key, activated_at)
      VALUES (?, ?, ?, ?)
    `)
      .bind(code, email, cleanDeviceKey, activatedAt)
      .run();

    return;
  }

  const existingAny = await db.prepare(`
    SELECT id
    FROM activations
    WHERE code = ? AND email = ?
    LIMIT 1
  `)
    .bind(code, email)
    .first();

  if (existingAny) return;

  await db.prepare(`
    INSERT INTO activations (code, email, device_key, activated_at)
    VALUES (?, ?, ?, ?)
  `)
    .bind(code, email, "", activatedAt)
    .run();
}

async function syncCodeToSheet({ code, status, email, deviceKey, activatedAt }) {
  const SHEET_SYNC_URL =
    "https://script.google.com/macros/s/AKfycbwtSHF43afcz2BRSBcOv19u8V9Fhg6XU4zThzvtG1-hhVu9xBAM-pwGt9M2Zf-TNcSz/exec";

  const SHEET_SYNC_SECRET = "BDON_KALAM_SYNC_2026";

  try {
    const response = await fetch(SHEET_SYNC_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        secret: SHEET_SYNC_SECRET,
        code,
        status,
        email,
        deviceKey: deviceKey || "",
        activatedAt,
      }),
    });

    let data = {};
    try {
      data = await response.json();
    } catch (_) {}

    if (!response.ok) {
      return {
        ok: false,
        message: data?.message || `HTTP ${response.status}`,
      };
    }

    return {
      ok: !!data?.ok,
      message: data?.message || "Sheet sync done",
    };
  } catch (error) {
    return {
      ok: false,
      message: String(error && error.message ? error.message : error),
    };
  }
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
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

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
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

function normalizeCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
}
