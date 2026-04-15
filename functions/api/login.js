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

    const body = await readJson(request);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    const deviceId = normalizeDeviceId(
      request.headers.get("X-Device-Id") ||
      body.deviceId ||
      ""
    );

    if (!email || !isValidEmail(email)) {
      return json(
        { ok: false, message: "أدخل إيميل صحيح." },
        400
      );
    }

    if (!password) {
      return json(
        { ok: false, message: "أدخل كلمة المرور." },
        400
      );
    }

    if (!deviceId || deviceId.length < 8) {
      return json(
        { ok: false, message: "تعذر التعرف على الجهاز. أعد المحاولة من نفس المتصفح." },
        400
      );
    }

    await ensureAccountDevicesTable(env.DB);

    const user = await env.DB.prepare(
      "SELECT email, password_hash, activated FROM users WHERE email = ? LIMIT 1"
    )
      .bind(email)
      .first();

    if (!user) {
      return json(
        { ok: false, message: "الإيميل أو كلمة المرور غير صحيحة." },
        401
      );
    }

    const passwordOk = await verifyPassword(password, user.password_hash);
    if (!passwordOk) {
      return json(
        { ok: false, message: "الإيميل أو كلمة المرور غير صحيحة." },
        401
      );
    }

    const deviceCheck = await bindOrCheckSingleDevice(env.DB, email, deviceId);
    if (!deviceCheck.ok) {
      return json(
        { ok: false, message: deviceCheck.message },
        409
      );
    }

    const token = generateToken();

    await env.DB.prepare(
      "DELETE FROM sessions WHERE email = ?"
    )
      .bind(email)
      .run();

    await env.DB.prepare(
      "INSERT INTO sessions (token, email) VALUES (?, ?)"
    )
      .bind(token, email)
      .run();

    return json({
      ok: true,
      message: "تم تسجيل الدخول بنجاح.",
      email,
      token,
      activated: !!user.activated,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: "حدث خطأ أثناء تسجيل الدخول.",
        error: String(error && error.message ? error.message : error),
      },
      500
    );
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

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeDeviceId(value) {
  return String(value || "").trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function ensureAccountDevicesTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS account_devices (
      email TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

async function bindOrCheckSingleDevice(db, email, deviceId) {
  const row = await db.prepare(
    "SELECT email, device_id FROM account_devices WHERE email = ? LIMIT 1"
  )
    .bind(email)
    .first();

  if (!row) {
    await db.prepare(`
      INSERT INTO account_devices (email, device_id, created_at, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `)
      .bind(email, deviceId)
      .run();

    return { ok: true };
  }

  const savedDeviceId = normalizeDeviceId(row.device_id);

  if (!savedDeviceId) {
    await db.prepare(`
      UPDATE account_devices
      SET device_id = ?, updated_at = CURRENT_TIMESTAMP
      WHERE email = ?
    `)
      .bind(deviceId, email)
      .run();

    return { ok: true };
  }

  if (savedDeviceId !== deviceId) {
    return {
      ok: false,
      message: "هذا الحساب مرتبط بجهاز آخر، ولا يمكن تسجيل الدخول من جهاز ثاني."
    };
  }

  await db.prepare(`
    UPDATE account_devices
    SET updated_at = CURRENT_TIMESTAMP
    WHERE email = ?
  `)
    .bind(email)
    .run();

  return { ok: true };
}

function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return "bdk_" + toHex(bytes);
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash || "").split("$");
    if (parts.length !== 4) return false;

    const [algo, iterationsStr, saltB64, hashB64] = parts;
    if (algo !== "pbkdf2_sha256") return false;

    const iterations = Number(iterationsStr);
    if (!Number.isFinite(iterations) || iterations <= 0) return false;

    const salt = fromBase64(saltB64);
    const expectedHash = fromBase64(hashB64);

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      key,
      expectedHash.length * 8
    );

    const actualHash = new Uint8Array(bits);
    return timingSafeEqual(actualHash, expectedHash);
  } catch {
    return false;
  }
}

function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
