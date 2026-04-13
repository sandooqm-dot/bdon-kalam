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

    if (!email || !isValidEmail(email)) {
      return json(
        { ok: false, message: "أدخل إيميل صحيح." },
        400
      );
    }

    if (password.length < 6) {
      return json(
        { ok: false, message: "كلمة المرور يجب أن تكون 6 أحرف أو أكثر." },
        400
      );
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? LIMIT 1"
    )
      .bind(email)
      .first();

    if (existing) {
      return json(
        { ok: false, message: "هذا الإيميل مسجل مسبقًا." },
        409
      );
    }

    const passwordHash = await hashPassword(password);
    const token = generateToken();

    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO users (email, password_hash, activated) VALUES (?, ?, 0)"
      ).bind(email, passwordHash),

      env.DB.prepare(
        "INSERT INTO sessions (token, email) VALUES (?, ?)"
      ).bind(token, email),
    ]);

    return json({
      ok: true,
      message: "تم إنشاء الحساب بنجاح.",
      email,
      token,
      activated: false,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: "حدث خطأ أثناء إنشاء الحساب.",
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return "bdk_" + toHex(bytes);
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;

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
    256
  );

  const hashBytes = new Uint8Array(bits);

  return [
    "pbkdf2_sha256",
    iterations,
    toBase64(salt),
    toBase64(hashBytes),
  ].join("$");
}

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
