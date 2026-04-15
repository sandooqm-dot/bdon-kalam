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

    if (!password) {
      return json(
        { ok: false, message: "أدخل كلمة المرور." },
        400
      );
    }

    const user = await env.DB.prepare(
      "SELECT email, password_hash, activated, created_at FROM users WHERE email = ? LIMIT 1"
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

    const token = generateToken();
    const activated = !!user.activated;
    const needsActivation = !activated;

    await env.DB.prepare(
      "INSERT INTO sessions (token, email) VALUES (?, ?)"
    )
      .bind(token, email)
      .run();

    return json({
      ok: true,
      message: activated
        ? "تم تسجيل الدخول بنجاح."
        : "تم تسجيل الدخول بنجاح. هذا الحساب يحتاج تفعيل.",
      email,
      token,
      activated,
      needs_activation: needsActivation,
      user: {
        email,
        activated,
        created_at: user.created_at || null,
      },
      session: {
        token,
      },
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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
