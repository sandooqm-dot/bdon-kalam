export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (!shouldProtect(request, pathname)) {
    return next();
  }

  const cookies = parseCookies(request.headers.get("cookie") || "");
  const token =
    cookies["bdonKalam_token_v1"] ||
    cookies["bdonKalam_token"] ||
    cookies["sandooq_token_v1"] ||
    cookies["sandooq_token"] ||
    "";

  if (token) {
    const isAllowed = await isActivatedSession(env, token);
    if (isAllowed) {
      return next();
    }
  }

  return buildClientGatePage(url);
}

function shouldProtect(request, pathname) {
  const method = (request.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const lower = pathname.toLowerCase();

  if (lower.startsWith("/api/")) return false;
  if (lower === "/activate.html" || lower === "/activate") return false;

  const publicFiles = [
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
    ".css", ".js", ".mjs", ".map", ".json", ".txt", ".xml",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm"
  ];

  if (publicFiles.some(ext => lower.endsWith(ext))) return false;

  if (lower === "/" || lower.endsWith(".html")) return true;

  return false;
}

async function isActivatedSession(env, token) {
  try {
    if (!env.DB || !token) return false;

    const row = await env.DB.prepare(`
      SELECT
        sessions.email AS email,
        users.activated AS activated
      FROM sessions
      INNER JOIN users ON users.email = sessions.email
      WHERE sessions.token = ?
      LIMIT 1
    `)
      .bind(String(token).trim())
      .first();

    return !!(row && Number(row.activated) === 1);
  } catch (_) {
    return false;
  }
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;

  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = decodeURIComponentSafe(value);
  }
  return out;
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch (_) {
    return value;
  }
}

function buildClientGatePage(url) {
  const currentPath = `${url.pathname}${url.search}`;
  const html = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>جاري التحقق...</title>
  <style>
    html,body{
      margin:0;
      min-height:100%;
      background:#f7efd8;
      color:#18131d;
      font-family:Tahoma,Arial,sans-serif;
    }
    body{
      display:flex;
      align-items:center;
      justify-content:center;
      padding:24px;
      text-align:center;
    }
    .box{
      width:min(92vw,520px);
      background:#fff8e6;
      border:4px solid #1d1922;
      border-radius:28px;
      box-shadow:0 10px 0 #17131d;
      padding:28px 18px;
    }
    h1{
      margin:0 0 10px;
      font-size:30px;
    }
    p{
      margin:0;
      font-size:18px;
      line-height:1.8;
      color:#444;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>جاري التحقق...</h1>
    <p>لحظة واحدة</p>
  </div>

  <script>
    (function () {
      const ACTIVATE_URL = "/activate.html";
      const CURRENT_URL = ${JSON.stringify(currentPath)};

      const TOKEN_KEYS = [
        "bdonKalam_token_v1",
        "bdonKalam_token",
        "sandooq_token_v1",
        "sandooq_token",
        "token"
      ];

      const EMAIL_KEYS = [
        "bdonKalam_email_v1",
        "bdonKalam_email",
        "sandooq_email",
        "user_email",
        "email"
      ];

      function readAny(keys) {
        for (const key of keys) {
          try {
            const local = localStorage.getItem(key);
            if (local && String(local).trim()) return String(local).trim();
          } catch (_) {}
          try {
            const session = sessionStorage.getItem(key);
            if (session && String(session).trim()) return String(session).trim();
          } catch (_) {}
        }
        return "";
      }

      function writeCookie(name, value) {
        if (!value) return;
        const secure = location.protocol === "https:" ? "; Secure" : "";
        document.cookie =
          name + "=" + encodeURIComponent(value) +
          "; Path=/; Max-Age=2592000; SameSite=Lax" + secure;
      }

      function normalizeEmail(value) {
        return String(value || "").trim().toLowerCase();
      }

      function isActivated(data) {
        return !!(
          data?.activated === true ||
          data?.is_activated === true ||
          data?.isActivated === true ||
          data?.user?.activated === true ||
          data?.user?.is_activated === true ||
          data?.user?.isActivated === true ||
          data?.status === "activated"
        );
      }

      async function run() {
        const token = readAny(TOKEN_KEYS);
        const email = normalizeEmail(readAny(EMAIL_KEYS));

        if (!token) {
          location.replace(ACTIVATE_URL);
          return;
        }

        try {
          const res = await fetch("/api/me", {
            method: "GET",
            headers: {
              Authorization: "Bearer " + token
            },
            cache: "no-store"
          });

          let data = {};
          try {
            data = await res.json();
          } catch (_) {}

          if (!res.ok || !isActivated(data)) {
            location.replace(ACTIVATE_URL);
            return;
          }

          const resolvedEmail = normalizeEmail(
            data?.email || data?.user?.email || email || ""
          );

          writeCookie("bdonKalam_token_v1", token);
          if (resolvedEmail) {
            writeCookie("bdonKalam_email_v1", resolvedEmail);
          }

          location.replace(CURRENT_URL);
        } catch (_) {
          location.replace(ACTIVATE_URL);
        }
      }

      run();
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
