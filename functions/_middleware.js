export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (!shouldProtect(request, pathname)) {
    return next();
  }

  const newSystemAccess = await checkNewSystemAccess(request, url);

  if (newSystemAccess.allowed) {
    if (newSystemAccess.redirectCleanUrl) {
      return redirectToCleanUrl(url, newSystemAccess.cookies || []);
    }

    const response = await next();
    return appendSetCookies(response, newSystemAccess.cookies || []);
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

const NEW_AUTH_API_BASE = "https://sandooq-games-api.sandooq-m.workers.dev";
const NEW_GAME_ID = "bdon-kalam";
const NEW_SITE_TOKEN_COOKIE = "sandooq_site_token_v1";
const NEW_SITE_GAME_COOKIE = "sandooq_site_game_v1";

const NEW_TOKEN_QUERY_KEYS = [
  "sg_token",
  "sandooq_token",
  "access_token",
  "token"
];

const NEW_GAME_QUERY_KEYS = [
  "sg_game",
  "game_id",
  "game"
];

function shouldProtect(request, pathname) {
  const method = (request.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const lower = pathname.toLowerCase();

  if (lower.startsWith("/api/")) return false;

  if (
    lower === "/activate.html" ||
    lower === "/activate" ||
    lower === "/reveal.html" ||
    lower === "/reveal"
  ) {
    return false;
  }

  const publicFiles = [
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
    ".css", ".js", ".mjs", ".map", ".json", ".txt", ".xml",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm"
  ];

  if (publicFiles.some(ext => lower.endsWith(ext))) return false;

  if (lower.startsWith("/images/")) return false;

  if (lower === "/" || lower.endsWith(".html")) return true;

  return false;
}

async function checkNewSystemAccess(request, currentUrl) {
  const cookies = parseCookies(request.headers.get("cookie") || "");

  const tokenFromQuery = readFirstQueryValue(currentUrl, NEW_TOKEN_QUERY_KEYS);
  const tokenFromCookie = String(
    cookies[NEW_SITE_TOKEN_COOKIE] ||
    cookies["sandooq_auth_token_v1"] ||
    cookies["sandooq_token_v1"] ||
    cookies["sandooq_token"] ||
    cookies["bdonKalam_site_token_v1"] ||
    ""
  ).trim();

  const token = tokenFromQuery || tokenFromCookie;

  if (!token) {
    return { allowed: false };
  }

  const gameFromQuery = normalizeGameId(readFirstQueryValue(currentUrl, NEW_GAME_QUERY_KEYS));
  const gameFromCookie = normalizeGameId(
    cookies[NEW_SITE_GAME_COOKIE] ||
    cookies["sandooq_site_game_id_v1"] ||
    cookies["bdonKalam_site_game_v1"]
  );

  const gameId = gameFromQuery || gameFromCookie || NEW_GAME_ID;

  if (gameId !== NEW_GAME_ID) {
    return { allowed: false };
  }

  const cookiesToSet = [
    buildSessionCookie(NEW_SITE_TOKEN_COOKIE, token, currentUrl),
    buildSessionCookie(NEW_SITE_GAME_COOKIE, NEW_GAME_ID, currentUrl),
    buildSessionCookie("sandooq_auth_token_v1", token, currentUrl),
    buildSessionCookie("bdonKalam_site_token_v1", token, currentUrl),
    buildSessionCookie("bdonKalam_site_game_v1", NEW_GAME_ID, currentUrl)
  ];

  const allowedByAccess = await verifyViaGameAccessEndpoint(token);
  const allowedByAccount = allowedByAccess ? true : await verifyViaAccountMe(token);

  if (allowedByAccess || allowedByAccount) {
    return {
      allowed: true,
      cookies: cookiesToSet,
      redirectCleanUrl: hasNewAccessQuery(currentUrl)
    };
  }

  return { allowed: false };
}

async function verifyViaGameAccessEndpoint(token) {
  try {
    const apiResponse = await fetch(`${NEW_AUTH_API_BASE}/api/game/access`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        game_id: NEW_GAME_ID,
        device_token: createTemporaryDeviceToken(),
        device_name: "Bdon Kalam Site Access",
        is_temporary: true
      }),
      cache: "no-store"
    });

    let data = {};
    try {
      data = await apiResponse.json();
    } catch (_) {}

    return apiResponse.ok && isAllowedAccessResponse(data);
  } catch (_) {
    return false;
  }
}

async function verifyViaAccountMe(token) {
  try {
    const apiResponse = await fetch(`${NEW_AUTH_API_BASE}/api/account/me`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`
      },
      cache: "no-store"
    });

    let data = {};
    try {
      data = await apiResponse.json();
    } catch (_) {}

    if (!apiResponse.ok || !data || data.ok === false) return false;

    const ownedIds = extractOwnedGameIds(data);
    return ownedIds.has(NEW_GAME_ID);
  } catch (_) {
    return false;
  }
}

function isAllowedAccessResponse(data) {
  if (!data || typeof data !== "object") return false;

  return (
    data.allowed === true ||
    data.access === true ||
    data.can_play === true ||
    data.canPlay === true ||
    data.has_access === true ||
    data.hasAccess === true ||
    data.permitted === true ||
    data?.access?.allowed === true ||
    data?.game?.allowed === true ||
    (
      data.ok === true &&
      data.allowed !== false &&
      (
        data.access === true ||
        data.can_play === true ||
        data.canPlay === true ||
        data.has_access === true ||
        data.hasAccess === true ||
        data?.access?.allowed === true ||
        data?.game?.allowed === true
      )
    )
  );
}

function extractOwnedGameIds(data) {
  const ids = new Set();

  function addId(value) {
    const id = String(value || "").trim().toLowerCase();
    if (id) ids.add(id);
  }

  function readGameObject(game) {
    if (!game || typeof game !== "object") return;

    addId(game.id);
    addId(game.slug);
    addId(game.game_id);
    addId(game.gameId);
    addId(game.product_id);
    addId(game.productId);
    addId(game.key);
  }

  function readArray(list) {
    if (!Array.isArray(list)) return;

    list.forEach(item => {
      if (!item) return;
      if (typeof item === "string") addId(item);
      else readGameObject(item);
    });
  }

  if (!data || typeof data !== "object") return ids;

  readArray(data.games);
  readArray(data.owned_games);
  readArray(data.ownedGames);
  readArray(data.entitlements);
  readArray(data.products);
  readArray(data.library);

  if (data.customer && typeof data.customer === "object") {
    readArray(data.customer.games);
    readArray(data.customer.owned_games);
    readArray(data.customer.ownedGames);
    readArray(data.customer.entitlements);
    readArray(data.customer.products);
    readArray(data.customer.library);
  }

  return ids;
}

function normalizeGameId(value) {
  const gameId = String(value || "").trim().toLowerCase();
  return gameId === NEW_GAME_ID ? NEW_GAME_ID : "";
}

function readFirstQueryValue(url, keys) {
  for (const key of keys) {
    const value = String(url.searchParams.get(key) || "").trim();
    if (value) return value;
  }

  return "";
}

function hasNewAccessQuery(url) {
  const keys = [
    ...NEW_TOKEN_QUERY_KEYS,
    ...NEW_GAME_QUERY_KEYS,
    "sg_temp",
    "temporary",
    "is_temporary"
  ];

  return keys.some(key => url.searchParams.has(key));
}

function createTemporaryDeviceToken() {
  try {
    if (crypto.randomUUID) return "bdon_site_" + crypto.randomUUID();
  } catch (_) {}

  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return "bdon_site_" + Array.from(bytes).map(byte => byte.toString(16).padStart(2, "0")).join("");
  } catch (_) {}

  return "bdon_site_" + Date.now().toString(36) + Math.random().toString(36).slice(2);
}

function buildSessionCookie(name, value, currentUrl) {
  const secure = currentUrl.protocol === "https:" ? "; Secure" : "";
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=2592000; SameSite=Lax${secure}`;
}

function redirectToCleanUrl(currentUrl, cookiesToSet = []) {
  const target = new URL(currentUrl.toString());

  [
    ...NEW_TOKEN_QUERY_KEYS,
    ...NEW_GAME_QUERY_KEYS,
    "sg_temp",
    "temporary",
    "is_temporary"
  ].forEach(key => target.searchParams.delete(key));

  const headers = new Headers();
  headers.set("Location", target.toString());
  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  headers.set("Vary", "Cookie, Authorization");

  cookiesToSet.forEach(cookie => headers.append("Set-Cookie", cookie));

  return new Response(null, {
    status: 302,
    headers
  });
}

function appendSetCookies(response, cookiesToSet = []) {
  if (!cookiesToSet.length) return response;

  const headers = new Headers(response.headers);
  cookiesToSet.forEach(cookie => headers.append("Set-Cookie", cookie));
  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  headers.set("Vary", "Cookie, Authorization");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
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
      const SITE_GAME_ID = "bdon-kalam";
      const SITE_TOKEN_COOKIE = "sandooq_site_token_v1";
      const SITE_GAME_COOKIE = "sandooq_site_game_v1";

      const SITE_TOKEN_KEYS = [
        SITE_TOKEN_COOKIE,
        "sandooq_auth_token_v1",
        "sandooq_token_v1",
        "sandooq_token",
        "bdonKalam_site_token_v1"
      ];

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

      function readCookie(name) {
        try {
          const cookie = document.cookie || "";
          const parts = cookie.split(";");
          for (const part of parts) {
            const [k, ...rest] = part.trim().split("=");
            if (k === name) return decodeURIComponent(rest.join("=") || "");
          }
        } catch (_) {}
        return "";
      }

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

          const cookieValue = readCookie(key);
          if (cookieValue && String(cookieValue).trim()) return String(cookieValue).trim();
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

      function retryWithSiteToken() {
        const siteToken = readAny(SITE_TOKEN_KEYS);
        if (!siteToken) return false;

        writeCookie(SITE_TOKEN_COOKIE, siteToken);
        writeCookie(SITE_GAME_COOKIE, SITE_GAME_ID);

        try { sessionStorage.setItem(SITE_TOKEN_COOKIE, siteToken); } catch (_) {}
        try { sessionStorage.setItem(SITE_GAME_COOKIE, SITE_GAME_ID); } catch (_) {}

        const target = new URL(CURRENT_URL || "/", location.origin);
        target.searchParams.set("sg_token", siteToken);
        target.searchParams.set("sg_game", SITE_GAME_ID);
        target.searchParams.set("sg_temp", "1");
        location.replace(target.toString());
        return true;
      }

      async function run() {
        if (retryWithSiteToken()) return;

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
