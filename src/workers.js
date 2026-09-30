const H = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "access-control-allow-headers": "Content-Type,Authorization"
};

const json = (x, s = 200) =>
  new Response(JSON.stringify(x), {
    status: s,
    headers: H
  });

const fail = (x, s = 400) => json({ error: x }, s);

async function body(r) {
  try {
    return await r.json();
  } catch {
    return {};
  }
}

async function sha(t) {
  const b = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(t)
  );

  let s = "";
  for (const x of new Uint8Array(b)) {
    s += String.fromCharCode(x);
  }

  return btoa(s);
}

async function randomToken() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);

  let s = "";
  for (const x of b) {
    s += x.toString(16).padStart(2, "0");
  }

  return s;
}

async function user(env, r) {
  const h = r.headers.get("authorization") || "";

  if (!h.startsWith("Bearer ")) {
    return null;
  }

  const x = await sha(h.slice(7));

  return await env.DB
    .prepare(`
      SELECT u.id, u.username, u.role
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      AND s.expires_at > ?
    `)
    .bind(x, Date.now())
    .first();
}

/* =========================
   ADMIN LOGIN
   קוד בלבד — ללא שם משתמש
   ========================= */

async function adminLogin(req, env) {
  const b = await body(req);
  const code = String(b.code || "").trim();

  if (!code) {
    return fail("יש להזין קוד מנהל", 400);
  }

  if (!env.ADMIN_CODE_HASH) {
    return fail("כניסת מנהלים לא הוגדרה בשרת", 503);
  }

  const hash = await sha(code);

  if (hash !== String(env.ADMIN_CODE_HASH)) {
    return fail("קוד מנהל שגוי", 401);
  }

  let admin = await env.DB
    .prepare(`
      SELECT id, username, role
      FROM users
      WHERE role = 'super_admin'
      ORDER BY id
      LIMIT 1
    `)
    .first();

  if (!admin) {
    await env.DB
      .prepare(`
        INSERT INTO users
        (username, password_hash, role, created_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `)
      .bind(
        "admin",
        "ADMIN_CODE_AUTH",
        "super_admin"
      )
      .run();

    admin = await env.DB
      .prepare(`
        SELECT id, username, role
        FROM users
        WHERE role = 'super_admin'
        ORDER BY id
        LIMIT 1
      `)
      .first();
  }

  const token = await randomToken();
  const tokenHash = await sha(token);
  const expires = Date.now() + 8 * 60 * 60 * 1000;

  await env.DB
    .prepare(`
      INSERT OR REPLACE INTO sessions
      (token_hash, user_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      tokenHash,
      admin.id,
      expires,
      Date.now()
    )
    .run();

  return json({
    token,
    user: {
      id: admin.id,
      username: "מנהל",
      role: "super_admin"
    },
    expiresAt: expires
  });
}

/* =========================
   AUTH
   ========================= */

async function authMe(req, env) {
  const u = await user(env, req);

  if (!u) {
    return fail("הסשן אינו תקף", 401);
  }

  return json({
    user: {
      id: u.id,
      username: u.username === "admin" ? "מנהל" : u.username,
      role: u.role
    }
  });
}

async function requireMgr(env, req) {
  const u = await user(env, req);

  if (
    !u ||
    ![
      "manager",
      "super_manager",
      "super_admin"
    ].includes(u.role)
  ) {
    return null;
  }

  return u;
}

/* =========================
   BOARD
   ========================= */

async function boardMessage(req, env) {
  const u = await requireMgr(env, req);

  if (!u) {
    return fail("נדרש חיבור מנהל", 401);
  }

  const b = await body(req);
  const message = String(b.message || "").trim();

  if (!message) {
    return fail("לא התקבלה הודעה", 400);
  }

  /*
    כאן בורד מקבל את ההודעה.
    אנחנו שומרים אותה כמשימת Board,
    כדי שלא תאבד גם אם ה-AI לא זמין.
  */

  const taskId = crypto.randomUUID();
  const expires = Date.now() + 30 * 60 * 1000;

  try {
    await env.DB
      .prepare(`
        CREATE TABLE IF NOT EXISTS board_tasks (
          id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          message TEXT NOT NULL,
          payload TEXT,
          status TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        )
      `)
      .run();

    await env.DB
      .prepare(`
        INSERT INTO board_tasks
        (id, user_id, message, payload, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        taskId,
        u.id,
        message,
        JSON.stringify({
          requestedBy: u.username,
          capabilities: [
            "inspect_site",
            "diagnose",
            "read_code",
            "search_code",
            "preview_change",
            "add_category",
            "update_settings",
            "stats",
            "list_categories"
          ]
        }),
        "pending",
        Date.now(),
        expires
      )
      .run();
  } catch (e) {
    return fail(
      "בורד לא הצליח לשמור את המשימה: " +
      String(e.message || e),
      500
    );
  }

  return json({
    stage: "received",
    taskId,
    reply:
      "קיבלתי את מה שכתבת. בורד מוכן לבדוק את המשימה.",
    needsApproval: false,
    expiresAt: expires
  });
}

/* =========================
   BOARD TASKS
   ========================= */

async function boardTasks(req, env) {
  const u = await requireMgr(env, req);

  if (!u) {
    return fail("אין הרשאה", 403);
  }

  const { results } = await env.DB
    .prepare(`
      SELECT
        id,
        message,
        status,
        created_at,
        expires_at
      FROM board_tasks
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `)
    .bind(u.id)
    .all();

  return json({
    tasks: results || []
  });
}

/* =========================
   HEALTH
   ========================= */

async function health() {
  return json({
    status: "ok",
    platform: "cloudflare",
    board: true,
    adminCodeLogin: true
  });
}

/* =========================
   MAIN WORKER
   ========================= */

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: H
      });
    }

    /* בדיקת שרת */
    if (
      url.pathname === "/api/health" &&
      req.method === "GET"
    ) {
      return health();
    }

    /* כניסת מנהלים — קוד בלבד */
    if (
      url.pathname === "/api/admin/login" &&
      req.method === "POST"
    ) {
      return adminLogin(req, env);
    }

    /* בדיקת משתמש מחובר */
    if (
      url.pathname === "/api/auth/me" &&
      req.method === "GET"
    ) {
      return authMe(req, env);
    }

    /* בורד מקבל הודעה */
    if (
      (url.pathname === "/api/board/message" ||
       url.pathname === "/api/ai/board") &&
      req.method === "POST"
    ) {
      return boardMessage(req, env);
    }

    /* רשימת משימות בורד */
    if (
      url.pathname === "/api/board/tasks" &&
      req.method === "GET"
    ) {
      return boardTasks(req, env);
    }

    return fail("הנתיב לא נמצא", 404);
  }
};
