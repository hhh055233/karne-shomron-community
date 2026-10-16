var __defProp = Object.defineProperty;
var __name = (target, value) =>
  __defProp(target, "name", { value, configurable: true });

// src/index.js
var H = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

var json = /* @__PURE__ */ __name((x, s = 200) =>
  new Response(JSON.stringify(x), {
    status: s,
    headers: H
  }), "json");

var fail = /* @__PURE__ */ __name((x, s = 400) =>
  json({ error: x }, s), "fail");

var ALLOWED_CATEGORIES = /* @__PURE__ */ new Set([
  "\u05D7\u05E0\u05D5\u05D9\u05D5\u05EA",
  "\u05D9\u05D3 \u05E9\u05E0\u05D9\u05D9\u05D4",
  "\u05DC\u05DE\u05E1\u05D9\u05E8\u05D4",
  "\u05D7\u05D5\u05D2\u05D9\u05DD",
  "\u05D0\u05D9\u05E8\u05D5\u05E2\u05D9\u05DD",
  "\u05D3\u05E8\u05D5\u05E9\u05D9\u05DD"
]);

var MANAGERS = ["manager", "super_manager", "super_admin"];

async function body(r) {
  try {
    return await r.json();
  } catch {
    return {};
  }
}
__name(body, "body");

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
__name(sha, "sha");

async function user(env, r) {
  const h = r.headers.get("authorization") || "";
  if (!h.startsWith("Bearer ")) return null;

  const x = await sha(h.slice(7));

  return await env.DB.prepare(
    "SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?"
  ).bind(x, Date.now()).first();
}
__name(user, "user");

async function randomToken() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);

  let s = "";
  for (const x of b) {
    s += x.toString(16).padStart(2, "0");
  }

  return s;
}
__name(randomToken, "randomToken");

async function adminLogin(req, env) {
  const b = await body(req);
  const code = String(b.code || "").trim();

  if (!code || !env.ADMIN_CODE_HASH) {
    return fail(
      "\u05DB\u05E0\u05D9\u05E1\u05EA \u05DE\u05E0\u05D4\u05DC\u05D9\u05DD \u05DC\u05D0 \u05D4\u05D5\u05D2\u05D3\u05E8\u05D4 \u05D1\u05E9\u05E8\u05EA",
      503
    );
  }

  const hash = await sha(code);

  if (hash !== String(env.ADMIN_CODE_HASH)) {
    return fail("\u05E7\u05D5\u05D3 \u05DE\u05E0\u05D4\u05DC \u05E9\u05D2\u05D5\u05D9", 401);
  }

  let admin = await env.DB.prepare(
    "SELECT id,username,role FROM users WHERE role='super_admin' ORDER BY id LIMIT 1"
  ).first();

  if (!admin) {
    await env.DB.prepare(
      "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)"
    ).bind("admin", "ADMIN_CODE_AUTH", "super_admin").run();

    admin = await env.DB.prepare(
      "SELECT id,username,role FROM users WHERE role='super_admin' ORDER BY id LIMIT 1"
    ).first();
  }

  const token = await randomToken();
  const tokenHash = await sha(token);
  const expires = Date.now() + 8 * 60 * 60 * 1e3;

  await env.DB.prepare(
    "INSERT OR REPLACE INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)"
  ).bind(
    tokenHash,
    admin.id,
    expires,
    Date.now()
  ).run();

  await audit(env, admin, "admin_login", "code_login");

  return json({
    token,
    user: {
      username: "\u05DE\u05E0\u05D4\u05DC",
      role: "super_admin"
    },
    expiresAt: expires
  });
}
__name(adminLogin, "adminLogin");

async function audit(env, u, a, d = "") {
  if (!u) return;

  await env.DB.prepare(
    "INSERT INTO audit_log(username,action,details,created_at) VALUES(?,?,?,?)"
  ).bind(
    u.username,
    a,
    String(d).slice(0, 1500),
    Date.now()
  ).run();
}
__name(audit, "audit");

async function authMe(req, env) {
  const u = await user(env, req);

  if (!u) {
    return fail("\u05D4\u05E1\u05E9\u05DF \u05D0\u05D9\u05E0\u05D5 \u05EA\u05E7\u05E3", 401);
  }

  return json({
    user: {
      id: u.id,
      username: u.username === "admin"
        ? "\u05DE\u05E0\u05D4\u05DC"
        : u.username,
      role: u.role
    }
  });
}
__name(authMe, "authMe");

async function adminUsers(req, env, u) {
  if (!u || ![
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  const { results } = await env.DB.prepare(
    "SELECT id,username,role,created_at FROM users ORDER BY id"
  ).all();

  return json({
    users: results || []
  });
}
__name(adminUsers, "adminUsers");

async function adminUserPatch(req, env, u, target) {
  if (!u || ![
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  const b = await body(req);
  const nr = String(b.role || "").trim();

  if (![
    "user",
    "manager",
    "super_manager",
    "super_admin"
  ].includes(nr)) {
    return fail("\u05EA\u05E4\u05E7\u05D9\u05D3 \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF", 400);
  }

  const targetUser = await env.DB.prepare(
    "SELECT id,username,role FROM users WHERE username=? LIMIT 1"
  ).bind(target).first();

  if (!targetUser) {
    return fail("\u05D4\u05DE\u05E9\u05EA\u05DE\u05E9 \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0", 404);
  }

  if (nr === "super_admin" && u.role !== "super_admin") {
    return fail(
      "\u05E8\u05E7 \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9 \u05D9\u05DB\u05D5\u05DC \u05DC\u05DE\u05E0\u05D5\u05EA \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9",
      403
    );
  }

  if (targetUser.role === "super_admin" && u.role !== "super_admin") {
    return fail(
      "\u05E8\u05E7 \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9 \u05D9\u05DB\u05D5\u05DC \u05DC\u05E9\u05E0\u05D5\u05EA \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9",
      403
    );
  }

  if (targetUser.id === u.id && nr !== "super_admin") {
    return fail(
      "\u05D0\u05D9 \u05D0\u05E4\u05E9\u05E8 \u05DC\u05D4\u05E1\u05D9\u05E8 \u05D0\u05EA \u05D4\u05DE\u05E0\u05D4\u05DC \u05D4\u05E8\u05D0\u05E9\u05D9 \u05E9\u05DE\u05D7\u05D5\u05D1\u05E8 \u05DB\u05E8\u05D2\u05E2",
      400
    );
  }

  await env.DB.prepare(
    "UPDATE users SET role=? WHERE id=?"
  ).bind(nr, targetUser.id).run();

  await audit(
    env,
    u,
    "role_change",
    JSON.stringify({
      target: targetUser.username,
      role: nr
    })
  );

  return json({
    ok: true,
    user: {
      id: targetUser.id,
      username: targetUser.username,
      role: nr
    }
  });
}
__name(adminUserPatch, "adminUserPatch");

async function postsApi(req, env, u, url) {
  if (req.method === "GET") {
    const admin = url.searchParams.get("admin") === "1";

    if (admin && (!u || ![
      "manager",
      "super_manager",
      "super_admin"
    ].includes(u.role))) {
      return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
    }

    const q = admin
      ? "SELECT * FROM posts ORDER BY created_at DESC"
      : "SELECT * FROM posts WHERE status='approved' ORDER BY created_at DESC";

    const { results } = await env.DB.prepare(q).all();

    const posts = (results || [])
      .map((p) => ({
        ...p,
        cat: p.cat === "\u05D9\u05D32"
          ? "\u05D9\u05D3 \u05E9\u05E0\u05D9\u05D9\u05D4"
          : p.cat
      }))
      .filter((p) => ALLOWED_CATEGORIES.has(p.cat));

    return json({ posts });
  }

  if (req.method === "POST") {
    const b = await body(req);
    const cat = String(b.cat || "").trim();
    const title = String(b.title || "").trim().slice(0, 120);
    const desc = String(b.desc || "").trim().slice(0, 1500);

    if (!ALLOWED_CATEGORIES.has(cat)) {
      return fail("\u05E7\u05D8\u05D2\u05D5\u05E8\u05D9\u05D4 \u05DC\u05D0 \u05DE\u05D0\u05D5\u05E9\u05E8\u05EA", 400);
    }

    if (!title || !desc) {
      return fail("\u05D7\u05E1\u05E8\u05D9\u05DD \u05E4\u05E8\u05D8\u05D9 \u05DE\u05D5\u05D3\u05E2\u05D4", 400);
    }

    if (
      cat === "\u05D0\u05D9\u05E8\u05D5\u05E2\u05D9\u05DD" &&
      (!u || !MANAGERS.includes(u.role))
    ) {
      return fail(
        "\u05E4\u05E8\u05E1\u05D5\u05DD \u05D0\u05D9\u05E8\u05D5\u05E2\u05D9\u05DD \u05DE\u05EA\u05D1\u05E6\u05E2 \u05D3\u05E8\u05DA \u05D4\u05E0\u05D4\u05DC\u05EA \u05D4\u05D0\u05EA\u05E8",
        403
      );
    }

    if (cat === "\u05D7\u05E0\u05D5\u05D9\u05D5\u05EA") {
      const shopSetting = await env.DB.prepare(
        "SELECT value FROM settings WHERE key='shop_free'"
      ).first();

      if (shopSetting?.value === "0") {
        return fail(
          "\u05E4\u05E8\u05E1\u05D5\u05DD \u05DE\u05D5\u05D3\u05E2\u05D5\u05EA \u05D1\u05D7\u05E0\u05D5\u05D9\u05D5\u05EA \u05D0\u05D9\u05E0\u05D5 \u05E4\u05EA\u05D5\u05D7 \u05DB\u05E8\u05D2\u05E2 \u05D1\u05D7\u05D9\u05E0\u05DD",
          402
        );
      }
    }

    const id2 = String(b.id || crypto.randomUUID()).slice(0, 100);

    // Image uploads are disabled; keep the legacy database field empty for schema compatibility.
    const item = {
      id: id2,
      cat,
      title,
      desc,
      age: String(b.age || "").slice(0, 60),
      salary: String(b.salary || "").slice(0, 80),
      location: String(b.location || "").slice(0, 120),
      phone: String(b.phone || "").replace(/[^\d+]/g, "").slice(0, 40),
      author: String(u?.username || "\u05D0\u05D5\u05E8\u05D7").slice(0, 80),
      image_url: "",
      status: cat === "\u05D3\u05E8\u05D5\u05E9\u05D9\u05DD" ? "approved" : "pending",
      promo: 0,
      date: new Date().toLocaleDateString("he-IL"),
      created_at: Date.now()
    };

    await env.DB.prepare(
      "INSERT INTO posts(id,cat,title,desc,age,salary,location,phone,author,status,promo,date,created_at,image_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(
      item.id,
      item.cat,
      item.title,
      item.desc,
      item.age,
      item.salary,
      item.location,
      item.phone,
      item.author,
      item.status,
      item.promo,
      item.date,
      item.created_at,
      item.image_url
    ).run();

    return json({ ok: true, post: item }, 201);
  }

  const id = decodeURIComponent(url.pathname.split("/").pop() || "");

  if (!u || ![
    "manager",
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  if (req.method === "DELETE") {
    await env.DB.prepare(
      "DELETE FROM posts WHERE id=?"
    ).bind(id).run();

    await audit(env, u, "post_delete", id);
    return json({ ok: true });
  }

  if (req.method === "PATCH") {
    const b = await body(req);

    const current = await env.DB.prepare(
      "SELECT * FROM posts WHERE id=?"
    ).bind(id).first();

    if (!current) {
      return fail("\u05D4\u05DE\u05D5\u05D3\u05E2\u05D4 \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0\u05D4", 404);
    }

    const status = b.status === void 0
      ? current.status
      : String(b.status).slice(0, 20);

    const promo = b.promo === void 0
      ? current.promo
      : b.promo ? 1 : 0;

    if (!["pending", "approved"].includes(status)) {
      return fail("\u05E1\u05D8\u05D8\u05D5\u05E1 \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF", 400);
    }

    await env.DB.prepare(
      "UPDATE posts SET status=?,promo=? WHERE id=?"
    ).bind(status, promo, id).run();

    await audit(
      env,
      u,
      "post_update",
      JSON.stringify({ id, status, promo })
    );

    return json({ ok: true });
  }

  return fail("\u05E9\u05D9\u05D8\u05EA \u05D1\u05E7\u05E9\u05D4 \u05DC\u05D0 \u05E0\u05EA\u05DE\u05DB\u05EA", 405);
}
__name(postsApi, "postsApi");

async function techDiagnose(req, env, u) {
  if (!u || ![
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  const [
    usersCount,
    postsCount,
    catsCount,
    pending
  ] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) c FROM users").first(),
    env.DB.prepare("SELECT COUNT(*) c FROM posts").first(),
    env.DB.prepare("SELECT COUNT(*) c FROM categories").first(),
    env.DB.prepare("SELECT COUNT(*) c FROM posts WHERE status='pending'").first()
  ]);

  return json({
    summary: `\u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD: ${usersCount?.c || 0}, \u05DE\u05D5\u05D3\u05E2\u05D5\u05EA: ${postsCount?.c || 0}, \u05E7\u05D8\u05D2\u05D5\u05E8\u05D9\u05D5\u05EA: ${catsCount?.c || 0}, \u05DE\u05DE\u05EA\u05D9\u05E0\u05D5\u05EA: ${pending?.c || 0}`
  });
}
__name(techDiagnose, "techDiagnose");

async function techAsk(req, env, u) {
  if (!u || ![
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  const b = await body(req);
  const msg = String(b.message || "").trim().slice(0, 500);

  return json({
    reply: msg
      ? `\u05E7\u05D9\u05D1\u05DC\u05EA\u05D9 \u05D0\u05EA \u05D4\u05D1\u05E7\u05E9\u05D4. \u05DB\u05E8\u05D2\u05E2 \u05D0\u05E4\u05E9\u05E8 \u05DC\u05D1\u05E6\u05E2 \u05D0\u05D1\u05D7\u05D5\u05DF \u05D5\u05E4\u05E2\u05D5\u05DC\u05D5\u05EA \u05DE\u05D5\u05E8\u05E9\u05D5\u05EA \u05D1\u05DC\u05D1\u05D3. \u05D4\u05D1\u05E7\u05E9\u05D4 \u05E9\u05E0\u05D1\u05D3\u05E7\u05D4: ${msg}`
      : "\u05DB\u05EA\u05D5\u05D1 \u05DE\u05D4 \u05DC\u05D1\u05D3\u05D5\u05E7."
  });
}
__name(techAsk, "techAsk");

async function ownerAi(req, env, u) {
  if (!u || ![
    "manager",
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  const b = await body(req);
  const msg = String(b.message || "").trim().slice(0, 1000);

  return json({
    reply: msg
      ? `\u05E7\u05D9\u05D1\u05DC\u05EA\u05D9. \u05D0\u05E4\u05E9\u05E8 \u05DC\u05D4\u05E4\u05D5\u05DA \u05D0\u05EA \u05D4\u05D1\u05E7\u05E9\u05D4 \u05DC\u05DE\u05E9\u05D9\u05DE\u05D4 \u05DE\u05E1\u05D5\u05D3\u05E8\u05EA \u05D0\u05D5 \u05DC\u05DE\u05E4\u05E8\u05D8. \u05D4\u05D1\u05E7\u05E9\u05D4: ${msg}`
      : "\u05DB\u05EA\u05D5\u05D1 \u05DC\u05D9 \u05DE\u05D4 \u05D0\u05EA\u05D4 \u05E6\u05E8\u05D9\u05DA.",
    quick: [
      "\u05EA\u05DB\u05D9\u05DF \u05DE\u05E9\u05D9\u05DE\u05D4",
      "\u05EA\u05DB\u05D9\u05DF \u05DE\u05E4\u05E8\u05D8 \u05DC\u05DC\u05E7\u05D5\u05D7"
    ]
  });
}
__name(ownerAi, "ownerAi");

async function developerAi(req, env, u) {
  if (!u || ![
    "super_manager",
    "super_admin"
  ].includes(u.role)) {
    return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
  }

  return json({
    action: "diagnose",
    reply: "\u05DB\u05DC\u05D9 \u05D4\u05DE\u05E4\u05EA\u05D7 \u05D6\u05DE\u05D9\u05DF \u05DC\u05D0\u05D1\u05D7\u05D5\u05DF \u05D1\u05E1\u05D9\u05E1\u05D9. \u05E2\u05D3\u05D9\u05D9\u05DF \u05DC\u05D0 \u05D1\u05D5\u05E6\u05E2 \u05E9\u05D9\u05E0\u05D5\u05D9 \u05D1\u05E7\u05D5\u05D3."
  });
}
__name(developerAi, "developerAi");

async function board(req, env, u) {
  const b = await body(req);
  const msg = String(b.message || "").trim().slice(0, 1000);

  if (!msg) {
    return json({
      stage: "chat",
      reply: "\u05E9\u05DC\u05D5\u05DD! \u05D0\u05E0\u05D9 \u05D1\u05D5\u05E8\u05D3. \u05D1\u05DE\u05D4 \u05D0\u05D5\u05DB\u05DC \u05DC\u05E2\u05D6\u05D5\u05E8?",
      needsApproval: false
    });
  }

  if (msg === "\u05D0\u05D9\u05E9\u05D5\u05E8") {
    if (!u || u.role !== "super_admin") {
      return fail("\u05E8\u05E7 \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9 \u05D9\u05DB\u05D5\u05DC \u05DC\u05D0\u05E9\u05E8 \u05D1\u05D9\u05E6\u05D5\u05E2", 403);
    }

    const pending = await env.DB.prepare(
      "SELECT id,message,plan_json FROM board_tasks WHERE user_id=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1"
    ).bind(u.id, Date.now()).first();

    if (!pending) {
      return json({
        stage: "chat",
        reply: "\u05D0\u05D9\u05DF \u05DE\u05E9\u05D9\u05DE\u05D4 \u05E9\u05DE\u05DE\u05EA\u05D9\u05E0\u05D4 \u05DC\u05D0\u05D9\u05E9\u05D5\u05E8.",
        needsApproval: false
      });
    }

    const p2 = JSON.parse(pending.plan_json || "{}");
    let result;

    if (p2.kind === "add_category") {
      const name = String(p2.name || "").trim().slice(0, 40);

      if (!name || !ALLOWED_CATEGORIES.has(name)) {
        return json({
          stage: "blocked",
          reply: "\u05D0\u05E4\u05E9\u05E8 \u05DC\u05D4\u05D5\u05E1\u05D9\u05E3 \u05E8\u05E7 \u05D0\u05EA \u05D4\u05E7\u05D8\u05D2\u05D5\u05E8\u05D9\u05D5\u05EA \u05D4\u05E7\u05D1\u05D5\u05E2\u05D5\u05EA \u05E9\u05DC \u05D4\u05D0\u05EA\u05E8.",
          needsApproval: false
        }, 422);
      }

      const existing = await env.DB.prepare(
        "SELECT name,icon,color FROM categories WHERE name=?"
      ).bind(name).first();

      if (existing) {
        result = {
          reply: "\u05D4\u05E7\u05D8\u05D2\u05D5\u05E8\u05D9\u05D4 \u05DB\u05D1\u05E8 \u05E7\u05D9\u05D9\u05DE\u05EA.",
          action: "add_category"
        };
      } else {
        const palette = [
          "#0ea5e9",
          "#16a34a",
          "#f59e0b",
          "#8b5cf6",
          "#ef4444",
          "#0891b2"
        ];

        const count = await env.DB.prepare(
          "SELECT COUNT(*) c FROM categories"
        ).first();

        const color = palette[Number(count?.c || 0) % palette.length];

        await env.DB.prepare(
          "INSERT INTO categories(name,icon,color) VALUES(?,?,?)"
        ).bind(
          name,
          String(p2.icon || "\u{1F3F7}\uFE0F"),
          color
        ).run();

        result = {
          reply: `\u05D4\u05E7\u05D8\u05D2\u05D5\u05E8\u05D9\u05D4 "${name}" \u05E0\u05D5\u05E1\u05E4\u05D4.`,
          action: "add_category"
        };
      }
    } else if (p2.kind === "set_announcement") {
      const announcement = String(p2.text || "").trim().slice(0, 300);

      await env.DB.prepare(
        "INSERT INTO settings(key,value) VALUES('ann',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).bind(announcement).run();

      result = {
        reply: "\u05D4\u05D5\u05D3\u05E2\u05EA \u05D3\u05E3 \u05D4\u05D1\u05D9\u05EA \u05E2\u05D5\u05D3\u05DB\u05E0\u05D4.",
        action: "set_announcement"
      };
    } else if (p2.kind === "diagnose") {
      const posts = await env.DB.prepare(
        "SELECT COUNT(*) c FROM posts"
      ).first();

      result = {
        reply: `\u05D4\u05D0\u05D1\u05D7\u05D5\u05DF \u05D4\u05E1\u05EA\u05D9\u05D9\u05DD. \u05DE\u05E1\u05E4\u05E8 \u05D4\u05DE\u05D5\u05D3\u05E2\u05D5\u05EA \u05D1\u05DE\u05E1\u05D3 \u05D4\u05E0\u05EA\u05D5\u05E0\u05D9\u05DD: ${posts?.c || 0}.`,
        action: "diagnose"
      };
    } else {
      return json({
        stage: "blocked",
        reply: "\u05E1\u05D5\u05D2 \u05D4\u05DE\u05E9\u05D9\u05DE\u05D4 \u05D4\u05D6\u05D4 \u05D0\u05D9\u05E0\u05D5 \u05E0\u05EA\u05DE\u05DA \u05DC\u05D1\u05D9\u05E6\u05D5\u05E2 \u05D0\u05D5\u05D8\u05D5\u05DE\u05D8\u05D9.",
        needsApproval: false
      }, 422);
    }

    await env.DB.prepare(
      "UPDATE board_tasks SET status='executed' WHERE id=?"
    ).bind(pending.id).run();

    await audit(env, u, "board_execute", pending.id);

    return json({
      ...result,
      stage: "executed",
      taskId: pending.id,
      needsApproval: false
    });
  }

  let p = null;

  const addMatch = msg.match(
    /(?:תוסיף|הוסף|צור|פתח)\s+(?:קטגור(?:יה|יית)|קטגוריה)\s+["״']?([^"״'\n]+?)["״']?(?:\s+עם\s+(.+))?$/i
  );

  if (addMatch) {
    const name = String(addMatch[1] || "").trim().slice(0, 40);

    if (name) {
      p = {
        kind: "add_category",
        name,
        icon: String(addMatch[2] || "\u{1F3F7}\uFE0F").trim().slice(0, 8),
        steps: [
          "\u05D1\u05D3\u05D9\u05E7\u05EA \u05D4\u05E7\u05D8\u05D2\u05D5\u05E8\u05D9\u05D4",
          "\u05D4\u05E6\u05D2\u05EA \u05EA\u05D5\u05DB\u05E0\u05D9\u05EA",
          "\u05D4\u05DE\u05EA\u05E0\u05D4 \u05DC\u05D0\u05D9\u05E9\u05D5\u05E8 \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9"
        ]
      };
    }
  }

  const annMatch = msg.match(
    /(?:שנה|עדכן|החלף)\s+(?:את\s+)?(?:הודעת\s+(?:דף\s*הבית|המערכת)|הודעה\s+ראשית)\s*(?:ל|:|-)\s*(.+)$/i
  );

  if (!p && annMatch) {
    p = {
      kind: "set_announcement",
      text: String(annMatch[1] || "").trim().slice(0, 300),
      steps: [
        "\u05D4\u05DB\u05E0\u05EA \u05D4\u05D5\u05D3\u05E2\u05EA \u05D3\u05E3 \u05D4\u05D1\u05D9\u05EA",
        "\u05D4\u05E6\u05D2\u05EA \u05EA\u05D5\u05DB\u05E0\u05D9\u05EA",
        "\u05D4\u05DE\u05EA\u05E0\u05D4 \u05DC\u05D0\u05D9\u05E9\u05D5\u05E8 \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9"
      ]
    };
  }

  if (!p && /בדוק|אבחון|באג|תקלה|סטטוס/.test(msg)) {
    p = {
      kind: "diagnose",
      steps: [
        "\u05D1\u05D3\u05D9\u05E7\u05EA \u05E0\u05EA\u05D5\u05E0\u05D9 \u05D4\u05D0\u05EA\u05E8",
        "\u05D4\u05E6\u05D2\u05EA \u05EA\u05D5\u05E6\u05D0\u05D5\u05EA \u05D4\u05D0\u05D1\u05D7\u05D5\u05DF"
      ]
    };
  }

  if (!p) {
    return json({
      stage: "chat",
      reply: `\u05E7\u05D9\u05D1\u05DC\u05EA\u05D9 \u05D0\u05EA \u05D4\u05D1\u05E7\u05E9\u05D4 \u05E9\u05DC\u05DA:

"${msg}"

\u05D0\u05E4\u05E9\u05E8 \u05DC\u05D4\u05DE\u05E9\u05D9\u05DA \u05DC\u05EA\u05DB\u05E0\u05DF \u05D0\u05EA \u05D4\u05DE\u05E9\u05D9\u05DE\u05D4. \u05DC\u05D0 \u05D1\u05D5\u05E6\u05E2 \u05E9\u05D9\u05E0\u05D5\u05D9 \u05D1\u05D0\u05EA\u05E8.`,
      needsApproval: false,
      action: "chat"
    });
  }

  if (!u) {
    return json({
      stage: "planned",
      taskId: null,
      reply: "\u05D4\u05DB\u05E0\u05EA\u05D9 \u05EA\u05D5\u05DB\u05E0\u05D9\u05EA \u05D1\u05DC\u05D1\u05D3. \u05DB\u05D3\u05D9 \u05DC\u05D1\u05E6\u05E2 \u05E9\u05D9\u05E0\u05D5\u05D9 \u05D1\u05E4\u05D5\u05E2\u05DC \u05E6\u05E8\u05D9\u05DA \u05DC\u05D4\u05EA\u05D7\u05D1\u05E8 \u05DB\u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9.",
      action: "preview_change",
      needsApproval: false,
      requiresAdmin: true,
      plan: { steps: p.steps }
    });
  }

  if (u.role !== "super_admin") {
    return fail("\u05E8\u05E7 \u05DE\u05E0\u05D4\u05DC \u05E8\u05D0\u05E9\u05D9 \u05D9\u05DB\u05D5\u05DC \u05DC\u05EA\u05DB\u05E0\u05DF \u05D5\u05DC\u05D0\u05E9\u05E8 \u05E9\u05D9\u05E0\u05D5\u05D9\u05D9\u05DD", 403);
  }

  const id = crypto.randomUUID();
  const expires = Date.now() + 10 * 60 * 1e3;

  await env.DB.prepare(
    "INSERT INTO board_tasks(id,user_id,message,plan_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)"
  ).bind(
    id,
    u.id,
    msg,
    JSON.stringify(p),
    "pending",
    Date.now(),
    expires
  ).run();

  await audit(env, u, "board_plan", id);

  return json({
    stage: "planned",
    taskId: id,
    reply: "\u05D4\u05DB\u05E0\u05EA\u05D9 \u05EA\u05D5\u05DB\u05E0\u05D9\u05EA. \u05E2\u05D3\u05D9\u05D9\u05DF \u05DC\u05D0 \u05D1\u05D5\u05E6\u05E2 \u05E9\u05D9\u05E0\u05D5\u05D9. \u05DB\u05D3\u05D9 \u05DC\u05D0\u05E9\u05E8, \u05DB\u05EA\u05D5\u05D1: \u05D0\u05D9\u05E9\u05D5\u05E8",
    action: "preview_change",
    needsApproval: true,
    plan: { steps: p.steps },
    expiresAt: expires
  });
}
__name(board, "board");

async function health(env) {
  const checks = {
    database: false,
    assets: false
  };

  try {
    await env.DB.prepare("SELECT 1 AS ok").first();
    checks.database = true;
  } catch {
  }

  checks.assets = !!env.ASSETS;

  return json({
    ok: checks.database,
    service: "karnei-shomron",
    checks
  }, checks.database ? 200 : 503);
}
__name(health, "health");

var index_default = {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = req.method.toUpperCase();

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...H,
          "access-control-allow-origin": url.origin,
          "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
          "access-control-allow-headers": "Content-Type,Authorization",
          "access-control-max-age": "86400"
        }
      });
    }

    try {
      if (path === "/api/health" && method === "GET") {
        return await health(env);
      }

      if (path === "/api/admin/login" && method === "POST") {
        return await adminLogin(req, env);
      }

      if (path === "/api/auth/me" && method === "GET") {
        return await authMe(req, env);
      }

      const u = await user(env, req);

      if (path === "/api/admin/users" && method === "GET") {
        return await adminUsers(req, env, u);
      }

      const userMatch = path.match(/^\/api\/admin\/users\/([^/]+)$/);

      if (userMatch && method === "PATCH") {
        return await adminUserPatch(
          req,
          env,
          u,
          decodeURIComponent(userMatch[1])
        );
      }

      if (path === "/api/posts") {
        return await postsApi(req, env, u, url);
      }

      if (path.startsWith("/api/posts/")) {
        return await postsApi(req, env, u, url);
      }

      if (path === "/api/ai/tech/diagnose" && method === "POST") {
        return await techDiagnose(req, env, u);
      }

      if (path === "/api/ai/tech" && method === "POST") {
        return await techAsk(req, env, u);
      }

      if (path === "/api/ai/developer" && method === "POST") {
        return await developerAi(req, env, u);
      }

      if (path === "/api/ai/owner" && method === "POST") {
        return await ownerAi(req, env, u);
      }

      if (
        (path === "/api/ai/board" || path === "/api/board/message") &&
        method === "POST"
      ) {
        return await board(req, env, u);
      }

      if (path === "/api/board/tasks" && method === "GET") {
        if (!u || u.role !== "super_admin") {
          return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
        }

        const { results } = await env.DB.prepare(
          "SELECT id,message,status,created_at,expires_at FROM board_tasks WHERE user_id=? ORDER BY created_at DESC LIMIT 50"
        ).bind(u.id).all();

        return json({ tasks: results || [] });
      }

      if (path === "/api/config" && method === "GET") {
        const rows = await env.DB.prepare(
          "SELECT key,value FROM settings"
        ).all();

        const config = {};

        for (const r of rows.results || []) {
          config[r.key] = r.value;
        }

        return json({ config });
      }

      if (path === "/api/config" && method === "PATCH") {
        if (!u || !MANAGERS.includes(u.role)) {
          return fail("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4", 403);
        }

        const b = await body(req);

        if (typeof b.shop_free === "boolean") {
          await env.DB.prepare(
            "INSERT INTO settings(key,value) VALUES('shop_free',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
          ).bind(b.shop_free ? "1" : "0").run();
        }

        await audit(env, u, "config_update", "site settings");

        return json({ ok: true });
      }

      if (path.startsWith("/api/")) {
        return fail("\u05E0\u05EA\u05D9\u05D1 API \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0", 404);
      }

      if (env.ASSETS) {
        const assetUrl = new URL(req.url);

        if (path === "/") {
          assetUrl.pathname = "/index.html";
        }

        return env.ASSETS.fetch(
          new Request(assetUrl, req)
        );
      }

      return fail("\u05D4\u05D0\u05EA\u05E8 \u05DC\u05D0 \u05D4\u05D5\u05D2\u05D3\u05E8", 503);
    } catch (e) {
      console.error("Worker error:", e);

      return json({
        error: "\u05E9\u05D2\u05D9\u05D0\u05D4 \u05E4\u05E0\u05D9\u05DE\u05D9\u05EA \u05D1\u05E9\u05E8\u05EA",
        path
      }, 500);
    }
  }
};

export {
  index_default as default
};
