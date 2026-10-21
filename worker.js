/* JARVIS Worker, Phase 3B.
   - Everything NOT under /api/ is the original Gemini endpoint (unchanged behaviour).
   - /api/* is the authenticated Social Hub API backed by D1 (binding "DB").
   - Phase 3B never contacts Facebook, Instagram, WhatsApp, TikTok or YouTube. */

const MAX_BODY = 20000, SESSION_TTL = 12 * 3600;
const PLATFORMS = ["facebook", "instagram", "whatsapp", "tiktok", "youtube"];
const COOKIE = "__Host-jv";
const NEED = {
  social_posts: ["id", "user_id", "text", "title", "hashtags", "platforms", "media", "status", "scheduled_at", "created_at", "updated_at"],
  audit_logs: ["id", "user_id", "action", "post_id", "outcome", "detail", "created_at"],
  rate_limits: ["key", "window_start", "count"]
};
const enc = new TextEncoder();

class HttpErr extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }

/* ================= original /ai endpoint (unchanged behaviour) ================= */
async function legacyAI(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  const okOrigin = allowed.includes(origin);
  const cors = {
    "Access-Control-Allow-Origin": okOrigin ? origin : "null",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
  const json = (o, s = 200) => new Response(JSON.stringify(o),
    { status: s, headers: { ...cors, "Content-Type": "application/json" } });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  if (!okOrigin) return json({ error: "Origin not allowed", code: "origin" }, 403);
  if (!env.GEMINI_API_KEY || !env.GEMINI_MODEL)
    return json({ error: "Worker is missing GEMINI_API_KEY or GEMINI_MODEL", code: "config" }, 500);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Bad JSON", code: "bad_request" }, 400); }
  const contents = [];
  for (const m of (Array.isArray(body.messages) ? body.messages : []).slice(-10)) {
    const role = m.role === "assistant" ? "model" : "user";
    const text = String(m.text || "").slice(0, 2000);
    if (!text) continue;
    const last = contents[contents.length - 1];
    if (last && last.role === role) last.parts[0].text += "\n" + text;
    else if (last || role === "user") contents.push({ role, parts: [{ text }] });
  }
  if (!contents.length || contents[contents.length - 1].role !== "user")
    return json({ error: "No user message", code: "bad_request" }, 400);
  const url = "https://generativelanguage.googleapis.com/v1beta/models/" +
    encodeURIComponent(env.GEMINI_MODEL) + ":generateContent";
  let r;
  try {
    r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: "You are JARVIS, a concise, helpful personal assistant. Reply in the user's language (English or Nepali). Keep answers short enough to be spoken aloud." }] },
        contents,
        generationConfig: { maxOutputTokens: 400 }
      })
    });
  } catch { return json({ error: "Could not reach Gemini", code: "upstream" }, 502); }
  if (r.status === 429) return json({ error: "Free tier limit reached", code: "limit" }, 429);
  if (!r.ok) return json({ error: "Gemini returned " + r.status + " (check key and model name)", code: "upstream" }, 502);
  const d = await r.json();
  const reply = (d.candidates?.[0]?.content?.parts || []).map(p => p.text || "").join("").trim();
  if (!reply) return json({ error: "Empty reply", code: "upstream" }, 502);
  return json({ reply });
}

/* ================= helpers ================= */
const b64u = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
async function hmac(env, data) {
  const k = await crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
function teq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
async function sameSecret(env, a, b) { return teq(await hmac(env, "pw:" + a), await hmac(env, "pw:" + b)); }

function users(env) {
  const m = new Map();
  try {
    const o = JSON.parse(env.AUTH_USERS || "{}");
    for (const [u, p] of Object.entries(o))
      if (/^[A-Za-z0-9_.-]{1,32}$/.test(u) && typeof p === "string" && p.length >= 12) m.set(u, p);
  } catch { /* treated as not configured */ }
  return m;
}
function missing(env) {
  const out = [];
  if (!env.DB) out.push("DB");
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) out.push("SESSION_SECRET");
  if (users(env).size === 0) out.push("AUTH_USERS");
  if (!env.ALLOWED_ORIGIN) out.push("ALLOWED_ORIGIN");
  return out;
}
async function makeToken(env, sub) {
  const iat = Math.floor(Date.now() / 1000);
  const p = b64u(enc.encode(JSON.stringify({ sub, iat, exp: iat + SESSION_TTL })));
  return p + "." + b64u(await hmac(env, "v1." + p));
}
async function readSession(request, env) {
  const c = (request.headers.get("Cookie") || "").split(";").map(s => s.trim()).find(s => s.startsWith(COOKIE + "="));
  if (!c) return null;
  const [p, sig] = c.slice(COOKIE.length + 1).split(".");
  if (!p || !sig) return null;
  try {
    if (!teq(await hmac(env, "v1." + p), unb64u(sig))) return null;
    const o = JSON.parse(new TextDecoder().decode(unb64u(p)));
    if (!o.exp || o.exp < Date.now() / 1000) return null;
    return users(env).has(o.sub) ? o.sub : null;
  } catch { return null; }
}
const setCookie = (v, age) => `${COOKIE}=${v}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=${age}`;

/* Atomic fixed-window rate limit: one INSERT ... ON CONFLICT ... RETURNING statement. */
async function rateLimit(env, key, limit, windowSec) {
  const w = Math.floor(Date.now() / 1000 / windowSec) * windowSec;
  const row = await env.DB.prepare(
    "INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1) " +
    "ON CONFLICT(key) DO UPDATE SET count = CASE WHEN window_start = excluded.window_start THEN count + 1 ELSE 1 END, " +
    "window_start = excluded.window_start RETURNING count").bind(key, w).first();
  return { ok: row.count <= limit, retry: w + windowSec - Math.floor(Date.now() / 1000) };
}
let schemaOkUntil = 0;
async function schemaProblems(env) {
  if (Date.now() < schemaOkUntil) return [];
  const bad = [];
  for (const [t, cols] of Object.entries(NEED)) { // table names are constants, never user input
    const r = await env.DB.prepare(`PRAGMA table_info(${t})`).all();
    const have = new Set((r.results || []).map(x => x.name));
    const m = cols.filter(c => !have.has(c));
    if (m.length) bad.push(`${t}: missing ${have.size ? m.join(", ") : "table"}`);
  }
  if (!bad.length) schemaOkUntil = Date.now() + 60000;
  return bad;
}
async function audit(env, user, action, postId, outcome, detail) {
  try {
    await env.DB.prepare("INSERT INTO audit_logs (id, user_id, action, post_id, outcome, detail, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)")
      .bind(crypto.randomUUID(), user, action, postId || null, outcome, detail ? String(detail).slice(0, 200) : null, new Date().toISOString()).run();
  } catch { console.error("audit_write_failed"); }
}
async function readJson(request) {
  if (!(request.headers.get("Content-Type") || "").toLowerCase().startsWith("application/json")) throw new HttpErr(415, "content_type_must_be_json");
  if (+request.headers.get("Content-Length") > MAX_BODY) throw new HttpErr(413, "body_too_large");
  const t = await request.text();
  if (t.length > MAX_BODY) throw new HttpErr(413, "body_too_large");
  let o; try { o = JSON.parse(t); } catch { throw new HttpErr(400, "malformed_json"); }
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new HttpErr(400, "json_object_required");
  return o;
}
function cleanPost(o) {
  const ok = ["text", "title", "hashtags", "platforms", "media"];
  for (const k of Object.keys(o)) if (!ok.includes(k)) throw new HttpErr(400, "unknown_field");
  const out = {};
  for (const [k, max] of [["text", 5000], ["title", 100], ["hashtags", 500]]) {
    if (o[k] === undefined) continue;
    if (typeof o[k] !== "string" || o[k].length > max) throw new HttpErr(400, "invalid_" + k);
    out[k] = o[k];
  }
  if (o.platforms !== undefined) {
    if (!Array.isArray(o.platforms) || o.platforms.length > 5 || !o.platforms.every(p => PLATFORMS.includes(p))) throw new HttpErr(400, "invalid_platforms");
    out.platforms = [...new Set(o.platforms)];
  }
  if (o.media !== undefined) {
    if (!Array.isArray(o.media) || o.media.length > 10) throw new HttpErr(400, "invalid_media");
    out.media = o.media.map(m => {
      if (!m || typeof m.name !== "string" || m.name.length > 100 || typeof m.type !== "string" || m.type.length > 100 ||
        !/^[\w.+-]+\/[\w.+-]+$/.test(m.type) || !Number.isInteger(m.size) || m.size < 0 || m.size > 5e9) throw new HttpErr(400, "invalid_media");
      return { name: m.name, type: m.type, size: m.size };
    });
  }
  return out;
}
const hasContent = p => !!((p.text || "").trim() || (p.title || "").trim() || (p.media || []).length);
const shape = r => ({
  id: r.id, text: r.text, title: r.title, hashtags: r.hashtags, platforms: JSON.parse(r.platforms || "[]"),
  media: JSON.parse(r.media || "[]"), status: r.status, scheduledAt: r.scheduled_at, createdAt: r.created_at, updatedAt: r.updated_at
});

/* ================= Social API ================= */
async function social(request, env, url) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  const okOrigin = allowed.includes(origin);
  const cors = { "Vary": "Origin" };
  if (okOrigin) Object.assign(cors, {
    "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Requested-With"
  });
  const send = (o, s = 200, extra = {}) => new Response(JSON.stringify(o), {
    status: s, headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra }
  });
  const m = request.method, path = url.pathname.replace(/\/+$/, "");
  if (m === "OPTIONS") return okOrigin ? new Response(null, { status: 204, headers: cors }) : send({ error: "origin_not_allowed" }, 403);
  if (!okOrigin) return send({ error: "origin_not_allowed" }, 403);
  if (m !== "GET" && request.headers.get("X-Requested-With") !== "jarvis") return send({ error: "csrf_header_required" }, 403);
  const miss = missing(env);
  if (miss.length) return send({ error: "not_configured", missing: miss }, 503);
  let user = null;
  try {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const bad = await schemaProblems(env); // fail closed before touching any data
    if (bad.length) {
      if (path === "/api/health" && m === "GET") {
        user = await readSession(request, env);
        return send({ ok: false, db: true, schema: "mismatch", ...(user ? { problems: bad } : {}) }, 503);
      }
      return send({ error: "schema_mismatch" }, 503);
    }
    const g = await rateLimit(env, "ip:" + ip, 120, 60);
    if (!g.ok) return send({ error: "rate_limited" }, 429, { "Retry-After": String(g.retry) });
    if (path === "/api/health" && m === "GET") return send({ ok: true, db: true, schema: "ok" });

    if (path === "/api/login") {
      if (m !== "POST") throw new HttpErr(405, "method_not_allowed");
      const l = await rateLimit(env, "login:" + ip, 10, 900);
      if (!l.ok) return send({ error: "rate_limited" }, 429, { "Retry-After": String(l.retry) });
      const b = await readJson(request);
      if (typeof b.username !== "string" || !/^[A-Za-z0-9_.-]{1,32}$/.test(b.username) || typeof b.passphrase !== "string" || !b.passphrase || b.passphrase.length > 200) throw new HttpErr(400, "invalid_credentials_format");
      const us = users(env), known = us.has(b.username);
      const good = await sameSecret(env, b.passphrase, known ? us.get(b.username) : "x".repeat(40)) && known;
      if (!good) { if (known) await audit(env, b.username, "login", null, "denied"); return send({ error: "invalid_credentials" }, 401); }
      await audit(env, b.username, "login", null, "ok");
      return send({ user: b.username }, 200, { "Set-Cookie": setCookie(await makeToken(env, b.username), SESSION_TTL) });
    }

    user = await readSession(request, env);
    if (!user) return send({ error: "unauthenticated" }, 401);
    const u = await rateLimit(env, "u:" + user, 60, 60);
    if (!u.ok) { await audit(env, user, "rate_limit", null, "denied"); return send({ error: "rate_limited" }, 429, { "Retry-After": String(u.retry) }); }

    if (path === "/api/me" && m === "GET") return send({ user });
    if (path === "/api/logout" && m === "POST") { await audit(env, user, "logout", null, "ok"); return send({ ok: true }, 200, { "Set-Cookie": setCookie("", 0) }); }

    if (path === "/api/audit") {
      if (m !== "GET") throw new HttpErr(405, "method_not_allowed");
      const lim = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 100);
      const r = await env.DB.prepare("SELECT id, action, post_id, outcome, detail, created_at FROM audit_logs WHERE user_id = ?1 ORDER BY created_at DESC LIMIT ?2").bind(user, lim).all();
      return send({ entries: (r.results || []).map(x => ({ id: x.id, action: x.action, postId: x.post_id, outcome: x.outcome, detail: x.detail, createdAt: x.created_at })) });
    }

    if (path === "/api/posts") {
      if (m === "GET") {
        const r = await env.DB.prepare("SELECT * FROM social_posts WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 200").bind(user).all();
        return send({ posts: (r.results || []).map(shape) });
      }
      if (m === "POST") {
        const p = { text: "", title: "", hashtags: "", platforms: [], media: [], ...cleanPost(await readJson(request)) };
        if (!hasContent(p)) throw new HttpErr(400, "empty_post");
        const id = crypto.randomUUID(), now = new Date().toISOString();
        await env.DB.prepare("INSERT INTO social_posts (id, user_id, text, title, hashtags, platforms, media, status, scheduled_at, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'draft',NULL,?8,?8)")
          .bind(id, user, p.text, p.title, p.hashtags, JSON.stringify(p.platforms), JSON.stringify(p.media), now).run();
        await audit(env, user, "create", id, "ok");
        return send({ post: { id, ...p, status: "draft", scheduledAt: null, createdAt: now, updatedAt: now } }, 201);
      }
      throw new HttpErr(405, "method_not_allowed");
    }

    const mm = path.match(/^\/api\/posts\/([0-9a-f-]{36})(?:\/(schedule|cancel))?$/);
    if (mm) {
      const [, id, sub] = mm;
      const row = await env.DB.prepare("SELECT * FROM social_posts WHERE id = ?1").bind(id).first();
      if (!row) throw new HttpErr(404, "not_found");
      if (row.user_id !== user) { await audit(env, user, "access", id, "denied", "not_owner"); throw new HttpErr(403, "forbidden"); }
      const now = new Date().toISOString();

      if (!sub && m === "GET") return send({ post: shape(row) });
      if (!sub && m === "PATCH") {
        if (row.status !== "draft") { await audit(env, user, "update", id, "denied", "not_draft"); throw new HttpErr(409, "only_drafts_can_be_edited"); }
        const c = cleanPost(await readJson(request)), cur = shape(row), n = { ...cur, ...c };
        if (!hasContent(n)) throw new HttpErr(400, "empty_post");
        const r = await env.DB.prepare("UPDATE social_posts SET text=?1, title=?2, hashtags=?3, platforms=?4, media=?5, updated_at=?6 WHERE id=?7 AND user_id=?8 AND status='draft'")
          .bind(n.text, n.title, n.hashtags, JSON.stringify(n.platforms), JSON.stringify(n.media), now, id, user).run();
        if (!r.meta.changes) throw new HttpErr(409, "state_changed");
        await audit(env, user, "update", id, "ok");
        return send({ post: { ...n, updatedAt: now } });
      }
      if (!sub && m === "DELETE") {
        const r = await env.DB.prepare("DELETE FROM social_posts WHERE id=?1 AND user_id=?2 AND status='draft'").bind(id, user).run();
        if (!r.meta.changes) { await audit(env, user, "delete", id, "denied", "not_draft"); throw new HttpErr(409, "only_drafts_can_be_deleted"); }
        await audit(env, user, "delete", id, "ok");
        return send({ ok: true });
      }
      if (sub === "schedule" && m === "POST") {
        const b = await readJson(request);
        if (Object.keys(b).some(k => k !== "scheduledAt") || typeof b.scheduledAt !== "string" || !/^\d{4}-\d\d-\d\dT[\d:.]+(Z|[+-]\d\d:\d\d)$/.test(b.scheduledAt)) throw new HttpErr(400, "invalid_scheduledAt");
        const t = Date.parse(b.scheduledAt);
        if (!(t > Date.now() + 60000) || t > Date.now() + 365 * 864e5) throw new HttpErr(400, "scheduledAt_out_of_range");
        if (row.status !== "draft") { await audit(env, user, "schedule", id, "denied", "invalid_transition"); throw new HttpErr(409, "invalid_transition"); }
        const cur = shape(row);
        if (!cur.platforms.length || !hasContent(cur)) throw new HttpErr(400, "needs_platforms_and_content");
        const iso = new Date(t).toISOString();
        const r = await env.DB.prepare("UPDATE social_posts SET status='scheduled', scheduled_at=?1, updated_at=?2 WHERE id=?3 AND user_id=?4 AND status='draft'").bind(iso, now, id, user).run();
        if (!r.meta.changes) throw new HttpErr(409, "state_changed");
        await audit(env, user, "schedule", id, "ok", iso);
        return send({ post: { ...cur, status: "scheduled", scheduledAt: iso, updatedAt: now } });
      }
      if (sub === "cancel" && m === "POST") {
        const r = await env.DB.prepare("UPDATE social_posts SET status='draft', scheduled_at=NULL, updated_at=?1 WHERE id=?2 AND user_id=?3 AND status='scheduled'").bind(now, id, user).run();
        if (!r.meta.changes) { await audit(env, user, "cancel", id, "denied", "invalid_transition"); throw new HttpErr(409, "invalid_transition"); }
        await audit(env, user, "cancel", id, "ok");
        return send({ post: { ...shape(row), status: "draft", scheduledAt: null, updatedAt: now } });
      }
      throw new HttpErr(405, "method_not_allowed");
    }
    throw new HttpErr(404, "not_found");
  } catch (e) {
    if (e instanceof HttpErr) return send({ error: e.code }, e.status);
    console.error("social_error", e && e.name);
    if (user) await audit(env, user, "server_error", null, "failure", e && e.name);
    return send({ error: "server_error" }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return social(request, env, url);
    return legacyAI(request, env);
  }
};
