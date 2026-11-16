// CS Manager API (Netlify Function v2) + Netlify Blobs
//   GET  /api/state     public read of the shared state (clients poll this every ~2.5 s, ETag supported)
//   PUT  /api/state     save changes (needs a session token; role is checked on the server)
//   POST /api/login | /api/register | /api/change-pin | GET,POST /api/accounts
// Passwords/PINs are only ever hashed here (PBKDF2-SHA256, 310k rounds, per-user salt).
// Account hashes never leave the server, so viewers cannot download them.
import { getStore } from "@netlify/blobs";
import { pbkdf2, randomBytes, timingSafeEqual, createHmac } from "node:crypto";
import { promisify } from "node:util";

const pb = promisify(pbkdf2), ITER = 310000;
// First admin. Only a salted hash of the TEMPORARY password lives here, never the password itself.
// It is replaced by the admin's own 6-digit PIN at first login (forced), then it is gone for good.
const SEED = { u: "aris211013", n: "Aris211013", role: "admin", st: "ok", tmp: true, s: "630cdfde42cb15468dbe7c1bc585e2f9", h: "993d9ec7bd455c0c5cbdd034635c495c1fb06531d246a7f1cd3fb58213704b4b", t: 0 };

const store = () => getStore({ name: "cs-manager", consistency: "strong" });
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...h } });
const hash = async (sec, salt) => (await pb(String(sec), Buffer.from(salt, "hex"), ITER, 32, "sha256")).toString("hex");
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const norm = (u) => String(u || "").trim().toLowerCase();
const okU = (u) => /^[a-z0-9\u0E00-\u0E7F_.-]{3,20}$/.test(u);
const ok6 = (v) => /^\d{6}$/.test(String(v));
const weak = (v) => /^(\d)\1{5}$/.test(v) || "0123456789".includes(v) || "9876543210".includes(v);
const bad = () => J({ error: "bad" }, 400);
const body = async (req) => { const t = await req.text(); if (t.length > 200000) return null; try { return JSON.parse(t); } catch { return null; } };

async function getSecret(st) {
  let s = await st.get("secret");
  if (!s) { s = randomBytes(32).toString("hex"); await st.set("secret", s); }
  return s;
}
const sign = (secret, p) => { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + createHmac("sha256", secret).update(b).digest("base64url"); };
function verify(secret, tok, kind) {
  if (typeof tok !== "string") return null;
  const [b, sg] = tok.split(".");
  if (!b || !sg || !eq(sg, createHmac("sha256", secret).update(b).digest("base64url"))) return null;
  let p; try { p = JSON.parse(Buffer.from(b, "base64url").toString()); } catch { return null; }
  return p && p.k === kind && p.exp > Date.now() ? p : null;
}
const who = (req, secret) => verify(secret, (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""), "s");
const session = (secret, usr) => ({ token: sign(secret, { u: usr.u, role: usr.role, k: "s", exp: Date.now() + 8 * 3600e3 }), user: { u: usr.u, n: usr.n, role: usr.role } });

async function getAcc(st) {
  let a = await st.get("accounts", { type: "json" });
  if (!a) { a = { users: [{ ...SEED }], lock: {} }; await st.setJSON("accounts", a); }
  return a;
}
const saveAcc = (st, a) => st.setJSON("accounts", a);

// ---------- shared state ----------
async function getState(st, req) {
  const s = (await st.get("state", { type: "json" })) || { rev: 0, tmp: true };
  const tag = `"${s.rev}-${s.tmp ? 1 : 0}"`;
  if (req.headers.get("if-none-match") === tag) return new Response(null, { status: 304, headers: { etag: tag, "cache-control": "no-store" } });
  return J({ rev: s.rev, tmp: !!s.tmp, app: s.app ?? null, status: s.status ?? null, practice: s.practice ?? null }, 200, { etag: tag });
}
const isInt = (v, a, b) => Number.isInteger(v) && v >= a && v <= b;
const validApp = (a) => a && typeof a === "object" && JSON.stringify(a).length < 60000 && isInt(a.total, 1, 500) && Array.isArray(a.teams) && a.teams.length <= 20 &&
  a.teams.every((t) => t && typeof t.id === "string" && t.id.length <= 20 && typeof t.name === "string" && t.name.length >= 1 && t.name.length <= 30 && isInt(t.cap, 0, 500) && typeof t.h === "number" && Array.isArray(t.m) && t.m.length <= 500 && t.m.every((n) => isInt(n, 1, 500)));
const validPractice = (p) => Array.isArray(p) && p.length <= 300 && p.every((x) => x && isInt(x.d, 0, 6) && /^\d{2}:\d{2}$/.test(x.t) && typeof x.a === "string" && x.a.length <= 30 && String(x.note || "").length <= 80);
const validEntry = (v) => v && typeof v === "object" && String(v.note || "").length <= 120 && (v.s === undefined || v.s === "ok" || v.s === "slack");
const cleanEntry = (v) => ({ s: v.s || "slack", note: String(v.note || "").slice(0, 120), t: Number(v.t) || Date.now() });

async function putState(st, req, secret) {
  const me = who(req, secret); if (!me) return J({ error: "auth" }, 401);
  const a = await getAcc(st), usr = a.users.find((x) => x.u === me.u);
  if (!usr || usr.st !== "ok") return J({ error: "auth" }, 401);
  const role = usr.role, b = await body(req);
  if (!b || typeof b !== "object" || Array.isArray(b)) return bad();
  const keys = Object.keys(b);
  if (!keys.every((k) => ["app", "status", "practice", "statusPatch"].includes(k))) return bad();
  if (role === "member" && keys.some((k) => k !== "statusPatch")) return J({ error: "forbidden" }, 403);
  if (role !== "admin" && role !== "member") return J({ error: "forbidden" }, 403);
  const s = (await st.get("state", { type: "json" })) || { rev: 0, tmp: false };
  if ("app" in b) { if (!validApp(b.app)) return bad(); s.app = b.app; }
  if ("practice" in b) { if (!validPractice(b.practice)) return bad(); s.practice = b.practice; }
  if ("status" in b) {
    const o = b.status;
    if (!o || typeof o !== "object" || Array.isArray(o) || Object.keys(o).length > 500 || !Object.entries(o).every(([k, v]) => /^\d{1,3}$/.test(k) && validEntry(v))) return bad();
    s.status = Object.fromEntries(Object.entries(o).map(([k, v]) => [k, cleanEntry(v)]));
  }
  if ("statusPatch" in b) {
    const p = b.statusPatch;
    if (!p || typeof p !== "object" || Array.isArray(p) || Object.keys(p).length > 100) return bad();
    const cur = { ...(s.status || {}) };
    for (const [k, v] of Object.entries(p)) {
      if (!/^\d{1,3}$/.test(k)) return bad();
      if (v === null) delete cur[k]; else { if (!validEntry(v)) return bad(); cur[k] = cleanEntry(v); }
    }
    s.status = cur;
  }
  s.rev = (s.rev || 0) + 1;
  await st.setJSON("state", s);
  return J({ rev: s.rev });
}

// ---------- accounts ----------
async function login(st, req, secret) {
  const b = await body(req), u = norm(b && b.u), sec = String((b && b.secret) ?? "");
  if (!u || !sec || sec.length > 64) return J({ error: "bad" }, 401);
  const a = await getAcc(st); a.lock = a.lock || {};
  const L = a.lock[u] || { f: 0, until: 0 };
  if (L.until > Date.now()) return J({ error: "locked", retry: Math.ceil((L.until - Date.now()) / 1000) }, 429);
  const usr = a.users.find((x) => x.u === u);
  const h = await hash(sec, usr ? usr.s : "00".repeat(16)); // same work for unknown users
  if (usr && eq(h, usr.h)) {
    if (usr.st === "pending") return J({ error: "pending" }, 403);
    if (usr.st === "off") return J({ error: "off" }, 403);
    if (a.lock[u]) { delete a.lock[u]; await saveAcc(st, a); }
    if (usr.tmp) return J({ mustChange: true, ticket: sign(secret, { u, k: "chg", exp: Date.now() + 300000 }) });
    return J(session(secret, usr));
  }
  const f = (L.f || 0) + 1, wait = f >= 5 ? Math.min(900, 30 * 2 ** (f - 5)) : 0;
  a.lock[u] = { f, until: wait ? Date.now() + wait * 1000 : 0 };
  if (Object.keys(a.lock).length > 500) a.lock = {};
  await saveAcc(st, a);
  return J(wait ? { error: "locked", retry: wait } : { error: "bad" }, wait ? 429 : 401);
}
async function register(st, req) {
  const b = await body(req); if (!b) return bad();
  const u = norm(b.u), n = String(b.n || "").trim().slice(0, 30) || u, pin = String(b.pin || "");
  if (!okU(u) || !ok6(pin)) return bad();
  if (weak(pin)) return J({ error: "weak" }, 400);
  const a = await getAcc(st);
  if (a.users.length >= 300 || a.users.filter((x) => x.st === "pending").length >= 100) return J({ error: "full" }, 429);
  if (a.users.some((x) => x.u === u)) return J({ error: "taken" }, 409);
  const s = randomBytes(16).toString("hex");
  a.users.push({ u, n, role: "member", st: "pending", s, h: await hash(pin, s), t: Date.now() });
  await saveAcc(st, a);
  return J({ ok: true });
}
async function changePin(st, req, secret) {
  const b = await body(req); if (!b) return bad();
  const pin = String(b.pin || ""); if (!ok6(pin)) return bad();
  if (weak(pin)) return J({ error: "weak" }, 400);
  let u, ticket = false;
  if (b.ticket) { const p = verify(secret, b.ticket, "chg"); if (!p) return J({ error: "auth" }, 401); u = p.u; ticket = true; }
  else { const me = who(req, secret); if (!me) return J({ error: "auth" }, 401); u = me.u; }
  const a = await getAcc(st), usr = a.users.find((x) => x.u === u);
  if (!usr || usr.st !== "ok" || (ticket && !usr.tmp)) return J({ error: "auth" }, 401);
  const wasTmp = !!usr.tmp;
  if (typeof b.name === "string" && b.name.trim()) usr.n = b.name.trim().slice(0, 30);
  usr.s = randomBytes(16).toString("hex"); usr.h = await hash(pin, usr.s); delete usr.tmp; // temporary password is gone for good
  await saveAcc(st, a);
  if (wasTmp) { const s = (await st.get("state", { type: "json" })) || { rev: 0 }; s.tmp = a.users.some((x) => x.tmp); s.rev = (s.rev || 0) + 1; await st.setJSON("state", s); }
  return J(session(secret, usr));
}
async function accounts(st, req, secret) {
  const me = who(req, secret); if (!me) return J({ error: "auth" }, 401);
  const a = await getAcc(st), usr = a.users.find((x) => x.u === me.u);
  if (!usr || usr.st !== "ok" || usr.role !== "admin") return J({ error: "forbidden" }, 403);
  if (req.method === "GET") return J({ users: a.users.map(({ u, n, role, st, t }) => ({ u, n, role, st, t })) });
  if (req.method !== "POST") return J({ error: "method" }, 405);
  const b = await body(req); if (!b) return bad();
  const t = a.users.find((x) => x.u === norm(b.u));
  if (!t || t.role === "admin") return bad();
  const act = b.action;
  if (act === "approve" && t.st === "pending") t.st = "ok";
  else if (act === "reject" && t.st === "pending") a.users = a.users.filter((x) => x !== t);
  else if (act === "suspend" && t.st === "ok") t.st = "off";
  else if (act === "restore" && t.st === "off") t.st = "ok";
  else if (act === "delete") a.users = a.users.filter((x) => x !== t);
  else return bad();
  await saveAcc(st, a);
  return J({ ok: true });
}

export default async (req) => {
  const st = store(), path = new URL(req.url).pathname.replace(/^\/api\//, "").replace(/\/+$/, "");
  try {
    if (path === "state" && req.method === "GET") return await getState(st, req);
    const secret = await getSecret(st);
    if (path === "state" && req.method === "PUT") return await putState(st, req, secret);
    if (path === "login" && req.method === "POST") return await login(st, req, secret);
    if (path === "register" && req.method === "POST") return await register(st, req);
    if (path === "change-pin" && req.method === "POST") return await changePin(st, req, secret);
    if (path === "accounts") return await accounts(st, req, secret);
    return J({ error: "not_found" }, 404);
  } catch (e) { console.error(e); return J({ error: "server" }, 500); }
};
export const config = { path: "/api/*" };
