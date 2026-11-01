// OC&S Typing Exam - server (Netlify Function + Netlify Blobs storage)
// Admin name/password are set below. (Netlify environment variables ADMIN_USER / ADMIN_PASS, if set, override them.)
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api" };

const ADMIN_USER = process.env.ADMIN_USER || "institution_admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "OC&S11749";

const DAYS = 7, DAY = 864e5, GRACE = 20000, MAXTEXT = 60000;

const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (m, s = 400) => json({ error: m }, s);

/* ---------- text helpers (same rules as the page) ---------- */
const norm = s => String(s || "").normalize("NFC").replace(/[\u200B-\u200F\u2060\uFEFF]/g, "").replace(/\u2020/g, "\u2021").replace(/\u0160/g, "\u2030");
// words are cut at spaces and at the punctuation marks । ॥ | , . ; : ? ! ( ) so "word", "word।" and "word ।" are one word
const words = t => norm(t).split(/[\s।॥|,.;:?!()]+/).filter(Boolean);
function grade(ref, typ) {
  const a = words(ref), b = words(typ), m = new Map();
  a.forEach(w => m.set(w, (m.get(w) || 0) + 1));
  let c = 0;
  b.forEach(w => { const n = m.get(w) || 0; if (n > 0) { m.set(w, n - 1); c++; } });
  return { total: a.length, typed: b.length, correct: c };
}
const marksOf = (g, full) => g.total ? Math.round(g.correct / g.total * full * 100) / 100 : 0;
function mism(lang, t) {
  t = String(t || "");
  const bn = (t.match(/[\u0980-\u09FF]/g) || []).length, lat = (t.match(/[A-Za-z]/g) || []).length;
  return bn > lat; // Bangla Unicode where Classic/English is expected
}
// roll numbers: 1, 01, " 1 " and Bangla digits are the same roll
function normRoll(r) {
  let n = String(r).trim().toLowerCase().replace(/\s+/g, "").replace(/[০-৯]/g, d => "০১২৩৪৫৬৭৮৯".indexOf(d));
  if (/^\d+$/.test(n)) n = n.replace(/^0+(?=\d)/, "");
  return [...n].map(ch => /[a-z0-9]/.test(ch) ? ch : "-" + ch.codePointAt(0).toString(16)).join("");
}

/* ---------- admin login token ---------- */
const secret = () => crypto.createHash("sha256").update("octs|" + ADMIN_PASS + "|" + ADMIN_USER).digest();
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + crypto.createHmac("sha256", secret()).update(b).digest("base64url"); };
function verify(tok) {
  if (!tok || !tok.includes(".")) return null;
  const [b, s] = tok.split("."), e = crypto.createHmac("sha256", secret()).update(b).digest("base64url");
  const A = Buffer.from(s), B = Buffer.from(e);
  if (A.length !== B.length || !crypto.timingSafeEqual(A, B)) return null;
  try { const p = JSON.parse(Buffer.from(b, "base64url").toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}
const same = (a, b) => crypto.timingSafeEqual(crypto.createHash("sha256").update(String(a)).digest(), crypto.createHash("sha256").update(String(b)).digest());

export default async (req, context) => {
  if (req.method !== "POST") return fail("POST only", 405);
  let b;
  try { const raw = await req.text(); if (raw.length > 250000) return fail("Request too large"); b = JSON.parse(raw); } catch { return fail("Bad request"); }

  const exams = getStore({ name: "exams", consistency: "strong" });
  const recs = getStore({ name: "recs", consistency: "strong" });
  const meta = getStore({ name: "meta", consistency: "strong" });
  const a = String(b.a || "");
  const admin = !!verify((req.headers.get("authorization") || "").replace(/^Bearer /, ""));

  async function purge(code) {
    const { blobs } = await recs.list({ prefix: code + "/" });
    for (const x of blobs) await recs.delete(x.key);
    await exams.delete(code);
  }
  async function purgeOld() {
    const { blobs } = await exams.list();
    for (const x of blobs) { const e = await exams.get(x.key, { type: "json" }); if (e && Date.now() > e.at + DAYS * DAY) await purge(x.key); }
  }
  const cleanCode = c => String(c || "").trim().toUpperCase();

  /* ===== admin login ===== */
  if (a === "login") {
    const ip = String((context && context.ip) || req.headers.get("x-nf-client-connection-ip") || "x").replace(/[^\w.:-]/g, "_");
    const k = "fail-" + ip;
    const f = (await meta.get(k, { type: "json" })) || { n: 0, until: 0 };
    if (f.until > Date.now()) return fail("Too many wrong attempts. Please try again in a few minutes.", 429);
    const ok1 = same(b.user || "", ADMIN_USER), ok2 = same(b.pass || "", ADMIN_PASS);
    if (ok1 && ok2) { await meta.delete(k).catch(() => {}); return json({ token: sign({ exp: Date.now() + 12 * 3600e3 }) }); }
    f.n++; if (f.n >= 6) { f.until = Date.now() + 15 * 60e3; f.n = 0; }
    await meta.setJSON(k, f);
    return fail("Wrong name or password.", 401);
  }

  /* ===== candidate: start ===== */
  if (a === "start") {
    const code = cleanCode(b.code), roll = String(b.roll || "").trim();
    if (!/^[A-Z0-9]{6}$/.test(code) || !roll || roll.length > 40) return fail("Enter both the exam code and your roll number.");
    const e = await exams.get(code, { type: "json" });
    if (!e) return fail("Invalid exam code.");
    if (Date.now() > e.at + DAYS * DAY) { await purge(code); return fail("This exam has expired."); }
    const n = normRoll(roll);
    if (e.allowed && e.allowed.length && !e.allowed.includes(n)) return fail("This roll number is not on the list for this exam.");
    const key = code + "/" + n, now = Date.now();
    const payload = r => ({ name: e.name, lang: e.lang, mins: e.mins, full: e.full, ref: e.text, left: Math.max(0, r.startedAt + e.mins * 60000 - now), text: r.text, tabs: r.tabs, blocked: r.blocked, token: r.token });
    const cur = await recs.get(key, { type: "json" });
    if (!cur) {
      const rec = { roll, token: crypto.randomBytes(24).toString("hex"), startedAt: now, text: "", status: "in progress", tabs: 0, blocked: 0 };
      const r = await recs.setJSON(key, rec, { onlyIfNew: true });
      if (!r.modified) return fail("This roll number has already been used for this exam.");
      return json(payload(rec));
    }
    // a roll can come back only from the same device (secret token), only until the time is over
    if (!b.token || !same(b.token, cur.token)) return fail("This roll number has already been used for this exam.");
    if (cur.status === "submitted") return fail("You have already submitted this exam.");
    if (now > cur.startedAt + e.mins * 60000 + GRACE) { cur.status = "submitted"; cur.submittedAt = now; await recs.setJSON(key, cur); return fail("Your exam time is over."); }
    return json(payload(cur));
  }

  /* ===== candidate: autosave / finish ===== */
  if (a === "save" || a === "finish") {
    const code = cleanCode(b.code), roll = String(b.roll || "").trim();
    if (!/^[A-Z0-9]{6}$/.test(code) || !roll) return fail("Bad request");
    const e = await exams.get(code, { type: "json" });
    if (!e) return fail("Invalid exam code.");
    const key = code + "/" + normRoll(roll), cur = await recs.get(key, { type: "json" });
    if (!cur || !b.token || !same(b.token, cur.token)) return fail("Not allowed.", 403);
    const now = Date.now(), deadline = cur.startedAt + e.mins * 60000;
    if (cur.status !== "submitted") {
      if (now <= deadline + GRACE) {
        cur.text = String(b.text || "").slice(0, MAXTEXT);
        cur.tabs = Math.min(999, Math.max(0, Math.floor(+b.tabs || 0)));
        cur.blocked = Math.min(9999, Math.max(0, Math.floor(+b.blocked || 0)));
      }
      if (a === "finish" || now > deadline + GRACE) { cur.status = "submitted"; cur.submittedAt = now; }
      await recs.setJSON(key, cur);
    }
    if (cur.status === "submitted") {
      const g = grade(e.text, cur.text);
      return json({ done: true, total: g.total, typed: g.typed, correct: g.correct, marks: marksOf(g, e.full), full: e.full, ref: e.text, name: e.name, lang: e.lang, text: cur.text });
    }
    return json({ left: Math.max(0, deadline - now) });
  }

  /* ===== everything below is admin only ===== */
  if (!admin) return fail("Please log in as admin.", 401);

  if (a === "create") {
    const name = String(b.name || "").trim().slice(0, 100), text = String(b.text || "").trim(), lang = b.lang === "en" ? "en" : "bc";
    const mins = Math.round(+b.mins), full = +b.full;
    if (!name || !text || !(mins > 0) || mins > 600 || !(full > 0) || text.length > MAXTEXT) return fail("Check the name, time, full marks and paragraph.");
    if (mism(lang, text)) return fail(lang === "bc" ? "This paragraph is Unicode Bangla. Please paste Bijoy Classic (SutonnyMJ) text instead." : "This paragraph is Bangla, but the language is English.");
    const allowed = [...new Set((Array.isArray(b.allowed) ? b.allowed : []).slice(0, 5000).map(normRoll).filter(Boolean))];
    const A = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    for (let i = 0; i < 8; i++) {
      let code = ""; const rb = crypto.randomBytes(6); for (let j = 0; j < 6; j++) code += A[rb[j] % A.length];
      const r = await exams.setJSON(code, { name, lang, text, mins, full, allowed, at: Date.now() }, { onlyIfNew: true });
      if (r.modified) return json({ code });
    }
    return fail("Could not make a code. Please try again.", 500);
  }

  if (a === "list") {
    await purgeOld();
    const { blobs } = await exams.list(), out = [];
    for (const x of blobs) {
      const e = await exams.get(x.key, { type: "json" }); if (!e) continue;
      const l = await recs.list({ prefix: x.key + "/" });
      out.push({ code: x.key, name: e.name, lang: e.lang, mins: e.mins, full: e.full, at: e.at, allowed: (e.allowed || []).length, count: l.blobs.length });
    }
    out.sort((p, q) => q.at - p.at);
    return json({ exams: out });
  }

  if (a === "results") {
    const code = cleanCode(b.code), e = await exams.get(code, { type: "json" });
    if (!e) return fail("Exam not found.", 404);
    const { blobs } = await recs.list({ prefix: code + "/" }), rows = [];
    for (let i = 0; i < blobs.length; i += 25) {
      const part = await Promise.all(blobs.slice(i, i + 25).map(x => recs.get(x.key, { type: "json" })));
      for (const r of part) {
        if (!r) continue;
        const g = grade(e.text, r.text || "");   // marks are always calculated here from the saved typing
        rows.push({ roll: r.roll, status: r.status, tabs: r.tabs || 0, blocked: r.blocked || 0, text: r.text || "", total: g.total, typed: g.typed, correct: g.correct, marks: marksOf(g, e.full), full: e.full, lang: e.lang });
      }
    }
    return json({ exam: { name: e.name, lang: e.lang, text: e.text, mins: e.mins, full: e.full, at: e.at }, rows });
  }

  if (a === "reset") {
    const code = cleanCode(b.code), roll = String(b.roll || "").trim();
    if (!/^[A-Z0-9]{6}$/.test(code) || !roll) return fail("Bad request");
    await recs.delete(code + "/" + normRoll(roll));
    return json({ ok: true });
  }

  if (a === "delete") {
    const code = cleanCode(b.code);
    if (!/^[A-Z0-9]{6}$/.test(code)) return fail("Bad request");
    await purge(code);
    return json({ ok: true });
  }

  return fail("Unknown request", 404);
};
