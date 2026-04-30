// Smart Budget sync API — Cloudflare Worker
// Zero-knowledge: server only stores ciphertext + a hash of the client-derived auth token.

const USERNAME_RE = /^[a-zA-Z0-9._-]{2,64}$/;
const MAX_VAULT_BYTES = 256 * 1024; // 256 KB ceiling per account

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...extra },
  });

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim());
  const allow = allowed.includes(origin) ? origin : allowed[0] || "*";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

async function sha256Hex(input) {
  const buf = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function normUser(u) {
  return String(u || "").trim().toLowerCase();
}

function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  return m ? m[1].trim() : null;
}

async function readJson(req) {
  try { return await req.json(); } catch { return null; }
}

function isValidVault(v) {
  return v && typeof v === "object" && typeof v.iv === "string" && typeof v.ct === "string";
}

function bytesOf(obj) {
  return new TextEncoder().encode(JSON.stringify(obj)).byteLength;
}

async function handle(req, env) {
  const url = new URL(req.url);
  const { pathname } = url;
  const m = (re) => pathname.match(re);

  // GET /api/account/:username  → { salt, iter } | 404
  let mm;
  if (req.method === "GET" && (mm = m(/^\/api\/account\/([^/]+)$/))) {
    const u = normUser(decodeURIComponent(mm[1]));
    if (!USERNAME_RE.test(u)) return json({ error: "invalid username" }, 400);
    const acct = await env.VAULT.get(`acct:${u}`, "json");
    if (!acct) return json({ error: "not found" }, 404);
    return json({ salt: acct.salt, iter: acct.iter });
  }

  // POST /api/signup  body: { username, salt, iter, authTokenHash, encryptedVault }
  if (req.method === "POST" && pathname === "/api/signup") {
    const body = await readJson(req);
    if (!body) return json({ error: "invalid body" }, 400);
    const u = normUser(body.username);
    if (!USERNAME_RE.test(u)) return json({ error: "invalid username" }, 400);
    if (typeof body.salt !== "string" || body.salt.length < 8) return json({ error: "invalid salt" }, 400);
    if (typeof body.iter !== "number" || body.iter < 50000) return json({ error: "invalid iter" }, 400);
    if (typeof body.authTokenHash !== "string" || body.authTokenHash.length < 32) return json({ error: "invalid authTokenHash" }, 400);
    if (!isValidVault(body.encryptedVault)) return json({ error: "invalid encryptedVault" }, 400);
    if (bytesOf(body.encryptedVault) > MAX_VAULT_BYTES) return json({ error: "vault too large" }, 413);

    const existing = await env.VAULT.get(`acct:${u}`);
    if (existing) return json({ error: "username taken" }, 409);

    const acct = {
      username: u,
      salt: body.salt,
      iter: body.iter,
      authTokenHash: body.authTokenHash,
      createdAt: Date.now(),
      v: 1,
    };
    await env.VAULT.put(`acct:${u}`, JSON.stringify(acct));
    await env.VAULT.put(`vault:${u}`, JSON.stringify({ ...body.encryptedVault, updatedAt: Date.now() }));
    return json({ ok: true }, 201);
  }

  // POST /api/login  body: { username, authTokenHash } → { encryptedVault }
  if (req.method === "POST" && pathname === "/api/login") {
    const body = await readJson(req);
    if (!body) return json({ error: "invalid body" }, 400);
    const u = normUser(body.username);
    if (!USERNAME_RE.test(u)) return json({ error: "invalid username" }, 400);
    const acct = await env.VAULT.get(`acct:${u}`, "json");
    if (!acct) return json({ error: "invalid credentials" }, 401);
    if (typeof body.authTokenHash !== "string" || body.authTokenHash !== acct.authTokenHash) {
      return json({ error: "invalid credentials" }, 401);
    }
    const vault = await env.VAULT.get(`vault:${u}`, "json");
    return json({ encryptedVault: vault ? { iv: vault.iv, ct: vault.ct, updatedAt: vault.updatedAt } : null });
  }

  // PUT /api/vault/:username  Authorization: Bearer <authToken>  body: { encryptedVault }
  if (req.method === "PUT" && (mm = m(/^\/api\/vault\/([^/]+)$/))) {
    const u = normUser(decodeURIComponent(mm[1]));
    if (!USERNAME_RE.test(u)) return json({ error: "invalid username" }, 400);
    const tok = bearer(req);
    if (!tok) return json({ error: "missing token" }, 401);
    const acct = await env.VAULT.get(`acct:${u}`, "json");
    if (!acct) return json({ error: "not found" }, 404);
    const tokHash = await sha256Hex(tok);
    if (tokHash !== acct.authTokenHash) return json({ error: "invalid token" }, 401);

    const body = await readJson(req);
    if (!body || !isValidVault(body.encryptedVault)) return json({ error: "invalid encryptedVault" }, 400);
    if (bytesOf(body.encryptedVault) > MAX_VAULT_BYTES) return json({ error: "vault too large" }, 413);

    await env.VAULT.put(`vault:${u}`, JSON.stringify({ ...body.encryptedVault, updatedAt: Date.now() }));
    return json({ ok: true });
  }

  // POST /api/rotate  Authorization: Bearer <oldAuthToken>
  // body: { username, salt, iter, authTokenHash, encryptedVault }
  if (req.method === "POST" && pathname === "/api/rotate") {
    const tok = bearer(req);
    if (!tok) return json({ error: "missing token" }, 401);
    const body = await readJson(req);
    if (!body) return json({ error: "invalid body" }, 400);
    const u = normUser(body.username);
    if (!USERNAME_RE.test(u)) return json({ error: "invalid username" }, 400);
    const acct = await env.VAULT.get(`acct:${u}`, "json");
    if (!acct) return json({ error: "not found" }, 404);
    const tokHash = await sha256Hex(tok);
    if (tokHash !== acct.authTokenHash) return json({ error: "invalid token" }, 401);
    if (typeof body.salt !== "string" || body.salt.length < 8) return json({ error: "invalid salt" }, 400);
    if (typeof body.iter !== "number" || body.iter < 50000) return json({ error: "invalid iter" }, 400);
    if (typeof body.authTokenHash !== "string" || body.authTokenHash.length < 32) return json({ error: "invalid authTokenHash" }, 400);
    if (!isValidVault(body.encryptedVault)) return json({ error: "invalid encryptedVault" }, 400);
    if (bytesOf(body.encryptedVault) > MAX_VAULT_BYTES) return json({ error: "vault too large" }, 413);
    const updated = { ...acct, salt: body.salt, iter: body.iter, authTokenHash: body.authTokenHash, rotatedAt: Date.now() };
    await env.VAULT.put(`acct:${u}`, JSON.stringify(updated));
    await env.VAULT.put(`vault:${u}`, JSON.stringify({ ...body.encryptedVault, updatedAt: Date.now() }));
    return json({ ok: true });
  }

  // DELETE /api/account/:username  Authorization: Bearer <authToken>
  if (req.method === "DELETE" && (mm = m(/^\/api\/account\/([^/]+)$/))) {
    const u = normUser(decodeURIComponent(mm[1]));
    if (!USERNAME_RE.test(u)) return json({ error: "invalid username" }, 400);
    const tok = bearer(req);
    if (!tok) return json({ error: "missing token" }, 401);
    const acct = await env.VAULT.get(`acct:${u}`, "json");
    if (!acct) return json({ ok: true });
    const tokHash = await sha256Hex(tok);
    if (tokHash !== acct.authTokenHash) return json({ error: "invalid token" }, 401);
    await env.VAULT.delete(`acct:${u}`);
    await env.VAULT.delete(`vault:${u}`);
    return json({ ok: true });
  }

  // Health
  if (req.method === "GET" && pathname === "/api/health") {
    return json({ ok: true, ts: Date.now() });
  }

  return json({ error: "not found" }, 404);
}

export default {
  async fetch(req, env, ctx) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    try {
      const res = await handle(req, env);
      const merged = new Headers(res.headers);
      for (const [k, v] of Object.entries(cors)) merged.set(k, v);
      return new Response(res.body, { status: res.status, headers: merged });
    } catch (err) {
      return new Response(JSON.stringify({ error: "internal error" }), {
        status: 500,
        headers: { "content-type": "application/json", ...cors },
      });
    }
  },
};
