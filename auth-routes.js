// auth-routes.js
// Add these handlers into your existing adagbor-api Worker (index.js / worker.js).
// Wire them into your router like:
//   if (url.pathname === "/api/members" && request.method === "POST") return handleRegister(request, env);
//   if (url.pathname === "/api/login" && request.method === "POST") return handleLogin(request, env);
//   if (url.pathname === "/api/member/me" && request.method === "GET") return handleMe(request, env);
//   if (url.pathname === "/api/logout" && request.method === "POST") return handleLogout(request, env);
//   if (url.pathname.match(/^\/api\/admin\/members\/\d+\/approve$/) && request.method === "PATCH") return handleApprove(request, env, id);

const SESSION_COOKIE = "adagbor_session";
const SESSION_DAYS = 30;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------- Password hashing (Web Crypto PBKDF2 — no bcrypt binding needed on Workers) ----------

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex
    ? hexToBytes(saltHex)
    : crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );

  return {
    hash: bytesToHex(new Uint8Array(derivedBits)),
    salt: bytesToHex(salt),
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  return timingSafeEqual(hash, storedHash);
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function generateToken() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

function cookieHeader(token, maxAgeDays = SESSION_DAYS) {
  const maxAge = maxAgeDays * 24 * 60 * 60;
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function getSessionToken(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  return match ? match[1] : null;
}

// ---------- Registration (extends your existing POST /api/members) ----------
// Assumes the incoming form now also includes a "password" field.
// New members land in the table with status = 'pending' and cannot log in
// until an admin approves them.

async function handleRegister(request, env) {
  const body = await request.json();
  const { full_name, gender, dob, branch, occupation, phone, email, address,
          next_of_kin_name, next_of_kin_phone, password } = body;

  if (!password || password.length < 8) {
    return json({ error: "Password must be at least 8 characters." }, 400);
  }
  if (!email && !phone) {
    return json({ error: "Email or phone is required to log in later." }, 400);
  }

  const { hash, salt } = await hashPassword(password);

  const result = await env.DB.prepare(
    `INSERT INTO members
      (full_name, gender, dob, branch, occupation, phone, email, address,
       next_of_kin_name, next_of_kin_phone, password_hash, password_salt, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`
  ).bind(
    full_name, gender, dob, branch, occupation, phone, email, address,
    next_of_kin_name, next_of_kin_phone, hash, salt
  ).run();

  return json({
    success: true,
    message: "Registration received. You'll be able to log in once an admin approves your membership.",
    id: result.meta.last_row_id,
  });
}

// ---------- Login ----------

async function handleLogin(request, env) {
  const { identifier, password } = await request.json(); // identifier = email or phone
  if (!identifier || !password) {
    return json({ error: "Missing credentials." }, 400);
  }

  const member = await env.DB.prepare(
    `SELECT id, password_hash, password_salt, status FROM members
     WHERE email = ?1 OR phone = ?1`
  ).bind(identifier).first();

  if (!member || !member.password_hash) {
    return json({ error: "Invalid email/phone or password." }, 401);
  }

  const ok = await verifyPassword(password, member.password_hash, member.password_salt);
  if (!ok) {
    return json({ error: "Invalid email/phone or password." }, 401);
  }

  if (member.status === "pending") {
    return json({ error: "Your membership is still awaiting admin approval." }, 403);
  }
  if (member.status === "rejected") {
    return json({ error: "Your membership application was not approved. Contact the association." }, 403);
  }

  const token = generateToken();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (token, member_id, expires_at) VALUES (?, ?, ?)`
  ).bind(token, member.id, expiresAt).run();

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": cookieHeader(token),
    },
  });
}

// ---------- Session-protected "my dashboard" endpoint ----------

async function handleMe(request, env) {
  const token = getSessionToken(request);
  if (!token) return json({ error: "Not logged in." }, 401);

  const session = await env.DB.prepare(
    `SELECT member_id, expires_at FROM sessions WHERE token = ?`
  ).bind(token).first();

  if (!session || new Date(session.expires_at) < new Date()) {
    return json({ error: "Session expired. Please log in again." }, 401);
  }

  const member = await env.DB.prepare(
    `SELECT id, full_name, gender, dob, branch, occupation, phone, email, address,
            next_of_kin_name, next_of_kin_phone, status
     FROM members WHERE id = ?`
  ).bind(session.member_id).first();

  return json({ member });
}

async function handleLogout(request, env) {
  const token = getSessionToken(request);
  if (token) {
    await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
  }
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
    },
  });
}

// ---------- Admin approval (extends your existing admin-key-protected routes) ----------
// PATCH /api/admin/members/:id/approve   body: { status: "approved" | "rejected" }
// Keep your existing X-Admin-Key check wrapping this handler.

async function handleApprove(request, env, memberId) {
  const { status } = await request.json();
  if (!["approved", "rejected", "pending"].includes(status)) {
    return json({ error: "Invalid status." }, 400);
  }
  await env.DB.prepare(`UPDATE members SET status = ? WHERE id = ?`)
    .bind(status, memberId).run();
  return json({ success: true, id: memberId, status });
}

export {
  handleRegister,
  handleLogin,
  handleMe,
  handleLogout,
  handleApprove,
};
