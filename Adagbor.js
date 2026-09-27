// Adagbor.js
// Single-file Cloudflare Worker for the Adagbor Descendant Association API.
//
// Bindings/secrets required (Cloudflare dashboard → Settings → Variables and Secrets):
//   DB               - D1 database binding
//   ADMIN_KEY        - shared secret for X-Admin-Key admin routes
//   RESEND_API_KEY   - Resend.com API key, for password-reset emails
//   KUDISMS_API_KEY  - KudiSMS API token (Developers section)
//   KUDISMS_SENDER_ID - approved promotional Sender ID (e.g. ADAGBOR)
//
// D1 table for auto-sync (run once in D1 Console):
//   CREATE TABLE IF NOT EXISTS app_store (
//     key TEXT PRIMARY KEY,
//     value TEXT NOT NULL,
//     updated_at TEXT NOT NULL
//   );

const SESSION_COOKIE = "adagbor_session";
const SESSION_DAYS = 30;
const SITE_URL = "https://adagbor1.umahglobal1000.workers.dev";
const RESET_TOKEN_MINUTES = 60;

// Must be an exact origin (scheme + host), never "*" — required because
// requests are sent with credentials: "include" (cookies).
const ALLOWED_ORIGIN = "https://adagbor1.umahglobal1000.workers.dev";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------- Password hashing (Web Crypto PBKDF2) ----------

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

// Numeric-only password for members added or reset by admin (e.g. "482915").
function generateNumericPassword(length = 6) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i++) out += (bytes[i] % 10).toString();
  return out;
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

// ---------- App store (announcements, resolutions, attendance, payments, etc.) ----------

async function storeGet(env, key) {
  const row = await env.DB.prepare(
    `SELECT value FROM app_store WHERE key = ?`
  ).bind(key).first();
  if (!row) return null;
  try {
    return JSON.parse(row.value);
  } catch {
    return row.value;
  }
}

async function storePut(env, key, value) {
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO app_store (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  ).bind(key, JSON.stringify(value), now).run();
}

// ---------- KudiSMS (promotional gateway) ----------

/** Normalise Nigerian phone → 234XXXXXXXXXX */
function normalizeNgPhone(phone) {
  let p = String(phone || "").replace(/\D/g, "");
  if (p.startsWith("0")) p = "234" + p.slice(1);
  if (p.length === 10) p = "234" + p;
  if (p.startsWith("2340")) p = "234" + p.slice(4);
  return p;
}

/**
 * Send one SMS via KudiSMS promotional route (gateway 2).
 * DND numbers will not receive the message (charge refunded by KudiSMS).
 * @returns {{ ok: boolean, error?: string, raw?: any }}
 */
async function sendSms(env, toPhone, message) {
  if (!env.KUDISMS_API_KEY) {
    console.error("KUDISMS_API_KEY not set");
    return { ok: false, error: "SMS not configured" };
  }

  const to = normalizeNgPhone(toPhone);
  if (!to || to.length < 13) {
    return { ok: false, error: "Invalid phone number" };
  }

  const body = {
    token: env.KUDISMS_API_KEY,
    senderID: env.KUDISMS_SENDER_ID || "ADAGBOR",
    recipients: to,
    message: String(message).slice(0, 320),
    gateway: "2",
  };

  try {
    const res = await fetch("https://my.kudisms.net/api/sms", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    const code = String(data.status || data.code || data.response || "");
    if (code === "000") {
      return { ok: true, raw: data };
    }
    console.error("KudiSMS error:", data);
    return {
      ok: false,
      error: data.message || data.error || code || res.statusText,
      raw: data,
    };
  } catch (e) {
    console.error("SMS send failed:", e);
    return { ok: false, error: String(e) };
  }
}

/**
 * Send SMS to many numbers (batches of 100).
 * @returns {{ ok: boolean, results?: any[], error?: string }}
 */
async function sendSmsBulk(env, phones, message) {
  if (!env.KUDISMS_API_KEY) {
    return { ok: false, error: "SMS not configured" };
  }
  const recipients = [
    ...new Set(
      (phones || []).map(normalizeNgPhone).filter((p) => p && p.length >= 13)
    ),
  ];
  if (!recipients.length) {
    return { ok: false, error: "No valid phone numbers" };
  }

  const chunks = [];
  for (let i = 0; i < recipients.length; i += 100) {
    chunks.push(recipients.slice(i, i + 100));
  }

  const results = [];
  for (const chunk of chunks) {
    const body = {
      token: env.KUDISMS_API_KEY,
      senderID: env.KUDISMS_SENDER_ID || "ADAGBOR",
      recipients: chunk.join(","),
      message: String(message).slice(0, 320),
      gateway: "2",
    };
    try {
      const res = await fetch("https://my.kudisms.net/api/sms", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      const code = String(data.status || data.code || "");
      results.push({ ok: code === "000", count: chunk.length, raw: data });
    } catch (e) {
      results.push({ ok: false, count: chunk.length, error: String(e) });
    }
  }
  return { ok: results.every((r) => r.ok), results, sent: recipients.length };
}

// ---------- Login ----------

async function handleLogin(request, env) {
  const { identifier, password } = await request.json();
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

async function handleMe(request, env) {
  const token = getSessionToken(request);
  if (!token) return json({ error: "Not logged in." }, 401);

  const session = await env.DB.prepare(
    `SELECT member_id, expires_at FROM sessions WHERE token = ?`
  ).bind(token).first();

  if (!session || new Date(session.expires_at) < new Date()) {
    return json({ error: "Session expired. Please log in again." }, 401);
  }

  // Include photo if column exists; query fails gracefully handled by optional second try
  let member = await env.DB.prepare(
    `SELECT id, full_name, gender, date_of_birth, branch, occupation, phone, email, address,
            next_of_kin_name, next_of_kin_phone, status, photo
     FROM members WHERE id = ?`
  ).bind(session.member_id).first().catch(() => null);

  if (!member) {
    member = await env.DB.prepare(
      `SELECT id, full_name, gender, date_of_birth, branch, occupation, phone, email, address,
              next_of_kin_name, next_of_kin_phone, status
       FROM members WHERE id = ?`
    ).bind(session.member_id).first();
  }

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

async function handleSetPassword(request, env, memberId) {
  const { password } = await request.json();

  if (!password || password.length < 8) {
    return json({ error: "Password must be at least 8 characters." }, 400);
  }

  const member = await env.DB.prepare(
    `SELECT id FROM members WHERE id = ?`
  ).bind(memberId).first();

  if (!member) {
    return json({ error: "Member not found." }, 404);
  }

  const { hash, salt } = await hashPassword(password);

  await env.DB.prepare(
    `UPDATE members SET password_hash = ?, password_salt = ? WHERE id = ?`
  ).bind(hash, salt, memberId).run();

  return json({
    success: true,
    message: "Password set. Give this to the member directly (phone call, WhatsApp, in person) — not by email/SMS unless your channel is secure.",
  });
}

// Admin adds a member directly (no self-registration). Member goes straight
// into the directory as approved, with a system-generated numeric password.
async function handleAdminCreateMember(request, env) {
  const body = await request.json();

  if (!body.full_name || !body.phone) {
    return json({ error: "Full name and phone are required." }, 400);
  }

  const plainPassword = generateNumericPassword(6);
  const { hash, salt } = await hashPassword(plainPassword);

  let insertedId = null;
  try {
    const result = await env.DB.prepare(
      `INSERT INTO members
       (full_name, gender, date_of_birth, branch, occupation, phone, email, address,
        next_of_kin_name, next_of_kin_phone, declared, status, password_hash, password_salt, photo)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'approved', ?, ?, ?)`
    ).bind(
      body.full_name,
      body.gender || null,
      body.date_of_birth || null,
      body.branch || null,
      body.occupation || null,
      body.phone,
      body.email || null,
      body.address || null,
      body.next_of_kin_name || null,
      body.next_of_kin_phone || null,
      hash,
      salt,
      body.photo || null
    ).run();
    insertedId = result.meta && result.meta.last_row_id != null ? result.meta.last_row_id : null;
  } catch (e) {
    // Fallback without photo column
    const result = await env.DB.prepare(
      `INSERT INTO members
       (full_name, gender, date_of_birth, branch, occupation, phone, email, address,
        next_of_kin_name, next_of_kin_phone, declared, status, password_hash, password_salt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'approved', ?, ?)`
    ).bind(
      body.full_name,
      body.gender || null,
      body.date_of_birth || null,
      body.branch || null,
      body.occupation || null,
      body.phone,
      body.email || null,
      body.address || null,
      body.next_of_kin_name || null,
      body.next_of_kin_phone || null,
      hash,
      salt
    ).run();
    insertedId = result.meta && result.meta.last_row_id != null ? result.meta.last_row_id : null;
  }

  return json({ success: true, id: insertedId, password: plainPassword }, 201);
}

// Admin generates a fresh numeric password for a member who lost theirs.
async function handleGeneratePassword(request, env, memberId) {
  const member = await env.DB.prepare(
    `SELECT id FROM members WHERE id = ?`
  ).bind(memberId).first();

  if (!member) {
    return json({ error: "Member not found." }, 404);
  }

  const plainPassword = generateNumericPassword(6);
  const { hash, salt } = await hashPassword(plainPassword);

  await env.DB.prepare(
    `UPDATE members SET password_hash = ?, password_salt = ? WHERE id = ?`
  ).bind(hash, salt, memberId).run();

  return json({ success: true, password: plainPassword });
}

async function handleForgotPassword(request, env) {
  const { email } = await request.json();
  if (!email) {
    return json({ error: "Email is required." }, 400);
  }

  const member = await env.DB.prepare(
    `SELECT id, full_name FROM members WHERE email = ?`
  ).bind(email).first();

  const genericResponse = {
    success: true,
    message: "If that email is registered, a reset link has been sent.",
  };

  if (!member) {
    return json(genericResponse);
  }

  const token = generateToken();
  const expiresAt = new Date(Date.now() + RESET_TOKEN_MINUTES * 60 * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO password_resets (token, member_id, expires_at) VALUES (?, ?, ?)`
  ).bind(token, member.id, expiresAt).run();

  const resetLink = `${SITE_URL}/reset-password.html?token=${token}`;

  await sendResetEmail(env, email, member.full_name, resetLink);

  return json(genericResponse);
}

async function sendResetEmail(env, toEmail, fullName, resetLink) {
  if (!env.RESEND_API_KEY) {
    console.error("RESEND_API_KEY not set");
    return;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Adagbor Descendant Association <onboarding@resend.dev>",
      to: [toEmail],
      subject: "Reset your Adagbor Descendant Association password",
      html: `
        <p>Hello ${fullName || "there"},</p>
        <p>We received a request to reset your password. Click the link below to set a new one:</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>This link expires in ${RESET_TOKEN_MINUTES} minutes. If you didn't request this, you can ignore this email.</p>
        <p>— Adagbor Descendant Association</p>
      `,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error("Resend error:", errText);
  }
}

async function handleResetPassword(request, env) {
  const { token, password } = await request.json();

  if (!token || !password) {
    return json({ error: "Missing token or password." }, 400);
  }
  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters." }, 400);
  }

  const reset = await env.DB.prepare(
    `SELECT member_id, expires_at, used FROM password_resets WHERE token = ?`
  ).bind(token).first();

  if (!reset) {
    return json({ error: "Invalid or expired reset link." }, 400);
  }
  if (reset.used) {
    return json({ error: "This reset link has already been used." }, 400);
  }
  if (new Date(reset.expires_at) < new Date()) {
    return json({ error: "This reset link has expired. Please request a new one." }, 400);
  }

  const { hash, salt } = await hashPassword(password);

  await env.DB.prepare(
    `UPDATE members SET password_hash = ?, password_salt = ? WHERE id = ?`
  ).bind(hash, salt, reset.member_id).run();

  await env.DB.prepare(
    `UPDATE password_resets SET used = 1 WHERE token = ?`
  ).bind(token).run();

  return json({ success: true, message: "Password updated. You can now log in." });
}

// ---------- Router ----------

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
      "Access-Control-Allow-Credentials": "true",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

    // ---- Public store read (announcements, resolutions, etc.) ----
    const storeMatch = url.pathname.match(/^\/api\/store\/([^/]+)$/);
    if (request.method === "GET" && storeMatch) {
      try {
        const key = decodeURIComponent(storeMatch[1]);
        const value = await storeGet(env, key);
        return new Response(JSON.stringify({ value }), {
          status: 200,
          headers: jsonHeaders,
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Server error", detail: String(err) }), {
          status: 500,
          headers: jsonHeaders,
        });
      }
    }

    // ---- Public: submit membership application ----
    if (request.method === "POST" && url.pathname === "/api/members") {
      try {
        const body = await request.json();

        if (!body.full_name || !body.phone || !body.declared) {
          return new Response(JSON.stringify({ error: "Missing required fields" }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        if (!body.password || body.password.length < 8) {
          return new Response(JSON.stringify({ error: "Password must be at least 8 characters." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }

        const { hash, salt } = await hashPassword(body.password);

        // Prefer insert with photo if column exists
        try {
          await env.DB.prepare(
            `INSERT INTO members
             (full_name, gender, date_of_birth, branch, occupation, phone, email, address,
              next_of_kin_name, next_of_kin_phone, declared, password_hash, password_salt, photo)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            body.full_name,
            body.gender || null,
            body.date_of_birth || null,
            body.branch || null,
            body.occupation || null,
            body.phone,
            body.email || null,
            body.address || null,
            body.next_of_kin_name || null,
            body.next_of_kin_phone || null,
            body.declared ? 1 : 0,
            hash,
            salt,
            body.photo || null
          ).run();
        } catch (e) {
          // Fallback without photo column
          await env.DB.prepare(
            `INSERT INTO members
             (full_name, gender, date_of_birth, branch, occupation, phone, email, address,
              next_of_kin_name, next_of_kin_phone, declared, password_hash, password_salt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            body.full_name,
            body.gender || null,
            body.date_of_birth || null,
            body.branch || null,
            body.occupation || null,
            body.phone,
            body.email || null,
            body.address || null,
            body.next_of_kin_name || null,
            body.next_of_kin_phone || null,
            body.declared ? 1 : 0,
            hash,
            salt
          ).run();
        }

        return new Response(JSON.stringify({ success: true }), {
          status: 201,
          headers: jsonHeaders,
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Server error" }), {
          status: 500,
          headers: jsonHeaders,
        });
      }
    }

    if (request.method === "POST" && url.pathname === "/api/login") {
      const res = await handleLogin(request, env);
      return withCors(res, corsHeaders);
    }

    if (request.method === "GET" && url.pathname === "/api/member/me") {
      const res = await handleMe(request, env);
      return withCors(res, corsHeaders);
    }

    if (request.method === "POST" && url.pathname === "/api/logout") {
      const res = await handleLogout(request, env);
      return withCors(res, corsHeaders);
    }

    if (request.method === "POST" && url.pathname === "/api/forgot-password") {
      const res = await handleForgotPassword(request, env);
      return withCors(res, corsHeaders);
    }

    if (request.method === "POST" && url.pathname === "/api/reset-password") {
      const res = await handleResetPassword(request, env);
      return withCors(res, corsHeaders);
    }

    // ---- Admin-only ----
    const adminKey = request.headers.get("X-Admin-Key");
    const isAdmin = adminKey && env.ADMIN_KEY && adminKey === env.ADMIN_KEY;

    // Admin store write (auto-sync for site data)
    const adminStoreMatch = url.pathname.match(/^\/api\/admin\/store\/([^/]+)$/);
    if (adminStoreMatch && request.method === "PUT") {
      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      try {
        const key = decodeURIComponent(adminStoreMatch[1]);
        const body = await request.json();
        await storePut(env, key, body.value);
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: jsonHeaders,
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Server error", detail: String(err) }), {
          status: 500,
          headers: jsonHeaders,
        });
      }
    }

    if (url.pathname === "/api/admin/members") {
      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }

      if (request.method === "GET") {
        try {
          let results;
          try {
            const q = await env.DB.prepare(
              `SELECT id, full_name, gender, date_of_birth, branch, occupation, phone, email,
                      address, next_of_kin_name, next_of_kin_phone, status, submitted_at, photo
               FROM members ORDER BY submitted_at DESC`
            ).all();
            results = q.results;
          } catch (e) {
            const q = await env.DB.prepare(
              `SELECT id, full_name, gender, date_of_birth, branch, occupation, phone, email,
                      address, next_of_kin_name, next_of_kin_phone, status, submitted_at
               FROM members ORDER BY submitted_at DESC`
            ).all();
            results = q.results;
          }

          return new Response(JSON.stringify({ members: results }), {
            status: 200,
            headers: jsonHeaders,
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: "Server error" }), {
            status: 500,
            headers: jsonHeaders,
          });
        }
      }

      if (request.method === "POST") {
        try {
          const res = await handleAdminCreateMember(request, env);
          return withCors(res, corsHeaders);
        } catch (err) {
          return new Response(JSON.stringify({ error: "Server error", detail: String(err) }), {
            status: 500,
            headers: jsonHeaders,
          });
        }
      }

      if (request.method === "PATCH") {
        try {
          const body = await request.json();
          if (!body.id) {
            return new Response(JSON.stringify({ error: "Missing id" }), {
              status: 400,
              headers: jsonHeaders,
            });
          }

          // Update whichever editable fields were sent, so both the quick
          // status-change dropdown and the full edit form work correctly.
          const editable = [
            "full_name", "gender", "date_of_birth", "branch", "occupation",
            "phone", "email", "address", "next_of_kin_name", "next_of_kin_phone",
            "status", "photo",
          ];
          const sets = [];
          const values = [];
          for (const field of editable) {
            if (Object.prototype.hasOwnProperty.call(body, field)) {
              sets.push(`${field} = ?`);
              values.push(body[field]);
            }
          }
          if (!sets.length) {
            return new Response(JSON.stringify({ error: "No fields to update" }), {
              status: 400,
              headers: jsonHeaders,
            });
          }
          values.push(body.id);

          try {
            await env.DB.prepare(`UPDATE members SET ${sets.join(", ")} WHERE id = ?`)
              .bind(...values)
              .run();
          } catch (e) {
            // Fallback if photo column doesn't exist on this database
            const idx = editable.indexOf("photo");
            if (Object.prototype.hasOwnProperty.call(body, "photo")) {
              const sets2 = sets.filter((s) => !s.startsWith("photo"));
              const values2 = [];
              for (const field of editable) {
                if (field === "photo") continue;
                if (Object.prototype.hasOwnProperty.call(body, field)) values2.push(body[field]);
              }
              values2.push(body.id);
              await env.DB.prepare(`UPDATE members SET ${sets2.join(", ")} WHERE id = ?`)
                .bind(...values2)
                .run();
            } else {
              throw e;
            }
          }

          // Optional SMS when membership is approved (promotional route)
          if (body.status === "approved") {
            try {
              const m = await env.DB.prepare(
                `SELECT full_name, phone FROM members WHERE id = ?`
              ).bind(body.id).first();
              if (m && m.phone) {
                await sendSms(
                  env,
                  m.phone,
                  `Adagbor Descendant Association: your membership is approved. Log in at ${SITE_URL}/login.html`
                );
              }
            } catch (smsErr) {
              console.error("Approval SMS failed:", smsErr);
            }
          }

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: jsonHeaders,
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: "Server error" }), {
            status: 500,
            headers: jsonHeaders,
          });
        }
      }
    }

    // ---- Admin: send promotional SMS ----
    if (request.method === "POST" && url.pathname === "/api/admin/sms") {
      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      try {
        const body = await request.json();
        const message = String(body.message || "").trim();
        if (!message) {
          return new Response(JSON.stringify({ error: "Message is required." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }

        let phones = [];
        if (Array.isArray(body.phones) && body.phones.length) {
          phones = body.phones;
        } else if (Array.isArray(body.memberIds) && body.memberIds.length) {
          const placeholders = body.memberIds.map(() => "?").join(",");
          const rows = await env.DB.prepare(
            `SELECT phone FROM members WHERE id IN (${placeholders}) AND phone IS NOT NULL AND phone != ''`
          )
            .bind(...body.memberIds)
            .all();
          phones = (rows.results || []).map((r) => r.phone);
        } else if (body.allApproved === true) {
          const rows = await env.DB.prepare(
            `SELECT phone FROM members WHERE status = 'approved' AND phone IS NOT NULL AND phone != ''`
          ).all();
          phones = (rows.results || []).map((r) => r.phone);
        } else {
          return new Response(
            JSON.stringify({ error: "Provide memberIds, phones, or allApproved: true." }),
            { status: 400, headers: jsonHeaders }
          );
        }

        const result = await sendSmsBulk(env, phones, message);
        return new Response(JSON.stringify(result), {
          status: result.ok ? 200 : 502,
          headers: jsonHeaders,
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: "Server error", detail: String(err) }),
          { status: 500, headers: jsonHeaders }
        );
      }
    }

    const setPasswordMatch = url.pathname.match(/^\/api\/admin\/members\/(\d+)\/set-password$/);
    if (setPasswordMatch && request.method === "PATCH") {
      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      const memberId = Number(setPasswordMatch[1]);
      const res = await handleSetPassword(request, env, memberId);
      return withCors(res, corsHeaders);
    }

    const generatePasswordMatch = url.pathname.match(/^\/api\/admin\/members\/(\d+)\/generate-password$/);
    if (generatePasswordMatch && request.method === "POST") {
      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      const memberId = Number(generatePasswordMatch[1]);
      const res = await handleGeneratePassword(request, env, memberId);
      return withCors(res, corsHeaders);
    }

    return new Response("Not found", { status: 404, headers: corsHeaders });
  },
};

async function withCors(response, corsHeaders) {
  const merged = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders)) {
    merged.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    headers: merged,
  });
}
