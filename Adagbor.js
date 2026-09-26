// Adagbor.js
// Single-file Cloudflare Worker for the Adagbor Descendant Association API.
// Combines what used to be worker.js + auth-routes.js + admin-set-password.js
// + forgot-password-routes.js into one file for easier mobile upload/management.
//
// Bindings/secrets required (Cloudflare dashboard → Settings → Variables and Secrets):
//   DB               - D1 database binding
//   ADMIN_KEY        - shared secret for X-Admin-Key admin routes
//   RESEND_API_KEY   - Resend.com API key, for password-reset emails

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
    `SELECT id, full_name, gender, date_of_birth, branch, occupation, phone, email, address,
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

// ---------- Admin: set a member's password directly (fallback/override) ----------

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

// ---------- Forgot / reset password ----------

async function handleForgotPassword(request, env) {
  const { email } = await request.json();
  if (!email) {
    return json({ error: "Email is required." }, 400);
  }

  const member = await env.DB.prepare(
    `SELECT id, full_name FROM members WHERE email = ?`
  ).bind(email).first();

  // Always return the same success message whether or not the email
  // exists — this avoids leaking which emails are registered members.
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
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Adagbor Descendant Association <onboarding@resend.dev>", // swap once your domain is verified
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
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
      "Access-Control-Allow-Credentials": "true",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

    // ---- Public: submit a new membership application (with password) ----
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

        await env.DB.prepare(
          `INSERT INTO members
           (full_name, gender, date_of_birth, branch, occupation, phone, email, address, next_of_kin_name, next_of_kin_phone, declared, password_hash, password_salt)
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

    // ---- Public: member login / session-protected dashboard / logout ----
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

    // ---- Public: forgot / reset password ----
    if (request.method === "POST" && url.pathname === "/api/forgot-password") {
      const res = await handleForgotPassword(request, env);
      return withCors(res, corsHeaders);
    }

    if (request.method === "POST" && url.pathname === "/api/reset-password") {
      const res = await handleResetPassword(request, env);
      return withCors(res, corsHeaders);
    }

    // ---- Admin-only endpoints below: require X-Admin-Key header ----
    const adminKey = request.headers.get("X-Admin-Key");
    const isAdmin = adminKey && env.ADMIN_KEY && adminKey === env.ADMIN_KEY;

    if (url.pathname === "/api/admin/members") {
      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }

      // List all members
      if (request.method === "GET") {
        try {
          const { results } = await env.DB.prepare(
            `SELECT id, full_name, gender, date_of_birth, branch, occupation, phone, email,
                    address, next_of_kin_name, next_of_kin_phone, status, submitted_at
             FROM members ORDER BY submitted_at DESC`
          ).all();

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

      // Update a member's status (approve/reject)
      if (request.method === "PATCH") {
        try {
          const body = await request.json();
          if (!body.id || !body.status) {
            return new Response(JSON.stringify({ error: "Missing id or status" }), {
              status: 400,
              headers: jsonHeaders,
            });
          }

          await env.DB.prepare(`UPDATE members SET status = ? WHERE id = ?`)
            .bind(body.status, body.id)
            .run();

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

    // Admin: set a member's password directly (fallback/override)
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

    return new Response("Not found", { status: 404, headers: corsHeaders });
  },
};

// The internal handlers above build their own Response objects without CORS
// headers; this re-wraps their response with this Worker's CORS headers,
// preserving status, body and any headers they already set (e.g. Set-Cookie).
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
