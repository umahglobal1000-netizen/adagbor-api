// forgot-password-routes.js
// Add these handlers into your adagbor-api Worker.
//
// Routes to add in your router:
//   if (url.pathname === "/api/forgot-password" && request.method === "POST")
//     return handleForgotPassword(request, env);
//   if (url.pathname === "/api/reset-password" && request.method === "POST")
//     return handleResetPassword(request, env);
//
// Requires a Resend account (https://resend.com) — free tier covers small
// volumes. After signing up:
//   1. Add and verify a sending domain (or use their onboarding@resend.dev
//      test address while you set your domain up).
//   2. Create an API key.
//   3. Add it as a secret on your adagbor-api Worker:
//        wrangler secret put RESEND_API_KEY
//
// Reuses hashPassword() from auth-routes.js.

import { hashPassword } from "./auth-routes.js"; // adjust path if needed

const SITE_URL = "https://adagbor1.umahglobal1000.workers.dev";
const RESET_TOKEN_MINUTES = 60;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function generateToken() {
  return [...crypto.getRandomValues(new Uint8Array(32))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------- Step 1: request a reset link ----------

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

// ---------- Step 2: submit new password with token ----------

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

export { handleForgotPassword, handleResetPassword };
