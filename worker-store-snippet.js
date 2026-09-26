/**
 * Paste these routes into your existing adagbor-api Worker (and bind D1 or use KV).
 * D1 SQL (run once):
 *   CREATE TABLE IF NOT EXISTS app_store (
 *     key TEXT PRIMARY KEY,
 *     value TEXT NOT NULL,
 *     updated_at TEXT NOT NULL
 *   );
 *
 * Expects env.DB (D1) and env.ADMIN_KEY (secret), same as membership admin.
 */

// --- helpers (reuse your existing json() and cors if you have them) ---
async function storeGet(env, key) {
  const row = await env.DB.prepare("SELECT value FROM app_store WHERE key = ?").bind(key).first();
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return row.value; }
}

async function storePut(env, key, value) {
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO app_store (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  ).bind(key, JSON.stringify(value), now).run();
}

// In your fetch handler, before other routes:
//
// const storeMatch = url.pathname.match(/^\/api\/store\/([^/]+)$/);
// if (request.method === "GET" && storeMatch) {
//   const value = await storeGet(env, decodeURIComponent(storeMatch[1]));
//   return json({ value }, 200);
// }
//
// const adminStoreMatch = url.pathname.match(/^\/api\/admin\/store\/([^/]+)$/);
// if (request.method === "PUT" && adminStoreMatch) {
//   const adminKey = request.headers.get("X-Admin-Key");
//   if (adminKey !== env.ADMIN_KEY) return json({ error: "Unauthorized" }, 401);
//   const body = await request.json();
//   await storePut(env, decodeURIComponent(adminStoreMatch[1]), body.value);
//   return json({ success: true }, 200);
// }

export { storeGet, storePut };
