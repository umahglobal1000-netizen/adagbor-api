/**
 * Shared store: admin writes → API → members/public read.
 * Falls back to localStorage if API is unavailable.
 */
(function (global) {
  const API_BASE = "https://adagbor-api.umahglobal1000.workers.dev";
  const CACHE_PREFIX = "adagbor_cache_";

  function cacheGet(key) {
    try {
      const raw = localStorage.getItem(CACHE_PREFIX + key);
      if (raw) return JSON.parse(raw);
    } catch (e) {}
    try {
      // legacy keys used before sync layer
      const legacy = {
        announcements: "adagbor_announcements",
        resolutions: "adagbor_resolutions",
        attendance: "adagbor_attendance",
        payments: "adagbor_contribution_payments",
        contribution_types: "adagbor_contribution_types",
        executives: "adagbor_executives",
      };
      const lk = legacy[key];
      if (lk) {
        const raw = localStorage.getItem(lk);
        if (raw) return JSON.parse(raw);
      }
    } catch (e) {}
    return null;
  }

  function cacheSet(key, value) {
    try {
      localStorage.setItem(CACHE_PREFIX + key, JSON.stringify(value));
      const legacy = {
        announcements: "adagbor_announcements",
        resolutions: "adagbor_resolutions",
        attendance: "adagbor_attendance",
        payments: "adagbor_contribution_payments",
        contribution_types: "adagbor_contribution_types",
        executives: "adagbor_executives",
      };
      if (legacy[key]) localStorage.setItem(legacy[key], JSON.stringify(value));
    } catch (e) {}
  }

  async function load(key, fallback) {
    const fb = fallback != null ? fallback : null;
    try {
      const res = await fetch(`${API_BASE}/api/store/${encodeURIComponent(key)}`, {
        credentials: "include",
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        const value = data.value !== undefined ? data.value : data;
        cacheSet(key, value);
        return value;
      }
    } catch (e) {}
    const cached = cacheGet(key);
    return cached != null ? cached : fb;
  }

  async function save(key, value, adminKey) {
    cacheSet(key, value);
    if (!adminKey) return { ok: true, local: true };
    try {
      const res = await fetch(`${API_BASE}/api/admin/store/${encodeURIComponent(key)}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Admin-Key": adminKey,
        },
        body: JSON.stringify({ value }),
      });
      if (res.ok) return { ok: true, remote: true };
      const err = await res.json().catch(() => ({}));
      return { ok: false, local: true, error: err.error || res.statusText };
    } catch (e) {
      return { ok: false, local: true, error: e.message };
    }
  }

  global.AdagborStore = { load, save, cacheGet, cacheSet, API_BASE };
})(typeof window !== "undefined" ? window : globalThis);
