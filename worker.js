export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

    // ---- Public: submit a new membership application ----
    if (request.method === "POST" && url.pathname === "/api/members") {
      try {
        const body = await request.json();

        if (!body.full_name || !body.phone || !body.declared) {
          return new Response(JSON.stringify({ error: "Missing required fields" }), {
            status: 400,
            headers: jsonHeaders,
          });
        }

        await env.DB.prepare(
          `INSERT INTO members
           (full_name, gender, date_of_birth, branch, occupation, phone, email, address, next_of_kin_name, next_of_kin_phone, declared)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
          body.declared ? 1 : 0
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

    return new Response("Not found", { status: 404, headers: corsHeaders });
   },
};
