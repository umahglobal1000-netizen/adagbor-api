export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/api/members") {
      try {
        const body = await request.json();

        if (!body.full_name || !body.phone || !body.declared) {
          return new Response(JSON.stringify({ error: "Missing required fields" }), {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
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
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Server error" }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }
    }

    return new Response("Not found", { status: 404, headers: corsHeaders });
  },
};
