// POST /api/admin-create-user   Authorization: Bearer <admin's Supabase JWT>
// body: { name, email, password, role, notes }
// Only a signed-in admin can call this. The new account is created with the Supabase admin API (server-side).
const ROLES = ["support", "listings", "finance", "operations"];

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY)
    return res.status(500).json({ error: "Server is not configured" });
  try {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Not signed in" });
    let body = req.body;
    if (typeof body === "string") body = JSON.parse(body || "{}");
    const { name, email, password, role, notes } = body || {};
    if (!name || !email || !password || !ROLES.includes(role))
      return res.status(400).json({ error: "Name, email, password and a valid role are required" });
    if (String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    // 1. Who is calling? Must be an admin.
    const uRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, { headers: { apikey: SUPABASE_ANON_KEY, Authorization: auth } });
    if (!uRes.ok) return res.status(401).json({ error: "Session expired" });
    const caller = await uRes.json();
    const pRes = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${caller.id}&select=role,name`, { headers: { apikey: SUPABASE_ANON_KEY, Authorization: auth } });
    const prof = pRes.ok ? (await pRes.json())[0] : null;
    if (!prof || prof.role !== "admin") return res.status(403).json({ error: "Only an admin can add team members" });

    const svc = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, "Content-Type": "application/json" };

    // 2. Create the account (already confirmed, so the new person can sign in straight away)
    const cRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST", headers: svc,
      body: JSON.stringify({ email, password, email_confirm: true, user_metadata: { name, account_type: "student" } }),
    });
    const created = await cRes.json();
    if (!cRes.ok) {
      const exists = /already|registered|exists/i.test(JSON.stringify(created));
      return res.status(exists ? 409 : 400).json({ error: exists ? "An account already exists for this email" : "Could not create the account", code: exists ? "auth/email-already-in-use" : undefined });
    }
    const uid = created.id;

    // 3. Give them their staff role and record the team member
    await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${uid}`, { method: "PATCH", headers: svc, body: JSON.stringify({ role, name }) });
    const tRes = await fetch(`${SUPABASE_URL}/rest/v1/team_members`, {
      method: "POST", headers: svc,
      body: JSON.stringify({ user_id: uid, name, email, role, notes: notes || null, active: true, created_by: prof.name || "admin" }),
    });
    if (!tRes.ok) return res.status(500).json({ error: "Account created but the team record failed - check team members" });
    return res.status(200).json({ ok: true, user_id: uid });
  } catch (e) {
    console.error("admin-create-user:", e.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
};
