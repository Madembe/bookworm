// POST /api/create-payment   Authorization: Bearer <Supabase user JWT>   body: { tx_id }
// Builds a signed PayFast payment request. The amount comes from the database, never from the browser.
const { sign, hosts, siteUrl, need } = require("./_lib/payfast");

// Field order matters for PayFast signatures.
const FIELD_ORDER = ["merchant_id", "merchant_key", "return_url", "cancel_url", "notify_url",
  "email_address", "m_payment_id", "amount", "item_name"];

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  try {
    need("PAYFAST_MERCHANT_ID", "PAYFAST_MERCHANT_KEY", "SUPABASE_URL", "SUPABASE_ANON_KEY");
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Not signed in" });

    let body = req.body;
    if (typeof body === "string") body = JSON.parse(body || "{}");
    const txId = body && body.tx_id;
    if (!txId || !/^[0-9a-f-]{36}$/i.test(txId)) return res.status(400).json({ error: "Invalid tx_id" });

    const sbHeaders = { apikey: process.env.SUPABASE_ANON_KEY, Authorization: auth };

    // Who is calling?
    const uRes = await fetch(`${process.env.SUPABASE_URL}/auth/v1/user`, { headers: sbHeaders });
    if (!uRes.ok) return res.status(401).json({ error: "Session expired - please sign in again" });
    const user = await uRes.json();

    // Row-level security means this only returns the caller's own transaction.
    const tRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/transactions?id=eq.${txId}&select=id,buyer_id,total_amount,status,books(title)`,
      { headers: sbHeaders });
    const rows = tRes.ok ? await tRes.json() : [];
    const tx = rows[0];
    if (!tx || tx.buyer_id !== user.id) return res.status(404).json({ error: "Order not found" });
    if (tx.status !== "awaiting_payment") return res.status(409).json({ error: "This order is not awaiting payment" });

    const base = siteUrl();
    const fields = {
      merchant_id: process.env.PAYFAST_MERCHANT_ID,
      merchant_key: process.env.PAYFAST_MERCHANT_KEY,
      return_url: `${base}/?payment=success&tx=${tx.id}`,
      cancel_url: `${base}/?payment=cancelled&tx=${tx.id}`,
      notify_url: `${base}/api/payfast-itn`,
      email_address: user.email || "",
      m_payment_id: tx.id,
      amount: Number(tx.total_amount).toFixed(2),
      item_name: `BookWorm: ${(tx.books && tx.books.title) || "Textbook"}`.slice(0, 100),
    };
    const pairs = FIELD_ORDER.filter((k) => fields[k]).map((k) => [k, fields[k]]);
    const signature = sign(pairs, process.env.PAYFAST_PASSPHRASE);
    return res.status(200).json({
      action: `https://${hosts()}/eng/process`,
      fields: { ...Object.fromEntries(pairs), signature },
    });
  } catch (e) {
    console.error("create-payment error:", e.message);
    return res.status(500).json({ error: "Could not start payment" });
  }
};
