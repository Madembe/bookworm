// POST /api/payfast-itn  - PayFast Instant Transaction Notification (server-to-server).
// Verifies the signature, the merchant, and PayFast's own confirmation, then marks the order paid.
const crypto = require("crypto");
const { buildParamString, hosts, need } = require("./_lib/payfast");

async function readRaw(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).end();
  try {
    need("PAYFAST_MERCHANT_ID", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY");
    const raw = await readRaw(req);
    const entries = [...new URLSearchParams(raw).entries()];
    const data = Object.fromEntries(entries);

    // 1. Signature (fields in the order received, excluding the signature itself)
    const pairs = entries.filter(([k]) => k !== "signature");
    const expected = crypto.createHash("md5")
      .update(buildParamString(pairs, process.env.PAYFAST_PASSPHRASE)).digest("hex");
    const given = String(data.signature || "");
    const ok = given.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
    if (!ok) { console.error("ITN: bad signature"); return res.status(400).end(); }

    // 2. Must be for our merchant account
    if (data.merchant_id !== process.env.PAYFAST_MERCHANT_ID) { console.error("ITN: wrong merchant"); return res.status(400).end(); }

    // 3. Ask PayFast to confirm this notification is genuine
    const vRes = await fetch(`https://${hosts()}/eng/query/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: buildParamString(pairs, null),
    });
    const vText = (await vRes.text()).trim();
    if (vText !== "VALID") { console.error("ITN: PayFast did not validate"); return res.status(400).end(); }

    // 4. Only completed payments change anything
    if (data.payment_status !== "COMPLETE") return res.status(200).end();

    // 5. Database re-checks the amount against what the buyer was actually charged
    const rpc = await fetch(`${process.env.SUPABASE_URL}/rest/v1/rpc/mark_transaction_paid`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify({
        p_tx_id: data.m_payment_id,
        p_amount: Number(data.amount_gross),
        p_pf_payment_id: data.pf_payment_id,
      }),
    });
    if (!rpc.ok) {
      const msg = await rpc.text();
      console.error("ITN: mark_transaction_paid failed:", msg);
      // A genuine mismatch will never succeed on retry; anything else should be retried by PayFast.
      if (/amount mismatch|transaction not found/.test(msg)) return res.status(200).end();
      return res.status(500).end();
    }
    return res.status(200).end();
  } catch (e) {
    console.error("ITN error:", e.message);
    return res.status(500).end();
  }
};
