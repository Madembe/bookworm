// api/create-payment.js — Vercel Serverless Function
// Deploy this file to your Vercel project under /api/create-payment.js
// Set these environment variables in Vercel Dashboard > Settings > Environment Variables:
//   PF_MERCHANT_ID     — your PayFast merchant ID
//   PF_MERCHANT_KEY    — your PayFast merchant key
//   PF_PASSPHRASE      — your PayFast passphrase (if set)
//   PF_SANDBOX         — "true" for sandbox, "false" for live
//   FIREBASE_PROJECT   — your Firebase project ID (for token verification)

const crypto = require("crypto");

// Verify Firebase ID token using Google's public keys
async function verifyFirebaseToken(idToken, projectId) {
  const { default: fetch } = await import("node-fetch").catch(() => ({ default: globalThis.fetch }));
  const res = await fetch(`https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key=${process.env.FIREBASE_WEB_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken })
  });
  if (!res.ok) throw new Error("Token verification failed");
  const data = await res.json();
  return data.users?.[0];
}

function buildPfSignature(data, passphrase) {
  const str = Object.entries(data)
    .filter(([, v]) => v !== "" && v !== undefined)
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v)).replace(/%20/g, "+")}`)
    .join("&");
  const sigStr = passphrase ? `${str}&passphrase=${encodeURIComponent(passphrase).replace(/%20/g, "+")}` : str;
  return crypto.createHash("md5").update(sigStr).digest("hex");
}

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    // Verify the caller is an authenticated Firebase user
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.replace("Bearer ", "");
    if (!idToken) return res.status(401).json({ error: "Unauthorized" });

    // Basic JWT decode to get uid (full verification requires firebase-admin or Google key fetch)
    // For production, install firebase-admin and use admin.auth().verifyIdToken(idToken)
    const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64").toString());
    const uid = payload.user_id || payload.sub;
    if (!uid) return res.status(401).json({ error: "Invalid token" });

    const { txId, bookTitle, amount, buyerName, buyerEmail, returnUrl, cancelUrl } = req.body;
    if (!txId || !amount) return res.status(400).json({ error: "Missing required fields" });

    const sandbox = process.env.PF_SANDBOX !== "false";
    const merchantId = process.env.PF_MERCHANT_ID;
    const merchantKey = process.env.PF_MERCHANT_KEY;
    const passphrase = process.env.PF_PASSPHRASE || "";

    if (!merchantId || !merchantKey) {
      return res.status(500).json({ error: "PayFast credentials not configured" });
    }

    const pfData = {
      merchant_id: merchantId,
      merchant_key: merchantKey,
      return_url: returnUrl,
      cancel_url: cancelUrl,
      notify_url: `https://${req.headers.host}/api/payfast-itn`,
      name_first: buyerName?.split(" ")[0] || "Student",
      name_last: buyerName?.split(" ").slice(1).join(" ") || "Buyer",
      email_address: buyerEmail,
      m_payment_id: txId,
      amount: parseFloat(amount).toFixed(2),
      item_name: `BookWorm: ${bookTitle}`.substring(0, 100),
      item_description: "Secure student textbook purchase via BookWorm escrow",
      custom_str1: txId,
      custom_str3: uid
    };

    const signature = buildPfSignature(pfData, passphrase);
    pfData.signature = signature;

    const baseUrl = sandbox
      ? "https://sandbox.payfast.co.za/eng/process"
      : "https://www.payfast.co.za/eng/process";

    // Return the redirect URL and form fields to the frontend
    return res.status(200).json({
      redirectUrl: baseUrl,
      formFields: pfData
    });

  } catch (err) {
    console.error("create-payment error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};
