// Shared PayFast helpers. Server-side only: secrets come from environment variables.
const crypto = require("crypto");

// PHP-style urlencode, which is what PayFast signs against.
function pfEncode(v) {
  return encodeURIComponent(String(v).trim())
    .replace(/%20/g, "+")
    .replace(/[!'()*~]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function buildParamString(pairs, passphrase) {
  let s = pairs.map(([k, v]) => `${k}=${pfEncode(v)}`).join("&");
  if (passphrase) s += `&passphrase=${pfEncode(passphrase)}`;
  return s;
}

function sign(pairs, passphrase) {
  return crypto.createHash("md5").update(buildParamString(pairs, passphrase)).digest("hex");
}

function isSandbox() {
  return String(process.env.PAYFAST_SANDBOX).toLowerCase() === "true";
}

const hosts = () => (isSandbox() ? "sandbox.payfast.co.za" : "www.payfast.co.za");

function siteUrl() {
  if (process.env.SITE_URL) return process.env.SITE_URL.replace(/\/$/, "");
  const h = process.env.VERCEL_BRANCH_URL || process.env.VERCEL_URL;
  return h ? `https://${h}` : "";
}

function need(...names) {
  const missing = names.filter((n) => !process.env[n]);
  if (missing.length) throw new Error("Missing environment variables: " + missing.join(", "));
}

module.exports = { pfEncode, buildParamString, sign, isSandbox, hosts, siteUrl, need };
