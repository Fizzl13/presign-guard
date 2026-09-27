// Signed verdicts: every paid answer carries a `receipt` signed by
// presign-guard's published signer, so a buyer (or an auditor later) can prove
// which verdict was delivered for which request, not only that money moved.
//
// What is signed: the whole response body with `receipt.signature` left out,
// serialised as canonical JSON (keys sorted at every level, no whitespace,
// non-ASCII escaped as \uXXXX, the same bytes as Python's
// json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)),
// signed with EIP-191 personal_sign. The receipt holds a request id, the route,
// a SHA-256 of the request input (recomputable by the buyer), the time and the
// signer, plus the payment (payer and EIP-3009 nonce, see paymentOf), so the
// verdict cannot be moved to another request or flipped without breaking the
// signature, and anyone can find the on-chain payment behind it.
//
// The key comes from RECEIPT_SIGNER_SECRET: any long random string (Render's
// "Generate" button), hashed into a private key. It holds no funds and signs
// nothing but receipts. Without it, answers are unsigned, as before.

import { createHash, randomUUID } from "node:crypto";
import { keccak256, stringToBytes, recoverMessageAddress, isAddress, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const ALGORITHM = "EIP-191 personal_sign over canonical JSON of the response without receipt.signature";

// Canonical JSON: sorted keys, compact, ASCII only. undefined members are dropped
// (as JSON.stringify does), so the signed bytes match what the client receives.
export function canonicalJson(value) {
  const ascii = (s) => JSON.stringify(s).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  const walk = (v) => {
    if (v === null || typeof v !== "object") return v === undefined ? undefined : typeof v === "string" ? ascii(v) : JSON.stringify(v);
    if (typeof v.toJSON === "function") return walk(v.toJSON());
    if (Array.isArray(v)) return `[${v.map((x) => walk(x) ?? "null").join(",")}]`;
    const parts = Object.keys(v).sort().flatMap((k) => {
      const inner = walk(v[k]);
      return inner === undefined ? [] : [`${ascii(k)}:${inner}`];
    });
    return `{${parts.join(",")}}`;
  };
  return walk(value);
}

export const sha256 = (s) => createHash("sha256").update(s).digest("hex");

// What the buyer sent, hashed the same way on both sides.
export const inputHash = (route, input) => sha256(canonicalJson({ route, input: input ?? {} }));

// The payment behind a paid answer, from the x402 payment payload (the
// PAYMENT-SIGNATURE / X-PAYMENT header, or _meta["x402/payment"] over MCP):
// - EVM (EIP-3009): payer and nonce. The settlement is the asset contract's
//   AuthorizationUsed(payer, nonce) event, so anyone can find the on-chain
//   transfer that paid for this answer without trusting us.
// - Solana: payer (the transfer authority) and a SHA-256 of the signed
//   transaction the client sent; the facilitator adds the fee-payer signature
//   when it settles, so the final transaction id is not known yet here.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
}

// The transfer authority of a partially signed Solana transaction: signer #2
// after the facilitator's fee payer (x402 exact on Solana).
export function svmPayer(base64Tx) {
  try {
    const b = Buffer.from(base64Tx, "base64");
    let o = 0;
    const compact = () => { let v = 0, shift = 0, byte; do { byte = b[o++]; v |= (byte & 0x7f) << shift; shift += 7; } while (byte & 0x80); return v; };
    const signatures = compact();
    o += 64 * signatures;
    if (b[o] & 0x80) o++; // versioned message prefix
    const required = b[o];
    o += 3; // header
    const keys = compact();
    if (required < 2 || keys < 2 || b.length < o + 64) return null;
    return base58(b.subarray(o + 32, o + 64));
  } catch {
    return null;
  }
}

export function paymentOf(p) {
  if (!p || typeof p !== "object") return null;
  const acc = p.accepted || p; // v2 carries the chosen requirement in accepted; v1 at the top level
  const out = { network: acc.network ?? null, asset: acc.asset ?? null, amount: acc.amount ?? acc.maxAmountRequired ?? null, pay_to: acc.payTo ?? null };
  const auth = p.payload && p.payload.authorization;
  const tx = p.payload && p.payload.transaction;
  if (auth && auth.from && auth.nonce) return { ...out, amount: auth.value ?? out.amount, payer: auth.from, nonce: auth.nonce, proof: "eip3009" };
  if (typeof tx === "string") return { ...out, payer: svmPayer(tx), transaction_sha256: sha256(tx), proof: "svm-transaction" };
  return out.network ? out : null;
}

// The decoded payment payload from the request headers (base64 or base64url JSON).
export function paymentFromHeaders(headers) {
  const raw = headers["payment-signature"] || headers["x-payment"];
  if (!raw) return null;
  try {
    return paymentOf(JSON.parse(Buffer.from(String(raw), "base64").toString("utf8")));
  } catch {
    return null;
  }
}

// Older signer addresses stay published so old receipts still verify:
// RECEIPT_RETIRED_SIGNERS="0xabc…:2026-09-27/2026-12-01,0xdef…:…/…".
function retiredSigners(env) {
  return String(env.RECEIPT_RETIRED_SIGNERS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      const [address, range = ""] = entry.split(":");
      const [valid_from = null, valid_until = null] = range.split("/");
      return isAddress(address) ? { address: getAddress(address), valid_from, valid_until } : null;
    })
    .filter(Boolean);
}

export function createSigner(env = process.env) {
  const secret = String(env.RECEIPT_SIGNER_SECRET || "").trim();
  if (secret.length < 32) return null; // unset (or too short to be a real secret): no signing
  const account = privateKeyToAccount(keccak256(stringToBytes(`presign-guard receipt signer v1:${secret}`)));
  const retired = retiredSigners(env);
  return {
    address: account.address,
    signers: [{ address: account.address, status: "current", valid_from: env.RECEIPT_SIGNER_SINCE || null, valid_until: null }, ...retired.map((r) => ({ ...r, status: "retired" }))],
    // Returns the body with a signed receipt added; the verdict fields are untouched.
    async sign(body, { route, input, payment = null }) {
      const receipt = {
        request_id: randomUUID(),
        route,
        input_sha256: inputHash(route, input),
        ...(payment && { payment }),
        signed_at: new Date().toISOString(),
        signer: account.address,
        algorithm: "eip191-canonical-json-v1",
      };
      const unsigned = { ...body, receipt };
      const signature = await account.signMessage({ message: canonicalJson(unsigned) });
      return { ...body, receipt: { ...receipt, signature } };
    },
  };
}

// Checks a signed body: the signature recovers to receipt.signer, and (with a
// signer list) that address is one of ours. Optionally checks the input hash.
export async function verifyReceipt(body, { signers = [], route, input } = {}) {
  const r = body && body.receipt;
  if (!r || typeof r.signature !== "string") return { valid: false, reason: "no receipt.signature in the body" };
  const { signature, ...rest } = r;
  let recovered;
  try {
    recovered = await recoverMessageAddress({ message: canonicalJson({ ...body, receipt: rest }), signature });
  } catch (err) {
    return { valid: false, reason: `signature does not parse: ${err.message}` };
  }
  if (!r.signer || recovered.toLowerCase() !== String(r.signer).toLowerCase()) {
    return { valid: false, reason: "signature does not match receipt.signer: the body or receipt was changed", recovered };
  }
  const known = signers.find((s) => s.address.toLowerCase() === recovered.toLowerCase());
  const out = { valid: true, signer: recovered, known_signer: signers.length ? Boolean(known) : null, signer_status: known ? known.status : null };
  if (route !== undefined && input !== undefined) out.input_matches = inputHash(route, input) === r.input_sha256;
  if (signers.length && !known) return { ...out, valid: false, reason: "signed, but not by a presign-guard signer" };
  if (out.input_matches === false) return { ...out, valid: false, reason: "signed, but for a different request input" };
  return out;
}

// Express: sign 200 JSON answers on the paid routes. Runs after the paywall, so
// only paid (or free-in-test) answers get here; errors stay unsigned.
export function signPaidResponses(signer, paidRoutes) {
  const paid = new Set(paidRoutes);
  return (req, res, next) => {
    const route = `${req.method} ${req.path}`;
    if (!signer || !paid.has(route)) return next();
    const json = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode !== 200 || !body || typeof body !== "object" || Array.isArray(body)) return json(body);
      const input = req.method === "GET" ? { ...req.query } : req.body;
      signer.sign(body, { route, input, payment: paymentFromHeaders(req.headers) }).then(json, (err) => {
        console.warn(`receipt signing failed on ${route}: ${err.message}`);
        json(body); // an unsigned verdict beats no verdict
      });
      return res;
    };
    next();
  };
}
