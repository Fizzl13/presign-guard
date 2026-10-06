// Mandate check (the x402 `authority` extension, draft x402-mandate/1, x402-foundation/x402#3220):
// a principal signs a bounded spending capability for an agent ("spend up to CAP, to recipients
// in R, until T"). Before the agent signs an EIP-3009 payment, presign-guard checks it against that
// grant, offline: the issuer's Ed25519 signature, payer = subject, token = asset, recipient in
// scope, amount within perPayment and cap, not expired, and the payment's nonce equal to the
// binding of (mandate, paymentId) (§7), so the settled payment will prove which grant it used.
//
// Only the single-payment checks (§6, §7). Cumulative spend (§8–§11: spend log, committed head,
// payee attestations) needs the accountant's state and is not checked here; the answer says so.
// Every check reads the payment from the typed data about to be signed, never from a claim (§6).
import { createHash, createPublicKey, verify } from "node:crypto";

export const MANDATE_VERSION = "x402-mandate/1";
const TAG = "x402-mandate/1\n";
const BINDING_TAG = "x402-mandate-binding/1\n";
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const AMOUNT_RE = /^(0|[1-9][0-9]*)$/;
const PAYMENT_ID_RE = /^[A-Za-z0-9._~-]{1,64}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const FIELDS = new Set(["v", "issuer", "subject", "asset", "cap", "perPayment", "recipients", "accountant", "purpose", "notAfter", "nonce", "parent"]);
const REQUIRED = ["v", "issuer", "subject", "asset", "cap", "recipients", "accountant", "purpose", "notAfter", "nonce"];

// RFC 8785 (JCS) for the JSON this profile signs: strings, integers within 2^52, arrays, objects.
export function jcs(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value) || Math.abs(value) > 2 ** 52) throw new Error("only integers within 2^52 are signed");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  throw new Error("value cannot be canonicalized");
}

const wellFormed = (s) => typeof s === "string" && s.isWellFormed();
const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");

// Strict RFC 3339 UTC that survives a round trip (2026-02-30 is invalid).
function strictTime(s) {
  if (typeof s !== "string" || !TIME_RE.test(s)) return null;
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) return null;
  const back = new Date(ms).toISOString();
  const norm = s.includes(".") ? s.replace(/\.(\d{1,3})Z$/, (_, f) => `.${f.padEnd(3, "0")}Z`) : s.replace(/Z$/, ".000Z");
  return back === norm ? ms : null;
}

// §3: null when valid, else the first reason it is not.
export function mandateProblem(m) {
  if (!m || typeof m !== "object" || Array.isArray(m)) return "mandate must be an object";
  for (const k of Object.keys(m)) if (!FIELDS.has(k)) return `unknown member '${k}' (the object is closed)`;
  for (const k of REQUIRED) if (m[k] === undefined) return `missing ${k}`;
  if (m.v !== MANDATE_VERSION) return `v must be ${MANDATE_VERSION}`;
  for (const k of ["issuer", "subject", "asset", "cap", "accountant", "purpose", "notAfter", "nonce", ...(m.parent !== undefined ? ["parent"] : []), ...(m.perPayment !== undefined ? ["perPayment"] : [])]) {
    if (!wellFormed(m[k])) return `${k} must be a well-formed string`;
  }
  if (!KEY_RE.test(m.issuer)) return "issuer must be a base64url Ed25519 public key";
  if (!AMOUNT_RE.test(m.cap)) return "cap must be an integer minor-unit string";
  if (m.perPayment !== undefined) {
    if (!AMOUNT_RE.test(m.perPayment)) return "perPayment must be an integer minor-unit string";
    if (BigInt(m.perPayment) > BigInt(m.cap)) return "perPayment exceeds cap";
  }
  if (!Array.isArray(m.recipients) || m.recipients.length === 0) return "recipients must be a non-empty array";
  if (!m.recipients.every(wellFormed)) return "recipients must be well-formed strings";
  if (m.recipients.includes("*") && m.recipients.length > 1) return "'*' must be the sole recipient";
  if (m.accountant !== "payees" && !KEY_RE.test(m.accountant)) return "accountant must be an Ed25519 key or 'payees'";
  if (m.accountant === "payees" && !m.recipients.every((r) => r === "*" || KEY_RE.test(r))) return "under 'payees' every recipient must be an Ed25519 key";
  if (strictTime(m.notAfter) === null) return "notAfter must be strict RFC 3339 UTC (…Z)";
  if (m.parent !== undefined && !DIGEST_RE.test(m.parent)) return "parent must be sha256:<64 hex>";
  return null;
}

export const mandateDigest = (m) => `sha256:${sha256Hex(TAG + jcs(m))}`;

// §7: the 32 bytes the payment's nonce must carry.
export function bindingBytes(digest, paymentId) {
  if (!DIGEST_RE.test(digest)) throw new Error("bad mandate digest");
  if (!PAYMENT_ID_RE.test(paymentId)) throw new Error("bad paymentId");
  return createHash("sha256").update(`${BINDING_TAG}${digest}\n${paymentId}`, "utf8").digest();
}
export const eip3009Binding = (digest, paymentId) => `0x${bindingBytes(digest, paymentId).toString("hex")}`;
export const permit2Binding = (digest, paymentId) => BigInt(`0x${bindingBytes(digest, paymentId).toString("hex")}`).toString();

function signatureValid(m, alg, sig) {
  if (alg !== "Ed25519" || typeof sig !== "string" || !SIG_RE.test(sig)) return false;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: m.issuer }, format: "jwk" });
    return verify(null, Buffer.from(TAG + jcs(m), "utf8"), key, Buffer.from(sig, "base64url"));
  } catch { return false; }
}

// A mandate names payer, recipient and asset as free strings; on EVM accept the bare address,
// a CAIP-10 account (eip155:<chain>:0x…) or a CAIP-19 asset (eip155:<chain>/erc20:0x…).
function evmMatch(id, address, chainId) {
  if (typeof id !== "string") return false;
  const m = /^(?:eip155:(\d+)[:/](?:erc20:)?)?(0x[0-9a-fA-F]{40})$/.exec(id.trim());
  if (!m) return false;
  if (m[1] && Number(m[1]) !== chainId) return false;
  return m[2].toLowerCase() === address.toLowerCase();
}

// envelope = { mandate, alg, sig }; payment = what the typed data says: { chainId, from, to,
// token, value (bigint), nonce (0x… bytes32) }. Returns { ok, digest?, failures[], warnings[] }.
// Total: malformed input gives a refusal, never an exception.
export function checkMandatePayment(envelope, paymentId, payment, { now = Date.now() } = {}) {
  const failures = [];
  const warnings = [];
  try {
    const m = envelope?.mandate;
    const problem = mandateProblem(m);
    if (problem) return { ok: false, failures: [{ code: "MANDATE_INVALID", reason: problem }], warnings };
    if (envelope.alg !== "Ed25519") return { ok: false, failures: [{ code: "MANDATE_BAD_SIGNATURE", reason: "alg must be Ed25519" }], warnings };
    const digest = mandateDigest(m);
    if (!signatureValid(m, envelope.alg, envelope.sig)) failures.push({ code: "MANDATE_BAD_SIGNATURE", reason: "the issuer's signature does not verify" });
    if (typeof paymentId !== "string" || !PAYMENT_ID_RE.test(paymentId)) {
      failures.push({ code: "MANDATE_BINDING_MISMATCH", reason: "paymentId must match ^[A-Za-z0-9._~-]{1,64}$" });
    } else if (String(payment.nonce).toLowerCase() !== eip3009Binding(digest, paymentId)) {
      failures.push({ code: "MANDATE_BINDING_MISMATCH", reason: "the payment nonce is not the binding of this mandate and paymentId", expected: eip3009Binding(digest, paymentId) });
    }
    if (!evmMatch(m.subject, payment.from, payment.chainId)) failures.push({ code: "MANDATE_WRONG_PAYER", reason: `payer ${payment.from} is not the mandate subject ${m.subject}` });
    if (!evmMatch(m.asset, payment.token, payment.chainId)) failures.push({ code: "MANDATE_WRONG_ASSET", reason: `token ${payment.token} is not the mandate asset ${m.asset}` });
    if (m.recipients[0] === "*") warnings.push({ code: "MANDATE_ANY_RECIPIENT", reason: "the mandate allows any recipient" });
    else if (!m.recipients.some((r) => evmMatch(r, payment.to, payment.chainId))) failures.push({ code: "MANDATE_RECIPIENT_OUT_OF_SCOPE", reason: `recipient ${payment.to} is not in the mandate's recipients` });
    const amount = BigInt(payment.value);
    if (m.perPayment !== undefined && amount > BigInt(m.perPayment)) failures.push({ code: "MANDATE_OVER_LIMIT", reason: `payment ${amount} exceeds per-payment bound ${m.perPayment}` });
    else if (amount > BigInt(m.cap)) failures.push({ code: "MANDATE_OVER_LIMIT", reason: `payment ${amount} exceeds cap ${m.cap}` });
    if (now >= strictTime(m.notAfter)) failures.push({ code: "MANDATE_EXPIRED", reason: `the mandate expired at ${m.notAfter}` });
    return { ok: failures.length === 0, digest, failures, warnings };
  } catch (err) {
    return { ok: false, failures: [{ code: "MANDATE_INVALID", reason: String(err?.message ?? err) }], warnings };
  }
}
