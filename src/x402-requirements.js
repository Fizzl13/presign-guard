// x402 payment check, payer side: before an agent signs an EIP-3009 payment for a 402 challenge, does the
// signature pay what the seller asked, to whom it asked, in the asset and on the network it asked, and no longer
// than needed? Research on x402 (arXiv 2604.11430 "Hardening x402", 2605.11781 "Five Attacks on x402", and the
// study of 15 facilitators, July 2026) shows a hostile or broken server or client library can inflate the
// price, swap the recipient or token, or ask for a long-lived authorization that works like a bearer token.
// The agent passes the requirements it is paying (`accepted`, one entry of the 402's accepts list); every
// check reads the payment from the typed data about to be signed, never from a claim. Offline, no sources.

const AMOUNT_RE = /^(0|[1-9][0-9]*)$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
// x402 v1 network names for the EVM chains presign-guard checks; v2 uses CAIP-2 (eip155:<id>).
const V1_NETWORKS = { base: 8453, "base-sepolia": 84532, ethereum: 1, optimism: 10, polygon: 137, arbitrum: 42161, bsc: 56, avalanche: 43114 };
// A signature that outlives the seller's timeout by this much is a standing payment anyone holding it can settle.
const VALIDITY_GRACE_SECONDS = 600;
const VALIDITY_FLOOR_SECONDS = 3600;

function chainOf(network) {
  if (typeof network !== "string") return null;
  const m = /^eip155:(\d{1,12})$/.exec(network.trim());
  if (m) return Number(m[1]);
  return V1_NETWORKS[network.trim().toLowerCase()] ?? null;
}

// Parse and lightly validate what the agent says it is paying. Throws on a malformed value.
export function parseRequirements(raw) {
  const a = raw && typeof raw === "object" && !Array.isArray(raw) && raw.accepted && typeof raw.accepted === "object" ? raw.accepted : raw;
  if (!a || typeof a !== "object" || Array.isArray(a)) throw new Error("x402 must be the payment requirements you are paying: { accepted: { scheme, network, amount, asset, payTo, maxTimeoutSeconds } }");
  const amount = a.amount ?? a.maxAmountRequired;
  if (amount !== undefined && !AMOUNT_RE.test(String(amount))) throw new Error("x402 amount must be an integer in base units");
  for (const k of ["asset", "payTo"]) if (a[k] !== undefined && !ADDRESS_RE.test(String(a[k]))) throw new Error(`x402 ${k} must be a 0x address`);
  if (a.maxTimeoutSeconds !== undefined && !(Number.isInteger(a.maxTimeoutSeconds) && a.maxTimeoutSeconds >= 0)) throw new Error("x402 maxTimeoutSeconds must be a whole number of seconds");
  return {
    scheme: typeof a.scheme === "string" ? a.scheme.slice(0, 32) : undefined,
    network: typeof a.network === "string" ? a.network.slice(0, 64) : undefined,
    amount: amount !== undefined ? String(amount) : undefined,
    asset: a.asset !== undefined ? String(a.asset).toLowerCase() : undefined,
    payTo: a.payTo !== undefined ? String(a.payTo).toLowerCase() : undefined,
    maxTimeoutSeconds: a.maxTimeoutSeconds,
    extra: a.extra && typeof a.extra === "object" ? { name: a.extra.name, version: a.extra.version } : undefined,
  };
}

// payment: { chainId, to, token, value, validBefore (unix s), domainName, domainVersion } from the typed data.
// Returns { ok, failures: [{ code, reason }] (red), warnings: [{ code, reason }] (orange), notes (info) }.
export function checkX402Payment(req, payment, { now = Math.floor(Date.now() / 1000) } = {}) {
  const failures = [];
  const warnings = [];
  const notes = [];
  const lower = (s) => String(s ?? "").toLowerCase();

  if (req.scheme && req.scheme !== "exact") warnings.push({ code: "X402_SCHEME_UNEXPECTED", reason: `an EIP-3009 signature pays the "exact" scheme; the requirements say "${req.scheme}"` });
  if (req.network !== undefined) {
    const chain = chainOf(req.network);
    if (chain === null) warnings.push({ code: "X402_NETWORK_UNKNOWN", reason: `network "${req.network}" is not an EVM chain presign-guard knows` });
    else if (chain !== payment.chainId) failures.push({ code: "X402_NETWORK_MISMATCH", reason: `the seller asked for ${req.network} (chain ${chain}); this signature is for chain ${payment.chainId}` });
  }
  if (req.asset !== undefined && req.asset !== lower(payment.token)) failures.push({ code: "X402_ASSET_MISMATCH", reason: `the seller asked for token ${req.asset}; this signature spends ${lower(payment.token)}` });
  if (req.payTo !== undefined && req.payTo !== lower(payment.to)) failures.push({ code: "X402_RECIPIENT_MISMATCH", reason: `the seller asked to be paid at ${req.payTo}; this signature pays ${lower(payment.to)}` });
  if (req.amount !== undefined) {
    const asked = BigInt(req.amount);
    const signing = BigInt(payment.value);
    if (signing > asked) failures.push({ code: "X402_AMOUNT_ABOVE_REQUIRED", reason: `the seller asked for ${asked}; this signature pays ${signing} (base units)`, required: asked.toString(), signing: signing.toString() });
    else if (signing < asked) notes.push({ code: "X402_AMOUNT_BELOW_REQUIRED", reason: `this signature pays ${signing}, less than the ${asked} asked; the seller will refuse it` });
  }
  if (payment.validBefore !== null && payment.validBefore !== undefined) {
    const left = payment.validBefore - now;
    const allowed = Math.max(VALIDITY_FLOOR_SECONDS, (req.maxTimeoutSeconds ?? 0) + VALIDITY_GRACE_SECONDS);
    if (left > allowed) warnings.push({ code: "X402_VALIDITY_TOO_LONG", reason: `the authorization stays valid for ${Math.round(left / 60)} minutes; whoever holds it can settle it until then (the seller's timeout is ${req.maxTimeoutSeconds ?? "not given"} seconds)`, validForSeconds: left });
  }
  if (req.extra) {
    if (typeof req.extra.name === "string" && payment.domainName && req.extra.name !== payment.domainName) warnings.push({ code: "X402_DOMAIN_MISMATCH", reason: `the seller names the token "${req.extra.name}"; the signature's domain says "${payment.domainName}"` });
    else if (typeof req.extra.version === "string" && payment.domainVersion && req.extra.version !== payment.domainVersion) warnings.push({ code: "X402_DOMAIN_MISMATCH", reason: `the seller gives EIP-712 version "${req.extra.version}"; the signature's domain says "${payment.domainVersion}"` });
  }
  return { ok: failures.length === 0 && warnings.length === 0, failures, warnings, notes };
}
