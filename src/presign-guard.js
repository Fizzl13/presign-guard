// presign-guard.js — pre-sign risk check for AI agents, sold via x402 (v2: adds EIP-712 signatures)
//
// Wired up in server.js.
//
// Env: PAY_TO, ANTHROPIC_API_KEY, optional GOPLUS_ACCESS_TOKEN, CLAUDE_MODEL, X402_NETWORK, FACILITATOR_URL
//
// Request types (POST body):
//   { type: "approval",    chainId, token, spender, amount }
//   { type: "transaction", chainId, to, data, value? }
//   { type: "signature",   chainId, typedData }   // eth_signTypedData_v4 payload (object or JSON string)
//   Add lang: "nl" | "en" on /v1/check/explain.
//
// Fail-closed rule: every error returns a non-2xx status and verdict: null, never "green".
// Verify in testing that your middleware version skips settlement on non-2xx responses.

import express from "express";
import { ROUTES, bazaarExtension, serviceMetadata } from "./discovery.js";
import { decodeFunctionData, isAddress, isHex, maxUint256, parseAbi } from "viem";

const GOPLUS_BASE = "https://api.gopluslabs.io/api/v1";
const GOPLUS_TIMEOUT_MS = 4000;
const CLAUDE_TIMEOUT_MS = 12000;
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX_ENTRIES = 5000;
const RECENT_DEPLOY_SECONDS = 30 * 86400;
const LONG_LIVED_SECONDS = 31 * 86400; // Permit2 UIs commonly default to 30 days
const SUPPORTED_CHAINS = new Set([1, 10, 56, 137, 8453, 42161]);
const UNLIMITED_THRESHOLD = maxUint256 / 2n; // dapps use 2^256-1, 2^255, or close to it
const UINT160_UNLIMITED = 2n ** 159n;         // Permit2 allowance amounts are uint160

// Canonical Permit2 deployment (same address on all supported chains)
const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const PERMIT2_ALLOWANCE_TYPES = new Set(["PermitSingle", "PermitBatch"]);
// EIP-3009 (USDC): one fixed payment to one recipient. This is what x402 asks agents to sign.
const TRANSFER_AUTHORIZATION_TYPES = new Set(["TransferWithAuthorization", "ReceiveWithAuthorization"]);
const PERMIT2_TRANSFER_TYPES = new Set([
  "PermitTransferFrom", "PermitBatchTransferFrom",
  "PermitWitnessTransferFrom", "PermitBatchWitnessTransferFrom",
]);

// approve(address,uint256) is shared by ERC-20 (amount) and ERC-721 (tokenId).
// A tokenId is small, so the unlimited check does not misfire on NFTs.
const APPROVAL_ABI = parseAbi([
  "function approve(address spender, uint256 amount)",
  "function increaseAllowance(address spender, uint256 addedValue)",
  "function setApprovalForAll(address operator, bool approved)",
]);

const ADDRESS_RED_FLAGS = [
  "cybercrime", "money_laundering", "phishing_activities", "stealing_attack",
  "blackmail_activities", "sanctioned", "financial_crime", "darkweb_transactions",
  "honeypot_related_address", "fake_kyc", "malicious_mining_activities",
];
const ADDRESS_ORANGE_FLAGS = ["blacklist_doubt", "mixer"];

// ---------- errors ----------

class ValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}
class UpstreamError extends Error {
  constructor(message) { super(message); this.status = 503; }
}

// ---------- cache (successes only; per instance, resets on restart) ----------

const cache = new Map();
async function cached(key, fn) {
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return hit.value;
  const value = await fn();
  cache.set(key, { value, expires: Date.now() + CACHE_TTL_MS });
  if (cache.size > CACHE_MAX_ENTRIES) cache.delete(cache.keys().next().value);
  return value;
}

// ---------- GoPlus ----------

async function goplus(path) {
  const headers = { accept: "application/json" };
  // Check GoPlus docs for the exact auth header format on your plan.
  if (process.env.GOPLUS_ACCESS_TOKEN) headers.Authorization = process.env.GOPLUS_ACCESS_TOKEN;

  let res;
  try {
    res = await fetch(`${GOPLUS_BASE}${path}`, { headers, signal: AbortSignal.timeout(GOPLUS_TIMEOUT_MS) });
  } catch (err) {
    throw new UpstreamError(`GoPlus unreachable (${err.name})`);
  }
  if (!res.ok) throw new UpstreamError(`GoPlus HTTP ${res.status}`);
  const body = await res.json().catch(() => null);
  if (!body || body.code !== 1 || !body.result) {
    throw new UpstreamError(`GoPlus error: ${body?.message ?? "unexpected response"}`);
  }
  return body.result;
}

// Some GoPlus endpoints key results by lowercase address, some return fields directly.
const pickResult = (result, address) => result?.[address] ?? result;
const flag = (v) => String(v) === "1";

function getAddressSecurity(chainId, address) {
  return cached(`addr:${chainId}:${address}`, () =>
    goplus(`/address_security/${address}?chain_id=${chainId}`));
}

function getContractSecurity(chainId, address) {
  return cached(`contract:${chainId}:${address}`, async () =>
    pickResult(await goplus(`/approval_security/${chainId}?contract_addresses=${address}`), address));
}

// ---------- input helpers ----------

function toAddress(v, name) {
  if (typeof v !== "string" || !isAddress(v, { strict: false })) {
    throw new ValidationError(`${name} must be a 0x-prefixed address`);
  }
  return v.toLowerCase();
}

function toUint(v, name) {
  if (typeof v !== "string" && typeof v !== "number") {
    throw new ValidationError(`${name} must be an integer string`);
  }
  try {
    const n = BigInt(v);
    if (n < 0n) throw new Error();
    return n;
  } catch {
    throw new ValidationError(`${name} must be a non-negative integer (decimal or 0x hex string)`);
  }
}

const toTimestamp = (v, name) => (v === undefined || v === null ? null : Number(toUint(v, name)));

// Internal shape shared by all request types:
// { chainId, kind, target, grants: [{ token, spender, amount, unlimited, mode, allForAll?, expiresAt? }],
//   revoke, revokedSpender?, offchain, value, selector?, primaryType?, signatureDeadline?, order? }

// ---------- on-chain transactions ----------

function decodeTransaction(to, data) {
  const base = { target: to, grants: [], revoke: false };
  if (data === "0x") return { ...base, kind: "native_transfer" };

  let decoded;
  try {
    decoded = decodeFunctionData({ abi: APPROVAL_ABI, data });
  } catch {
    return { ...base, kind: "contract_call", selector: data.slice(0, 10) };
  }
  const { functionName, args } = decoded;
  const spender = args[0].toLowerCase();

  if (functionName === "setApprovalForAll") {
    if (!args[1]) return { ...base, kind: "approval_for_all", revoke: true, revokedSpender: spender };
    return {
      ...base, kind: "approval_for_all",
      grants: [{ token: to, spender, amount: null, unlimited: true, allForAll: true, mode: "allowance" }],
    };
  }

  const amount = args[1];
  if (functionName === "approve" && amount === 0n) {
    return { ...base, kind: "token_approve", revoke: true, revokedSpender: spender };
  }
  return {
    ...base, kind: "token_approve",
    grants: amount === 0n ? [] : [{ token: to, spender, amount, unlimited: amount >= UNLIMITED_THRESHOLD, mode: "allowance" }],
  };
}

// ---------- EIP-712 signatures ----------

function parseSignature(raw, chainId) {
  let td = raw;
  if (typeof td === "string") {
    try { td = JSON.parse(td); } catch { throw new ValidationError("typedData must be valid JSON"); }
  }
  if (!td || typeof td !== "object" || typeof td.primaryType !== "string" ||
      !td.domain || typeof td.domain !== "object" || !td.message || typeof td.message !== "object") {
    throw new ValidationError("typedData must include domain, primaryType and message");
  }
  const { domain, message, primaryType } = td;

  // A signature for another chain would be checked against the wrong contracts.
  if (domain.chainId !== undefined && domain.chainId !== null) {
    let domainChain;
    try { domainChain = Number(BigInt(domain.chainId)); } catch {
      throw new ValidationError("typedData.domain.chainId is invalid");
    }
    if (domainChain !== chainId) {
      throw new ValidationError(`typedData.domain.chainId (${domainChain}) does not match chainId (${chainId})`);
    }
  }

  const verifying = domain.verifyingContract
    ? toAddress(domain.verifyingContract, "typedData.domain.verifyingContract")
    : null;
  const requireVerifying = () => {
    if (!verifying) throw new ValidationError(`${primaryType} signatures need domain.verifyingContract`);
    return verifying;
  };
  const base = { primaryType, target: verifying, grants: [], revoke: false };

  // EIP-2612 permit, and DAI-style permit (holder/allowed/expiry)
  if (primaryType === "Permit") {
    const token = requireVerifying();
    const spender = toAddress(message.spender, "message.spender");

    if ("allowed" in message) {
      const allowed = message.allowed === true || message.allowed === "true";
      const expiry = toTimestamp(message.expiry, "message.expiry"); // 0 = never expires
      if (!allowed) return { ...base, kind: "permit", revoke: true, revokedSpender: spender, signatureDeadline: expiry || null };
      return {
        ...base, kind: "permit", signatureDeadline: expiry || null,
        grants: [{ token, spender, amount: null, unlimited: true, mode: "allowance", expiresAt: null }],
      };
    }

    const amount = toUint(message.value, "message.value");
    const deadline = toTimestamp(message.deadline, "message.deadline");
    if (amount === 0n) return { ...base, kind: "permit", revoke: true, revokedSpender: spender, signatureDeadline: deadline };
    return {
      ...base, kind: "permit", signatureDeadline: deadline,
      // An EIP-2612 allowance stays until spent; the deadline only limits when the signature can be used.
      grants: [{ token, spender, amount, unlimited: amount >= UNLIMITED_THRESHOLD, mode: "allowance", expiresAt: null }],
    };
  }

  // Permit2 AllowanceTransfer: grants an allowance with its own expiration
  if (PERMIT2_ALLOWANCE_TYPES.has(primaryType)) {
    requireVerifying();
    const spender = toAddress(message.spender, "message.spender");
    const list = primaryType === "PermitBatch" ? message.details : [message.details];
    if (!Array.isArray(list) || !list.length || list.some((d) => !d || typeof d !== "object")) {
      throw new ValidationError("message.details is missing or malformed");
    }
    const grants = list
      .map((d, i) => {
        const amount = toUint(d.amount, `message.details[${i}].amount`);
        return {
          token: toAddress(d.token, `message.details[${i}].token`),
          spender, amount,
          unlimited: amount >= UINT160_UNLIMITED,
          mode: "allowance",
          // Permit2 treats expiration 0 as "expires this block"
          expiresAt: toTimestamp(d.expiration, `message.details[${i}].expiration`),
        };
      })
      .filter((g) => g.amount > 0n);
    return {
      ...base, kind: "permit2_allowance", grants,
      revoke: grants.length === 0, revokedSpender: grants.length === 0 ? spender : undefined,
      signatureDeadline: toTimestamp(message.sigDeadline, "message.sigDeadline"),
    };
  }

  // Permit2 SignatureTransfer: lets the spender move tokens directly, once
  if (PERMIT2_TRANSFER_TYPES.has(primaryType)) {
    requireVerifying();
    const spender = toAddress(message.spender, "message.spender");
    const list = primaryType.includes("Batch") ? message.permitted : [message.permitted];
    if (!Array.isArray(list) || !list.length || list.some((p) => !p || typeof p !== "object")) {
      throw new ValidationError("message.permitted is missing or malformed");
    }
    const deadline = toTimestamp(message.deadline, "message.deadline");
    const grants = list
      .map((p, i) => {
        const amount = toUint(p.amount, `message.permitted[${i}].amount`);
        return {
          token: toAddress(p.token, `message.permitted[${i}].token`),
          spender, amount,
          unlimited: amount >= UINT160_UNLIMITED,
          mode: "transfer",
          expiresAt: deadline,
        };
      })
      .filter((g) => g.amount > 0n);
    return { ...base, kind: "permit2_transfer", grants, signatureDeadline: deadline };
  }

  // EIP-3009 payment: moves exactly `value` to `to`, once, between validAfter and validBefore.
  // Unlike a permit it grants no allowance, so a plain wallet as recipient is normal.
  if (TRANSFER_AUTHORIZATION_TYPES.has(primaryType)) {
    const token = requireVerifying();
    const amount = toUint(message.value, "message.value");
    const validBefore = toTimestamp(message.validBefore, "message.validBefore");
    return {
      ...base, kind: "transfer_authorization", signatureDeadline: validBefore,
      grants: [{
        token, spender: toAddress(message.to, "message.to"), amount,
        unlimited: amount >= UNLIMITED_THRESHOLD, mode: "payment", expiresAt: validBefore,
      }],
    };
  }

  // Seaport listing: the classic fake-listing phish sells your NFTs for nothing
  if (primaryType === "OrderComponents") {
    const offerer = toAddress(message.offerer, "message.offerer");
    const offer = Array.isArray(message.offer) ? message.offer : [];
    const consideration = Array.isArray(message.consideration) ? message.consideration : [];
    const paysOfferer = consideration.some((c) =>
      typeof c?.recipient === "string" && c.recipient.toLowerCase() === offerer);
    return {
      ...base, kind: "marketplace_order",
      signatureDeadline: toTimestamp(message.endTime, "message.endTime"),
      order: { offerer, offerCount: offer.length, considerationCount: consideration.length, paysOfferer },
    };
  }

  return { ...base, kind: "unknown_signature" };
}

// ---------- request parsing ----------

function parseRequest(body) {
  if (!body || typeof body !== "object") throw new ValidationError("JSON body required");

  const chainId = Number(body.chainId);
  if (!SUPPORTED_CHAINS.has(chainId)) {
    throw new ValidationError(`Unsupported chainId. Supported: ${[...SUPPORTED_CHAINS].join(", ")}`);
  }

  if (body.type === "approval") {
    const token = toAddress(body.token, "token");
    const spender = toAddress(body.spender, "spender");
    const amount = toUint(body.amount, "amount");
    return {
      chainId, kind: "token_approve", target: token, offchain: false, value: 0n,
      revoke: amount === 0n, revokedSpender: amount === 0n ? spender : undefined,
      grants: amount === 0n ? [] : [{ token, spender, amount, unlimited: amount >= UNLIMITED_THRESHOLD, mode: "allowance" }],
    };
  }

  if (body.type === "transaction") {
    const to = toAddress(body.to, "to");
    const data = body.data ?? "0x";
    if (typeof data !== "string" || !isHex(data)) throw new ValidationError("data must be 0x-prefixed hex");
    const value = toUint(body.value ?? "0", "value");
    return { chainId, offchain: false, value, ...decodeTransaction(to, data.toLowerCase()) };
  }

  if (body.type === "signature") {
    return { chainId, offchain: true, value: 0n, ...parseSignature(body.typedData, chainId) };
  }

  throw new ValidationError('type must be "approval", "transaction" or "signature"');
}

// ---------- analysis ----------

async function analyze(req) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    const d = details ? JSON.stringify(details) : "";
    if (reasons.some((r) => r.code === code && r.subject === subject && (r.details ? JSON.stringify(r.details) : "") === d)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };

  // Revoked spenders are not looked up: revoking a bad address is safe.
  const subjects = new Set([req.target, ...req.grants.map((g) => g.spender)].filter(Boolean));

  const lookups = await Promise.all([...subjects].map(async (address) => {
    const [addrSec, contract] = await Promise.all([
      getAddressSecurity(req.chainId, address),
      getContractSecurity(req.chainId, address),
    ]);
    return [address, { addrSec, contract }];
  }));
  const results = new Map(lookups);
  const isContract = (address) => flag(results.get(address)?.contract?.is_contract);
  const now = Math.floor(Date.now() / 1000);

  for (const [address, { addrSec, contract }] of results) {
    for (const f of ADDRESS_RED_FLAGS) if (flag(addrSec?.[f])) add(f.toUpperCase(), "red", address);
    for (const f of ADDRESS_ORANGE_FLAGS) if (flag(addrSec?.[f])) add(f.toUpperCase(), "orange", address);
    if (Number(addrSec?.number_of_malicious_contracts_created) > 0) {
      add("CREATOR_OF_MALICIOUS_CONTRACTS", "red", address);
    }

    if (flag(contract?.is_contract)) {
      const malicious = Array.isArray(contract.malicious_behavior) ? contract.malicious_behavior : [];
      if (malicious.length) add("MALICIOUS_CONTRACT_BEHAVIOR", "red", address, malicious);
      if (flag(contract.doubt_list)) add("ON_DOUBT_LIST", "red", address);
      if (!flag(contract.is_open_source)) add("UNVERIFIED_CONTRACT", "orange", address);
      if (flag(contract.is_proxy)) add("UPGRADEABLE_PROXY", "info", address);
      const deployed = Number(contract.deployed_time);
      if (deployed && now - deployed < RECENT_DEPLOY_SECONDS) add("RECENTLY_DEPLOYED", "orange", address);
      if (flag(contract.trust_list)) add("ON_TRUST_LIST", "info", address);
    }
  }

  if (req.revoke) add("REVOKES_APPROVAL", "info", req.revokedSpender ?? req.target);

  for (const g of req.grants) {
    const token = { token: g.token };
    if (g.mode === "payment") {
      add("PAYMENT_AUTHORIZATION", "info", g.spender, { ...token, amount: g.amount.toString() });
      if (g.unlimited) add("UNLIMITED_TRANSFER", "orange", g.spender, token);
      if (g.expiresAt !== null && g.expiresAt - now > LONG_LIVED_SECONDS) {
        add("LONG_LIVED_PERMISSION", "orange", g.spender, { ...token, expiresAt: g.expiresAt });
      }
      continue;
    }
    if (g.allForAll) add("APPROVAL_FOR_ALL", "orange", g.spender, token);
    else if (g.unlimited) add(g.mode === "transfer" ? "UNLIMITED_TRANSFER" : "UNLIMITED_APPROVAL", "orange", g.spender, token);

    if (g.mode === "transfer") add("SIGNATURE_TRANSFER", "orange", g.spender, token);

    if (!isContract(g.spender)) {
      // Signatures granting a plain wallet access are almost always phishing.
      if (req.offchain) add("SIGNATURE_GRANT_TO_EOA", "red", g.spender);
      else add(g.unlimited ? "UNLIMITED_APPROVAL_TO_EOA" : "APPROVAL_TO_EOA", g.unlimited ? "red" : "orange", g.spender);
    }

    if (req.kind === "permit2_allowance" && g.expiresAt !== null && g.expiresAt - now > LONG_LIVED_SECONDS) {
      add("LONG_LIVED_PERMISSION", "orange", g.spender, { ...token, expiresAt: g.expiresAt });
    }
  }

  if (req.offchain) {
    add("OFFCHAIN_SIGNATURE", "info", req.target);
    if (req.kind.startsWith("permit2") && req.target !== PERMIT2) add("NONCANONICAL_PERMIT2", "orange", req.target);
    if (req.signatureDeadline && req.signatureDeadline < now) add("SIGNATURE_EXPIRED", "info", req.target);
  }

  if (req.kind === "marketplace_order") {
    add("MARKETPLACE_ORDER", "orange", req.target, { offerCount: req.order.offerCount });
    if (req.order.offerCount > 0 && !req.order.paysOfferer) add("ORDER_PAYS_YOU_NOTHING", "red", req.order.offerer);
  }
  if (req.kind === "unknown_signature") add("UNRECOGNIZED_SIGNATURE", "orange", req.target, { primaryType: req.primaryType });
  if (req.kind === "contract_call") add("UNDECODED_CALL", "info", req.target, { selector: req.selector });

  const verdict = reasons.some((r) => r.severity === "red") ? "red"
    : reasons.some((r) => r.severity === "orange") ? "orange"
    : "green";

  // All bigints converted to strings here: JSON.stringify cannot serialize BigInt.
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      chainId: req.chainId,
      kind: req.kind,
      target: req.target,
      offchain: req.offchain,
      ...(req.primaryType && { primaryType: req.primaryType }),
      grants: req.grants.map((g) => ({
        token: g.token,
        spender: g.spender,
        amount: g.amount === null ? null : g.amount.toString(),
        unlimited: g.unlimited,
        mode: g.mode,
        ...(g.allForAll && { allForAll: true }),
        ...(g.expiresAt !== undefined && { expiresAt: g.expiresAt }),
      })),
      ...(req.revoke && { revokes: req.revokedSpender ?? null }),
      ...(req.signatureDeadline != null && { signatureDeadline: req.signatureDeadline }),
      ...(req.selector && { selector: req.selector }),
      value: req.value.toString(),
    },
    scope: "On-chain transactions and approvals, plus EIP-712 Permit, Permit2, EIP-3009 (x402 payment) and Seaport signatures. Not covered: eth_sign/personal_sign messages and transaction simulation.",
    sources: ["goplus"],
    checkedAt: new Date().toISOString(),
  };
}

// ---------- plain-language explanation ----------

async function explain(result, lang) {
  if (!process.env.ANTHROPIC_API_KEY) throw new UpstreamError("Explanation service not configured");

  const system = [
    `You explain blockchain transaction risk checks to people without crypto knowledge. Write in ${lang === "nl" ? "Dutch" : "English"}.`,
    "Use 3 to 5 short sentences, no jargon, no markdown.",
    "The verdict is final: never change, soften or contradict it.",
    "Use only the facts in the check result. Do not speculate beyond them.",
    "If subject.offchain is true, make clear that signing costs nothing and sends no transaction, but still hands over the permission described.",
    "Say plainly what signing would allow, and what the person should do next.",
  ].join(" ");

  let res;
  try {
    res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: process.env.CLAUDE_MODEL ?? "claude-haiku-4-5-20251001",
        max_tokens: 400,
        system,
        messages: [{ role: "user", content: JSON.stringify(result) }],
      }),
      signal: AbortSignal.timeout(CLAUDE_TIMEOUT_MS),
    });
  } catch (err) {
    throw new UpstreamError(`Explanation service unreachable (${err.name})`);
  }
  if (!res.ok) throw new UpstreamError(`Explanation service HTTP ${res.status}`);

  const body = await res.json().catch(() => null);
  const text = body?.content?.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
  if (!text) throw new UpstreamError("Explanation service returned no text");
  return text;
}

// ---------- routes ----------

export function x402Routes(payTo, network = "eip155:8453") {
  if (!payTo) throw new Error("PAY_TO address is required");
  const route = (path, description) => ({
    accepts: [{ scheme: "exact", price: `$${ROUTES[path].price}`, network, payTo }],
    description,
    mimeType: "application/json",
    ...serviceMetadata,
    extensions: bazaarExtension(),
  });
  return {
    "POST /v1/check": route("/v1/check",
      "Pre-sign risk verdict (green/orange/red + reason codes) for EVM transactions, token approvals and Permit/Permit2/EIP-3009/Seaport signatures"),
    "POST /v1/check/explain": route("/v1/check/explain",
      "Pre-sign risk verdict plus a plain-language explanation in Dutch or English"),
  };
}

export function createCheckRouter() {
  const router = express.Router();
  router.use(express.json({ limit: "64kb" })); // batch permits and Seaport orders can be large

  const handler = (withExplanation) => async (req, res) => {
    try {
      const parsed = parseRequest(req.body);
      const result = await analyze(parsed);
      if (withExplanation) {
        const lang = req.body.lang === "nl" ? "nl" : "en";
        result.explanation = { lang, text: await explain(result, lang) };
      }
      res.set("Cache-Control", "no-store").json(result);
    } catch (err) {
      const status = err.status ?? 500;
      if (status >= 500) console.error("[presign-guard]", err);
      res.status(status).json({
        error: status === 400 ? "invalid_request" : status === 503 ? "upstream_unavailable" : "internal_error",
        message: status === 500 ? "Internal error" : err.message,
        verdict: null,
      });
    }
  };

  router.post("/v1/check", handler(false));
  router.post("/v1/check/explain", handler(true));
  return router;
}
