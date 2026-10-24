// presign-guard.js — pre-sign risk check for AI agents, sold via x402 (v2: adds EIP-712 signatures)
//
// Wired up in server.js.
//
// Env: PAY_TO, ANTHROPIC_API_KEY, optional GOPLUS_ACCESS_TOKEN, CLAUDE_MODEL, X402_NETWORK, FACILITATOR_URL,
//      TYPESAFE_API_KEY (Jev second opinion, src/jev.js)
//
// Request types (POST body):
//   { type: "approval",    chainId, token, spender, amount }
//   { type: "transaction", chainId, to, data, value? }
//   { type: "signature",   chainId, typedData }   // eth_signTypedData_v4 payload (object or JSON string)
//   { type: "authorization", chainId, address, authorizationChainId?, nonce?, from? } // an EIP-7702 delegation
//   { type: "xrpl",        network?, tx }          // an unsigned XRP Ledger transaction (src/xrpl.js)
//   { type: "algorand",    transaction | transactions, from? } // base64 msgpack Algorand transaction(s) (src/algorand-tx.js)
//   { chain_id, request_type, transaction | typed_data, policy_config? } // an OWS PolicyContext (src/ows.js): the
//                                                    answer also carries the OWS PolicyResult, { allow, reason }
//   Add lang: "nl" | "en" on /v1/check/explain.
//
// Fail-closed rule: every error returns a non-2xx status and verdict: null, never "green".
// Verify in testing that your middleware version skips settlement on non-2xx responses.

import express from "express";
import {
  ROUTES, TOKEN_ROUTE, APPROVALS_ROUTE, bazaarExtension, serviceMetadata, tokenBazaarExtension, tokenServiceMetadata,
  approvalsBazaarExtension, approvalsServiceMetadata, SCREEN_ROUTE, screenBazaarExtension, screenServiceMetadata,
  INJECTION_ROUTE, injectionBazaarExtension, injectionServiceMetadata,
} from "./discovery.js";
import { builderCodeExtension, merchantExtension } from "./merchant.js";
import { decodeFunctionData, encodeFunctionData, isAddress, isHex, maxUint256, parseAbi, zeroAddress } from "viem";
import { screenSanctions, domainAge, hostnameReputation, originHost, walletAge, NEW_DOMAIN_DAYS } from "./pg1.js";
import { screenOfacLoaded, partySanctionsReasons } from "./ofac.js";

// A plain wallet that receives an allowance or transfer right and has no
// history, or only a day of it, is how drainers work: fresh wallets, used once.
// Under a week old is a caution. (PG1 check_wallet_age; payments are not
// screened this way: a new seller's payout wallet is normal.)
export const NEW_WALLET_DAYS = 7;
export const BRAND_NEW_WALLET_DAYS = 1;
import { metamaskSiteScan } from "./site-scan.js";
import { secondOpinion, intentCheck, CLAUDE_MODEL, claudeModelParams } from "./jev.js";
import { checkMandatePayment } from "./mandate.js";
import { parseRequirements, checkX402Payment } from "./x402-requirements.js";
import { createSimulator, simulationReasons, simulationEffects, SIMULATED_CHAINS } from "./simulate.js";
import { isXrplRequest, parseXrplRequest, analyzeXrpl } from "./xrpl.js";
import { isOwsContext, owsToCheck, owsResult } from "./ows.js";
import { decodeMessage, parseSignIn, siteOf } from "./message.js";
import { createHistory, poisoningReasons, transferRecipients } from "./poisoning.js";
import { parseSolanaRequest, instructionReasons, simulateSolana, solanaSimulationReasons, addAgentPaymentRecipients } from "./solana-tx.js";
import { parseAlgorandRequest, algorandReasons, simulateAlgorand, algorandSimulationReasons, describeAlgorandTxn, ALGORAND_NETWORKS } from "./algorand-tx.js";
import { xrplAccept } from "./xrpl-facilitator.js";
import { algorandAccept } from "./algorand.js";
import { stellarAccept } from "./stellar.js";

const GOPLUS_BASE = "https://api.gopluslabs.io/api";
const GOPLUS_TIMEOUT_MS = 4000;
const RPC_TIMEOUT_MS = 4000;
const CLAUDE_TIMEOUT_MS = 12000;
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX_ENTRIES = 5000;
const RECENT_DEPLOY_SECONDS = 30 * 86400;
const LONG_LIVED_SECONDS = 31 * 86400; // Permit2 UIs commonly default to 30 days
const SUPPORTED_CHAINS = new Set([1, 10, 56, 137, 8453, 42161]);
// Public RPCs for eth_getCode; override per chain with RPC_URL_<chainId>.
const RPC_URLS = {
  1: "https://ethereum-rpc.publicnode.com",
  10: "https://optimism-rpc.publicnode.com",
  56: "https://bsc-rpc.publicnode.com",
  137: "https://polygon-bor-rpc.publicnode.com",
  8453: "https://base-rpc.publicnode.com",
  42161: "https://arb1.arbitrum.io/rpc",
};
// EIP-7702: a plain wallet with delegated code. Its private key still controls it.
const DELEGATION_CODE = /^0xef0100[0-9a-f]{40}$/i;
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

// GoPlus token_security fields for the token being approved, permitted or paid.
// Red: the token itself is a trap. Orange: the owner can take or freeze your tokens
// in ways a normal token cannot. Info: common issuer controls (USDC has several),
// reported for context without changing the verdict.
const TOKEN_RED_FLAGS = { is_honeypot: "TOKEN_HONEYPOT", is_airdrop_scam: "TOKEN_AIRDROP_SCAM" };
const TOKEN_ORANGE_FLAGS = {
  owner_change_balance: "TOKEN_OWNER_CAN_CHANGE_BALANCES",
  can_take_back_ownership: "TOKEN_OWNERSHIP_RECLAIMABLE",
  hidden_owner: "TOKEN_HIDDEN_OWNER",
  selfdestruct: "TOKEN_SELFDESTRUCT",
  cannot_sell_all: "TOKEN_CANNOT_SELL_ALL",
  honeypot_with_same_creator: "TOKEN_CREATOR_MADE_HONEYPOTS",
};
const TOKEN_INFO_FLAGS = {
  is_mintable: "TOKEN_MINTABLE",
  transfer_pausable: "TOKEN_PAUSABLE",
  is_blacklisted: "TOKEN_BLACKLIST",
  is_proxy: "TOKEN_UPGRADEABLE",
  slippage_modifiable: "TOKEN_TAX_MODIFIABLE",
  trading_cooldown: "TOKEN_TRADING_COOLDOWN",
};
const HIGH_TOKEN_TAX = 0.1; // 10% buy or sell tax

// ---------- errors ----------

class ValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}
class UpstreamError extends Error {
  constructor(message) { super(message); this.status = 503; }
}

// ---------- cache (successes only; per instance, resets on restart) ----------

const cache = new Map();
async function cached(key, fn, ttlMs = CACHE_TTL_MS) {
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return hit.value;
  const value = await fn();
  cache.set(key, { value, expires: Date.now() + ttlMs });
  if (cache.size > CACHE_MAX_ENTRIES) cache.delete(cache.keys().next().value);
  return value;
}

// ---------- GoPlus ----------

// version: "v1" for most endpoints, "v2" for token_approval_security.
// emptyOk: a null result means "nothing found" (a wallet without approvals), not an error.
// timeoutMs: longer for heavy lookups such as a busy wallet's full approval list.
async function goplus(path, { version = "v1", emptyOk = false, timeoutMs = GOPLUS_TIMEOUT_MS } = {}) {
  const headers = { accept: "application/json" };
  // Check GoPlus docs for the exact auth header format on your plan.
  if (process.env.GOPLUS_ACCESS_TOKEN) headers.Authorization = process.env.GOPLUS_ACCESS_TOKEN;

  let res;
  try {
    res = await fetch(`${GOPLUS_BASE}/${version}${path}`, { headers, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    throw new UpstreamError(`GoPlus unreachable (${err.name})`);
  }
  if (!res.ok) throw new UpstreamError(`GoPlus HTTP ${res.status}`);
  const body = await res.json().catch(() => null);
  if (emptyOk && body && (body.code === 1 || body.code === 2) && (body.result === null || body.result === undefined)) {
    return { result: [], partial: body.code === 2 };
  }
  // code 2 = "partial data obtained": the result is usable but some fields may be missing.
  // Missing fields raise no flags, except a missing is_contract, which counts as a plain wallet (stricter).
  if (!body || (body.code !== 1 && body.code !== 2) || !body.result || typeof body.result !== "object") {
    throw new UpstreamError(`GoPlus error: ${body?.message ?? "unexpected response"}`);
  }
  return { result: body.result, partial: body.code === 2 };
}

// GoPlus phishing_site for the origin: { phishing: boolean } or null when unavailable.
function goplusPhishing(host) {
  return cached(`phishing:${host}`, async () => {
    try {
      const { result } = await goplus(`/phishing_site?url=${encodeURIComponent(`https://${host}`)}`);
      return result.phishing_site === undefined ? null : { phishing: Number(result.phishing_site) === 1 };
    } catch {
      return null;
    }
  });
}

// Phishing, lookalike and wallet-block checks on the origin; ORIGIN_REPUTATION=off disables them.
const originReputationOn = () => process.env.ORIGIN_REPUTATION !== "off";

// ---------- chain RPC ----------

function getCode(chainId, address) {
  return cached(`code:${chainId}:${address}`, async () => {
    let res;
    try {
      res = await fetch(process.env[`RPC_URL_${chainId}`] || RPC_URLS[chainId], {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] }),
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
    } catch (err) {
      throw new UpstreamError(`Chain RPC unreachable (${err.name})`);
    }
    const body = res.ok ? await res.json().catch(() => null) : null;
    if (typeof body?.result !== "string") throw new UpstreamError(`Chain RPC error${res.ok ? "" : ` (HTTP ${res.status})`}`);
    return body.result;
  });
}

function getStorageAt(chainId, address, slot) {
  return cached(`slot:${chainId}:${address}:${slot}`, async () => {
    let res;
    try {
      res = await fetch(process.env[`RPC_URL_${chainId}`] || RPC_URLS[chainId], {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getStorageAt", params: [address, slot, "latest"] }),
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
    } catch (err) {
      throw new UpstreamError(`Chain RPC unreachable (${err.name})`);
    }
    const body = res.ok ? await res.json().catch(() => null) : null;
    if (typeof body?.result !== "string") throw new UpstreamError(`Chain RPC error${res.ok ? "" : ` (HTTP ${res.status})`}`);
    return body.result;
  });
}

// Read-only contract calls, sent as one JSON-RPC batch (public RPCs rate-limit
// bursts of single requests). Returns one raw result per call, or null where the
// call reverts (the contract has no such function). Throws UpstreamError when the
// RPC can't be asked.
function ethCalls(chainId, to, datas) {
  return cached(`calls:${chainId}:${to}:${datas.join(",")}`, async () => {
    let res;
    try {
      res = await fetch(process.env[`RPC_URL_${chainId}`] || RPC_URLS[chainId], {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(datas.map((data, id) => ({ jsonrpc: "2.0", id, method: "eth_call", params: [{ to, data }, "latest"] }))),
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
    } catch (err) {
      throw new UpstreamError(`Chain RPC unreachable (${err.name})`);
    }
    const body = res.ok ? await res.json().catch(() => null) : null;
    if (!Array.isArray(body)) throw new UpstreamError(`Chain RPC error${res.ok ? "" : ` (HTTP ${res.status})`}`);
    const results = datas.map((_, id) => {
      const answer = body.find((x) => x?.id === id);
      if (typeof answer?.result === "string") return answer.result;
      if (answer?.error && /revert/i.test(String(answer.error.message))) return null;
      return undefined; // no answer (rate limit, RPC error): unknown
    });
    if (results.every((x) => x === undefined)) throw new UpstreamError("Chain RPC error (no answers)"); // not cached
    return results;
  });
}

// Any read-only JSON-RPC requests ([method, params] pairs) as one batch, with the same answers as ethCalls:
// the result, null for a revert, undefined for no answer. Used by the token controller reads (controllers.js).
function rpcBatch(chainId, requests) {
  return cached(`batch:${chainId}:${JSON.stringify(requests)}`, async () => {
    let res;
    try {
      res = await fetch(process.env[`RPC_URL_${chainId}`] || RPC_URLS[chainId], {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(requests.map(([method, params], id) => ({ jsonrpc: "2.0", id, method, params }))),
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
    } catch (err) {
      throw new UpstreamError(`Chain RPC unreachable (${err.name})`);
    }
    const body = res.ok ? await res.json().catch(() => null) : null;
    if (!Array.isArray(body)) throw new UpstreamError(`Chain RPC error${res.ok ? "" : ` (HTTP ${res.status})`}`);
    const results = requests.map((_, id) => {
      const answer = body.find((x) => x?.id === id);
      if (typeof answer?.result === "string") return answer.result;
      if (answer?.error && /revert/i.test(String(answer.error.message))) return null;
      return undefined;
    });
    if (results.every((x) => x === undefined)) throw new UpstreamError("Chain RPC error (no answers)"); // not cached
    return results;
  });
}

// GoPlus approval_security sometimes calls a plain contract a proxy (DEGEN on
// Base: a full 11.6 KB contract with no proxy slot set, while token_security
// says is_proxy=0). Confirm on-chain against the standard layouts; the first
// match names what points where.
const PROXY_SLOTS = [
  ["eip1967", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"],
  ["eip1967-beacon", "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"],
  ["eip1822", "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"],
  ["openzeppelin-legacy", "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"],
];
const MINIMAL_PROXY = /^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/i;

// { kind, points_to } when confirmed, null when no standard layout matches,
// "unchecked" when the chain RPC can't be asked.
async function confirmProxy(chainId, address) {
  try {
    const code = await getCode(chainId, address);
    const minimal = MINIMAL_PROXY.exec(code);
    if (minimal) return { kind: "eip1167", points_to: `0x${minimal[1].toLowerCase()}` };
    for (const [kind, slot] of PROXY_SLOTS) {
      const value = await getStorageAt(chainId, address, slot);
      const target = /^0x0*([0-9a-f]{1,40})$/i.exec(value);
      if (target && /[1-9a-f]/i.test(target[1])) return { kind, points_to: `0x${target[1].padStart(40, "0").toLowerCase()}` };
    }
    return null;
  } catch {
    return "unchecked";
  }
}

// Some GoPlus endpoints key results by lowercase address, some return fields directly.
const pickResult = (result, address) => result?.[address] ?? result;
const flag = (v) => String(v) === "1";

// Both return { data, partial }.
function getAddressSecurity(chainId, address) {
  return cached(`addr:${chainId}:${address}`, async () => {
    const { result, partial } = await goplus(`/address_security/${address}?chain_id=${chainId}`);
    return { data: result, partial };
  });
}

function getContractSecurity(chainId, address) {
  return cached(`contract:${chainId}:${address}`, async () => {
    const { result, partial } = await goplus(`/approval_security/${chainId}?contract_addresses=${address}`);
    return { data: pickResult(result, address), partial };
  });
}

// Is the code at an address source-verified? GoPlus's is_open_source misses contracts verified on Sourcify only:
// Coinbase's EIP7702Proxy on Base (0x7702cb55…, the delegate of Coinbase Smart Wallet's 7702 upgrade) was
// "unverified" per GoPlus on 22 Oct 2026 and an exact match on Sourcify, which made every payment to such a wallet
// orange and an authorization to it red. So before calling code unverified, Sourcify is asked.
// "goplus" or "sourcify" when verified, null when not (or Sourcify can't be reached: then GoPlus's answer stands).
const SOURCIFY_URL = (process.env.SOURCIFY_URL || "https://sourcify.dev/server").replace(/\/+$/, "");
async function verifiedBy(chainId, address, goplusContract) {
  if (flag(goplusContract?.is_open_source)) return "goplus";
  if (process.env.SOURCIFY === "off") return null;
  const onSourcify = await cached(`sourcify:${chainId}:${address.toLowerCase()}`, async () => {
    const res = await fetch(`${SOURCIFY_URL}/v2/contract/${chainId}/${address}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(4000) });
    if (res.status === 404) return false;
    if (!res.ok) throw new Error(`sourcify ${res.status}`); // not cached: asked again next time
    const j = await res.json();
    return [j.match, j.runtimeMatch, j.creationMatch].some((m) => m === "exact_match" || m === "match");
  }).catch(() => false);
  return onSourcify ? "sourcify" : null;
}

// Token risk for an ERC-20 (null data when GoPlus has no record, e.g. an NFT collection).
function getTokenSecurity(chainId, token) {
  return cached(`token:${chainId}:${token}`, async () => {
    const { result, partial } = await goplus(`/token_security/${chainId}?contract_addresses=${token}`);
    const data = result?.[token];
    return { data: data && typeof data === "object" && Object.keys(data).length ? data : null, partial };
  });
}

function tokenReasons(token, t, add) {
  if (!t) { add("TOKEN_NO_SECURITY_DATA", "info", token); return; }
  for (const [field, code] of Object.entries(TOKEN_RED_FLAGS)) if (flag(t[field])) add(code, "red", token);
  const fake = t.fake_token;
  if (fake && typeof fake === "object" && flag(fake.value)) {
    add("TOKEN_IMPERSONATION", "red", token, fake.true_token_address ? { realToken: String(fake.true_token_address).toLowerCase() } : undefined);
  }
  for (const [field, code] of Object.entries(TOKEN_ORANGE_FLAGS)) if (flag(t[field])) add(code, "orange", token);
  if (t.is_open_source !== undefined && !flag(t.is_open_source)) add("TOKEN_UNVERIFIED", "orange", token);
  const buyTax = Number(t.buy_tax) || 0;
  const sellTax = Number(t.sell_tax) || 0;
  if (Math.max(buyTax, sellTax) >= HIGH_TOKEN_TAX) add("TOKEN_HIGH_TAX", "orange", token, { buyTax, sellTax });
  else if (buyTax > 0 || sellTax > 0) add("TOKEN_TAX", "info", token, { buyTax, sellTax });
  for (const [field, code] of Object.entries(TOKEN_INFO_FLAGS)) if (flag(t[field])) add(code, "info", token);
  if (flag(t.trust_list)) add("TOKEN_ON_TRUST_LIST", "info", token);
}

// GoPlus leaves the control fields out for a proxy token (USDC, cbBTC, EURC, wstETH):
// it only reports is_proxy and the owner. Then ask the token itself, through the
// getters that the common issuer contracts expose (Circle's FiatToken, which cbBTC
// also uses; OpenZeppelin Pausable and AccessControl; Tether's blacklist).
const CONTROL_ABI = parseAbi([
  "function paused() view returns (bool)",
  "function pauser() view returns (address)",
  "function PAUSER_ROLE() view returns (bytes32)",
  "function blacklister() view returns (address)",
  "function isBlacklisted(address) view returns (bool)",
  "function isBlackListed(address) view returns (bool)",
]);
const CONTROL_CALLS = {
  paused: encodeFunctionData({ abi: CONTROL_ABI, functionName: "paused" }),
  pauser: encodeFunctionData({ abi: CONTROL_ABI, functionName: "pauser" }),
  pauserRole: encodeFunctionData({ abi: CONTROL_ABI, functionName: "PAUSER_ROLE" }),
  blacklister: encodeFunctionData({ abi: CONTROL_ABI, functionName: "blacklister" }),
  isBlacklisted: encodeFunctionData({ abi: CONTROL_ABI, functionName: "isBlacklisted", args: [zeroAddress] }),
  isBlackListed: encodeFunctionData({ abi: CONTROL_ABI, functionName: "isBlackListed", args: [zeroAddress] }),
};
const word = (r) => (typeof r === "string" && /^0x[0-9a-f]{64}$/i.test(r) ? r.toLowerCase() : null);
const wordAddress = (r) => { const w = word(r); return w && /^0x0{24}/.test(w) ? `0x${w.slice(26)}` : null; };

// { paused, pauser, blacklister, pausable, blacklist }, or null when the chain RPC can't be asked.
async function issuerControls(chainId, address) {
  const names = Object.keys(CONTROL_CALLS);
  let results;
  try { results = await ethCalls(chainId, address, Object.values(CONTROL_CALLS)); } catch { return null; }
  const entries = names.map((name, i) => [name, results[i]]);
  const r = Object.fromEntries(entries);
  const pauser = wordAddress(r.pauser);
  const blacklister = wordAddress(r.blacklister);
  const bool = (x) => (word(x) ? BigInt(x) === 1n : null);
  return {
    paused: bool(r.paused) === true,
    pauser: pauser && pauser !== zeroAddress ? pauser : null,
    blacklister: blacklister && blacklister !== zeroAddress ? blacklister : null,
    pausable: Boolean((pauser && pauser !== zeroAddress) || word(r.pauserRole) || bool(r.paused) !== null),
    blacklist: Boolean((blacklister && blacklister !== zeroAddress) || bool(r.isBlacklisted) !== null || bool(r.isBlackListed) !== null),
  };
}

// Only asked when GoPlus has no answer for these fields, so a normal token costs no RPC calls.
// add(code, severity, details).
function controlReasons(controls, add) {
  if (!controls) return;
  if (controls.paused) add("TOKEN_PAUSED", "orange", { source: "onchain" });
  if (controls.pausable) add("TOKEN_PAUSABLE", "info", { source: "onchain", ...(controls.pauser && { pauser: controls.pauser }) });
  if (controls.blacklist) add("TOKEN_BLACKLIST", "info", { source: "onchain", ...(controls.blacklister && { blacklister: controls.blacklister }) });
}

const needsControlCheck = (sec) => sec && sec.transfer_pausable === undefined && sec.is_blacklisted === undefined;

// Shared with the token verdict (token-verdict.js).
export {
  ValidationError, UpstreamError, cached, goplus, flag, getTokenSecurity, tokenReasons,
  issuerControls, controlReasons, needsControlCheck, rpcBatch,
};

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
  const base = { primaryType, target: verifying, grants: [], revoke: false, ...(typeof domain.name === "string" && domain.name && { domainName: domain.name.slice(0, 64) }), ...(typeof domain.version === "string" && domain.version && { domainVersion: domain.version.slice(0, 16) }) };

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

// Optional for every type: origin, the site asking for the signature or transaction
// (a URL or hostname). Its domain age is checked; local and IP origins are not.
export function parseRequest(body) {
  const req = parseSubject(body);
  if (body.origin !== undefined && body.origin !== null && body.origin !== "") {
    if (typeof body.origin !== "string" || body.origin.length > 2048) throw new ValidationError("origin must be a URL or hostname");
    const host = originHost(body.origin);
    if (host === undefined) throw new ValidationError("origin must be a URL or hostname");
    if (host) req.origin = host;
  }
  // Optional: what the agent says this is for, in its own words ("swap 10 USDC for ETH on Uniswap"); Jev checks
  // that signing does that and nothing more (src/jev.js intentCheck).
  if (body.intent !== undefined && body.intent !== null && body.intent !== "") {
    if (typeof body.intent !== "string" || body.intent.length > 500) throw new ValidationError("intent must be a short text (up to 500 characters) saying what the agent wants to do");
    req.intent = body.intent.trim();
  }
  // Optional: the spending mandate (x402 `authority` extension, mandate.js) this EIP-3009 payment
  // claims to be made under: { mandate, alg, sig, paymentId }.
  if (body.mandate !== undefined && body.mandate !== null) {
    if (req.kind !== "transfer_authorization") throw new ValidationError("mandate applies to EIP-3009 payment signatures (TransferWithAuthorization)");
    const m = body.mandate;
    if (typeof m !== "object" || Array.isArray(m)) throw new ValidationError("mandate must be { mandate, alg, sig, paymentId }");
    const msg = body.typedData.message;
    req.mandate = {
      envelope: { mandate: m.mandate, alg: m.alg, sig: m.sig },
      paymentId: m.paymentId,
      payment: { chainId: req.chainId, from: toAddress(msg.from, "message.from"), to: req.grants[0].spender, token: req.grants[0].token, value: req.grants[0].amount, nonce: String(msg.nonce ?? "") },
    };
  }
  // Optional: the x402 payment requirements this EIP-3009 payment answers (one entry of the 402's accepts list,
  // as { accepted: {…} } or the entry itself); x402-requirements.js checks the signature pays exactly that.
  if (body.x402 !== undefined && body.x402 !== null) {
    if (req.kind !== "transfer_authorization") throw new ValidationError("x402 applies to EIP-3009 payment signatures (TransferWithAuthorization)");
    try { req.x402 = parseRequirements(body.x402); } catch (err) { throw new ValidationError(err.message); }
  }
  return req;
}

// A plain message signature: { type: "message", method: "personal_sign" | "eth_sign", message, chainId?, from? }.
function parseMessage(body) {
  const method = body.method ?? "personal_sign";
  if (method !== "personal_sign" && method !== "eth_sign") throw new ValidationError('method must be "personal_sign" or "eth_sign"');
  let decoded;
  try { decoded = decodeMessage(body.message); } catch (err) { throw new ValidationError(err.message); }
  let chainId;
  if (body.chainId !== undefined && body.chainId !== null) {
    chainId = Number(body.chainId);
    if (!Number.isInteger(chainId) || chainId <= 0) throw new ValidationError("chainId must be a chain id number");
  }
  const from = body.from !== undefined && body.from !== null && body.from !== "" ? toAddress(body.from, "from") : undefined;
  return {
    kind: "message", method, offchain: true, value: 0n, grants: [], target: null,
    ...(chainId && { chainId }), ...(from && { from }),
    text: decoded.text, bytes: decoded.bytes, signIn: decoded.text !== null ? parseSignIn(decoded.text) : null,
    // Set by src/ows.js for a Solana or XRPL message whose bytes are a whole transaction of that chain.
    ...((body.disguisedTransaction === "solana" || body.disguisedTransaction === "xrpl") && { disguisedTransaction: body.disguisedTransaction }),
  };
}

// An EIP-7702 authorization: { type: "authorization", chainId, address, authorizationChainId?, nonce?, from? }.
// Signing it makes the wallet run the code at `address`, which can then move everything the wallet holds, on
// authorizationChainId (the chain id inside the authorization; 0 = every chain). address 0x0…0 clears a delegation.
function parseAuthorization(body, chainId) {
  const delegate = toAddress(body.address, "address");
  let authorizationChainId = chainId;
  if (body.authorizationChainId !== undefined && body.authorizationChainId !== null) {
    authorizationChainId = Number(body.authorizationChainId);
    if (!Number.isInteger(authorizationChainId) || (authorizationChainId !== 0 && authorizationChainId !== chainId)) {
      throw new ValidationError(`authorizationChainId must be ${chainId} (chainId) or 0 (every chain)`);
    }
  }
  const nonce = body.nonce !== undefined && body.nonce !== null ? toUint(body.nonce, "nonce").toString() : undefined;
  const from = body.from !== undefined && body.from !== null && body.from !== "" ? toAddress(body.from, "from") : undefined;
  return {
    chainId, kind: "authorization", offchain: true, value: 0n, grants: [], target: delegate, delegate, authorizationChainId,
    ...(nonce !== undefined && { nonce }), ...(from && { from }),
  };
}

function parseSubject(body) {
  if (!body || typeof body !== "object") throw new ValidationError("JSON body required");
  if (body.type === "message") return parseMessage(body);
  if (body.type === "solana") return { kind: "solana", offchain: false, value: 0n, grants: [], target: null, ...parseSolanaRequest(body) };
  if (body.type === "algorand") return { kind: "algorand", offchain: false, value: 0n, grants: [], target: null, ...parseAlgorandRequest(body) };

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
    // Optional: the wallet that would send it. With it the transaction is simulated (src/simulate.js).
    const from = body.from !== undefined && body.from !== null && body.from !== "" ? toAddress(body.from, "from") : undefined;
    return { chainId, offchain: false, value, ...(from && { from, data: data.toLowerCase() }), ...decodeTransaction(to, data.toLowerCase()) };
  }

  if (body.type === "signature") {
    return { chainId, offchain: true, value: 0n, ...parseSignature(body.typedData, chainId) };
  }

  if (body.type === "authorization") return parseAuthorization(body, chainId);

  throw new ValidationError('type must be "approval", "transaction", "signature", "authorization", "message", "solana", "xrpl" or "algorand"');
}

// ---------- analysis ----------

// The requesting site's reasons: domain age (PG1), phishing lists (PG1 and GoPlus) and MetaMask's site scanner.
// domain is domainAge()'s answer, rep the [pg1, goplus, metamask] answers (null when not asked).
function addOriginReasons(origin, domain, rep, add) {
  let pg1Used = false;
  if (origin) {
    if (!domain) add("DOMAIN_AGE_UNAVAILABLE", "info", origin);
    else {
      pg1Used = true;
      if (domain.found && domain.ageDays < NEW_DOMAIN_DAYS) add("NEW_DOMAIN", "orange", domain.domain, { ageDays: domain.ageDays, registered: domain.registered });
      else if (!domain.found && domain.unregistered) add("DOMAIN_NOT_REGISTERED", "orange", domain.domain);
      else if (!domain.found) add("DOMAIN_AGE_UNKNOWN", "info", domain.domain);
      else add("DOMAIN_AGE", "info", domain.domain, { ageDays: domain.ageDays });
    }
  }

  let metamaskUsed = false;
  if (rep) {
    const [pg1Rep, gpPhish, scan] = rep;
    if (pg1Rep) pg1Used = true;
    const flaggedBy = [...(pg1Rep?.verdict === "listed" ? ["pg1"] : []), ...(gpPhish?.phishing ? ["goplus"] : [])];
    if (flaggedBy.length) {
      add("PHISHING_SITE", "red", origin, {
        flaggedBy,
        ...(pg1Rep?.verdict === "listed" && { list: "MetaMask eth-phishing-detect", matchType: pg1Rep.matchType, listSynced: pg1Rep.listSynced }),
        ...(pg1Rep?.lookalikeOf && { lookalikeOf: pg1Rep.lookalikeOf }),
      });
    } else if (pg1Rep?.verdict === "lookalike") {
      add("LOOKALIKE_SITE", "orange", origin, { lookalikeOf: pg1Rep.lookalikeOf, listSynced: pg1Rep.listSynced });
    } else if (pg1Rep?.verdict === "allowlisted") {
      add("SITE_ALLOWLISTED", "info", origin, { list: "MetaMask eth-phishing-detect" });
    }
    if (scan) {
      metamaskUsed = true;
      if (scan.action === "BLOCK" || (scan.action && scan.action !== "NONE")) {
        add("WALLET_BLOCKS_SITE", "orange", origin, { wallet: "MetaMask", action: scan.action, risks: scan.risks });
      }
    }
    const unavailable = [...(pg1Rep ? [] : ["pg1"]), ...(gpPhish ? [] : ["goplus"]), ...(scan || process.env.METAMASK_SCAN !== "on" ? [] : ["metamask"])];
    if (unavailable.length) add("SITE_REPUTATION_UNAVAILABLE", "info", origin, { sources: unavailable });
  }
  return { pg1Used, metamaskUsed };
}

// A Solana transaction (src/solana-tx.js): its instructions decoded, then simulated on the RPC to see what really
// leaves the wallet; the site and intent as for any request.
async function analyzeSolana(req) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };
  const domain = req.origin ? domainAge(req.origin) : Promise.resolve(undefined);
  const reputation = req.origin && originReputationOn()
    ? Promise.all([hostnameReputation(req.origin), goplusPhishing(req.origin), metamaskSiteScan(req.origin)])
    : Promise.resolve(null);
  const simulation = simulateSolana(req);
  const intent = req.intent
    ? simulation.then((sim) => intentCheck({ intent: req.intent, effects: {
        chain: "solana",
        programs: [...new Set(req.instructions.map((ix) => ix.program).filter(Boolean))],
        ...(sim && { simulated: sim.ok ? { wallet_changes: sim.changes } : { would_fail: sim.error } }),
      } })).catch(() => ({ reasons: [], sources: [] }))
    : Promise.resolve({ reasons: [], sources: [] });

  for (const r of instructionReasons(req)) add(r.code, r.severity, r.subject, r.details);
  const sim = await simulation;
  const shown = new Set(reasons.map((r) => r.code));
  for (const r of solanaSimulationReasons(sim, req, shown)) add(r.code, r.severity, r.subject, r.details);
  if (req.usesLookupTables) add("SOLANA_LOOKUP_TABLES", "info", req.wallet, { note: "some accounts come from address lookup tables; the simulation covers them, the instruction decoding does not" });
  if (!sim) add("SIMULATION_UNAVAILABLE", "info", req.wallet);
  await addAgentPaymentRecipients(reasons, sim?.tokenOwners);
  // Every account the transaction names, the new authorities and delegates, and the owners of the token accounts it
  // writes to (a token transfer names the recipient's token account, not the recipient), against the OFAC SDN list.
  const sanctions = partySanctionsReasons([
    req.feePayer, ...req.instructions.flatMap((ix) => ix.accounts), ...reasons.map((r) => r.subject), ...(sim?.tokenOwners ?? []),
  ], { exclude: [req.wallet] });
  for (const r of sanctions.reasons) add(r.code, r.severity, r.subject, r.details);

  const site = await addOriginReasons(req.origin, await domain, await reputation, add);
  const intentAnswer = await intent;
  for (const r of intentAnswer.reasons) add(r.code, r.severity, r.subject, r.details);

  const verdict = reasons.some((r) => r.severity === "red") ? "red" : reasons.some((r) => r.severity === "orange") ? "orange" : "green";
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      kind: "solana_transaction",
      network: "solana:mainnet",
      wallet: req.wallet,
      ...(req.origin && { origin: req.origin }),
      programs: [...new Set(req.instructions.map((ix) => ix.program).filter(Boolean))],
      ...(req.agentExecutes?.length && { agents: req.agentExecutes.map((e) => ({ asset: e.asset, wallet: e.assetSigner, program: e.inner.program })) }),
    },
    ...(sim && { simulation: sim }),
    scope: "Solana transactions before signing: token accounts handed to another owner (SetAuthority), the wallet handed to a program (System Assign), token delegates (Approve), durable nonces, closing token accounts to someone else, all also when hidden inside other programs (simulateTransaction: SOL and token balances, owners and delegates after); Metaplex agents: what a Core Execute makes the agent's own wallet do (an x402 payment, an approval, another program) and execution delegates that let an executive pay for the agent; every account involved (and the owners of the token accounts written to) against the OFAC SDN list, plus the requesting site's phishing-list status and domain age. Not covered: what a program may do later with a delegate it was given.",
    sources: ["solana-rpc", ...(sanctions.used ? ["ofac-sdn"] : []), ...(site.pg1Used ? ["pg1"] : []), ...(req.origin ? ["goplus"] : []), ...(site.metamaskUsed ? ["metamask"] : []), ...intentAnswer.sources],
    checkedAt: new Date().toISOString(),
  };
}

// Algorand transactions (src/algorand-tx.js): every transaction the wallet sends judged by its fields (rekey, close,
// clawback, app update or clear, asset control), then the group simulated on a public node; the site and intent as
// for any request.
async function analyzeAlgorand(req) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };
  const net = ALGORAND_NETWORKS[req.network];
  const txns = req.txns.map(describeAlgorandTxn);
  const domain = req.origin ? domainAge(req.origin) : Promise.resolve(undefined);
  const reputation = req.origin && originReputationOn()
    ? Promise.all([hostnameReputation(req.origin), goplusPhishing(req.origin), metamaskSiteScan(req.origin)])
    : Promise.resolve(null);
  const simulation = simulateAlgorand(req);
  const intent = req.intent
    ? simulation.then((sim) => intentCheck({ intent: req.intent, effects: {
        chain: net.name,
        wallet: req.wallet,
        transactions: txns,
        ...(sim && { simulated: sim.ok ? { closing: sim.closing } : { would_fail: sim.error } }),
      } })).catch(() => ({ reasons: [], sources: [] }))
    : Promise.resolve({ reasons: [], sources: [] });

  const rules = await algorandReasons(req);
  for (const r of rules.reasons) add(r.code, r.severity, r.subject, r.details);
  const sim = await simulation;
  for (const r of algorandSimulationReasons(sim, req, reasons)) add(r.code, r.severity, r.subject, r.details);
  // Everyone the group pays, closes to, rekeys to, claws back from or freezes, and the other senders in it, against
  // the OFAC SDN list.
  const sanctions = partySanctionsReasons(txns.flatMap((t) => [t.sender, t.receiver, t.closeTo, t.rekeyTo, t.clawbackFrom, t.freezeAccount]), { exclude: [req.wallet] });
  for (const r of sanctions.reasons) add(r.code, r.severity, r.subject, r.details);

  const site = await addOriginReasons(req.origin, await domain, await reputation, add);
  const intentAnswer = await intent;
  for (const r of intentAnswer.reasons) add(r.code, r.severity, r.subject, r.details);

  const verdict = reasons.some((r) => r.severity === "red") ? "red" : reasons.some((r) => r.severity === "orange") ? "orange" : "green";
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      kind: "algorand_transaction",
      network: net.caip2,
      wallet: req.wallet,
      ...(req.origin && { origin: req.origin }),
      transactions: txns,
    },
    scope: "Algorand transactions before signing: rekeying the account to another key, closing the account or an asset holding to someone else, clawback transfers, fake USDC/USDt (and assets named ALGO), opting in to assets with a clawback or frozen by default, app updates, deletes and clear-state, asset control addresses handed over or cleared, giving up consensus participation, fees far above normal, transactions from a group that wasn't sent whole, and whether the group would fail (algod simulate, with the amounts a close would send), every receiver, close-to, rekey and other sender against the OFAC SDN list, plus the requesting site's phishing-list status and domain age. Not covered: what an app's program does with the state it keeps for you.",
    sources: [...(rules.nodeUsed || sim ? ["algod"] : []), ...(sanctions.used ? ["ofac-sdn"] : []), ...(site.pg1Used ? ["pg1"] : []), ...(req.origin ? ["goplus"] : []), ...(site.metamaskUsed ? ["metamask"] : []), ...intentAnswer.sources],
    checkedAt: new Date().toISOString(),
  };
}

// personal_sign / eth_sign. eth_sign is red: it signs a raw hash, so nobody can see what is agreed to. A message
// that isn't readable text is orange for the same reason. A sign-in message (EIP-4361) for another site than the one
// asking is red: that is a phishing site relaying a real site's login. The site itself is checked as for any request.
async function analyzeMessage(req) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };
  const domain = req.origin ? domainAge(req.origin) : Promise.resolve(undefined);
  const reputation = req.origin && originReputationOn()
    ? Promise.all([hostnameReputation(req.origin), goplusPhishing(req.origin), metamaskSiteScan(req.origin)])
    : Promise.resolve(null);
  const s = req.signIn;
  const intent = req.intent
    ? intentCheck({ intent: req.intent, effects: {
        signing: `a plain message (${req.method}); it moves no tokens by itself`,
        message: req.text !== null ? req.text.slice(0, 1500) : `${req.bytes} bytes of unreadable binary data`,
        ...(s && { sign_in: { site: s.domain, account: s.address, uri: s.uri, chainId: s.chainId } }),
      } }).catch(() => ({ reasons: [], sources: [] }))
    : Promise.resolve({ reasons: [], sources: [] });

  if (req.method === "eth_sign") add("ETH_SIGN", "red", req.from ?? null, { bytes: req.bytes });
  else if (req.text === null) add("UNREADABLE_MESSAGE", "orange", req.from ?? null, { bytes: req.bytes, ...(req.bytes === 32 && { looksLike: "a 32-byte hash" }) });
  if (req.disguisedTransaction) add("MESSAGE_IS_TRANSACTION", "red", req.from ?? null, { chain: req.disguisedTransaction, effect: `signing this message signs ${req.disguisedTransaction === "solana" ? "a Solana" : "an XRPL"} transaction` });

  if (s) {
    add("SIGN_IN_REQUEST", "info", s.domain, { address: s.address, uri: s.uri, chainId: s.chainId, ...(s.expirationTime && { expirationTime: s.expirationTime }) });
    const site = siteOf(s.domain);
    if (req.origin && site && site !== siteOf(req.origin)) add("SIGN_IN_DOMAIN_MISMATCH", "red", s.domain, { origin: req.origin });
    const uriSite = siteOf(s.uri);
    if (uriSite && site && /^https?:/i.test(s.uri) && uriSite !== site) add("SIGN_IN_URI_MISMATCH", "orange", s.uri, { domain: s.domain });
    if (req.from && s.address.toLowerCase() !== req.from) add("SIGN_IN_ADDRESS_MISMATCH", "orange", s.address, { from: req.from });
    if (req.chainId && s.chainId && s.chainId !== req.chainId) add("SIGN_IN_CHAIN_MISMATCH", "orange", s.domain, { messageChainId: s.chainId, chainId: req.chainId });
  } else if (req.text !== null && req.method === "personal_sign") {
    add("PLAIN_MESSAGE", "info", req.from ?? null, { characters: req.text.length });
  }

  const site = await addOriginReasons(req.origin, await domain, await reputation, add);
  const intentAnswer = await intent;
  for (const r of intentAnswer.reasons) add(r.code, r.severity, r.subject, r.details);

  const verdict = reasons.some((r) => r.severity === "red") ? "red" : reasons.some((r) => r.severity === "orange") ? "orange" : "green";
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      kind: "message",
      method: req.method,
      ...(req.chainId && { chainId: req.chainId }),
      ...(req.from && { from: req.from }),
      ...(req.origin && { origin: req.origin }),
      ...(s && { signIn: { domain: s.domain, address: s.address, uri: s.uri, chainId: s.chainId } }),
      preview: req.text !== null ? req.text.slice(0, 200) : null,
    },
    scope: "Plain message signatures (personal_sign, eth_sign): eth_sign and unreadable messages, Sign-In with Ethereum messages for another site than the one asking, and the requesting site's phishing-list status and domain age. A message moves no tokens by itself; what a site does with a signed message is not covered.",
    sources: [...(site.pg1Used ? ["pg1"] : []), ...(req.origin ? ["goplus"] : []), ...(site.metamaskUsed ? ["metamask"] : []), ...intentAnswer.sources],
    checkedAt: new Date().toISOString(),
  };
}

// An EIP-7702 authorization hands the wallet to the code at the delegate address: from then on that contract can move
// everything the wallet holds, and drainers ask agents and users to sign exactly this ("sweeper" contracts). So even a
// clean, verified contract is orange (ask the user); only a contract on GoPlus's trust list, or clearing a delegation,
// is green. Red: no contract there yet (whoever deploys code at that address later controls the wallet), a flagged or
// sanctioned contract, unverified code, or an address that is itself a delegated wallet.
async function analyzeAuthorization(req) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };
  const d = req.delegate;
  const everyChain = req.authorizationChainId === 0;
  const domain = req.origin ? domainAge(req.origin) : Promise.resolve(undefined);
  const reputation = req.origin && originReputationOn()
    ? Promise.all([hostnameReputation(req.origin), goplusPhishing(req.origin), metamaskSiteScan(req.origin)])
    : Promise.resolve(null);
  const current = req.from ? getCode(req.chainId, req.from).catch(() => null) : Promise.resolve(null);
  const intent = req.intent
    ? intentCheck({ intent: req.intent, effects: {
        action: d === zeroAddress ? "sign an EIP-7702 authorization that clears the wallet's delegated code" : "sign an EIP-7702 authorization: the wallet will run this contract's code, which can then move everything the wallet holds",
        delegate: d, chains: everyChain ? "every EVM chain" : String(req.chainId),
        ...(req.origin && { requested_by_site: req.origin }),
      } }).catch(() => ({ reasons: [], sources: [] }))
    : Promise.resolve({ reasons: [], sources: [] });

  let ofacUsed = false;
  let pg1Used = false;
  if (d === zeroAddress) {
    add("REVOKES_DELEGATION", "info", req.from ?? null);
  } else {
    const [code, a, c, sc] = await Promise.all([
      getCode(req.chainId, d).catch(() => undefined),
      getAddressSecurity(req.chainId, d),
      getContractSecurity(req.chainId, d),
      screenParty(d),
    ]);
    if (a.partial || c.partial) add("PARTIAL_SOURCE_DATA", "info", d);
    const trusted = flag(c.data?.trust_list);
    add("EIP7702_AUTHORIZATION", trusted ? "info" : "orange", d, { chains: everyChain ? "all" : [req.chainId] });
    if (trusted) add("ON_TRUST_LIST", "info", d);
    if (everyChain) add("AUTHORIZATION_ALL_CHAINS", "orange", d);
    if (code === undefined) add("DELEGATE_CODE_UNKNOWN", "orange", d);
    else if (!/^0x[0-9a-f]+$/i.test(code) || /^0x0*$/i.test(code)) add("AUTHORIZATION_TO_NO_CONTRACT", "red", d);
    else if (DELEGATION_CODE.test(code)) add("AUTHORIZATION_TO_DELEGATED_WALLET", "red", d, { delegate: "0x" + code.slice(8).toLowerCase() });
    const flags = [
      ...ADDRESS_RED_FLAGS.filter((f) => flag(a.data?.[f])),
      ...(Array.isArray(c.data?.malicious_behavior) ? c.data.malicious_behavior : []),
      ...(flag(c.data?.doubt_list) ? ["doubt_list"] : []),
    ];
    if (flags.length) add("AUTHORIZATION_TO_FLAGGED_CONTRACT", "red", d, { flags });
    const deployedCode = code !== undefined && /^0x[0-9a-f]+$/i.test(code) && !/^0x0*$/i.test(code) && !DELEGATION_CODE.test(code);
    const verified = deployedCode && c.data ? await verifiedBy(req.chainId, d, c.data) : null;
    if (deployedCode && c.data && !verified) add("AUTHORIZATION_TO_UNVERIFIED_CONTRACT", "red", d);
    if (verified === "sourcify") add("VERIFIED_ON_SOURCIFY", "info", d);
    const deployed = Number(c.data?.deployed_time);
    if (deployed && Math.floor(Date.now() / 1000) - deployed < RECENT_DEPLOY_SECONDS) add("RECENTLY_DEPLOYED", "orange", d);
    if (!sc) add("SANCTIONS_SCREEN_UNAVAILABLE", "info", d);
    else {
      if (sc.source === "pg1") pg1Used = true;
      else ofacUsed = true;
      if (sc.listed) add("SANCTIONED_ADDRESS", "red", d, { list: "OFAC SDN", matches: sc.matches.map((m) => ({ name: m.sdnName, programs: m.programs })), listSynced: sc.listSynced });
      else add("SANCTIONS_SCREENED", "info", d, { list: "OFAC SDN", listed: false, listSynced: sc.listSynced });
    }
  }
  const walletCode = await current;
  if (walletCode && DELEGATION_CODE.test(walletCode)) {
    const delegate = "0x" + walletCode.slice(8).toLowerCase();
    add("CURRENT_DELEGATION", "info", req.from, { delegate, ...(delegate === d && { unchanged: true }) });
  }

  const site = await addOriginReasons(req.origin, await domain, await reputation, add);
  const intentAnswer = await intent;
  for (const r of intentAnswer.reasons) add(r.code, r.severity, r.subject, r.details);

  const verdict = reasons.some((r) => r.severity === "red") ? "red" : reasons.some((r) => r.severity === "orange") ? "orange" : "green";
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      kind: "authorization",
      chainId: req.chainId,
      delegate: d,
      authorizationChainId: req.authorizationChainId,
      ...(req.nonce !== undefined && { nonce: req.nonce }),
      ...(req.from && { from: req.from }),
      ...(req.origin && { origin: req.origin }),
    },
    scope: "EIP-7702 authorizations (delegating the wallet's code to a contract): whether the contract exists, is verified, flagged or on GoPlus's trust list, recently deployed or on the OFAC SDN list, an authorization valid on every chain, the wallet's current delegation (with from), and the requesting site's phishing-list status and domain age. What a verified contract's code does is not audited: delegating to any contract hands it the wallet.",
    sources: [...new Set([...(d !== zeroAddress ? ["goplus", "chain-rpc"] : []), ...(req.from ? ["chain-rpc"] : []), ...(ofacUsed ? ["ofac-sdn"] : []), ...(pg1Used || site.pg1Used ? ["pg1"] : []), ...(req.origin ? ["goplus"] : []), ...(site.metamaskUsed ? ["metamask"] : []), ...intentAnswer.sources])],
    checkedAt: new Date().toISOString(),
  };
}

// One address against the OFAC SDN list: our own copy of the Treasury list (src/ofac.js), PG1 while it isn't loaded.
async function screenParty(address) {
  const own = screenOfacLoaded(address);
  if (own) return { listed: own.listed, matches: own.matches.map((m) => ({ sdnName: m.name, programs: m.programs })), listSynced: own.published, source: "ofac-sdn" };
  const pg1 = await screenSanctions(address);
  return pg1 && { ...pg1, source: "pg1" };
}

export async function analyze(req) {
  if (req.kind === "message") return analyzeMessage(req);
  if (req.kind === "authorization") return analyzeAuthorization(req);
  if (req.kind === "solana") return analyzeSolana(req);
  if (req.kind === "algorand") return analyzeAlgorand(req);
  const reasons = [];
  const add = (code, severity, subject, details) => {
    const d = details ? JSON.stringify(details) : "";
    if (reasons.some((r) => r.code === code && r.subject === subject && (r.details ? JSON.stringify(r.details) : "") === d)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };

  // What the transaction really does to the sender's wallet (only with `from`; eth_simulateV1, src/simulate.js), asked
  // first so the intent check below can compare the stated intent with the simulated balance changes.
  const simulation = req.from ? createSimulator().simulate({ chainId: req.chainId, from: req.from, to: req.target, data: req.data, value: req.value }) : Promise.resolve(null);
  // Who this wallet has paid before (src/poisoning.js), to catch a look-alike recipient (address poisoning).
  const history = req.from ? createHistory().recipientsOf(req.chainId, req.from) : Promise.resolve(null);

  // Revoked spenders are not looked up: revoking a bad address is safe.
  const subjects = new Set([req.target, ...req.grants.map((g) => g.spender)].filter(Boolean));

  // Addresses that would receive an allowance, transfer right or payment: GoPlus
  // calls an EIP-7702 wallet a contract (it has code), so check the code ourselves.
  const spenders = new Set(req.grants.map((g) => g.spender));

  // How old the wallets that would get an allowance or transfer right are (PG1),
  // asked alongside GoPlus; only plain wallets are judged on it below.
  const ageSubjects = [...new Set(req.grants.filter((g) => g.mode !== "payment").map((g) => g.spender))];
  const ages = Promise.all(ageSubjects.map(async (address) => [address, await walletAge(address, req.chainId)]))
    .then((list) => new Map(list));

  // OFAC SDN (our own copy of the Treasury list, PG1 while it isn't loaded) and RDAP (PG1) run alongside GoPlus;
  // null = no list available, never an error.
  const pg1 = Promise.all([
    Promise.all([...subjects].map(async (address) => [address, await screenParty(address)])),
    req.origin ? domainAge(req.origin) : Promise.resolve(undefined),
  ]);
  // The origin against phishing lists (PG1: MetaMask eth-phishing-detect + lookalikes;
  // GoPlus phishing_site) and MetaMask's site scanner; each null when unavailable.
  const reputation = req.origin && originReputationOn()
    ? Promise.all([hostnameReputation(req.origin), goplusPhishing(req.origin), metamaskSiteScan(req.origin)])
    : Promise.resolve(null);

  const lookups = await Promise.all([...subjects].map(async (address) => {
    const [a, c] = await Promise.all([
      getAddressSecurity(req.chainId, address),
      getContractSecurity(req.chainId, address),
    ]);
    const code = spenders.has(address) && flag(c.data?.is_contract) ? await getCode(req.chainId, address) : null;
    const delegated = DELEGATION_CODE.test(code ?? "");
    // The contract an EIP-7702 wallet delegates to runs with the wallet's authority:
    // screen it like a spender contract.
    let delegate = null;
    if (delegated) {
      const address7702 = "0x" + code.slice(8).toLowerCase();
      const [da, dc] = await Promise.all([
        getAddressSecurity(req.chainId, address7702),
        getContractSecurity(req.chainId, address7702),
      ]);
      const verified = flag(dc.data?.is_contract) ? await verifiedBy(req.chainId, address7702, dc.data) : null;
      delegate = { address: address7702, addrSec: da.data, contract: dc.data, partial: da.partial || dc.partial, verified };
    }
    const contract = !delegated && flag(c.data?.is_contract);
    const [proxy, verified] = await Promise.all([
      contract && flag(c.data?.is_proxy) ? confirmProxy(req.chainId, address) : null,
      contract ? verifiedBy(req.chainId, address, c.data) : null,
    ]);
    return [address, { addrSec: a.data, contract: c.data, partial: a.partial || c.partial, delegated, delegate, proxy, verified }];
  }));
  const results = new Map(lookups);

  // The tokens being approved, permitted or paid (not NFT approve-for-all).
  const tokens = [...new Set(req.grants.filter((g) => !g.allForAll && g.token).map((g) => g.token))];
  // A proxy token (USDC, cbBTC, EURC) gets no pause or blacklist fields from GoPlus:
  // then the token is asked on-chain, as in the token verdict.
  const tokenLookups = await Promise.all(tokens.map(async (token) => {
    const sec = await getTokenSecurity(req.chainId, token);
    return [token, sec, needsControlCheck(sec.data) ? await issuerControls(req.chainId, token) : null];
  }));
  // Symbol and name from the same GoPlus record, so callers can name the token.
  const tokenMeta = new Map(tokenLookups.map(([token, { data }]) => [token, {
    ...(typeof data?.token_symbol === "string" && data.token_symbol && { symbol: data.token_symbol.slice(0, 32) }),
    ...(typeof data?.token_name === "string" && data.token_name && { name: data.token_name.slice(0, 64) }),
  }]));
  for (const [token, { data, partial }, controls] of tokenLookups) {
    if (partial) add("PARTIAL_SOURCE_DATA", "info", token);
    tokenReasons(token, data, add);
    controlReasons(controls, (code, severity, details) => add(code, severity, token, details));
  }
  // Jev's second opinion on the site name and the token names (src/jev.js), alongside the checks below.
  const aiSecond = secondOpinion({
    chainId: req.chainId,
    origin: req.origin ?? null,
    tokens: tokens.map((address) => ({ address, ...tokenMeta.get(address) })),
    skipTokens: new Set(reasons.filter((r) => r.code === "TOKEN_IMPERSONATION").map((r) => r.subject)),
    // Skipped when the code already flags it (a Permit2 signature at another contract is NONCANONICAL_PERMIT2).
    domain: req.domainName && req.target && !(req.kind?.startsWith("permit2") && req.target !== PERMIT2) ? { name: req.domainName, verifyingContract: req.target } : null,
  }).catch(() => ({ reasons: [], sources: [] }));
  // Does signing do what the agent says it is for (only when it passed intent)?
  const intentAnswer = req.intent
    ? simulation.then((sim) => intentCheck({ intent: req.intent, effects: { ...effectsOf(req, tokenMeta), ...(sim && { simulated: simulationEffects(sim, req.from) }) } })).catch(() => ({ reasons: [], sources: [] }))
    : null;
  const isContract = (address) => flag(results.get(address)?.contract?.is_contract) && !results.get(address).delegated;
  const now = Math.floor(Date.now() / 1000);

  for (const [address, { addrSec, contract, partial, delegated, delegate, proxy, verified }] of results) {
    if (partial) add("PARTIAL_SOURCE_DATA", "info", address);
    if (delegated) add("EIP7702_DELEGATED_WALLET", "info", address, { delegate: delegate.address });
    if (delegate) {
      if (delegate.partial) add("PARTIAL_SOURCE_DATA", "info", delegate.address);
      const flags = [
        ...ADDRESS_RED_FLAGS.filter((f) => flag(delegate.addrSec?.[f])),
        ...(Array.isArray(delegate.contract?.malicious_behavior) ? delegate.contract.malicious_behavior : []),
        ...(flag(delegate.contract?.doubt_list) ? ["doubt_list"] : []),
      ];
      if (flags.length) add("MALICIOUS_DELEGATE", "red", address, { delegate: delegate.address, flags });
      else if (delegate.contract && flag(delegate.contract.is_contract) && !delegate.verified) {
        add("UNVERIFIED_DELEGATE", "orange", address, { delegate: delegate.address });
      }
      if (delegate.verified === "sourcify") add("VERIFIED_ON_SOURCIFY", "info", delegate.address);
    }
    for (const f of ADDRESS_RED_FLAGS) if (flag(addrSec?.[f])) add(f.toUpperCase(), "red", address);
    for (const f of ADDRESS_ORANGE_FLAGS) if (flag(addrSec?.[f])) add(f.toUpperCase(), "orange", address);
    if (Number(addrSec?.number_of_malicious_contracts_created) > 0) {
      add("CREATOR_OF_MALICIOUS_CONTRACTS", "red", address);
    }

    if (isContract(address)) {
      const malicious = Array.isArray(contract.malicious_behavior) ? contract.malicious_behavior : [];
      if (malicious.length) add("MALICIOUS_CONTRACT_BEHAVIOR", "red", address, malicious);
      if (flag(contract.doubt_list)) add("ON_DOUBT_LIST", "red", address);
      if (!verified) add("UNVERIFIED_CONTRACT", "orange", address);
      else if (verified === "sourcify") add("VERIFIED_ON_SOURCIFY", "info", address);
      if (proxy === "unchecked") add("UPGRADEABLE_PROXY", "info", address, { confirmed: false });
      else if (proxy) add("UPGRADEABLE_PROXY", "info", address, proxy);
      const deployed = Number(contract.deployed_time);
      if (deployed && now - deployed < RECENT_DEPLOY_SECONDS) add("RECENTLY_DEPLOYED", "orange", address);
      if (flag(contract.trust_list)) add("ON_TRUST_LIST", "info", address);
    }
  }

  const [sanctions, domain] = await pg1;
  let pg1Used = false;
  let ofacUsed = false;
  for (const [address, sc] of sanctions) {
    if (!sc) { add("SANCTIONS_SCREEN_UNAVAILABLE", "info", address); continue; }
    if (sc.source === "pg1") pg1Used = true;
    else ofacUsed = true;
    if (sc.listed) {
      // One sanctions reason per address: GoPlus's bare SANCTIONED flag folds into
      // the OFAC entry, credited in alsoFlaggedBy.
      const goplusIdx = reasons.findIndex((r) => r.code === "SANCTIONED" && r.subject === address);
      if (goplusIdx !== -1) reasons.splice(goplusIdx, 1);
      add("SANCTIONED_ADDRESS", "red", address, {
        list: "OFAC SDN", matches: sc.matches.map((m) => ({ name: m.sdnName, programs: m.programs })), listSynced: sc.listSynced,
        ...(goplusIdx !== -1 && { alsoFlaggedBy: ["goplus"] }),
      });
    } else {
      // A clean result names the list and its last sync too, inside the signed
      // receipt: a buyer can show which version of the list it was screened against.
      add("SANCTIONS_SCREENED", "info", address, { list: "OFAC SDN", listed: false, listSynced: sc.listSynced });
    }
  }
  const site = await addOriginReasons(req.origin, domain, await reputation, add);
  if (site.pg1Used) pg1Used = true;
  const metamaskUsed = site.metamaskUsed;

  if (req.revoke) add("REVOKES_APPROVAL", "info", req.revokedSpender ?? req.target);
  const walletAges = await ages;

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
      const age = walletAges.get(g.spender);
      if (!age) add("WALLET_AGE_UNAVAILABLE", "info", g.spender);
      else if (!age.found) add("NEW_WALLET_SPENDER", "red", g.spender, { ageDays: null, firstSeen: null, history: "none" });
      else {
        const seen = { ageDays: age.ageDays, firstSeen: age.firstSeen, chain: age.chain, ...(age.minimum ? { minimum: true } : {}) };
        // A minimum age under the threshold can't tell new from old: orange, never red.
        if (age.ageDays < NEW_WALLET_DAYS) add("NEW_WALLET_SPENDER", age.ageDays < BRAND_NEW_WALLET_DAYS && !age.minimum ? "red" : "orange", g.spender, seen);
        else add("WALLET_AGE", "info", g.spender, seen);
      }
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

  // Only adds orange, and not where a phishing list already named the site.
  const ai = await aiSecond;
  const listedSite = reasons.some((r) => r.code === "PHISHING_SITE" || r.code === "LOOKALIKE_SITE");
  for (const r of ai.reasons) {
    if (listedSite && (r.code === "AI_LOOKALIKE_SITE" || r.code === "AI_LURE_SITE")) continue;
    add(r.code, r.severity, r.subject, r.details);
  }

  // The agent's stated intent against what signing does: INTENT_MISMATCH is orange, a match an info line.
  const intent = intentAnswer ? await intentAnswer : { reasons: [], sources: [] };
  for (const r of intent.reasons) add(r.code, r.severity, r.subject, r.details);

  // The simulation: an approval or NFT leaving the wallet that the decoded call doesn't show, or a transaction
  // that would fail, is orange; what leaves and arrives is an info line and the answer's `simulation` field.
  const sim = await simulation;
  for (const r of simulationReasons(sim, { from: req.from, kind: req.kind })) add(r.code, r.severity, r.subject, r.details);
  // A recipient that starts and ends like an address this wallet has paid before, but isn't it, is red.
  const pastRecipients = await history;
  for (const r of poisoningReasons(pastRecipients, transferRecipients(req, sim))) add(r.code, r.severity, r.subject, r.details);

  // Not what the seller asked (x402 requirements): paying more, someone else, another token or chain is red.
  if (req.x402) {
    const g = req.grants[0];
    const x = checkX402Payment(req.x402, { chainId: req.chainId, to: g.spender, token: g.token, value: g.amount, validBefore: g.expiresAt, domainName: req.domainName, domainVersion: req.domainVersion }, { now });
    for (const f of x.failures) { const { code, ...d } = f; add(code, "red", g.spender, d); }
    for (const w of x.warnings) { const { code, ...d } = w; add(code, "orange", g.spender, d); }
    for (const n of x.notes) { const { code, ...d } = n; add(code, "info", g.spender, d); }
    if (x.ok) add("X402_REQUIREMENTS_MATCH", "info", g.spender, { amount: g.amount.toString() });
  }

  // Outside the agent's mandate is red: signing would spend beyond what the principal granted.
  let mandate = null;
  if (req.mandate) {
    const m = checkMandatePayment(req.mandate.envelope, req.mandate.paymentId, req.mandate.payment);
    for (const f of m.failures) add(f.code, "red", req.mandate.payment.to, { reason: f.reason, ...(f.expected && { expectedNonce: f.expected }) });
    for (const w of m.warnings) add(w.code, "orange", req.mandate.payment.to, { reason: w.reason });
    if (m.ok) add("MANDATE_OK", "info", req.mandate.payment.to, { mandateDigest: m.digest });
    mandate = { ok: m.ok, ...(m.digest && { digest: m.digest }), checked: "single payment (§6, §7); cumulative spend against the cap is not checked" };
  }

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
        ...(tokenMeta.get(g.token)?.symbol && { tokenSymbol: tokenMeta.get(g.token).symbol }),
        ...(tokenMeta.get(g.token)?.name && { tokenName: tokenMeta.get(g.token).name }),
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
      ...(req.origin && { origin: req.origin }),
      value: req.value.toString(),
    },
    scope: `On-chain transactions and approvals, plus EIP-712 Permit, Permit2, EIP-3009 (x402 payment) and Seaport signatures, with GoPlus token security for the tokens involved, OFAC SDN sanctions screening (the US Treasury list, PG1 as fallback) and the requesting site's domain age (via PG1). ${createSimulator().enabled ? `Transactions sent with \`from\` are simulated (asset changes, on chains ${SIMULATED_CHAINS.join(", ")}).` : "Not covered: transaction simulation."} Plain messages (personal_sign, eth_sign) are checked with type \"message\".`,
    ...(mandate && { mandate }),
    ...(sim && { simulation: sim }),
    sources: [...new Set(["goplus", "chain-rpc", ...(ofacUsed ? ["ofac-sdn"] : []), ...(pg1Used ? ["pg1"] : []), ...(metamaskUsed ? ["metamask"] : []), ...(sim?.source === "alchemy" || pastRecipients ? ["alchemy"] : []), ...ai.sources, ...intent.sources])],
    checkedAt: new Date().toISOString(),
  };
}

// What signing does, in words Jev can compare with the agent's intent: the kind of action, the token symbols
// where known, who gets an allowance, a payment or a transfer, how much and whether it is unlimited.
const KIND_TEXT = {
  native_transfer: "send native coin", contract_call: "call a contract (calldata not decoded)", token_approve: "approve a token allowance",
  approval_for_all: "approve an operator for ALL NFTs of a collection", permit: "sign a Permit (an allowance without a transaction)",
  permit2_allowance: "sign a Permit2 allowance", permit2_transfer: "sign a Permit2 transfer", transfer_authorization: "sign a token payment (EIP-3009, as in x402)",
  marketplace_order: "sign a marketplace listing (Seaport order)", unknown_signature: "sign an unrecognized message",
};
export function effectsOf(req, tokenMeta = new Map()) {
  const sym = (t) => tokenMeta.get(t)?.symbol || null;
  const what = { allowance: "may spend", payment: "is paid", transfer: "receives" };
  return {
    action: KIND_TEXT[req.kind] || req.kind,
    target: req.target ?? null,
    ...(sym(req.target) && { target_token: sym(req.target) }),
    ...(req.value > 0n && { native_value_wei: req.value.toString() }),
    grants: req.grants.map((g) => ({
      to: g.spender,
      [g.allForAll ? "gets" : what[g.mode] ?? "gets"]: g.allForAll ? "permission over every NFT of the collection" : `${g.unlimited ? "UNLIMITED" : g.amount === null ? "?" : g.amount.toString()} ${sym(g.token) ?? g.token}${g.unlimited ? "" : " (base units)"}`,
    })),
    ...(req.revoke && { revokes_approval_of: req.revokedSpender ?? "?" }),
    ...(req.order && { listing: { items_offered: req.order.offerCount, pays_the_signer: req.order.paysOfferer } }),
    ...(req.primaryType && { signature_type: req.primaryType }),
    ...(req.origin && { requested_by_site: req.origin }),
  };
}

// ---------- plain-language explanation ----------

export async function explain(result, lang) {
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
        model: process.env.CLAUDE_MODEL ?? CLAUDE_MODEL,
        ...claudeModelParams(process.env.CLAUDE_MODEL ?? CLAUDE_MODEL),
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

// solana: optional { network, payTo }; the token verdict can then also be paid in USDC on Solana.
// xrpl: optional { network, payTo }; every route can then also be paid in RLUSD on the XRP Ledger.
// algorand: optional { network, payTo }; every route can then also be paid in USDC on Algorand.
// builderCode: optional Base Builder Code (env BUILDER_CODE), so Base can attribute the payments to Fizzl.
// stellar: optional { network, payTo }; every route can then also be paid in USDC on Stellar.
export function x402Routes(payTo, network = "eip155:8453", solana = null, xrpl = null, algorand = null, builderCode = null, stellar = null) {
  if (!payTo) throw new Error("PAY_TO address is required");
  const sellerExtensions = { ...merchantExtension, ...builderCodeExtension(builderCode) };
  const route = (path, description) => ({
    accepts: [
      { scheme: "exact", price: `$${ROUTES[path].price}`, network, payTo },
      // Solana agents pay the check in USDC on Solana: it covers their own transactions too.
      ...(solana?.payTo ? [{ scheme: "exact", price: `$${ROUTES[path].price}`, network: solana.network, payTo: solana.payTo }] : []),
      ...xrplAccept(xrpl, `$${ROUTES[path].price}`, `POST ${path}`),
      ...algorandAccept(algorand, `$${ROUTES[path].price}`),
      ...stellarAccept(stellar, `$${ROUTES[path].price}`),
    ],
    description,
    mimeType: "application/json",
    ...serviceMetadata,
    extensions: { ...bazaarExtension(), ...sellerExtensions },
  });
  const tokenPrice = `$${TOKEN_ROUTE.price}`;
  const approvalsPrice = `$${APPROVALS_ROUTE.price}`;
  const screenPrice = `$${SCREEN_ROUTE.price}`;
  const injectionPrice = `$${INJECTION_ROUTE.price}`;
  return {
    "POST /v1/check": route("/v1/check",
      "Is this transaction, approval or signature safe to sign? Check it before your AI agent or wallet signs it: pre-sign verdict (green/orange/red + reason codes) for EVM and Solana transactions, token approvals and Permit/Permit2/EIP-3009/Seaport signatures. Screens the spender or recipient wallet for OFAC sanctions and scam, phishing or theft reports, and flags unlimited allowances, plain-wallet spenders and risky tokens"),
    "POST /v1/check/explain": route("/v1/check/explain",
      "Is this transaction, approval or signature safe to sign, explained for a person? The same pre-sign verdict as /v1/check (green/orange/red + reason codes) plus a short plain-language explanation in English or Dutch, for an agent to show its user before asking for approval"),
    [`GET ${TOKEN_ROUTE.path}`]: {
      accepts: [
        { scheme: "exact", price: tokenPrice, network, payTo },
        ...(solana?.payTo ? [{ scheme: "exact", price: tokenPrice, network: solana.network, payTo: solana.payTo }] : []),
        ...xrplAccept(xrpl, tokenPrice, `GET ${TOKEN_ROUTE.path}`),
        ...algorandAccept(algorand, tokenPrice),
        ...stellarAccept(stellar, tokenPrice),
      ],
      description: "Is this token safe to buy, or a honeypot or rug pull? Checks a Solana or EVM token before you buy, hold or accept it (mint or freeze authority still active, LP not locked, buy/sell tax, low liquidity, brand-new token, concentrated holders) and answers green/orange/red with a grade (SAFE/CAUTION/RISKY/AVOID), the reasons, a one-line summary and market data",
      mimeType: "application/json",
      ...tokenServiceMetadata,
      extensions: { ...tokenBazaarExtension(), ...sellerExtensions },
    },
    [`GET ${APPROVALS_ROUTE.path}`]: {
      accepts: [
        { scheme: "exact", price: approvalsPrice, network, payTo },
        ...(solana?.payTo ? [{ scheme: "exact", price: approvalsPrice, network: solana.network, payTo: solana.payTo }] : []),
        ...xrplAccept(xrpl, approvalsPrice, `GET ${APPROVALS_ROUTE.path}`),
        ...algorandAccept(algorand, approvalsPrice),
        ...stellarAccept(stellar, approvalsPrice),
      ],
      description: "Wallet approval audit (green/orange/red, grade, one-line summary): every open ERC-20 allowance of an EVM wallet with who the spender is (flagged, plain wallet, unverified, unlimited) and which ones to revoke",
      mimeType: "application/json",
      ...approvalsServiceMetadata,
      extensions: { ...approvalsBazaarExtension(), ...sellerExtensions },
    },
    [`GET ${SCREEN_ROUTE.path}`]: {
      accepts: [
        { scheme: "exact", price: screenPrice, network, payTo },
        ...(solana?.payTo ? [{ scheme: "exact", price: screenPrice, network: solana.network, payTo: solana.payTo }] : []),
        ...xrplAccept(xrpl, screenPrice, `GET ${SCREEN_ROUTE.path}`),
        ...algorandAccept(algorand, screenPrice),
        ...stellarAccept(stellar, screenPrice),
      ],
      description: "Is this wallet sanctioned? Screens any chain's address (EVM, Solana, Tron, Bitcoin, XRP Ledger, Algorand) against the OFAC SDN list, synced from the US Treasury, plus theft, phishing and mixer reports for EVM addresses. Green/orange/red with the SDN entry (name, programs) when listed. For sellers screening who pays them and agents checking who they pay",
      mimeType: "application/json",
      ...screenServiceMetadata,
      extensions: { ...screenBazaarExtension(), ...sellerExtensions },
    },
    [`POST ${INJECTION_ROUTE.path}`]: {
      accepts: [
        { scheme: "exact", price: injectionPrice, network, payTo },
        ...(solana?.payTo ? [{ scheme: "exact", price: injectionPrice, network: solana.network, payTo: solana.payTo }] : []),
        ...xrplAccept(xrpl, injectionPrice, `POST ${INJECTION_ROUTE.path}`),
        ...algorandAccept(algorand, injectionPrice),
        ...stellarAccept(stellar, injectionPrice),
      ],
      description: "Is this text a prompt-injection trap for your AI agent? Checks a web page, email, tool result, API answer or another agent's message before your agent acts on it: does it try to make the agent ignore its instructions, pay or send money, hand over keys or private data, or obey a fake user, admin or support message? Green/orange/red with reason codes, judged by TypeSafe's Jev, plus hidden-character tricks and OFAC-sanctioned addresses in the text",
      mimeType: "application/json",
      ...injectionServiceMetadata,
      extensions: { ...injectionBazaarExtension(), ...sellerExtensions },
    },
  };
}

export function createCheckRouter() {
  const router = express.Router();
  router.use(express.json({ limit: "64kb" })); // batch permits and Seaport orders can be large
  // server.js parses /v1/check before the paywall (for OWS's 402); a body it couldn't parse fails here, after payment.
  router.use((req, _res, next) => next(req.fizzlJsonError));

  // OWS kills a policy that hasn't answered within 5 s and denies; answering first keeps the reason and the error
  // status (so nothing is charged for a check OWS would throw away). Most checks take 1–2 s; a slow lookup can take more.
  const OWS_BUDGET_MS = 4200;
  const withinBudget = (work) => {
    let timer;
    const late = new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(`the check took longer than ${OWS_BUDGET_MS / 1000} s, and OWS waits at most 5 s`), { status: 504 })), OWS_BUDGET_MS); });
    return Promise.race([work, late]).finally(() => clearTimeout(timer));
  };
  const handler = (withExplanation) => async (req, res) => {
    // An OWS policy's PolicyContext (src/ows.js) becomes an ordinary check; the answer adds { allow, reason }.
    const ows = isOwsContext(req.body);
    const allowUnchecked = ows && req.body.policy_config?.allow_unchecked === true;
    try {
      const translated = ows ? owsToCheck(req.body) : null;
      const body = translated ? translated.body : req.body;
      const work = (async () => {
        // XRP Ledger transactions have their own parser and rules (src/xrpl.js).
        const result = isXrplRequest(body) ? await analyzeXrpl(await parseXrplRequest(body)) : await analyze(parseRequest(body));
        if (withExplanation) {
          const lang = req.body.lang === "nl" ? "nl" : "en";
          result.explanation = { lang, text: await explain(result, lang) };
        }
        return result;
      })();
      const result = translated ? await withinBudget(work) : await work;
      if (translated) Object.assign(result, owsResult(result, translated.options));
      res.set("Cache-Control", "no-store").json(result);
    } catch (err) {
      const status = err.status ?? 500;
      if (status >= 500) console.error("[presign-guard]", err);
      // For OWS: something presign-guard can't judge is denied, unless the policy allows unchecked requests. Either
      // way the status stays an error, so no payment settles and credits come back.
      const policy = ows ? { allow: status < 500 && allowUnchecked, reason: `presign-guard ${status < 500 && allowUnchecked ? "didn't check this (allow_unchecked)" : "denied"}: ${status === 500 ? "internal error" : err.message}`.slice(0, 500) } : {};
      res.status(status).json({
        error: status === 400 ? "invalid_request" : status === 503 ? "upstream_unavailable" : status === 504 ? "timeout" : "internal_error",
        message: status === 500 ? "Internal error" : err.message,
        verdict: null,
        ...policy,
      });
    }
  };

  router.post("/v1/check", handler(false));
  router.post("/v1/check/explain", handler(true));
  return router;
}
