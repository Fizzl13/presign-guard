// Run: npm test
// No network: GoPlus and Claude are mocked through globalThis.fetch.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createCheckRouter } from "../src/presign-guard.js";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { jcs, mandateDigest, eip3009Binding } from "../src/mandate.js";
import { resetPg1, pg1Paused, pg1KeyStatus, pg1KeyStatusNow } from "../src/pg1.js";

process.env.ANTHROPIC_API_KEY = "test-key";

const realFetch = globalThis.fetch;
const TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const GOOD = "0x2222222222222222222222222222222222222222"; // verified contract
const EOA = "0xbad0000000000000000000000000000000000001";  // plain wallet
const PHISH = "0xbad0000000000000000000000000000000000002"; // flagged contract
const USER = "0x1111111111111111111111111111111111111111";
const DELEGATED = "0xbad0000000000000000000000000000000000004"; // EIP-7702 wallet: GoPlus says contract
const DELEGATED_BAD = "0xbad0000000000000000000000000000000000005"; // EIP-7702 wallet delegating to PHISH
const DELEGATED_UNVERIFIED = "0xbad0000000000000000000000000000000000006"; // delegating to unverified code
const UNVERIFIED_IMPL = "0xbad0000000000000000000000000000000000007";
const REAL_PROXY = "0x3333000000000000000000000000000000000001"; // GoPlus is_proxy, EIP-1967 slot set on-chain
const FAKE_PROXY = "0x3333000000000000000000000000000000000002"; // GoPlus is_proxy, no proxy layout on-chain (like DEGEN)
const MIN_PROXY = "0x3333000000000000000000000000000000000003";  // GoPlus is_proxy, an EIP-1167 clone
const UNCHECKED_PROXY = "0x3333000000000000000000000000000000000005"; // GoPlus is_proxy, looked up only while the RPC is down
const IMPL = "0x4444000000000000000000000000000000000004";
const PARTIAL = "0xbad0000000000000000000000000000000000003"; // GoPlus answers code 2, fields missing
const HONEY = "0x7777000000000000000000000000000000000001";   // honeypot token
const FAKE_USDC = "0x7777000000000000000000000000000000000002"; // impersonates USDC
const TAXED = "0x7777000000000000000000000000000000000003";   // 12% buy / 15% sell tax
const MINTABLE = "0x7777000000000000000000000000000000000004"; // mintable, otherwise normal (like DEGEN)
const PAUSED_TOKEN = "0x7777000000000000000000000000000000000009"; // proxy token, transfers paused
const SANCTIONED = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"; // Lazarus (Ronin hack), OFAC SDN
// Plain wallets for the wallet-age tests (GoPlus: not a contract).
const FRESH = "0xbad0000000000000000000000000000000000011";      // first seen 3 days ago
const BRAND_NEW = "0xbad0000000000000000000000000000000000012";  // first seen hours ago
const NO_HISTORY = "0xbad0000000000000000000000000000000000013"; // never seen on-chain
const APPROX = "0xbad0000000000000000000000000000000000014";     // 2 days, but only a minimum (WALLET_AGE_PARTIAL)
const AGE_TIMEOUT = "0xbad0000000000000000000000000000000000015"; // the lookup times out
const OLD_ON_ETH = "0xbad0000000000000000000000000000000000016"; // new to Base, years on Ethereum
const AGE_WALLETS = [FRESH, BRAND_NEW, NO_HISTORY, APPROX, AGE_TIMEOUT, OLD_ON_ETH];
const FAR = "9999999999";
const MAX256 = (2n ** 256n - 1n).toString();
const MAX160 = (2n ** 160n - 1n).toString();

// Per-test switches
let goplusDown = false;
let claudeDown = false;
let goplusCalls = 0;
let rpcDown = false;
let pg1Down = false;
let pg1Calls = 0;
let pg1RateLimited = false;
let pg1FailNext = 0; // this many PG1 calls answer 503 before it recovers
let pg1LastKey;

// PG1 MCP: check_wallet_sanctions and check_domain_age, shaped like the live responses.
const DOMAINS = {
  "uniswap.org": { available: true, domain: "uniswap.org", registration_date: "2018-11-26T05:33:07Z", age_days: 2860 },
  "claim-usdc-drop.xyz": { available: true, domain: "claim-usdc-drop.xyz", registration_date: "2026-09-22T10:00:00Z", age_days: 3 },
  "fizzl.eu": { available: false, domain: "fizzl.eu", reason: "No RDAP server registered for the '.eu' TLD in the IANA bootstrap file." },
};
// check_wallet_age, shaped like the live answers (the default: a wallet with 600 days of history).
const WALLET_AGES = {
  [FRESH]: { age_days: 3, first_seen: "2026-09-27T10:00:00.000Z" },
  [BRAND_NEW]: { age_days: 0.2, first_seen: "2026-09-30T08:00:00.000Z" },
  [NO_HISTORY]: { found: false, first_seen: null, age_days: null, note: "No transactions found for this address.", reasons: [{ code: "WALLET_NO_HISTORY" }] },
  [APPROX]: { age_days: 2, note: "The internal-transfer check did not finish.", reasons: [{ code: "WALLET_AGE_PARTIAL" }] },
  [OLD_ON_ETH]: { found: false, first_seen: null, age_days: null, note: "No transfer history on base." },
};
// Ethereum answers where they differ from the chain asked about.
const WALLET_AGES_ETH = { [OLD_ON_ETH]: { found: true, age_days: 1400, first_seen: "2022-11-20T00:00:00.000Z", note: null } };
const ageChains = [];
const WALLET_AGE_TIMEOUT = new Set([AGE_TIMEOUT]);
// check_hostname_reputation, shaped like the live answers.
const REPUTATION = {
  "002271coinbase.com": { verdict: "listed", sources: [{ name: "MetaMask eth-phishing-detect", match_type: "exact" }], lookalike_of: null },
  "metamask-login.com": { verdict: "lookalike", sources: [{ name: "PG1 lookalike detection", match_type: "keyword" }], lookalike_of: "metamask.io" },
  "metamask.io": { verdict: "allowlisted", sources: [{ name: "MetaMask eth-phishing-detect", match_type: "exact" }], lookalike_of: null },
};
const GOPLUS_PHISHING = new Set(["002271coinbase.com", "only-goplus-knows.com"]);
const METAMASK_BLOCKS = new Set(["x402-shop.example"]);
let metamaskDown = false;
let reputationDown = false;
function mockMetamask(url) {
  if (metamaskDown) return new Response("down", { status: 503 });
  const host = new URL(decodeURIComponent(new URL(url).searchParams.get("url"))).hostname;
  const block = METAMASK_BLOCKS.has(host);
  return new Response(JSON.stringify({ domainName: host, recommendedAction: block ? "BLOCK" : "NONE", riskFactors: block ? [{ type: "DRAINER", severity: "CRITICAL", message: "Domain identified as a wallet drainer." }] : null, verified: false, status: "COMPLETE" }));
}

async function mockPg1(opts) {
  pg1Calls++;
  pg1LastKey = opts.headers["x-api-key"];
  if (pg1Down) return new Response("down", { status: 503 });
  if (pg1FailNext > 0) { pg1FailNext--; return new Response("cold start", { status: 503 }); }
  if (pg1RateLimited) {
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: JSON.stringify({ error: "Rate limit reached", code: "rate_limited" }) }] } }));
  }
  const { params } = JSON.parse(opts.body);
  let out;
  if (params.name === "get_usage_status") {
    out = { identifier: "1.2.3.4", license_status: params.arguments.license_key === "good-key" ? "active" : "invalid_or_expired" };
  } else if (params.name === "check_wallet_sanctions") {
    const listed = params.arguments.address.toLowerCase() === SANCTIONED;
    out = { address: params.arguments.address, listed, list_last_synced: "2026-09-25T20:10:41Z",
      matches: listed ? [{ sdn_name: "LAZARUS GROUP", currency: "ETH", programs: ["DPRK3"], sdn_uid: "27307" }] : [] };
  } else if (params.name === "check_wallet_age") {
    const a = params.arguments.address.toLowerCase();
    if (WALLET_AGE_TIMEOUT.has(a)) return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: JSON.stringify({ error: true, code: "upstream_unavailable", message: "Wallet age lookup timed out after 2500ms." }) }] } }));
    out = { address: a, chain: params.arguments.chain, found: true, first_seen: "2025-01-01T00:00:00.000Z", age_days: 600, is_contract: false, note: null, ...WALLET_AGES[a], ...(params.arguments.chain === "ethereum" ? WALLET_AGES_ETH[a] : {}) };
    ageChains.push(`${params.arguments.chain}:${a}`);
  } else if (params.name === "check_hostname_reputation") {
    if (reputationDown) return new Response("db unreachable", { status: 503 });
    const h = params.arguments.hostname;
    out = { hostname: h, sources: [], lookalike_of: null, verdict: "not_listed", ...REPUTATION[h], list_synced_at: "2026-09-27T02:21:33Z" };
  } else {
    const d = params.arguments.domain;
    out = DOMAINS[d] ?? { available: false, domain: d, reason: `RDAP server responded with 404 for '${d}'.` };
  }
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(out) }] } }));
}

const EIP1967_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
let rpcMethods = [];
// Issuer control getters by token and selector (sent as one batch); anything else reverts.
const word = (hex) => "0x" + hex.padStart(64, "0");
const CONTROLS = {
  [TOKEN]: { "0x5c975abb": word("0"), "0x9fd0506d": word("1ac78dfcae082e9fe286d1ccb12c17a3e906b906"), "0xbd102430": word("158cfa498b1f72f458acf8df993c709efca11e31"), "0xfe575a87": word("0") },
  [PAUSED_TOKEN]: { "0x5c975abb": word("1") },
};
function mockRpc(opts) {
  if (rpcDown) return new Response("down", { status: 502 });
  const body = JSON.parse(opts.body);
  if (Array.isArray(body)) {
    return new Response(JSON.stringify(body.map(({ id, method, params: [{ to, data }] }) => {
      rpcMethods.push(method);
      const result = CONTROLS[to.toLowerCase()]?.[data.slice(0, 10)];
      return result ? { jsonrpc: "2.0", id, result } : { jsonrpc: "2.0", id, error: { code: 3, message: "execution reverted" } };
    })));
  }
  const { method, params } = body;
  rpcMethods.push(method);
  const address = params[0].toLowerCase();
  if (method === "eth_getStorageAt") {
    const set = address === REAL_PROXY && params[1] === EIP1967_SLOT;
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: set ? "0x000000000000000000000000" + IMPL.slice(2) : "0x" + "0".repeat(64) }));
  }
  if (address === MIN_PROXY) {
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: `0x363d3d373d3d3d363d73${IMPL.slice(2)}5af43d82803e903d91602b57fd5bf3` }));
  }
  const delegateTo = { [DELEGATED]: "ab".repeat(20), [DELEGATED_BAD]: PHISH.slice(2), [DELEGATED_UNVERIFIED]: UNVERIFIED_IMPL.slice(2) }[address];
  const result = delegateTo ? "0xef0100" + delegateTo : "0x6080604052";
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
}

// GoPlus token_security, keyed by lowercase address like the real API; unknown tokens have no record.
const TOKEN_DATA = {
  [TOKEN]: { token_symbol: "USDC", is_open_source: "1", is_proxy: "1", trust_list: "1", buy_tax: "0", sell_tax: "0" },
  [HONEY]: { token_symbol: "HONEY", is_open_source: "1", is_honeypot: "1", sell_tax: "1" },
  [FAKE_USDC]: { token_symbol: "USDC", is_open_source: "1", fake_token: { true_token_address: TOKEN, value: 1 } },
  [TAXED]: { token_symbol: "TAX", is_open_source: "1", buy_tax: "0.12", sell_tax: "0.15" },
  [MINTABLE]: { token_symbol: "DEGEN", is_open_source: "1", is_mintable: "1", transfer_pausable: "0", is_blacklisted: "0", buy_tax: "0", sell_tax: "0" },
  [PAUSED_TOKEN]: { token_symbol: "PSD", is_open_source: "1", is_proxy: "1", buy_tax: "0", sell_tax: "0" },
};

function mockGoplus(url) {
  goplusCalls++;
  if (goplusDown) return new Response("oops", { status: 502 });
  const u = String(url);
  if (u.includes("/phishing_site")) {
    const host = new URL(new URL(u).searchParams.get("url")).hostname;
    return new Response(JSON.stringify({ code: 1, message: "OK", result: { website_contract_security: [], phishing_site: GOPLUS_PHISHING.has(host) ? 1 : 0 } }));
  }
  if (u.includes("/token_security/")) {
    const address = new URL(u).searchParams.get("contract_addresses").toLowerCase();
    const result = TOKEN_DATA[address] ? { [address]: TOKEN_DATA[address] } : {};
    return new Response(JSON.stringify({ code: 1, message: "OK", result }));
  }
  if (u.includes(PARTIAL)) return new Response(JSON.stringify({ code: 2, message: "partial data obtained", result: {} }));
  const isEoa = [EOA, ...AGE_WALLETS].some((w) => u.includes(w));
  const isPhish = u.includes(PHISH);
  const result = u.includes("/address_security/")
    ? { phishing_activities: isPhish ? "1" : "0", sanctioned: u.includes(SANCTIONED) ? "1" : "0" }
    : { is_contract: isEoa ? "0" : "1", is_open_source: u.includes(UNVERIFIED_IMPL) ? "0" : "1", malicious_behavior: isPhish ? ["drainer"] : [],
        ...([REAL_PROXY, FAKE_PROXY, MIN_PROXY, UNCHECKED_PROXY].some((p) => u.includes(p)) && { is_proxy: "1" }) };
  return new Response(JSON.stringify({ code: 1, message: "OK", result }));
}

function mockClaude() {
  if (claudeDown) return new Response("{}", { status: 529 });
  return new Response(JSON.stringify({ content: [{ type: "text", text: "Uitleg in gewone taal." }] }));
}

let jevAnswers = {};
// Alchemy's alchemy_simulateAssetChanges (src/simulate.js): the next answer, or an HTTP error.
let alchemyResult = { changes: [], gasUsed: "0x5208", error: null };
const alchemyCalls = [];
const alchemyAnswer = () => (alchemyResult === "down" ? new Response("{}", { status: 503 }) : Response.json({ jsonrpc: "2.0", id: 1, result: alchemyResult }));
const jevCalls = [];
let server, base;
before(async () => {
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.includes("gopluslabs")) return mockGoplus(u);
    if (u.includes("api.anthropic.com")) return mockClaude();
    if (u.includes("api.typesafe.ai")) {
      const q = JSON.parse(opts.body).questions;
      jevCalls.push(JSON.parse(opts.body));
      return Response.json({ model: "jev-test", answers: Object.fromEntries(Object.keys(q).map((id) => [id, { type: "noul", noul: jevAnswers[id] ?? 0.02 }])), usage: {} });
    }
    if (u.includes("g.alchemy.com")) { alchemyCalls.push({ url: u, body: JSON.parse(opts.body) }); return alchemyAnswer(u, JSON.parse(opts.body)); }
    if (u.includes("pg1-ai-agent.vercel.app")) return mockPg1(opts);
    if (u.includes("dapp-scanning.api.cx.metamask.io")) return mockMetamask(u);
    if (/publicnode\.com|mainnet\.base\.org|arbitrum\.io/.test(u)) return mockRpc(opts);
    return realFetch(url, opts);
  };
  const app = express();
  app.use(createCheckRouter());
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); globalThis.fetch = realFetch; });
beforeEach(() => { metamaskDown = false; reputationDown = false; goplusDown = false; claudeDown = false; rpcDown = false; goplusCalls = 0; pg1Down = false; pg1Calls = 0; pg1RateLimited = false; pg1FailNext = 0; });

async function check(body, path = "/v1/check") {
  const res = await realFetch(base + path, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}
const codes = (r) => r.body.reasons.map((x) => x.code);
const approveData = (spender, amount) =>
  "0x095ea7b3" + spender.slice(2).padStart(64, "0") + BigInt(amount).toString(16).padStart(64, "0");

// ---------- approvals and transactions ----------

// ---------- wallet age (PG1 check_wallet_age) ----------
const ageReason = (r, code) => r.body.reasons.find((x) => x.code === code);

test("wallet age: approving a wallet first seen 3 days ago is orange, with the age", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: FRESH, amount: "1000000" });
  assert.equal(r.body.verdict, "orange");
  const hit = ageReason(r, "NEW_WALLET_SPENDER");
  assert.equal(hit.severity, "orange");
  assert.equal(hit.subject, FRESH);
  assert.equal(hit.details.ageDays, 3);
});

test("wallet age: a spender wallet under a day old or with no history is red", async () => {
  for (const spender of [BRAND_NEW, NO_HISTORY]) {
    const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender, amount: "1000000" });
    assert.equal(r.body.verdict, "red", spender);
    assert.equal(ageReason(r, "NEW_WALLET_SPENDER").severity, "red");
  }
  const none = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: NO_HISTORY, amount: "1000000" });
  assert.equal(ageReason(none, "NEW_WALLET_SPENDER").details.history, "none");
});

test("wallet age: an old wallet is context only; a minimum age under 7 days is orange, never red", async () => {
  const old = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: EOA, amount: "1000000" });
  assert.equal(ageReason(old, "WALLET_AGE").severity, "info");
  assert.equal(ageReason(old, "WALLET_AGE").details.ageDays, 600);
  assert.ok(!codes(old).includes("NEW_WALLET_SPENDER"));
  const approx = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: APPROX, amount: "1000000" });
  const hit = ageReason(approx, "NEW_WALLET_SPENDER");
  assert.equal(hit.severity, "orange");
  assert.equal(hit.details.minimum, true);
});

test("wallet age: a wallet new to Base but old on Ethereum is not new; Base wallets with history skip the second lookup", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: OLD_ON_ETH, amount: "1000000" });
  assert.ok(!codes(r).includes("NEW_WALLET_SPENDER"));
  const age = ageReason(r, "WALLET_AGE");
  assert.equal(age.details.chain, "ethereum");
  assert.equal(age.details.ageDays, 1400);
  ageChains.length = 0;
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender: EOA, amount: "1" });
  assert.ok(!ageChains.some((c) => c.startsWith("ethereum:")), ageChains.join());
});

test("wallet age: a lookup that times out is info and the check still answers", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: AGE_TIMEOUT, amount: "1000000" });
  assert.equal(r.status, 200);
  assert.ok(codes(r).includes("WALLET_AGE_UNAVAILABLE"));
  assert.ok(!codes(r).includes("NEW_WALLET_SPENDER"));
});

test("wallet age: an x402 payment to a brand-new wallet is not judged by its age", async () => {
  const r = await check(payment(BRAND_NEW, "20000"));
  assert.equal(r.body.verdict, "green");
  assert.ok(!codes(r).some((c) => c.startsWith("NEW_WALLET") || c.startsWith("WALLET_AGE")));
});

test("wallet age: contract spenders are not looked up", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" });
  assert.ok(!codes(r).some((c) => c.startsWith("NEW_WALLET") || c.startsWith("WALLET_AGE")));
});

test("exact approval to a verified contract is green", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000" });
  assert.equal(r.status, 200);
  assert.equal(r.body.verdict, "green");
});

test("unlimited approval to a contract is orange", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: MAX256 });
  assert.equal(r.body.verdict, "orange");
  assert.ok(codes(r).includes("UNLIMITED_APPROVAL"));
});

test("unlimited approval to a plain wallet is red", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: EOA, amount: MAX256 });
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("UNLIMITED_APPROVAL_TO_EOA"));
});

test("approval to a flagged contract is red", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: PHISH, amount: "1" });
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("MALICIOUS_CONTRACT_BEHAVIOR"));
});

test("revoking a flagged spender is not red", async () => {
  const r = await check({ type: "transaction", chainId: 8453, to: TOKEN, data: approveData(PHISH, 0) });
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("REVOKES_APPROVAL"));
});

test("approve calldata is decoded like an approval", async () => {
  const r = await check({ type: "transaction", chainId: 8453, to: TOKEN, data: approveData(EOA, MAX256) });
  assert.equal(r.body.subject.kind, "token_approve");
  assert.equal(r.body.verdict, "red");
});

test("unknown calldata reports its selector", async () => {
  const r = await check({ type: "transaction", chainId: 8453, to: GOOD, data: "0xdeadbeef" });
  assert.equal(r.body.subject.selector, "0xdeadbeef");
  assert.ok(codes(r).includes("UNDECODED_CALL"));
});

// ---------- signatures ----------

const sig = (primaryType, message, domain = {}) => ({
  type: "signature", chainId: 8453,
  typedData: { primaryType, domain: { chainId: 8453, verifyingContract: PERMIT2, ...domain }, message },
});

test("exact EIP-2612 permit to a contract is green", async () => {
  const r = await check(sig("Permit", { owner: USER, spender: GOOD, value: "1000000", nonce: 0, deadline: FAR }, { verifyingContract: TOKEN }));
  assert.equal(r.body.verdict, "green");
  assert.equal(r.body.subject.offchain, true);
});

test("any permit to a plain wallet is red", async () => {
  const r = await check(sig("Permit", { owner: USER, spender: EOA, value: "5", nonce: 0, deadline: FAR }, { verifyingContract: TOKEN }));
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("SIGNATURE_GRANT_TO_EOA"));
});

test("DAI-style permit is treated as unlimited", async () => {
  const r = await check(sig("Permit", { holder: USER, spender: GOOD, nonce: 0, expiry: 0, allowed: true }, { verifyingContract: TOKEN }));
  assert.ok(codes(r).includes("UNLIMITED_APPROVAL"));
});

test("Permit2 batch checks every token and flags long expirations", async () => {
  const r = await check(sig("PermitBatch", {
    details: [
      { token: TOKEN, amount: MAX160, expiration: FAR, nonce: 0 },
      { token: GOOD, amount: "10", expiration: "0", nonce: 0 },
    ],
    spender: GOOD, sigDeadline: FAR,
  }));
  assert.equal(r.body.subject.grants.length, 2);
  assert.equal(r.body.subject.grants[0].tokenSymbol, "USDC");
  assert.equal(r.body.subject.grants[1].tokenSymbol, undefined); // no GoPlus token record
  assert.equal(r.body.verdict, "orange");
  assert.ok(codes(r).includes("LONG_LIVED_PERMISSION"));
});

test("Permit2 domain that is not the canonical contract is flagged", async () => {
  const r = await check(sig("PermitSingle",
    { details: { token: TOKEN, amount: "10", expiration: "0", nonce: 0 }, spender: GOOD, sigDeadline: FAR },
    { verifyingContract: GOOD }));
  assert.ok(codes(r).includes("NONCANONICAL_PERMIT2"));
});

test("Permit2 signature transfer is at least orange", async () => {
  const r = await check(sig("PermitTransferFrom", { permitted: { token: TOKEN, amount: "10" }, spender: GOOD, nonce: 0, deadline: FAR }));
  assert.equal(r.body.verdict, "orange");
  assert.ok(codes(r).includes("SIGNATURE_TRANSFER"));
});

test("Seaport listing that pays the offerer nothing is red", async () => {
  const r = await check({
    type: "signature", chainId: 1,
    typedData: {
      primaryType: "OrderComponents",
      domain: { name: "Seaport", chainId: 1, verifyingContract: "0x0000000000000068F116a894984e2DB1123eB395" },
      message: { offerer: USER, offer: [{ itemType: 2 }], consideration: [{ recipient: EOA }], endTime: FAR },
    },
  });
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("ORDER_PAYS_YOU_NOTHING"));
});

const payment = (to, value, validBefore = String(Math.floor(Date.now() / 1000) + 300)) =>
  sig("TransferWithAuthorization", { from: USER, to, value, validAfter: "0", validBefore, nonce: "0x" + "00".repeat(32) },
    { name: "USD Coin", version: "2", verifyingContract: TOKEN });

test("x402 payment (EIP-3009) to a plain wallet is green", async () => {
  const r = await check(payment(EOA, "20000"));
  assert.equal(r.body.verdict, "green");
  assert.equal(r.body.subject.kind, "transfer_authorization");
  assert.equal(r.body.subject.grants[0].mode, "payment");
  assert.ok(codes(r).includes("PAYMENT_AUTHORIZATION"));
  assert.ok(!codes(r).includes("SIGNATURE_GRANT_TO_EOA"));
});

test("x402 payment to a flagged recipient is red", async () => {
  const r = await check(payment(PHISH, "20000"));
  assert.equal(r.body.verdict, "red");
});

test("x402 payment to an EIP-7702 wallet is green, not an unverified contract", async () => {
  const r = await check(payment(DELEGATED, "20000"));
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("EIP7702_DELEGATED_WALLET"));
  assert.ok(!codes(r).includes("UNVERIFIED_CONTRACT"));
});

test("payment authorization valid for months is orange", async () => {
  const r = await check(payment(EOA, "20000", FAR));
  assert.equal(r.body.verdict, "orange");
  assert.ok(codes(r).includes("LONG_LIVED_PERMISSION"));
});

test("unrecognized typed data is orange, not green", async () => {
  const r = await check(sig("SomethingNew", { foo: "bar" }, { verifyingContract: GOOD }));
  assert.equal(r.body.verdict, "orange");
  assert.ok(codes(r).includes("UNRECOGNIZED_SIGNATURE"));
});

test("typedData may be sent as a JSON string", async () => {
  const body = sig("Permit", { owner: USER, spender: GOOD, value: "1", nonce: 0, deadline: FAR }, { verifyingContract: TOKEN });
  body.typedData = JSON.stringify(body.typedData);
  assert.equal((await check(body)).status, 200);
});

test("GoPlus partial data still gives a verdict, marked, and a missing is_contract counts as a plain wallet", async () => {
  const r = await check(sig("Permit", { owner: USER, spender: PARTIAL, value: "5", nonce: 0, deadline: FAR }, { verifyingContract: TOKEN }));
  assert.equal(r.status, 200);
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("SIGNATURE_GRANT_TO_EOA"));
  assert.ok(codes(r).includes("PARTIAL_SOURCE_DATA"));
});

test("EIP-7702 wallet: the delegate contract is named and screened; a clean one adds nothing", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: DELEGATED, amount: "1000000" });
  const d = r.body.reasons.find((x) => x.code === "EIP7702_DELEGATED_WALLET");
  assert.equal(d.details.delegate, "0x" + "ab".repeat(20));
  assert.ok(!codes(r).includes("MALICIOUS_DELEGATE"));
  assert.ok(!codes(r).includes("UNVERIFIED_DELEGATE"));
});

test("EIP-7702 wallet delegating to a flagged contract is red, with the delegate and flags", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: DELEGATED_BAD, amount: "1000000" });
  assert.equal(r.body.verdict, "red");
  const m = r.body.reasons.find((x) => x.code === "MALICIOUS_DELEGATE");
  assert.equal(m.subject, DELEGATED_BAD);
  assert.equal(m.details.delegate, PHISH);
  assert.deepEqual(m.details.flags, ["phishing_activities", "drainer"]);
});

test("EIP-7702 wallet delegating to unverified code is orange", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: DELEGATED_UNVERIFIED, amount: "1000000" });
  assert.equal(r.body.verdict, "orange");
  const u = r.body.reasons.find((x) => x.code === "UNVERIFIED_DELEGATE");
  assert.equal(u.details.delegate, UNVERIFIED_IMPL);
});

test("UPGRADEABLE_PROXY only when the chain confirms it: EIP-1967 slot or EIP-1167 clone, naming what it points to", async () => {
  const real = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: REAL_PROXY, amount: "1000000" });
  const r = real.body.reasons.find((x) => x.code === "UPGRADEABLE_PROXY" && x.subject === REAL_PROXY);
  assert.deepStrictEqual(r.details, { kind: "eip1967", points_to: IMPL });
  const clone = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: MIN_PROXY, amount: "1000000" });
  assert.deepStrictEqual(clone.body.reasons.find((x) => x.code === "UPGRADEABLE_PROXY").details, { kind: "eip1167", points_to: IMPL });
});

test("a GoPlus is_proxy with no proxy layout on-chain (like DEGEN) is not shown", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: FAKE_PROXY, amount: "1000000" });
  assert.strictEqual(r.status, 200);
  assert.ok(!r.body.reasons.some((x) => x.code === "UPGRADEABLE_PROXY"), JSON.stringify(r.body.reasons));
});

test("chain RPC down: the GoPlus proxy flag stays, marked unconfirmed, and the check still answers", async () => {
  rpcDown = true;
  try {
    const FRESH = UNCHECKED_PROXY; // the approved token (the check's target), never looked up before (lookups are cached)
    const r = await check({ type: "approval", chainId: 8453, token: FRESH, spender: EOA, amount: "1000000" });
    assert.strictEqual(r.status, 200);
    const p = r.body.reasons.find((x) => x.code === "UPGRADEABLE_PROXY" && x.subject === FRESH);
    assert.deepStrictEqual(p && p.details, { confirmed: false });
  } finally {
    rpcDown = false;
  }
});

test("contracts GoPlus doesn't call a proxy cost no storage reads", async () => {
  rpcMethods = [];
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender: "0x2222222222222222222222222222222222222299", amount: "1000000" });
  assert.ok(!rpcMethods.includes("eth_getStorageAt"), rpcMethods.join(","));
});

test("permit to an EIP-7702 wallet is red, not an unverified contract", async () => {
  const r = await check(sig("Permit", { owner: USER, spender: DELEGATED, value: "5", nonce: 0, deadline: FAR }, { verifyingContract: TOKEN }));
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("SIGNATURE_GRANT_TO_EOA"));
  assert.ok(codes(r).includes("EIP7702_DELEGATED_WALLET"));
  assert.ok(!codes(r).includes("UNVERIFIED_CONTRACT"));
});

test("chain RPC outage returns 503 and no verdict", async () => {
  rpcDown = true;
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: "0x4444444444444444444444444444444444444444", amount: "1" });
  assert.equal(r.status, 503);
  assert.equal(r.body.verdict, null);
});

// ---------- validation and fail-closed ----------

test("domain chainId mismatch is rejected", async () => {
  const r = await check(sig("Permit", {}, { chainId: 1, verifyingContract: TOKEN }));
  assert.equal(r.status, 400);
  assert.equal(r.body.verdict, null);
});

for (const [name, body] of Object.entries({
  "unsupported chain": { type: "approval", chainId: 999, token: TOKEN, spender: GOOD, amount: "1" },
  "bad address": { type: "approval", chainId: 8453, token: "0x123", spender: GOOD, amount: "1" },
  "negative amount": { type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "-1" },
  "boolean amount": { type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: true },
  "bad calldata": { type: "transaction", chainId: 8453, to: TOKEN, data: "hello" },
  "unknown type": { type: "vibes", chainId: 8453 },
})) {
  test(`validation: ${name} → 400`, async () => {
    const r = await check(body);
    assert.equal(r.status, 400);
    assert.equal(r.body.verdict, null);
  });
}

test("GoPlus outage returns 503 and no verdict", async () => {
  goplusDown = true;
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: "0x3333333333333333333333333333333333333333", amount: "1" });
  assert.equal(r.status, 503);
  assert.equal(r.body.verdict, null);
});

test("Claude outage on /explain returns 503, never a bare verdict", async () => {
  claudeDown = true;
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" }, "/v1/check/explain");
  assert.equal(r.status, 503);
  assert.equal(r.body.verdict, null);
});

test("/explain returns the explanation in the requested language", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1", lang: "nl" }, "/v1/check/explain");
  assert.equal(r.status, 200);
  assert.equal(r.body.explanation.lang, "nl");
  assert.ok(r.body.explanation.text.length > 0);
});

// ---------- token security ----------

test("USDC-like token: issuer controls are reported as info, the verdict stays green", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000" });
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("TOKEN_ON_TRUST_LIST"));
  assert.ok(codes(r).includes("TOKEN_UPGRADEABLE"));
  assert.equal(r.body.reasons.find((x) => x.code === "TOKEN_UPGRADEABLE").severity, "info");
  // GoPlus has no control fields for this proxy token, so the chain is asked.
  const pausable = r.body.reasons.find((x) => x.code === "TOKEN_PAUSABLE");
  assert.deepEqual(pausable, { code: "TOKEN_PAUSABLE", severity: "info", subject: TOKEN, details: { source: "onchain", pauser: "0x1ac78dfcae082e9fe286d1ccb12c17a3e906b906" } });
  assert.equal(r.body.reasons.find((x) => x.code === "TOKEN_BLACKLIST").details.blacklister, "0x158cfa498b1f72f458acf8df993c709efca11e31");
});

test("paying or approving a token whose transfers are paused right now is orange", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: PAUSED_TOKEN, spender: GOOD, amount: "1000000" });
  assert.equal(r.body.verdict, "orange");
  assert.equal(r.body.reasons.find((x) => x.code === "TOKEN_PAUSED").subject, PAUSED_TOKEN);
});

test("a token GoPlus answers for costs no eth_call", async () => {
  rpcMethods = [];
  await check({ type: "approval", chainId: 8453, token: MINTABLE, spender: GOOD, amount: "1000000" });
  assert.ok(!rpcMethods.includes("eth_call"), rpcMethods.join(","));
});

test("approving a honeypot token is red, even for an exact amount to a verified contract", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: HONEY, spender: GOOD, amount: "1000000" });
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("TOKEN_HONEYPOT"));
  assert.equal(r.body.reasons.find((x) => x.code === "TOKEN_HONEYPOT").subject, HONEY);
});

test("an x402 payment in a fake USDC is red and names the real token", async () => {
  const fake = sig("TransferWithAuthorization", { from: USER, to: EOA, value: "20000", validAfter: "0", validBefore: String(Math.floor(Date.now() / 1000) + 300), nonce: "0x" + "00".repeat(32) },
    { name: "USD Coin", version: "2", verifyingContract: FAKE_USDC });
  const r = await check(fake);
  assert.equal(r.body.verdict, "red");
  const reason = r.body.reasons.find((x) => x.code === "TOKEN_IMPERSONATION");
  assert.equal(reason.details.realToken, TOKEN);
  // The real USDC payment stays green.
  assert.equal((await check(payment(EOA, "20000"))).body.verdict, "green");
});

test("a 10%+ buy or sell tax is orange; a mintable token alone is only info", async () => {
  const taxed = await check({ type: "approval", chainId: 8453, token: TAXED, spender: GOOD, amount: "1000000" });
  assert.equal(taxed.body.verdict, "orange");
  assert.deepEqual(taxed.body.reasons.find((x) => x.code === "TOKEN_HIGH_TAX").details, { buyTax: 0.12, sellTax: 0.15 });
  const mint = await check({ type: "approval", chainId: 8453, token: MINTABLE, spender: GOOD, amount: "1000000" });
  assert.equal(mint.body.verdict, "green");
  assert.equal(mint.body.reasons.find((x) => x.code === "TOKEN_MINTABLE").severity, "info");
});

test("a token GoPlus does not know is reported, not guessed", async () => {
  const unknown = "0x7777000000000000000000000000000000000099";
  const r = await check({ type: "approval", chainId: 8453, token: unknown, spender: GOOD, amount: "1000000" });
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("TOKEN_NO_SECURITY_DATA"));
});

test("revoking needs no token lookup", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: HONEY, spender: PHISH, amount: "0" });
  assert.ok(!codes(r).includes("TOKEN_HONEYPOT"));
});

test("repeated checks are served from cache", async () => {
  const spender = "0x4444444444444444444444444444444444444444";
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender, amount: "1" });
  const first = goplusCalls;
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender, amount: "1" });
  assert.equal(goplusCalls, first);
});

// ---------- PG1: OFAC sanctions and domain age ----------

test("a sanctioned spender is red, with the SDN entry; PG1 is credited", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: SANCTIONED, amount: "1000000" });
  assert.equal(r.body.verdict, "red");
  const hit = r.body.reasons.find((x) => x.code === "SANCTIONED_ADDRESS");
  assert.equal(hit.subject, SANCTIONED);
  assert.deepEqual(hit.details.matches, [{ name: "LAZARUS GROUP", programs: ["DPRK3"] }]);
  assert.equal(hit.details.list, "OFAC SDN");
  assert.ok(r.body.sources.includes("pg1"));
  // GoPlus flags it too: one sanctions reason, crediting both sources.
  assert.ok(!codes(r).includes("SANCTIONED"));
  assert.equal(r.body.reasons.filter((x) => x.code === "SANCTIONED_ADDRESS").length, 1);
  assert.deepEqual(hit.details.alsoFlaggedBy, ["goplus"]);
});

test("a clean address says which list version it was screened against (info, signed)", async () => {
  const CLEAN = "0x5eeded0000000000000000000000000000000002";
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: CLEAN, amount: "1" });
  const s = r.body.reasons.find((x) => x.code === "SANCTIONS_SCREENED" && x.subject === CLEAN);
  assert.equal(s.severity, "info");
  assert.deepEqual(s.details, { list: "OFAC SDN", listed: false, listSynced: "2026-09-25T20:10:41Z" });
  assert.ok(!r.body.reasons.some((x) => x.code === "SANCTIONS_SCREENED" && x.subject === SANCTIONED));
});

test("PG1 down: GoPlus's SANCTIONED flag still makes a sanctioned spender red", async () => {
  resetPg1(); // forget the cached PG1 answer from the test above
  pg1Down = true;
  try {
    const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: SANCTIONED, amount: "1000000" });
    assert.equal(r.body.verdict, "red");
    assert.ok(codes(r).includes("SANCTIONED"));
    assert.ok(!codes(r).includes("SANCTIONED_ADDRESS"));
  } finally {
    pg1Down = false;
  }
});

test("a sanctioned payment recipient in an x402 signature is red", async () => {
  const typedData = {
    primaryType: "TransferWithAuthorization",
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: TOKEN },
    message: { from: USER, to: SANCTIONED, value: "10000", validAfter: "0", validBefore: FAR, nonce: "0x" + "00".repeat(32) },
  };
  const r = await check({ type: "signature", chainId: 8453, typedData });
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("SANCTIONED_ADDRESS"));
});

test("PG1 down: the check still answers, the gap is info, not charged as an error", async () => {
  pg1Down = true;
  const FRESH = "0x5eeded0000000000000000000000000000000001"; // not screened before (results are cached)
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: FRESH, amount: "1000000", origin: "uniswap.org" });
  assert.equal(r.status, 200);
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("SANCTIONS_SCREEN_UNAVAILABLE"));
  assert.ok(codes(r).includes("DOMAIN_AGE_UNAVAILABLE"));
});

test("origin: a 3-day-old domain is orange; an old one is context", async () => {
  const fresh = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "https://claim-usdc-drop.xyz/connect?ref=1" });
  assert.equal(fresh.body.verdict, "orange");
  const hit = fresh.body.reasons.find((x) => x.code === "NEW_DOMAIN");
  assert.deepEqual([hit.subject, hit.details.ageDays], ["claim-usdc-drop.xyz", 3]);
  assert.equal(fresh.body.subject.origin, "claim-usdc-drop.xyz");
  const old = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "uniswap.org" });
  assert.equal(old.body.verdict, "green");
  assert.ok(codes(old).includes("DOMAIN_AGE"));
});

test("origin: an unregistered domain is orange; a TLD without RDAP is unknown, not a warning", async () => {
  const gone = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "no-such-site-3k2.com" });
  assert.equal(gone.body.verdict, "orange");
  assert.ok(codes(gone).includes("DOMAIN_NOT_REGISTERED"));
  const eu = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "fizzl.eu" });
  assert.equal(eu.body.verdict, "green");
  assert.ok(codes(eu).includes("DOMAIN_AGE_UNKNOWN"));
});

test("origin reputation: a listed phishing site is red, credited to every list that has it", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "https://002271coinbase.com/claim" });
  assert.equal(r.body.verdict, "red");
  const hit = r.body.reasons.find((x) => x.code === "PHISHING_SITE");
  assert.deepEqual(hit.details.flaggedBy, ["pg1", "goplus"]);
  assert.equal(hit.details.matchType, "exact");
  assert.ok(r.body.sources.includes("pg1"));
  // GoPlus alone is enough for red.
  const gp = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "only-goplus-knows.com" });
  assert.equal(gp.body.verdict, "red");
  assert.deepEqual(gp.body.reasons.find((x) => x.code === "PHISHING_SITE").details.flaggedBy, ["goplus"]);
});

test("origin reputation: a lookalike is orange and names the brand; the real brand is allowlisted context", async () => {
  const fake = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "metamask-login.com" });
  assert.equal(fake.body.verdict, "orange");
  assert.equal(fake.body.reasons.find((x) => x.code === "LOOKALIKE_SITE").details.lookalikeOf, "metamask.io");
  const real = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "metamask.io" });
  assert.ok(codes(real).includes("SITE_ALLOWLISTED"));
  assert.ok(!codes(real).includes("LOOKALIKE_SITE"));
});

test("origin reputation: the MetaMask scanner is off by default", async () => {
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "x402-shop.example" });
  assert.ok(!codes(r).includes("WALLET_BLOCKS_SITE"));
  assert.ok(!r.body.sources.includes("metamask"));
  assert.ok(!codes(r).includes("SITE_REPUTATION_UNAVAILABLE"), "off is not unavailable");
});

test("origin reputation: with METAMASK_SCAN=on a MetaMask block is orange (scanner false positives), not red", async () => {
  process.env.METAMASK_SCAN = "on";
  try {
    const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "x402-shop.example" });
    const hit = r.body.reasons.find((x) => x.code === "WALLET_BLOCKS_SITE");
    assert.equal(hit.severity, "orange");
    assert.deepEqual(hit.details, { wallet: "MetaMask", action: "BLOCK", risks: [{ type: "DRAINER", severity: "CRITICAL" }] });
    assert.notEqual(r.body.verdict, "red");
    assert.ok(r.body.sources.includes("metamask"));
  } finally {
    delete process.env.METAMASK_SCAN;
  }
});

test("origin reputation: an unavailable source is info, never a clean result; ORIGIN_REPUTATION=off skips it", async () => {
  process.env.METAMASK_SCAN = "on";
  metamaskDown = true;
  reputationDown = true;
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "sourcesdown.example" });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.reasons.find((x) => x.code === "SITE_REPUTATION_UNAVAILABLE").details.sources, ["pg1", "metamask"]);
  process.env.ORIGIN_REPUTATION = "off";
  try {
    const off = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "002271coinbase.com" });
    assert.ok(!codes(off).some((c) => /PHISHING_SITE|LOOKALIKE_SITE|WALLET_BLOCKS_SITE|SITE_REPUTATION/.test(c)));
  } finally {
    delete process.env.ORIGIN_REPUTATION;
    delete process.env.METAMASK_SCAN;
  }
});

test("origin: localhost and IPs are not looked up; junk is a 400 before any lookup", async () => {
  const local = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "http://localhost:3000" });
  assert.equal(local.status, 200);
  assert.equal(local.body.subject.origin, undefined);
  assert.ok(!codes(local).some((c) => c.startsWith("DOMAIN")));
  pg1Calls = 0;
  goplusCalls = 0;
  const bad = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1", origin: "not a url" });
  assert.equal(bad.status, 400);
  assert.equal(pg1Calls + goplusCalls, 0);
});

test("PG1: the membership key goes along as x-api-key when set, and only then", async () => {
  resetPg1();
  process.env.PG1_API_KEY = " test-member-key \n";
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" });
  assert.equal(pg1LastKey, "test-member-key");
  delete process.env.PG1_API_KEY;
  resetPg1();
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" });
  assert.equal(pg1LastKey, undefined);
});

test("PG1 rate_limited: the check answers, and PG1 is left alone for a while", async () => {
  resetPg1();
  pg1RateLimited = true;
  const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" });
  assert.equal(r.status, 200);
  assert.ok(codes(r).includes("SANCTIONS_SCREEN_UNAVAILABLE"));
  assert.ok(pg1Paused());
  const calls = pg1Calls;
  const again = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "2" });
  assert.equal(again.status, 200);
  assert.equal(pg1Calls, calls, "no PG1 calls while paused");
  resetPg1();
});

// Collects console.warn lines while fn runs.
async function warnings(fn) {
  const lines = [];
  const orig = console.warn;
  console.warn = (...a) => lines.push(a.join(" "));
  try { await fn(); } finally { console.warn = orig; }
  return lines;
}

test("PG1 slow start: one 503 is tried again, the address is still screened, and the reason is logged", async () => {
  resetPg1();
  process.env.PG1_API_KEY = "secret-member-key";
  pg1FailNext = 1;
  let r;
  const lines = await warnings(async () => {
    r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: SANCTIONED, amount: "1" });
  });
  delete process.env.PG1_API_KEY;
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("SANCTIONED_ADDRESS"));
  assert.ok(!codes(r).includes("SANCTIONS_SCREEN_UNAVAILABLE"));
  // The 503 hits whichever PG1 call goes first: the sanctions screen or the wallet age.
  assert.ok(lines.some((l) => /^PG1 check_wallet_(sanctions|age): HTTP 503, retry ok$/.test(l)), lines.join("\n"));
  assert.ok(!lines.some((l) => l.includes("secret-member-key")), "the key is never logged");
  resetPg1();
});

test("PG1 down: tried twice, then the gap is info and both reasons are logged", async () => {
  resetPg1();
  pg1Down = true;
  let r;
  const lines = await warnings(async () => {
    r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" });
  });
  assert.ok(codes(r).includes("SANCTIONS_SCREEN_UNAVAILABLE"));
  const failed = lines.filter((l) => l === "PG1 check_wallet_sanctions: HTTP 503, retry HTTP 503");
  assert.ok(failed.length >= 1, lines.join("\n"));
  assert.equal(pg1Calls, 2 * lines.length, "each screened address: one call and one retry");
  resetPg1();
});

test("PG1 rate_limited is not tried again", async () => {
  resetPg1();
  pg1RateLimited = true;
  const lines = await warnings(() => check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1" }));
  assert.ok(lines.length >= 1 && lines.every((l) => /^PG1 check_wallet_(sanctions|age): rate_limited, paused 5 min$/.test(l)), lines.join("\n"));
  assert.equal(pg1Calls, lines.length, "one call per screened address, no retry");
  resetPg1();
});

test("PG1 key status for /health: unset, PG1's verdict on the key, never the key", async () => {
  resetPg1();
  delete process.env.PG1_API_KEY;
  assert.equal(await pg1KeyStatus(), "unset");
  process.env.PG1_API_KEY = "good-key";
  assert.equal(await pg1KeyStatus(), "active");
  resetPg1();
  process.env.PG1_API_KEY = "wrong-key";
  assert.equal(await pg1KeyStatus(), "invalid_or_expired");
  resetPg1();
  pg1Down = true;
  assert.equal(await pg1KeyStatus(), "unknown");
  pg1Down = false;
  resetPg1();
  process.env.PG1_API_KEY = "good-key";
  assert.equal(pg1KeyStatusNow(), "checking", "never waits on PG1");
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(pg1KeyStatusNow(), "active");
  delete process.env.PG1_API_KEY;
  resetPg1();
});

test("Jev second opinion: adds orange for a brand-imitating site name the lists miss; off without TYPESAFE_API_KEY", async () => {
  try {
    jevAnswers = { site_imitates_brand: 0.96 };
    const before = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "uniswap.org" });
    assert.ok(!codes(before).includes("AI_LOOKALIKE_SITE")); // no key: no Jev
    process.env.TYPESAFE_API_KEY = "ts-test";
    const r = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "uniswap.org" });
    const hit = r.body.reasons.find((x) => x.code === "AI_LOOKALIKE_SITE");
    assert.equal(hit.severity, "orange");
    assert.equal(hit.details.decidedBy, "jev");
    assert.equal(r.body.verdict, "orange");
    assert.ok(r.body.sources.includes("typesafe-jev"));
    // A site a phishing list already names gets no extra AI reason.
    const listed = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", origin: "metamask-login.com" });
    assert.ok(codes(listed).includes("LOOKALIKE_SITE"));
    assert.ok(!codes(listed).includes("AI_LOOKALIKE_SITE"));
    // The real USDC is never asked about: no AI token reason.
    assert.ok(!codes(r).includes("AI_TOKEN_IMPERSONATION"));
  } finally { delete process.env.TYPESAFE_API_KEY; jevAnswers = {}; }
});

test("Jev second opinion: a signature whose contract calls itself Uniswap is orange; the real token's permit is not asked", async () => {
  try {
    process.env.TYPESAFE_API_KEY = "ts-test";
    jevAnswers = { domain_impersonates: 0.95 };
    const fake = await check(sig("Permit", { owner: USER, spender: GOOD, value: "1000000", nonce: 0, deadline: FAR }, { verifyingContract: GOOD, name: "Uniswap V3" }));
    const hit = fake.body.reasons.find((x) => x.code === "AI_SIGNATURE_IMPERSONATION");
    assert.equal(hit.severity, "orange");
    assert.equal(hit.subject, GOOD.toLowerCase());
    assert.equal(fake.body.verdict, "orange");
    const real = await check(sig("Permit", { owner: USER, spender: GOOD, value: "1000000", nonce: 0, deadline: FAR }, { verifyingContract: TOKEN, name: "USD Coin" }));
    assert.ok(!codes(real).includes("AI_SIGNATURE_IMPERSONATION"));
  } finally { delete process.env.TYPESAFE_API_KEY; jevAnswers = {}; }
});

test("intent check: signing that does more than the agent says is orange INTENT_MISMATCH; a match is info; off without a key", async () => {
  try {
    const plain = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", intent: "pay 1 USDC for a price API" });
    assert.ok(!codes(plain).some((c) => c.startsWith("INTENT_")), "no key: not asked");
    process.env.TYPESAFE_API_KEY = "ts-test";
    jevAnswers = { intent_mismatch: 0.93 };
    jevCalls.length = 0;
    const bad = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: MAX256, intent: "pay 1 USDC for a price API" });
    const hit = bad.body.reasons.find((x) => x.code === "INTENT_MISMATCH");
    assert.equal(hit.severity, "orange");
    assert.equal(hit.details.intent, "pay 1 USDC for a price API");
    assert.equal(hit.details.decidedBy, "jev");
    assert.notEqual(bad.body.verdict, "green");
    const asked = jevCalls.find((c) => c.questions.intent_mismatch);
    assert.equal(asked.state.intent, "pay 1 USDC for a price API");
    assert.match(asked.state.effects.action, /allowance/);
    assert.match(asked.state.effects.grants[0]["may spend"], /^UNLIMITED/);
    jevAnswers = { intent_mismatch: 0.05 };
    const ok = await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000", intent: "approve 1 USDC for the swap" });
    assert.equal(ok.body.reasons.find((x) => x.code === "INTENT_MATCHES").severity, "info");
    assert.ok(!codes(ok).includes("INTENT_MISMATCH"));
    // Too long an intent is a 400; no intent, no question.
    assert.equal((await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1", intent: "x".repeat(501) })).status, 400);
    jevCalls.length = 0;
    await check({ type: "approval", chainId: 8453, token: TOKEN, spender: GOOD, amount: "1000000" });
    assert.ok(!jevCalls.some((c) => c.questions.intent_mismatch));
  } finally { delete process.env.TYPESAFE_API_KEY; jevAnswers = {}; }
});

// x402 requirements (src/x402-requirements.js): the signature against the 402 entry the agent is paying.
const accepted = (over = {}) => ({ accepted: { scheme: "exact", network: "eip155:8453", amount: "20000", asset: TOKEN, payTo: EOA, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" }, ...over } });

test("x402 payment that matches what the seller asked: green with X402_REQUIREMENTS_MATCH", async () => {
  const r = await check({ ...payment(EOA, "20000"), x402: accepted() });
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("X402_REQUIREMENTS_MATCH"));
});

test("x402 payment for more, to someone else, in another token or on another chain than asked is red", async () => {
  const more = await check({ ...payment(EOA, "2000000"), x402: accepted() });
  assert.equal(more.body.verdict, "red");
  const r = more.body.reasons.find((x) => x.code === "X402_AMOUNT_ABOVE_REQUIRED");
  assert.equal(r.severity, "red");
  assert.equal(r.details.required, "20000");
  assert.equal(r.details.signing, "2000000");
  assert.ok(codes(await check({ ...payment(EOA, "20000"), x402: accepted({ payTo: "0x2222222222222222222222222222222222222222" }) })).includes("X402_RECIPIENT_MISMATCH"));
  assert.ok(codes(await check({ ...payment(EOA, "20000"), x402: accepted({ asset: "0x3333333333333333333333333333333333333333" }) })).includes("X402_ASSET_MISMATCH"));
  assert.ok(codes(await check({ ...payment(EOA, "20000"), x402: { accepted: { ...accepted().accepted, network: "eip155:1" } } })).includes("X402_NETWORK_MISMATCH"));
  assert.ok(!codes(await check({ ...payment(EOA, "20000"), x402: { ...accepted().accepted, network: "base", maxAmountRequired: "20000", amount: undefined } })).includes("X402_NETWORK_MISMATCH"), "v1 network names and maxAmountRequired, without the accepted wrapper");
});

test("x402: a signature valid far beyond the seller's timeout, or another EIP-712 domain, is orange", async () => {
  const long = await check({ ...payment(EOA, "20000", String(Math.floor(Date.now() / 1000) + 7 * 86400)), x402: accepted() });
  assert.equal(long.body.verdict, "orange");
  assert.ok(codes(long).includes("X402_VALIDITY_TOO_LONG"));
  const dom = await check({ ...payment(EOA, "20000"), x402: accepted({ extra: { name: "USDC", version: "2" } }) });
  assert.ok(codes(dom).includes("X402_DOMAIN_MISMATCH"));
  const less = await check({ ...payment(EOA, "10000"), x402: accepted() });
  assert.equal(less.body.verdict, "green");
  assert.ok(codes(less).includes("X402_AMOUNT_BELOW_REQUIRED"));
});

test("x402 field: only on EIP-3009 payments, and malformed values are a 400", async () => {
  assert.equal((await check({ type: "approval", chainId: 8453, token: TOKEN, spender: EOA, amount: "1", x402: accepted() })).status, 400);
  assert.equal((await check({ ...payment(EOA, "20000"), x402: accepted({ amount: "1.5" }) })).status, 400);
  assert.equal((await check({ ...payment(EOA, "20000"), x402: accepted({ payTo: "nope" }) })).status, 400);
});

// Mandate check (x402 `authority` extension draft, src/mandate.js): the payment against the grant.
const edKeys = generateKeyPairSync("ed25519");
const mandateFor = (over = {}) => {
  const issuer = edKeys.publicKey.export({ format: "jwk" }).x;
  return { v: "x402-mandate/1", issuer, subject: USER, asset: TOKEN, cap: "100000", perPayment: "50000", recipients: [EOA], accountant: issuer, purpose: "test", notAfter: "2030-01-01T00:00:00Z", nonce: "n1", ...over };
};
const withMandate = (m, value, paymentId = "p1") => {
  const body = sig("TransferWithAuthorization", { from: USER, to: EOA, value, validAfter: "0", validBefore: String(Math.floor(Date.now() / 1000) + 300), nonce: eip3009Binding(mandateDigest(m), "p1") },
    { name: "USD Coin", version: "2", verifyingContract: TOKEN });
  return { ...body, mandate: { mandate: m, alg: "Ed25519", sig: edSign(null, Buffer.from("x402-mandate/1\n" + jcs(m)), edKeys.privateKey).toString("base64url"), paymentId } };
};

test("x402 payment inside its mandate: green with MANDATE_OK", async () => {
  const r = await check(withMandate(mandateFor(), "20000"));
  assert.equal(r.body.verdict, "green");
  assert.ok(codes(r).includes("MANDATE_OK"));
  assert.equal(r.body.mandate.ok, true);
});

test("x402 payment over its mandate's per-payment bound is red", async () => {
  const r = await check(withMandate(mandateFor(), "60000"));
  assert.equal(r.body.verdict, "red");
  assert.ok(codes(r).includes("MANDATE_OVER_LIMIT"));
  assert.equal(r.body.mandate.ok, false);
});

test("a nonce that is not the mandate binding is red", async () => {
  const r = await check(withMandate(mandateFor(), "20000", "p2"));
  assert.ok(codes(r).includes("MANDATE_BINDING_MISMATCH"));
  assert.equal(r.body.verdict, "red");
});

test("a mandate on something other than an EIP-3009 payment is refused before payment", async () => {
  const r = await check({ ...payment(EOA, "20000"), type: "approval", token: TOKEN, spender: EOA, amount: "1", mandate: {} });
  assert.equal(r.status, 400);
});

// ---------- simulation (src/simulate.js, Alchemy) ----------
const SENDER = USER;
const ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"; // a contract (Uniswap's universal router)
const withAlchemy = async (result, fn) => {
  const before = process.env.ALCHEMY_API_KEY;
  process.env.ALCHEMY_API_KEY = "test-key";
  alchemyResult = result;
  alchemyCalls.length = 0;
  try { return await fn(); } finally { if (before === undefined) delete process.env.ALCHEMY_API_KEY; else process.env.ALCHEMY_API_KEY = before; alchemyResult = { changes: [], gasUsed: "0x5208", error: null }; }
};

test("simulation: a transaction with from is simulated; what leaves and arrives is in the answer and an info line", async () => {
  const result = { gasUsed: "0x1", error: null, changes: [
    { assetType: "ERC20", changeType: "TRANSFER", from: SENDER, to: ROUTER, rawAmount: "10000000", amount: "10", symbol: "USDC", decimals: 6, contractAddress: TOKEN },
    { assetType: "NATIVE", changeType: "TRANSFER", from: ROUTER, to: SENDER, rawAmount: "3000000000000000", amount: "0.003", symbol: "ETH", decimals: 18 },
  ] };
  const r = await withAlchemy(result, () => check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c", value: "0" }));
  assert.equal(alchemyCalls.length, 1);
  assert.match(alchemyCalls[0].url, /base-mainnet\.g\.alchemy\.com\/v2\/test-key/);
  assert.deepEqual(alchemyCalls[0].body.params[0], { from: SENDER.toLowerCase(), to: ROUTER.toLowerCase(), data: "0x3593564c", value: "0x0" });
  assert.equal(r.body.simulation.ok, true);
  assert.equal(r.body.simulation.changes.length, 2);
  const info = r.body.reasons.find((x) => x.code === "SIMULATED");
  assert.deepEqual(info.details.leaves, [{ to: ROUTER.toLowerCase(), asset: "erc20", symbol: "USDC", amount: "10" }]);
  assert.equal(info.details.arrives[0].symbol, "ETH");
  assert.ok(r.body.sources.includes("alchemy"));
  assert.match(r.body.scope, /simulated/);
});

test("simulation: an approval the call doesn't show, an NFT leaving, or a failing transaction is orange", async () => {
  const hidden = await withAlchemy({ error: null, changes: [{ assetType: "ERC20", changeType: "APPROVE", from: SENDER, to: EOA, rawAmount: "115792089237316195423570985008687907853269984665640564039457584007913129639935", symbol: "USDC", contractAddress: TOKEN }] },
    () => check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c" }));
  assert.equal(hidden.body.verdict, "orange");
  assert.equal(hidden.body.reasons.find((x) => x.code === "HIDDEN_APPROVAL").subject, EOA);
  const nft = await withAlchemy({ error: null, changes: [{ assetType: "ERC721", changeType: "TRANSFER", from: SENDER, to: EOA, tokenId: "7", contractAddress: ROUTER }] },
    () => check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c" }));
  assert.ok(nft.body.reasons.some((x) => x.code === "SIMULATION_NFT_OUT" && x.details.tokenId === "7"));
  const fails = await withAlchemy({ error: { message: "execution reverted" }, changes: [] },
    () => check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c" }));
  assert.equal(fails.body.verdict, "orange");
  assert.equal(fails.body.reasons.find((x) => x.code === "SIMULATION_FAILS").details.error, "execution reverted");
  assert.equal(fails.body.simulation.ok, false);
});

test("simulation: a plain approve call is not a hidden approval; no from, no key, other chains or Alchemy down: no simulation", async () => {
  const approve = await withAlchemy({ error: null, changes: [{ assetType: "ERC20", changeType: "APPROVE", from: SENDER, to: ROUTER, rawAmount: "1000000", contractAddress: TOKEN }] },
    () => check({ type: "transaction", chainId: 8453, from: SENDER, to: TOKEN, data: approveData(ROUTER, 1000000) }));
  assert.ok(!approve.body.reasons.some((x) => x.code === "HIDDEN_APPROVAL"));
  const noFrom = await withAlchemy({ error: null, changes: [] }, () => check({ type: "transaction", chainId: 8453, to: ROUTER, data: "0x3593564c" }));
  assert.equal(noFrom.body.simulation, undefined);
  assert.equal(alchemyCalls.length, 0);
  const bsc = await withAlchemy({ error: null, changes: [] }, () => check({ type: "transaction", chainId: 56, from: SENDER, to: ROUTER, data: "0x3593564c" }));
  assert.equal(bsc.body.simulation, undefined);
  const down = await withAlchemy("down", () => check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c" }));
  assert.equal(down.body.simulation, undefined);
  assert.ok(!down.body.reasons.some((x) => x.code.startsWith("SIMULAT")));
  const noKey = await check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c" });
  assert.equal(noKey.body.simulation, undefined);
  assert.match(noKey.body.scope, /transaction simulation/);
  assert.equal((await check({ type: "transaction", chainId: 8453, from: "nope", to: ROUTER, data: "0x" })).status, 400);
});

test("simulation: the intent check sees the simulated balance changes", async () => {
  jevCalls.length = 0;
  const before = process.env.TYPESAFE_API_KEY;
  process.env.TYPESAFE_API_KEY = "test";
  try {
    await withAlchemy({ error: null, changes: [{ assetType: "ERC20", changeType: "TRANSFER", from: SENDER, to: EOA, rawAmount: "5000000000", amount: "5000", symbol: "USDC", contractAddress: TOKEN }] },
      () => check({ type: "transaction", chainId: 8453, from: SENDER, to: ROUTER, data: "0x3593564c", intent: "swap 10 USDC for ETH" }));
  } finally { if (before === undefined) delete process.env.TYPESAFE_API_KEY; else process.env.TYPESAFE_API_KEY = before; }
  const asked = JSON.stringify(jevCalls.at(-1) ?? {});
  assert.match(asked, /5000 USDC to 0xbad0000000000000000000000000000000000001/);
});
