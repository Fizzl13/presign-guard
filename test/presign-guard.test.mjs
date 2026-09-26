// Run: npm test
// No network: GoPlus and Claude are mocked through globalThis.fetch.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createCheckRouter } from "../src/presign-guard.js";
import { resetPg1, pg1Paused } from "../src/pg1.js";

process.env.ANTHROPIC_API_KEY = "test-key";

const realFetch = globalThis.fetch;
const TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const GOOD = "0x2222222222222222222222222222222222222222"; // verified contract
const EOA = "0xbad0000000000000000000000000000000000001";  // plain wallet
const PHISH = "0xbad0000000000000000000000000000000000002"; // flagged contract
const USER = "0x1111111111111111111111111111111111111111";
const DELEGATED = "0xbad0000000000000000000000000000000000004"; // EIP-7702 wallet: GoPlus says contract
const PARTIAL = "0xbad0000000000000000000000000000000000003"; // GoPlus answers code 2, fields missing
const HONEY = "0x7777000000000000000000000000000000000001";   // honeypot token
const FAKE_USDC = "0x7777000000000000000000000000000000000002"; // impersonates USDC
const TAXED = "0x7777000000000000000000000000000000000003";   // 12% buy / 15% sell tax
const MINTABLE = "0x7777000000000000000000000000000000000004"; // mintable, otherwise normal (like DEGEN)
const SANCTIONED = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"; // Lazarus (Ronin hack), OFAC SDN
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
let pg1LastKey;

// PG1 MCP: check_wallet_sanctions and check_domain_age, shaped like the live responses.
const DOMAINS = {
  "uniswap.org": { available: true, domain: "uniswap.org", registration_date: "2018-11-26T05:33:07Z", age_days: 2860 },
  "claim-usdc-drop.xyz": { available: true, domain: "claim-usdc-drop.xyz", registration_date: "2026-09-22T10:00:00Z", age_days: 3 },
  "fizzl.eu": { available: false, domain: "fizzl.eu", reason: "No RDAP server registered for the '.eu' TLD in the IANA bootstrap file." },
};
async function mockPg1(opts) {
  pg1Calls++;
  pg1LastKey = opts.headers["x-api-key"];
  if (pg1Down) return new Response("down", { status: 503 });
  if (pg1RateLimited) {
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: JSON.stringify({ error: "Rate limit reached", code: "rate_limited" }) }] } }));
  }
  const { params } = JSON.parse(opts.body);
  let out;
  if (params.name === "check_wallet_sanctions") {
    const listed = params.arguments.address.toLowerCase() === SANCTIONED;
    out = { address: params.arguments.address, listed, list_last_synced: "2026-09-25T20:10:41Z",
      matches: listed ? [{ sdn_name: "LAZARUS GROUP", currency: "ETH", programs: ["DPRK3"], sdn_uid: "27307" }] : [] };
  } else {
    const d = params.arguments.domain;
    out = DOMAINS[d] ?? { available: false, domain: d, reason: `RDAP server responded with 404 for '${d}'.` };
  }
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(out) }] } }));
}

function mockRpc(opts) {
  if (rpcDown) return new Response("down", { status: 502 });
  const address = JSON.parse(opts.body).params[0].toLowerCase();
  const result = address === DELEGATED ? "0xef0100" + "ab".repeat(20) : "0x6080604052";
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
}

// GoPlus token_security, keyed by lowercase address like the real API; unknown tokens have no record.
const TOKEN_DATA = {
  [TOKEN]: { token_symbol: "USDC", is_open_source: "1", is_proxy: "1", trust_list: "1", buy_tax: "0", sell_tax: "0" },
  [HONEY]: { token_symbol: "HONEY", is_open_source: "1", is_honeypot: "1", sell_tax: "1" },
  [FAKE_USDC]: { token_symbol: "USDC", is_open_source: "1", fake_token: { true_token_address: TOKEN, value: 1 } },
  [TAXED]: { token_symbol: "TAX", is_open_source: "1", buy_tax: "0.12", sell_tax: "0.15" },
  [MINTABLE]: { token_symbol: "DEGEN", is_open_source: "1", is_mintable: "1", buy_tax: "0", sell_tax: "0" },
};

function mockGoplus(url) {
  goplusCalls++;
  if (goplusDown) return new Response("oops", { status: 502 });
  const u = String(url);
  if (u.includes("/token_security/")) {
    const address = new URL(u).searchParams.get("contract_addresses").toLowerCase();
    const result = TOKEN_DATA[address] ? { [address]: TOKEN_DATA[address] } : {};
    return new Response(JSON.stringify({ code: 1, message: "OK", result }));
  }
  if (u.includes(PARTIAL)) return new Response(JSON.stringify({ code: 2, message: "partial data obtained", result: {} }));
  const isEoa = u.includes(EOA);
  const isPhish = u.includes(PHISH);
  const result = u.includes("/address_security/")
    ? { phishing_activities: isPhish ? "1" : "0" }
    : { is_contract: isEoa ? "0" : "1", is_open_source: "1", malicious_behavior: isPhish ? ["drainer"] : [] };
  return new Response(JSON.stringify({ code: 1, message: "OK", result }));
}

function mockClaude() {
  if (claudeDown) return new Response("{}", { status: 529 });
  return new Response(JSON.stringify({ content: [{ type: "text", text: "Uitleg in gewone taal." }] }));
}

let server, base;
before(async () => {
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.includes("gopluslabs")) return mockGoplus(u);
    if (u.includes("api.anthropic.com")) return mockClaude();
    if (u.includes("pg1-ai-agent.vercel.app")) return mockPg1(opts);
    if (/publicnode\.com|mainnet\.base\.org|arbitrum\.io/.test(u)) return mockRpc(opts);
    return realFetch(url, opts);
  };
  const app = express();
  app.use(createCheckRouter());
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); globalThis.fetch = realFetch; });
beforeEach(() => { goplusDown = false; claudeDown = false; rpcDown = false; goplusCalls = 0; pg1Down = false; pg1Calls = 0; pg1RateLimited = false; });

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
