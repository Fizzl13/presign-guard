// Run: npm test
// No network: GoPlus and Claude are mocked through globalThis.fetch.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createCheckRouter } from "../src/presign-guard.js";

process.env.ANTHROPIC_API_KEY = "test-key";

const realFetch = globalThis.fetch;
const TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const GOOD = "0x2222222222222222222222222222222222222222"; // verified contract
const EOA = "0xbad0000000000000000000000000000000000001";  // plain wallet
const PHISH = "0xbad0000000000000000000000000000000000002"; // flagged contract
const USER = "0x1111111111111111111111111111111111111111";
const FAR = "9999999999";
const MAX256 = (2n ** 256n - 1n).toString();
const MAX160 = (2n ** 160n - 1n).toString();

// Per-test switches
let goplusDown = false;
let claudeDown = false;
let goplusCalls = 0;

function mockGoplus(url) {
  goplusCalls++;
  if (goplusDown) return new Response("oops", { status: 502 });
  const u = String(url);
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
    return realFetch(url, opts);
  };
  const app = express();
  app.use(createCheckRouter());
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); globalThis.fetch = realFetch; });
beforeEach(() => { goplusDown = false; claudeDown = false; goplusCalls = 0; });

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

test("repeated checks are served from cache", async () => {
  const spender = "0x4444444444444444444444444444444444444444";
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender, amount: "1" });
  const first = goplusCalls;
  await check({ type: "approval", chainId: 8453, token: TOKEN, spender, amount: "1" });
  assert.equal(goplusCalls, first);
});
