// Wallet approval audit (GET /v1/approvals), without network: GoPlus is mocked
// through globalThis.fetch. The fixtures follow a real token_approval_security
// v2 response (items with approved_list and address_info per spender).
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import {
  walletApprovals, parseApprovalsRequest, assessApproval, isUnlimited, approvalsOneLiner,
  validateApprovalsQuery, createApprovalsRouter,
} from "../src/approvals.js";

const NOW = Date.UTC(2026, 8, 26, 12);
const DAY = 86400;
const at = (daysAgo) => Math.floor(NOW / 1000) - daysAgo * DAY;

const EMPTY = "0x1000000000000000000000000000000000000001";
const NULLRES = "0x1000000000000000000000000000000000000002";
const MIXED = "0x1000000000000000000000000000000000000003";
const CALM = "0x1000000000000000000000000000000000000004";
const DOWN = "0x1000000000000000000000000000000000000005";

const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const DEGEN = "0x4ed4e862860bed51a9570b96d89af5e1b0efefed";
const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const ROUTER = "0x1111111254eeb25477b68fb85ed929f73a960582";
const DRAINER = "0xbad0000000000000000000000000000000000bad";
const PERSON = "0x2222222222222222222222222222222222222222";

const spenderInfo = (over = {}) => ({
  contract_name: "Contract", tag: null, creator_address: "0xc", is_contract: 1, doubt_list: 0,
  malicious_behavior: [], deployed_time: at(900), trust_list: 0, is_open_source: 1, ...over,
});
const approval = (spender, amount, daysAgo, info) => ({
  approved_contract: spender, approved_amount: amount, approved_time: at(daysAgo),
  initial_approval_time: at(daysAgo), hash: "0xh", address_info: spenderInfo(info),
});
const token = (address, symbol, approved_list, over = {}) => ({
  token_address: address, chain_id: "8453", token_name: symbol, token_symbol: symbol, decimals: 6,
  balance: "1000", is_open_source: 1, malicious_address: 0, malicious_behavior: [], approved_list, ...over,
});

const FIXTURES = {
  [EMPTY]: [],
  [MIXED]: [
    token(USDC, "USDC", [
      approval(PERMIT2, "Unlimited", 30, { contract_name: "Permit2", trust_list: 1 }),
      approval(ROUTER, "115792089237316195423570985008687907853269984665640564039457584007913129639935", 10, { contract_name: "AggregationRouterV5" }),
      approval(DRAINER, "500", 2, { contract_name: null, malicious_behavior: ["phishing_activities"] }),
    ]),
    token(DEGEN, "DEGEN", [
      approval(PERSON, "250", 5, { contract_name: null, is_contract: 0, is_open_source: 0 }),
      approval(ROUTER, "100", 800, { contract_name: "AggregationRouterV5" }),
    ]),
  ],
  [CALM]: [token(USDC, "USDC", [approval(PERMIT2, "Unlimited", 30, { contract_name: "Permit2", trust_list: 1 }), approval(ROUTER, "20", 400)])],
};

const realFetch = globalThis.fetch;
const urls = [];
let goplusDown = false;

before(() => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    urls.push(u);
    if (u.hostname !== "api.gopluslabs.io") throw new Error(`unexpected fetch ${u}`);
    if (goplusDown) return new Response("busy", { status: 503 });
    const wallet = u.searchParams.get("addresses");
    if (wallet === NULLRES) return Response.json({ code: 1, message: "ok", result: null });
    return Response.json({ code: 1, message: "ok", result: FIXTURES[wallet] ?? [] });
  };
});
after(() => { globalThis.fetch = realFetch; });
beforeEach(() => { urls.length = 0; goplusDown = false; });

test("input: EVM chains only, wallet address checked and lowercased", () => {
  assert.deepEqual(parseApprovalsRequest({ chain: "Base", address: ` ${MIXED.toUpperCase().replace("0X", "0x")} ` }), { chain: "base", address: MIXED });
  assert.throws(() => parseApprovalsRequest({ chain: "solana", address: MIXED }), /chain must be one of: base, ethereum/);
  assert.throws(() => parseApprovalsRequest({ chain: "base", address: "0x123" }), /wallet address/);
  assert.throws(() => parseApprovalsRequest({}), /chain/);
});

test("unlimited: 'Unlimited', 2^256-1 and huge numbers; normal amounts are not", () => {
  assert.equal(isUnlimited("Unlimited"), true);
  assert.equal(isUnlimited("115792089237316195423570985008687907853269984665640564039457584007913129639935"), true);
  assert.equal(isUnlimited("1e31"), true);
  assert.equal(isUnlimited("4000"), false);
  assert.equal(isUnlimited(""), false);
});

test("a wallet without approvals is green, from GoPlus v2 (also when GoPlus answers result: null)", async () => {
  const r = await walletApprovals({ chain: "base", address: EMPTY }, NOW);
  assert.equal(r.verdict, "green");
  assert.equal(r.grade, "SAFE");
  assert.equal(r.one_liner, "SAFE: no open token approvals on base");
  assert.deepEqual(r.reasons, [{ code: "NO_APPROVALS", severity: "info" }]);
  assert.deepEqual(r.summary, { approvals: 0, tokens: 0, unlimited: 0, toRevoke: 0 });
  assert.equal(urls[0].pathname, "/api/v2/token_approval_security/8453");
  assert.equal(r.revokeUrl, `https://revoke.cash/address/${EMPTY}?chainId=8453`);

  const n = await walletApprovals({ chain: "ethereum", address: NULLRES }, NOW);
  assert.equal(n.grade, "SAFE");
  assert.equal(urls[1].pathname, "/api/v2/token_approval_security/1");
});

test("mixed wallet: a malicious spender is red; wallet, unlimited and flagged approvals are listed to revoke", async () => {
  const r = await walletApprovals({ chain: "base", address: MIXED }, NOW);
  assert.equal(r.verdict, "red");
  assert.equal(r.grade, "AVOID");
  assert.deepEqual(r.summary, { approvals: 5, tokens: 2, unlimited: 2, toRevoke: 3 });
  assert.equal(r.one_liner, "AVOID: 5 approvals, 1 to a flagged address, 1 to a plain wallet, 1 unlimited; revoke 3");

  const bySpender = (s, sym) => r.approvals.find((a) => a.spender.address === s && a.token.symbol === sym);
  assert.equal(r.approvals[0].spender.address, DRAINER, "red first");
  assert.deepEqual(bySpender(DRAINER, "USDC").codes, [{ code: "SPENDER_MALICIOUS", severity: "red", details: { behaviors: ["phishing_activities"] } }]);
  assert.equal(bySpender(ROUTER, "USDC").amount, "unlimited");
  assert.deepEqual(bySpender(ROUTER, "USDC").codes.map((c) => c.code), ["UNLIMITED_APPROVAL"]);
  assert.equal(bySpender(ROUTER, "USDC").spender.name, "AggregationRouterV5");
  assert.deepEqual(bySpender(PERSON, "DEGEN").codes.map((c) => c.code), ["APPROVAL_TO_WALLET"]);
  assert.equal(bySpender(PERSON, "DEGEN").spender.contract, false);

  // Context, not a reason to revoke: unlimited to a trust-list spender, an old small approval.
  const permit2 = bySpender(PERMIT2, "USDC");
  assert.deepEqual(permit2.codes, [{ code: "UNLIMITED_APPROVAL_TRUSTED", severity: "info" }]);
  assert.equal(permit2.revoke, false);
  assert.equal(permit2.spender.trusted, true);
  assert.deepEqual(bySpender(ROUTER, "DEGEN").codes, [{ code: "STALE_APPROVAL", severity: "info" }]);

  const unlimited = r.reasons.find((x) => x.code === "UNLIMITED_APPROVAL");
  assert.deepEqual(unlimited, { code: "UNLIMITED_APPROVAL", severity: "orange", details: { count: 1, spenders: [ROUTER] } });
  assert.deepEqual(r.reasons.map((x) => x.severity), [...r.reasons.map((x) => x.severity)].sort((a, b) => ["red", "orange", "info"].indexOf(a) - ["red", "orange", "info"].indexOf(b)));
});

test("only trusted or harmless approvals: green, nothing to revoke", async () => {
  const r = await walletApprovals({ chain: "base", address: CALM }, NOW);
  assert.equal(r.verdict, "green");
  assert.equal(r.one_liner, "SAFE: 2 approvals, none risky");
  assert.equal(r.summary.toRevoke, 0);
});

test("unverified contract and doubt list are orange; the approved token itself flagged is context", () => {
  const unverified = assessApproval(token(USDC, "USDC", []), approval(ROUTER, "10", 1, { is_open_source: 0 }), NOW);
  assert.deepEqual(unverified.codes.map((c) => c.code), ["SPENDER_UNVERIFIED"]);
  const doubt = assessApproval(token(USDC, "USDC", []), approval(ROUTER, "10", 1, { doubt_list: 1 }), NOW);
  assert.deepEqual(doubt.codes.map((c) => c.code), ["SPENDER_SUSPICIOUS"]);
  const scamToken = assessApproval(token(DEGEN, "SCAM", [], { malicious_address: 1 }), approval(ROUTER, "10", 1), NOW);
  assert.deepEqual(scamToken.codes, [{ code: "TOKEN_FLAGGED", severity: "info" }]);
  assert.equal(scamToken.revoke, false);
});

test("one-liner: counts, at most three phrases, capped at 140 characters", () => {
  const reason = (code, count) => ({ code, severity: "orange", details: { count, spenders: [] } });
  assert.equal(approvalsOneLiner({ grade: "RISKY", chain: "base", total: 12, toRevoke: 9,
    reasons: [reason("APPROVAL_TO_WALLET", 2), reason("SPENDER_UNVERIFIED", 3), reason("UNLIMITED_APPROVAL", 7), reason("SPENDER_SUSPICIOUS", 1)] }),
  "RISKY: 12 approvals, 2 to a plain wallet, 1 to a suspicious spender, 3 to an unverified contract; revoke 9", "the most serious kinds win the three places");
  assert.equal(approvalsOneLiner({ grade: "SAFE", chain: "base", total: 1, toRevoke: 0, reasons: [] }), "SAFE: 1 approval, none risky");
});

// ---------- HTTP route ----------

async function withApp(fn) {
  const app = express();
  app.use(validateApprovalsQuery);
  app.get("/v1/approvals", (req, res, next) => (req.query.paid === "no" ? res.status(402).json({ price: true }) : next())); // stands in for the paywall
  app.use(createApprovalsRouter());
  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

test("route: invalid input is a 400 before the paywall; a bare probe gets the price; an audit otherwise", async () => {
  await withApp(async (base) => {
    const bad = await realFetch(`${base}/v1/approvals?chain=base&address=nope&paid=no`);
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, "invalid_request");
    assert.equal((await realFetch(`${base}/v1/approvals?paid=no`)).status, 402, "a bare probe gets the price, not a 400");
    assert.equal((await realFetch(`${base}/v1/approvals`)).status, 400, "paying without a query still gets a 400 (never settled)");
    assert.equal((await realFetch(`${base}/v1/approvals?chain=base&address=${MIXED}&paid=no`)).status, 402);
    const ok = await realFetch(`${base}/v1/approvals?chain=base&address=${MIXED}`);
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).grade, "AVOID");
  });
});

test("route: GoPlus down is a 503 with no verdict (nothing is charged)", async () => {
  await withApp(async (base) => {
    goplusDown = true;
    const r = await realFetch(`${base}/v1/approvals?chain=base&address=${DOWN}`);
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: "upstream_unavailable", message: "GoPlus HTTP 503", verdict: null });
  });
});
