// Token verdict rules and the GET /v1/token route, without network: GoPlus,
// RugCheck and DexScreener are mocked through globalThis.fetch. The fixtures
// follow real responses (BONK, a fresh pump token, DEGEN on Base).
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import {
  tokenVerdict, parseTokenRequest, summarizeMarket, gradeOf, oneLiner,
  validateTokenQuery, createTokenRouter,
} from "../src/token-verdict.js";

const NOW = Date.UTC(2026, 8, 25, 12);
const DAY = 86400e3;
const BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
const FRESH = "qikeUfbJaWPHy7sTTYfQuBuafzmUBZAH7SjCbjZCyFA";
const RUGGED = "Rug1111111111111111111111111111111111111111";
const USDC_SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const UNKNOWN_SOL = "Unkn111111111111111111111111111111111111111";
const DOWN_SOL = "Down111111111111111111111111111111111111111";
const DEGEN = "0x4ed4e862860bed51a9570b96d89af5e1b0efefed";
const HONEY = "0x1111111111111111111111111111111111111111";
const NOMARKET = "0x2222222222222222222222222222222222222222";
const WETH = "0x4200000000000000000000000000000000000006";

const off = { status: "0" };
const on = { status: "1" };
const solSec = (over = {}) => ({
  mintable: off, freezable: off, closable: off, balance_mutable_authority: { status: "0", authority: [] },
  non_transferable: "0", transfer_fee: {}, transfer_fee_upgradable: off, transfer_hook: [], transfer_hook_upgradable: off,
  default_account_state_upgradable: off, metadata_mutable: { status: "0", metadata_upgrade_authority: [] }, creators: [],
  trusted_token: 0, holders: [], ...over,
});

const pair = (address, { liq, createdDaysAgo, symbol = "TKN", socials = true, h24 = 1000 }) => ({
  dexId: "raydium", url: `https://dexscreener.com/x/${address}`, pairCreatedAt: NOW - createdDaysAgo * DAY,
  baseToken: { address, name: symbol, symbol }, quoteToken: { address: "So11111111111111111111111111111111111111112", symbol: "SOL" },
  priceUsd: "0.5", liquidity: { usd: liq }, marketCap: 1e6, fdv: 2e6, volume: { h24 },
  ...(socials ? { info: { socials: [{ type: "twitter", url: "https://x.com/t" }] } } : {}),
});

const FIXTURES = {
  goplusSol: {
    [BONK]: solSec({ metadata_mutable: { status: "1", metadata_upgrade_authority: [{ address: "9AhK", malicious_address: 0 }] },
      holders: [{ account: "a", percent: "0.088" }, { account: "b", percent: "0.05", tag: "Raydium" }] }),
    [FRESH]: solSec({ transfer_fee: { current_fee_rate: { fee_rate: "0.01", maximum_fee: "1000" } }, transfer_fee_upgradable: on,
      holders: [{ account: "whale", percent: "0.194" }, { account: "w2", percent: "0.12" }, { account: "w3", percent: "0.11" }, { account: "w4", percent: "0.1" }] }),
    [RUGGED]: solSec({ mintable: on, freezable: on }),
    [USDC_SOL]: solSec({ mintable: on, freezable: on, trusted_token: 1 }),
    [DOWN_SOL]: solSec(),
  },
  rugcheck: {
    [BONK]: { rugged: false, risks: [], markets: [{ lp: { lpLockedPct: 0 } }] },
    [FRESH]: { rugged: false, risks: [{ name: "Top 10 holders high ownership", level: "danger" }], markets: [{ lp: { lpLockedPct: 100 } }] },
    [RUGGED]: { rugged: true, risks: [], markets: [{ lp: { lpLockedPct: 0 } }] },
  },
  dex: {
    [BONK]: [pair(BONK, { liq: 422000, createdDaysAgo: 1000, symbol: "Bonk" })],
    [FRESH]: [pair(FRESH, { liq: 21000, createdDaysAgo: 0.01, symbol: "LITECAT", socials: false })],
    [RUGGED]: [pair(RUGGED, { liq: 300, createdDaysAgo: 3 })],
    [USDC_SOL]: [pair(USDC_SOL, { liq: 5e7, createdDaysAgo: 900, symbol: "USDC" })],
    [UNKNOWN_SOL]: [],
    [DOWN_SOL]: [pair(DOWN_SOL, { liq: 1e6, createdDaysAgo: 100 })],
    [DEGEN]: [pair(DEGEN, { liq: 3e6, createdDaysAgo: 900, symbol: "DEGEN" })],
    [HONEY]: [pair(HONEY, { liq: 80000, createdDaysAgo: 0.5 })],
    [NOMARKET]: [],
    [WETH]: [pair(WETH, { liq: 20000, createdDaysAgo: 800, symbol: "WETH" })],
  },
  goplusEvm: {
    [DEGEN]: { is_open_source: "1", is_honeypot: "0", buy_tax: "0", sell_tax: "0", holder_count: "900000",
      holders: [{ address: "0xpool", percent: "0.3", is_locked: 0 }, { address: "0xstaking", percent: "0.4", is_contract: 1 }, { address: "0xa", percent: "0.05", is_locked: 0 }],
      dex: [{ pair: "0xpool", liquidity: "3000000" }] },
    [HONEY]: { is_open_source: "1", is_honeypot: "1", buy_tax: "0", sell_tax: "1" },
    [NOMARKET]: { is_open_source: "0" },
    [WETH]: { is_open_source: "1", trust_list: "1", holders: [{ address: "0xw", percent: "0.25", is_contract: 0 }] },
  },
};

const realFetch = globalThis.fetch;
const calls = [];
let down = new Set();

before(() => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    calls.push(u.hostname);
    if (down.has(u.hostname)) return new Response("busy", { status: 503 });
    if (u.hostname === "api.gopluslabs.io") {
      const a = u.searchParams.get("contract_addresses");
      const table = u.pathname.includes("/solana/") ? FIXTURES.goplusSol : FIXTURES.goplusEvm;
      return Response.json({ code: 1, message: "OK", result: table[a] ? { [a]: table[a] } : {} });
    }
    if (u.hostname === "api.rugcheck.xyz") {
      const mint = u.pathname.split("/")[3];
      if (mint === DOWN_SOL) return new Response("rate limited", { status: 429 });
      return FIXTURES.rugcheck[mint] ? Response.json(FIXTURES.rugcheck[mint]) : new Response("not found", { status: 404 });
    }
    if (u.hostname === "api.dexscreener.com") {
      return Response.json(FIXTURES.dex[u.pathname.split("/").pop()] ?? []);
    }
    throw new Error(`unexpected fetch ${u}`);
  };
});
after(() => { globalThis.fetch = realFetch; });
beforeEach(() => { calls.length = 0; down = new Set(); });

const codes = (r, severity) => r.reasons.filter((x) => !severity || x.severity === severity).map((x) => x.code).sort();

test("input: chain and address are checked, EVM addresses lowercased", () => {
  assert.deepEqual(parseTokenRequest({ chain: "Base", address: "0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed" }), { chain: "base", address: DEGEN });
  assert.deepEqual(parseTokenRequest({ chain: "solana", address: BONK }), { chain: "solana", address: BONK });
  assert.throws(() => parseTokenRequest({ chain: "tron", address: BONK }), /chain must be one of/);
  assert.throws(() => parseTokenRequest({ chain: "solana", address: DEGEN }), /Solana mint/);
  assert.throws(() => parseTokenRequest({ chain: "base", address: BONK }), /0x-prefixed/);
  assert.throws(() => parseTokenRequest({}), /chain/);
});

test("Solana, established token (BONK): green, SAFE, market facts in the one-liner", async () => {
  const r = await tokenVerdict({ chain: "solana", address: BONK }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  // LP 0% locked on a 2.7-year-old token is context (concentrated-liquidity pools have no LP token).
  assert.deepEqual(codes(r, "info"), ["LP_NOT_LOCKED", "MUTABLE_METADATA"]);
  assert.equal(r.one_liner, "SAFE: no red flags, $422k liquidity, 2.7 years old");
  assert.deepEqual([r.market.symbol, r.market.liquidityUsd, r.market.priceUsd], ["Bonk", 422000, 0.5]);
  assert.deepEqual(r.sources, ["goplus", "dexscreener", "rugcheck"]);
});

test("Solana, fresh pump token: orange, RISKY, reasons in order of weight", async () => {
  const r = await tokenVerdict({ chain: "solana", address: FRESH }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "RISKY"]);
  assert.deepEqual(codes(r, "orange"), ["LOW_LIQUIDITY", "NEW_TOKEN", "TOP_HOLDERS_CONCENTRATED", "TRANSFER_FEE", "TRANSFER_FEE_UPGRADABLE"]);
  assert.deepEqual(r.reasons.find((x) => x.code === "TOP_HOLDERS_CONCENTRATED").details, { top1Pct: 19.4, top10Pct: 52.4 });
  assert.deepEqual(r.reasons.find((x) => x.code === "TRANSFER_FEE").details, { feePct: 1 });
  assert.ok(codes(r, "info").includes("NO_SOCIALS"));
  assert.ok(codes(r, "info").includes("RUGCHECK_DANGER"));
  assert.ok(!codes(r).includes("LP_NOT_LOCKED"), "100% LP locked");
  assert.ok(r.one_liner.startsWith("RISKY: "));
  assert.ok(r.one_liner.length <= 140);
});

test("Solana, rugged: red, AVOID", async () => {
  const r = await tokenVerdict({ chain: "solana", address: RUGGED }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["red", "AVOID"]);
  assert.equal(r.reasons[0].code, "RUGGED");
  assert.ok(codes(r, "orange").includes("MINT_AUTHORITY_ACTIVE"));
  assert.ok(codes(r, "orange").includes("LP_NOT_LOCKED"), "a 3-day-old token with unlocked LP");
  assert.match(r.one_liner, /^AVOID: marked rugged by RugCheck; /);
});

test("Solana, trusted issuer (USDC): mint and freeze authority are context, not a warning", async () => {
  const r = await tokenVerdict({ chain: "solana", address: USDC_SOL }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.deepEqual(codes(r, "info"), ["FREEZE_AUTHORITY_ACTIVE", "MINT_AUTHORITY_ACTIVE", "TOKEN_ON_TRUST_LIST"]);
});

test("unknown token: no data is orange, never red", async () => {
  const r = await tokenVerdict({ chain: "solana", address: UNKNOWN_SOL }, NOW);
  assert.equal(r.verdict, "orange");
  assert.deepEqual(codes(r, "orange"), ["NO_DEX_MARKET"]);
  assert.ok(codes(r, "info").includes("NO_SECURITY_DATA"));
  assert.equal(r.market, null);
  assert.deepEqual(r.sources, ["goplus", "dexscreener"], "RugCheck 404: not a source");
});

test("RugCheck down: still a verdict, with the gap reported", async () => {
  const r = await tokenVerdict({ chain: "solana", address: DOWN_SOL }, NOW);
  assert.equal(r.verdict, "green");
  assert.deepEqual(codes(r, "info"), ["RUGCHECK_UNAVAILABLE"]);
  assert.ok(!r.sources.includes("rugcheck"));
});

test("Base, established token (DEGEN): pools and contracts are not counted as whales", async () => {
  const r = await tokenVerdict({ chain: "base", address: DEGEN }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.ok(!codes(r).includes("TOP_HOLDERS_CONCENTRATED"));
});

test("Base, trusted token: thin DexScreener liquidity is context, a big wallet still counts", async () => {
  const r = await tokenVerdict({ chain: "base", address: WETH }, NOW);
  assert.deepEqual(codes(r, "orange"), ["TOP_HOLDERS_CONCENTRATED"]);
  assert.ok(codes(r, "info").includes("LOW_LIQUIDITY"));
});

test("Base, honeypot: red, AVOID, and the GoPlus token rules from /v1/check apply", async () => {
  const r = await tokenVerdict({ chain: "base", address: HONEY }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["red", "AVOID"]);
  assert.deepEqual(codes(r, "red"), ["TOKEN_HONEYPOT"]);
  assert.ok(codes(r, "orange").includes("TOKEN_HIGH_TAX"));
  assert.ok(codes(r, "orange").includes("NEW_TOKEN"));
  assert.match(r.one_liner, /^AVOID: honeypot: can't be sold; /);
});

test("Base, unverified token with no market: orange", async () => {
  const r = await tokenVerdict({ chain: "base", address: NOMARKET }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "RISKY"]);
  assert.deepEqual(codes(r, "orange"), ["NO_DEX_MARKET", "TOKEN_UNVERIFIED"]);
});

test("market summary: liquidity summed, price from the pair where the token is the base", () => {
  const quoteSide = { ...pair("other", { liq: 900, createdDaysAgo: 10 }), quoteToken: { address: BONK, symbol: "Bonk", name: "Bonk" }, priceUsd: "99" };
  const m = summarizeMarket([quoteSide, pair(BONK, { liq: 100, createdDaysAgo: 20, symbol: "Bonk" })], "solana", BONK, NOW);
  assert.deepEqual([m.liquidityUsd, m.priceUsd, m.pairs, m.symbol], [1000, 0.5, 2, "Bonk"]);
  assert.equal(m.ageSeconds, 20 * 86400, "age from the oldest pair");
  assert.equal(summarizeMarket([], "solana", BONK, NOW), null);
});

test("grades and the one-liner", () => {
  const o = (code) => ({ code, severity: "orange" });
  assert.deepEqual(gradeOf([]), { verdict: "green", grade: "SAFE" });
  assert.deepEqual(gradeOf([o("NEW_TOKEN")]), { verdict: "orange", grade: "CAUTION" });
  assert.deepEqual(gradeOf([o("NEW_TOKEN"), o("LOW_LIQUIDITY")]), { verdict: "orange", grade: "RISKY" });
  assert.deepEqual(gradeOf([{ code: "RUGGED", severity: "red" }, o("NEW_TOKEN")]), { verdict: "red", grade: "AVOID" });
  const many = ["MINT_AUTHORITY_ACTIVE", "FREEZE_AUTHORITY_ACTIVE", "BALANCE_MUTABLE", "CLOSABLE"].map(o);
  assert.equal(oneLiner({ grade: "RISKY", reasons: many, market: null }),
    "RISKY: supply can still be minted; holders can be frozen; balances can be changed (+1 more)");
});

// ---------- HTTP route ----------

async function withApp(fn) {
  const app = express();
  app.use(validateTokenQuery);
  app.get("/v1/token", (req, res, next) => (req.query.paid === "no" ? res.status(402).json({ price: true }) : next())); // stands in for the paywall
  app.use(createTokenRouter());
  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

test("route: invalid input is a 400 before the paywall; a verdict otherwise", async () => {
  await withApp(async (base) => {
    const bad = await realFetch(`${base}/v1/token?chain=solana&address=nope&paid=no`);
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, "invalid_request");
    const unpaid = await realFetch(`${base}/v1/token?chain=solana&address=${BONK}&paid=no`);
    assert.equal(unpaid.status, 402);
    const ok = await realFetch(`${base}/v1/token?chain=solana&address=${BONK}`);
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).grade, "SAFE");
  });
});

test("route: DexScreener or GoPlus down is a 503 with no verdict (nothing is charged)", async () => {
  await withApp(async (base) => {
    down = new Set(["api.dexscreener.com"]);
    const r = await realFetch(`${base}/v1/token?chain=base&address=0x3333333333333333333333333333333333333333`);
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: "upstream_unavailable", message: "DexScreener HTTP 503", verdict: null });
    down = new Set(["api.gopluslabs.io"]);
    const g = await realFetch(`${base}/v1/token?chain=solana&address=So44444444444444444444444444444444444444444`);
    assert.equal(g.status, 503);
  });
});
