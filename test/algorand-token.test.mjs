// The Algorand token verdict (chain "algorand" on /v1/token) against a stand-in node, indexer and DexScreener.
// Every test uses its own asset ids: answers are cached per asset.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTokenRequest, tokenVerdict } from "../src/token-verdict.js";

const ZERO = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"; // the zero address: a cleared control address
const CREATOR = "CREATORAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const RESERVE = "RESERVEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const POOL = "POOLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const realFetch = globalThis.fetch;
const DAY = 86400;
const now = Date.now();

// A stand-in for algod, the indexer and DexScreener. asset: the ASA params (null = no such asset); balances: the
// indexer's holder list; createdSecondsAgo: the asset's age; reserveHolds: the reserve's balance.
function stand({ asset, balances = [], createdSecondsAgo = 400 * DAY, reserveHolds = 0, pairs = [], indexerDown = false }) {
  const calls = [];
  const fetchImpl = async (url) => {
    const u = new URL(url);
    calls.push(u.pathname);
    let m;
    if (u.host.includes("dexscreener")) return Response.json(pairs);
    if (u.host.includes("idx")) {
      if (indexerDown) throw new Error("ETIMEDOUT");
      if ((m = u.pathname.match(/^\/v2\/assets\/(\d+)$/))) return Response.json({ asset: { index: Number(m[1]), "created-at-round": Number(m[1]), params: asset } }); // its own round: blocks are cached per round
      if (u.pathname.startsWith("/v2/blocks/")) return Response.json({ timestamp: Math.floor(now / 1000) - createdSecondsAgo });
      if (/\/balances$/.test(u.pathname)) {
        const floor = Number(u.searchParams.get("currency-greater-than"));
        return Response.json({ balances: balances.filter((b) => b.amount > floor) });
      }
    }
    if ((m = u.pathname.match(/^\/v2\/assets\/(\d+)$/))) return asset ? Response.json({ index: Number(m[1]), params: asset }) : new Response("{}", { status: 404 });
    if (u.pathname.match(/^\/v2\/accounts\/[A-Z2-7]+\/assets\/\d+$/)) return Response.json({ "asset-holding": { amount: reserveHolds } });
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, calls };
}
// DexScreener goes through the global fetch, the node and indexer through fetchImpl.
async function verdict(id, opts) {
  const s = stand(opts);
  globalThis.fetch = s.fetchImpl;
  try {
    return await tokenVerdict(parseTokenRequest({ chain: "algorand", address: String(id) }), now, { fetchImpl: s.fetchImpl });
  } finally {
    globalThis.fetch = realFetch;
  }
}
const params = (o = {}) => ({ creator: CREATOR, total: 1_000_000, decimals: 0, "default-frozen": false, name: "Game Token", "unit-name": "GAME", manager: CREATOR, reserve: ZERO, freeze: ZERO, clawback: ZERO, ...o });
const deep = (id) => [{ chainId: "algorand", dexId: "tinyman", pairAddress: POOL, baseToken: { address: String(id), name: "Game Token", symbol: "GAME" }, liquidity: { usd: 250_000 }, priceUsd: "0.5", pairCreatedAt: now - 300 * DAY * 1000, info: { websites: [{ url: "https://game.example" }] } }];
const codes = (r) => r.reasons.map((x) => `${x.severity}:${x.code}`);

test("parse: an asset id; ALGO, 0 and anything else refused", () => {
  assert.deepEqual(parseTokenRequest({ chain: "algorand", address: "31566704" }), { chain: "algorand", address: "31566704" });
  assert.equal(parseTokenRequest({ chain: "algorand", address: "007" }).address, "7");
  assert.throws(() => parseTokenRequest({ chain: "algorand", address: "0" }), /native coin/);
  assert.throws(() => parseTokenRequest({ chain: "algorand", address: "ALGO" }), /native coin/);
  assert.throws(() => parseTokenRequest({ chain: "algorand", address: "abc" }), /asset id/);
  assert.throws(() => parseTokenRequest({ chain: "algorand", address: "18446744073709551616" }), /asset id/, "above 2^64 - 1");
});

test("a plain asset with a deep market and spread holders is green, with its age", async () => {
  const r = await verdict(9_000_001, { asset: params(), pairs: deep(9_000_001), balances: [{ address: "A".repeat(58), amount: 50_000 }, { address: POOL, amount: 600_000 }] });
  assert.equal(r.verdict, "green", JSON.stringify(r.reasons));
  assert.equal(r.token.symbol, "GAME");
  assert.ok(r.token.createdAt);
  assert.ok(r.sources.includes("algorand-indexer"));
});

test("fake USDC is red, an asset named ALGO orange; Circle's USDC is green with its powers as context", async () => {
  const fake = await verdict(9_000_002, { asset: params({ "unit-name": "USDC", name: "USD Coin" }) });
  assert.equal(fake.verdict, "red");
  assert.equal(fake.reasons[0].code, "TOKEN_IMPERSONATION");
  const algo = await verdict(9_000_003, { asset: params({ "unit-name": "xALGO2", name: "Algo" }), pairs: deep(9_000_003) });
  assert.ok(codes(algo).includes("orange:TOKEN_IMPERSONATION"));
  const usdc = await verdict(31566704, { asset: params({ "unit-name": "USDC", name: "USDC", freeze: CREATOR, clawback: CREATOR, total: 1e19 }), reserveHolds: 9e18 });
  assert.equal(usdc.verdict, "green", JSON.stringify(usdc.reasons));
  assert.match(usdc.one_liner, /Circle's USDC/);
  assert.ok(codes(usdc).includes("info:CLAWBACK_ENABLED"));
});

test("control addresses: clawback and default-frozen are orange, freeze is context, none at all is renounced", async () => {
  assert.ok(codes(await verdict(9_000_004, { asset: params({ clawback: CREATOR }), pairs: deep(9_000_004) })).includes("orange:CLAWBACK_ENABLED"));
  assert.ok(codes(await verdict(9_000_005, { asset: params({ "default-frozen": true, freeze: CREATOR }), pairs: deep(9_000_005) })).includes("orange:PERMISSIONED_TOKEN"));
  const frz = await verdict(9_000_006, { asset: params({ freeze: CREATOR }), pairs: deep(9_000_006) });
  assert.ok(codes(frz).includes("info:FREEZE_AUTHORITY_ACTIVE"));
  assert.equal(frz.verdict, "green");
  assert.ok(codes(await verdict(9_000_007, { asset: params({ manager: ZERO }), pairs: deep(9_000_007) })).includes("info:ISSUER_RENOUNCED"));
});

test("holders: concentration counts circulating supply, without the reserve and the DEX pool", async () => {
  const opts = (balances) => ({ asset: params({ reserve: RESERVE }), reserveHolds: 600_000, pairs: deep(9_000_008), balances });
  // 400,000 circulating: one wallet with 120,000 is 30%.
  const conc = await verdict(9_000_008, opts([{ address: RESERVE, amount: 600_000 }, { address: POOL, amount: 200_000 }, { address: "B".repeat(58), amount: 120_000 }]));
  const c = conc.reasons.find((r) => r.code === "TOP_HOLDERS_CONCENTRATED");
  assert.equal(c.severity, "orange");
  assert.equal(c.details.top1Pct, 30);
  const spread = await verdict(9_000_009, { ...opts([{ address: RESERVE, amount: 600_000 }, { address: POOL, amount: 380_000 }, { address: "C".repeat(58), amount: 20_000 }]), pairs: deep(9_000_009) });
  assert.ok(!codes(spread).includes("orange:TOP_HOLDERS_CONCENTRATED"));
});

test("a new asset is orange; a missing asset is red; the indexer being down is context, not a verdict", async () => {
  assert.ok(codes(await verdict(9_000_010, { asset: params(), pairs: deep(9_000_010).map((p) => ({ ...p, pairCreatedAt: undefined })), createdSecondsAgo: 3600 })).includes("orange:NEW_TOKEN"));
  const gone = await verdict(9_000_011, { asset: null });
  assert.equal(gone.verdict, "red");
  assert.equal(gone.reasons[0].code, "TOKEN_NOT_FOUND");
  const down = await verdict(9_000_012, { asset: params(), pairs: deep(9_000_012), indexerDown: true });
  assert.ok(codes(down).includes("info:INDEXER_UNAVAILABLE"));
  assert.equal(down.verdict, "green");
  assert.ok(!down.sources.includes("algorand-indexer"));
});

test("the algorand chain is in the token schema the routes and MCP tools use", async () => {
  const { TOKEN_INPUT_SCHEMA } = await import("../src/discovery.js");
  assert.ok(TOKEN_INPUT_SCHEMA.properties.chain.enum.includes("algorand"));
});
