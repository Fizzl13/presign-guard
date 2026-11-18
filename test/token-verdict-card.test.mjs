// POST /v1/token/verdict (src/token-verdict-card.js), its sell check (src/sell-check.js) and share links
// (src/token-share.js), without network: GoPlus, RugCheck and DexScreener are mocked through globalThis.fetch, the
// chain simulation through a stand-in simulator, and the paywall is the real @x402/express one with a stand-in
// facilitator that counts settlements.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactEvmScheme as ExactEvmClient } from "@x402/evm/exact/client";
import { x402Client } from "@x402/core/client";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { decodeFunctionData, parseAbi } from "viem";
import { x402Routes } from "../src/presign-guard.js";
import { validateTokenQuery, createTokenRouter } from "../src/token-verdict.js";
import { createTokenVerdictRouter, validateTokenVerdictBody, parseVerdictBody, decisionOf, takeOf } from "../src/token-verdict-card.js";
import { sellCheck, poolOf, SIM_HOLDER } from "../src/sell-check.js";
import { createShareRouter, readShare, signShare, sharePayload, shareCard, sharePage, wrap, SHARE_PREFIX, MAX_SHARE_CHARS } from "../src/token-share.js";
import { createLru, createPngCards } from "../src/token-card-png.js";
import { createSigner, signPaidResponses, verifyReceipt, canonicalJson } from "../src/receipt.js";
import { describePresignCall } from "../src/usage.js";

process.env.TOLL = "off";
delete process.env.TYPESAFE_API_KEY;
delete process.env.ANTHROPIC_API_KEY;

const BASE = "eip155:8453";
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const NOW = Date.now();
const DAY = 86400e3;
const addr = (c) => `0x${c.repeat(40)}`;
const GOOD = addr("a"); // SAFE, sells fine in the simulation
const UNVERIFIED = addr("b"); // CAUTION: unverified source
const RISKY = addr("c"); // RISKY: unverified and thin liquidity
const HONEY = addr("d"); // AVOID: honeypot
const STUCK = addr("e"); // SAFE in the data, but the simulated sell reverts
const TAXED = addr("f"); // SAFE in the data, a 20% tax in the simulated sell
const HOSTILE = addr("9"); // SAFE, with a name and symbol that try to break out of HTML
const DOWN = addr("8"); // DexScreener answers 503
const POOL = (t) => `0x${"5".repeat(38)}${t.slice(2, 4)}`;
const BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";

const okSec = { is_open_source: "1", is_honeypot: "0", cannot_sell_all: "0", buy_tax: "0", sell_tax: "0", transfer_pausable: "0", is_blacklisted: "0", holder_count: "50000" };
const GOPLUS = {
  [GOOD]: okSec, [STUCK]: okSec, [TAXED]: okSec, [HOSTILE]: okSec, [DOWN]: okSec,
  [UNVERIFIED]: { ...okSec, is_open_source: "0" },
  [RISKY]: { ...okSec, is_open_source: "0" },
  [HONEY]: { ...okSec, is_honeypot: "1", sell_tax: "1" },
};
const pair = (t, { liq = 2e6, days = 900, name = "Good Token", symbol = "GOOD" } = {}) => ({
  dexId: "uniswap", pairAddress: POOL(t), labels: ["v2"], url: `https://dexscreener.com/base/${POOL(t)}`, pairCreatedAt: NOW - days * DAY,
  baseToken: { address: t, name, symbol }, quoteToken: { address: "0x4200000000000000000000000000000000000006", symbol: "WETH" },
  priceUsd: "0.0123", liquidity: { usd: liq }, marketCap: 5e6, volume: { h24: 40000 }, info: { socials: [{ type: "twitter" }] },
});
const DEX = {
  [GOOD]: [pair(GOOD)], [UNVERIFIED]: [pair(UNVERIFIED)], [RISKY]: [pair(RISKY, { liq: 9000 })], [HONEY]: [pair(HONEY, { liq: 80000 })],
  [STUCK]: [pair(STUCK)], [TAXED]: [pair(TAXED)],
  [HOSTILE]: [pair(HOSTILE, { name: "<script>alert(1)</script>", symbol: "\"onload=alert(1)" })],
  [BONK]: [{ ...pair(BONK, { name: "Bonk", symbol: "Bonk" }), pairAddress: "Pool1111111111111111111111111111111111111111", baseToken: { address: BONK, name: "Bonk", symbol: "Bonk" } }],
};
const off = { status: "0" };
const SOL_SEC = {
  [BONK]: { mintable: off, freezable: off, closable: off, balance_mutable_authority: { status: "0", authority: [] }, non_transferable: "0", transfer_fee: {},
    transfer_fee_upgradable: off, transfer_hook: [], transfer_hook_upgradable: off, default_account_state_upgradable: off,
    metadata_mutable: { status: "0", metadata_upgrade_authority: [] }, creators: [], trusted_token: 0, holders: [] },
};

const realFetch = globalThis.fetch;
const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
before(() => {
  globalThis.fetch = async (url, init) => {
    const u = new URL(typeof url === "string" ? url : url.url);
    if (u.hostname === "127.0.0.1") return realFetch(url, init);
    if (u.hostname === "api.gopluslabs.io") {
      const a = u.searchParams.get("contract_addresses");
      const table = u.pathname.includes("/solana/") ? SOL_SEC : GOPLUS;
      return reply({ code: 1, message: "OK", result: table[a] ? { [a]: table[a] } : {} });
    }
    if (u.hostname === "api.dexscreener.com") {
      const a = u.pathname.split("/").pop();
      return a === DOWN ? reply({}, 503) : reply(DEX[a] ?? []);
    }
    if (u.hostname === "api.rugcheck.xyz") return reply({ rugged: false, risks: [], markets: [{ lp: { lpLockedPct: 100 } }] });
    throw new Error(`unexpected fetch ${u}`);
  };
});
after(() => { globalThis.fetch = realFetch; });

// A stand-in for src/simulate.js's send(): the pool holds 1e24 base units; per token what the sell transfer does.
const ERC20 = parseAbi(["function transfer(address to, uint256 amount) returns (bool)", "function balanceOf(address owner) view returns (uint256)"]);
const word = (n) => `0x${BigInt(n).toString(16).padStart(64, "0")}`;
const T_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const topic = (a) => `0x${"0".repeat(24)}${a.slice(2)}`;
const SELL = { [STUCK]: { ok: false }, [TAXED]: { ok: true, arrived: 0.8 } };
function fakeSimulator(log = []) {
  return {
    enabled: true,
    async send(chainId, body) {
      log.push(Array.isArray(body) ? "batch" : body.method);
      if (Array.isArray(body)) return { source: "rpc", answer: [{ id: 1, result: word(10n ** 24n) }, { id: 2, result: { number: "0x100", timestamp: "0x6000" } }] };
      const [b1, b2] = body.params[0].blockStateCalls;
      assert.equal(body.params[1], "0x100", "simulated on the block that was read");
      assert.equal(b2.blockOverrides.number, "0x102");
      const token = b1.calls[0].to;
      const { args: [, amount] } = decodeFunctionData({ abi: ERC20, data: b1.calls[0].data });
      const { args: [to, sent] } = decodeFunctionData({ abi: ERC20, data: b2.calls[0].data });
      assert.equal(b2.calls[0].from, SIM_HOLDER);
      const how = SELL[token] ?? { ok: true, arrived: 1 };
      const arrived = (sent * BigInt(Math.round((how.arrived ?? 1) * 100))) / 100n;
      return { source: "rpc", answer: { result: [
        { calls: [{ status: "0x1", returnData: word(1), logs: [] }, { status: "0x1", returnData: word(amount) }] },
        { calls: [how.ok
          ? { status: "0x1", returnData: word(1), logs: [{ address: token, topics: [T_TRANSFER, topic(SIM_HOLDER), topic(to)], data: word(arrived) }] }
          : { status: "0x0", returnData: "0x", error: { message: "execution reverted: TRADING_BLOCKED" } }] },
      ] } };
    },
  };
}

const SIGNER = createSigner({ RECEIPT_SIGNER_SECRET: "test-secret-for-share-links-0123456789" });
const ORIGIN = "https://pg.test";

// The routes as server.js mounts them, behind the real x402 paywall.
async function boot({ png } = {}) {
  let settled = 0;
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: BASE }], extensions: [], signers: {} }),
    verify: async (payload) => ({ isValid: true, payer: payload.payload.authorization.from }),
    settle: async (payload) => (settled++, { success: true, transaction: `0x${String(settled).padStart(64, "0")}`, network: BASE, payer: payload.payload.authorization.from }),
  };
  const resourceServer = new x402ResourceServer(facilitator).register(BASE, new ExactEvmScheme());
  const all = x402Routes(PAY_TO, BASE);
  const routes = { "GET /v1/token": all["GET /v1/token"], "POST /v1/token/verdict": all["POST /v1/token/verdict"] };
  const app = express();
  app.use(createShareRouter({ signer: SIGNER, publicUrl: ORIGIN, ...(png && { png }) }));
  app.use(validateTokenQuery);
  app.use(validateTokenVerdictBody);
  app.use(paymentMiddleware(routes, resourceServer));
  app.use(signPaidResponses(SIGNER, Object.keys(routes)));
  app.use(createTokenRouter());
  app.use(createTokenVerdictRouter({ signer: SIGNER, publicUrl: ORIGIN, sell: (request, verdict) => sellCheck(request, verdict, { simulator: fakeSimulator() }) }));
  const http = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  return { base: `http://127.0.0.1:${http.address().port}`, close: () => http.close(), settled: () => settled };
}

const post = (url, body, headers = {}) => fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
async function paidPost(url, body) {
  const challenge = JSON.parse(Buffer.from((await post(url, {})).headers.get("payment-required"), "base64").toString());
  const client = new x402Client().register(BASE, new ExactEvmClient(privateKeyToAccount(generatePrivateKey())));
  const payment = Buffer.from(JSON.stringify(await client.createPaymentPayload(challenge))).toString("base64");
  return post(url, body, { "payment-signature": payment });
}
const sharePath = (url) => new URL(url).pathname;

test("unpaid: the same 402 as GET /v1/token ($0.01 on Base); an invalid body is a 400 before the price", async () => {
  const s = await boot();
  try {
    const get = await fetch(`${s.base}/v1/token`);
    const probe = await post(`${s.base}/v1/token/verdict`, {});
    assert.equal(get.status, 402);
    assert.equal(probe.status, 402);
    const terms = (r) => JSON.parse(Buffer.from(r.headers.get("payment-required"), "base64").toString()).accepts.map((a) => [a.network, a.amount, a.payTo]);
    assert.deepEqual(terms(probe), terms(get));
    assert.equal((await post(`${s.base}/v1/token/verdict`, { tokenAddress: GOOD, chain: "base" })).status, 402, "a valid body without payment gets the price");
    for (const body of [{ tokenAddress: "nope" }, { tokenAddress: GOOD, chain: "dogechain" }, { chain: "base" }, { tokenAddress: 42 }, { tokenAddress: GOOD, requestKey: "x".repeat(129) }, "{not json", "[1]"]) {
      const r = await post(`${s.base}/v1/token/verdict`, body);
      assert.equal(r.status, 400, JSON.stringify(body));
      const answer = await r.json();
      assert.equal(answer.error, "invalid_request");
      assert.equal(answer.verdict, null);
    }
    assert.equal(s.settled(), 0);
  } finally { s.close(); }
});

test("paid: GET /v1/token's answer plus decision, take, sell check, share link and the echoed requestKey; settled once", async () => {
  const s = await boot();
  try {
    const body = { tokenAddress: GOOD.toUpperCase().replace("0X", "0x"), requestKey: "req-1" }; // chain defaults to base
    const r = await paidPost(`${s.base}/v1/token/verdict`, body);
    assert.equal(r.status, 200);
    const a = await r.json();
    assert.deepEqual([a.verdict, a.grade, a.decision], ["green", "SAFE", "buy"]);
    assert.equal(a.requestKey, "req-1");
    assert.equal(a.token.address, GOOD);
    assert.match(a.one_liner, /^SAFE: no red flags/);
    assert.equal(a.take, "No known red flags ($2.0M liquidity, 2.5 years old). Nothing found that should stop a buy, but this says nothing about where the price goes.");
    assert.equal(a.sell_check.can_sell, "yes");
    assert.equal(a.sell_check.simulated, true);
    assert.deepEqual(a.sell_check.checks.map((c) => [c.check, c.result, c.source]), [
      ["honeypot", "pass", "GoPlus"], ["sell_all", "pass", "GoPlus"], ["sell_tax", "pass", "GoPlus"], ["liquidity", "pass", "DexScreener"], ["simulated_sell", "pass", "simulation (public RPC)"],
    ]);
    assert.equal(a.sell_check.simulation.pool, POOL(GOOD));
    assert.equal(a.sell_check.simulation.sell_tax_pct, 0);
    assert.match(a.share.url, /^https:\/\/pg\.test\/v\/token\/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{87}$/);
    assert.equal(a.share.image_url, `${a.share.url}/card.svg`);
    assert.equal(a.share.png_url, `${a.share.url}/card.png`);
    // The receipt covers the whole answer and has the request id the share link names.
    const v = await verifyReceipt(a, { signers: SIGNER.signers, route: "POST /v1/token/verdict", input: body });
    assert.equal(v.valid, true);
    assert.equal(v.input_matches, true);
    const shared = await readShare(sharePath(a.share.url).split("/").pop(), SIGNER.signers);
    assert.equal(shared.payload.request_id, a.receipt.request_id);
    assert.equal(s.settled(), 1);
  } finally { s.close(); }
});

test("paid but a data source is down: 503, verdict null, requestKey echoed, nothing settled", async () => {
  const s = await boot();
  try {
    const r = await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: DOWN, chain: "base", requestKey: "k" });
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: "upstream_unavailable", message: "DexScreener HTTP 503", verdict: null, requestKey: "k" });
    assert.equal(s.settled(), 0);
  } finally { s.close(); }
});

test("grade to decision, and the take in plain words", async () => {
  assert.deepEqual(["SAFE", "CAUTION", "RISKY", "AVOID", undefined].map(decisionOf), ["buy", "small_only", "do_not_buy", "do_not_buy", null]);
  assert.equal(takeOf({ grade: null, reasons: [] }), null);
  const s = await boot();
  try {
    const answer = async (tokenAddress) => (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress })).json();
    const caution = await answer(UNVERIFIED);
    assert.deepEqual([caution.grade, caution.decision], ["CAUTION", "small_only"]);
    assert.equal(caution.take, "One warning: token unverified. If you buy, keep it to an amount you can afford to lose.");
    const risky = await answer(RISKY);
    assert.deepEqual([risky.grade, risky.decision], ["RISKY", "do_not_buy"]);
    assert.equal(risky.take, "2 warnings, including token unverified and $9k liquidity. Don't buy unless you know why each of these is fine.");
    assert.equal(risky.sell_check.can_sell, "limited");
    const honey = await answer(HONEY);
    assert.deepEqual([honey.grade, honey.decision], ["AVOID", "do_not_buy"]);
    assert.equal(honey.take, "Honeypot: can't be sold. Don't buy: you may not be able to sell it.");
    assert.equal(honey.sell_check.can_sell, "no");
    assert.equal(honey.sell_check.simulated, false, "a known honeypot is not simulated");
    assert.deepEqual(honey.sell_check.checks.find((c) => c.check === "honeypot"), { check: "honeypot", result: "fail", code: "TOKEN_HONEYPOT", source: "GoPlus" });
    assert.deepEqual(honey.sell_check.checks.find((c) => c.check === "sell_tax"), { check: "sell_tax", result: "warn", code: "TOKEN_HIGH_TAX", source: "GoPlus", value: 100 });
  } finally { s.close(); }
});

test("sell check: a simulated sell that reverts is a no; a measured 20% sell tax is limited; the grade stays the data's", async () => {
  const s = await boot();
  try {
    const stuck = await (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: STUCK })).json();
    assert.deepEqual([stuck.grade, stuck.decision, stuck.sell_check.can_sell, stuck.sell_check.simulated], ["SAFE", "buy", "no", true]);
    assert.equal(stuck.sell_check.simulation.ok, false);
    assert.match(stuck.sell_check.simulation.error, /TRADING_BLOCKED/);
    assert.match(stuck.take, /simulated sell transfer into its pool failed/);
    const taxed = await (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: TAXED })).json();
    assert.equal(taxed.sell_check.can_sell, "limited");
    assert.equal(taxed.sell_check.simulation.sell_tax_pct, 20);
    assert.deepEqual(taxed.sell_check.checks.at(-1), { check: "simulated_sell", result: "warn", value: 20, source: "simulation (public RPC)" });
    assert.match(taxed.take, /lost 20% on the way to the pool/);
  } finally { s.close(); }
});

test("sell check without a simulation: Solana from GoPlus; no RPC, or no pool, means simulated false and a reason", async () => {
  const bonk = { chain: "solana", address: BONK };
  const verdict = { verdict: "green", grade: "SAFE", reasons: [], market: { liquidityUsd: 2e6 }, sources: ["goplus", "dexscreener"] };
  const log = [];
  const sol = await sellCheck(bonk, verdict, { simulator: fakeSimulator(log) });
  assert.deepEqual(sol.checks.map((c) => [c.check, c.result, c.source]), [["transferable", "pass", "GoPlus"], ["freeze", "pass", "GoPlus"], ["liquidity", "pass", "DexScreener"]]);
  assert.deepEqual([sol.can_sell, sol.simulated, sol.simulation], ["yes", false, undefined]);
  assert.deepEqual(log, [], "Solana is never simulated");
  assert.match(sol.note, /^Not simulated/);

  const noRpc = await sellCheck({ chain: "base", address: GOOD }, verdict, { simulator: { enabled: true, send: async () => null } });
  assert.deepEqual([noRpc.can_sell, noRpc.simulated, noRpc.simulation.why], ["yes", false, "no RPC answered"]);
  assert.ok(!noRpc.checks.some((c) => c.check === "simulated_sell"), "never a simulation that did not run");

  const unknown = await sellCheck({ chain: "base", address: addr("7") }, { ...verdict, market: null }, { simulator: fakeSimulator() });
  assert.deepEqual([unknown.can_sell, unknown.simulated, unknown.simulation.why], ["unknown", false, "no pool with a contract address to sell into"]);
  assert.deepEqual(unknown.checks, [{ check: "honeypot", result: "unknown", source: "GoPlus" }], "missing data is unknown, never a no");

  assert.equal(poolOf([{ pairAddress: `0x${"1".repeat(64)}`, baseToken: { address: GOOD } }], GOOD), null, "a v4 pool id is not a pool address");
});

test("body: ax1-style fields, chain defaults to base, every GET /v1/token form", () => {
  assert.deepEqual(parseVerdictBody({ tokenAddress: GOOD }), { chain: "base", address: GOOD });
  assert.deepEqual(parseVerdictBody({ tokenAddress: BONK, chain: "Solana", requestKey: "abc" }), { chain: "solana", address: BONK, requestKey: "abc" });
  assert.deepEqual(parseVerdictBody({ tokenAddress: "31566704", chain: "algorand" }), { chain: "algorand", address: "31566704" });
  assert.equal(parseVerdictBody({ tokenAddress: "RLUSD.rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De", chain: "xrpl" }).issuer, "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De");
  assert.throws(() => parseVerdictBody({ tokenAddress: BONK }), /0x-prefixed/);
});

test("share link: page and card render from a signed link; a changed link, another signer or an oversized link is a 400", async () => {
  const s = await boot();
  try {
    const a = await (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: GOOD })).json();
    const path = sharePath(a.share.url);
    const page = await fetch(`${s.base}${path}`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-type"), /text\/html/);
    assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
    const html = await page.text();
    assert.doesNotMatch(html, /<script/i);
    for (const s of ["Good Token (GOOD)", "SAFE", "No red flags found", a.take.replace(/'/g, "&#39;"), "$2.0M", SIGNER.address, a.receipt.request_id, `<meta property="og:image" content="${a.share.png_url}">`, `<meta name="twitter:image" content="${a.share.png_url}">`, "summary_large_image", "not financial advice"]) {
      assert.ok(html.includes(s), s);
    }
    const card = await fetch(`${s.base}${path}/card.svg`);
    assert.equal(card.status, 200);
    assert.match(card.headers.get("content-type"), /image\/svg\+xml/);
    const svg = await card.text();
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="1200" height="630"/);
    assert.ok(svg.includes("Good Token (GOOD)") && svg.includes("SAFE"));

    const token = path.split("/").pop();
    const [payload, sig] = token.split(".");
    const json = JSON.parse(Buffer.from(payload, "base64url").toString());
    const tampered = Buffer.from(canonicalJson({ ...json, grade: "AVOID" })).toString("base64url");
    const flippedSig = sig.slice(0, 10) + (sig[10] === "A" ? "B" : "A") + sig.slice(11);
    const stranger = createSigner({ RECEIPT_SIGNER_SECRET: "another-secret-that-is-not-presign-guard-0000" });
    const foreign = await signShare(stranger, json);
    for (const bad of [`${tampered}.${sig}`, `${payload}.${flippedSig}`, foreign, `${payload}x.${sig}`, "nope", "a".repeat(MAX_SHARE_CHARS + 1)]) {
      for (const suffix of ["", "/card.svg", "/card.png"]) {
        const r = await fetch(`${s.base}/v/token/${bad}${suffix}`);
        assert.equal(r.status, 400, `${bad.slice(0, 20)}${suffix}`);
        assert.match(r.headers.get("content-type"), /text\/plain/);
        assert.doesNotMatch(await r.text(), /<html|<svg|PNG/);
      }
    }
    // Not canonical (the same content with a space) doesn't render either, even with a valid signature over it.
    const spaced = JSON.stringify(json, null, 1);
    const sigOverSpaced = Buffer.from((await SIGNER.signText(SHARE_PREFIX + spaced)).slice(2), "hex").toString("base64url");
    assert.equal((await fetch(`${s.base}/v/token/${Buffer.from(spaced).toString("base64url")}.${sigOverSpaced}`)).status, 400);
  } finally { s.close(); }
});

test("share link: a hostile token name and symbol are escaped in the page, the meta tags and the card", async () => {
  const s = await boot();
  try {
    const a = await (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: HOSTILE })).json();
    assert.equal(a.token.name, "<script>alert(1)</script>");
    const path = sharePath(a.share.url);
    const html = await (await fetch(`${s.base}${path}`)).text();
    const svg = await (await fetch(`${s.base}${path}/card.svg`)).text();
    for (const out of [html, svg]) {
      assert.doesNotMatch(out, /<script/i);
      assert.doesNotMatch(out, /"onload=/);
      assert.ok(out.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
    assert.ok(html.includes("&quot;onload=alert(1)"));
    assert.ok(svg.includes("(&quot;"), "the card cuts the long label, escaped all the same");
    assert.ok(html.includes('<meta property="og:title" content="&lt;script&gt;alert(1)&lt;/script&gt; (&quot;onload=alert(1)): SAFE'));
  } finally { s.close(); }
});

test("share payload: compact, capped, and the rendering helpers stay inside the card", async () => {
  const answer = {
    verdict: "orange", grade: "CAUTION", decision: "small_only", take: "x ".repeat(400), checkedAt: "2026-11-17T10:00:00.000Z",
    reasons: [{ code: "MUTABLE_METADATA", severity: "info" }, { code: "LOW_LIQUIDITY", severity: "orange" }],
    token: { chain: "base", address: GOOD, name: "N".repeat(100), symbol: null }, market: { priceUsd: 1, liquidityUsd: 1000, marketCapUsd: null, volume24hUsd: 5, ageSeconds: null },
    sell_check: { can_sell: "limited", simulated: false },
  };
  const p = sharePayload(answer, "3f1c2a4e-1111-4222-8333-944455556666");
  assert.deepEqual(p.reasons, ["LOW_LIQUIDITY"], "the warnings, not the context");
  assert.equal(p.name.length, 48);
  assert.equal(p.symbol, undefined);
  assert.ok(p.take.length <= 320);
  assert.deepEqual(p.market, { price: 1, liquidity: 1000, vol24h: 5 });
  assert.equal(p.simulated, undefined);
  const token = await signShare(SIGNER, p);
  assert.ok(token.length < MAX_SHARE_CHARS);
  assert.equal((await readShare(token, SIGNER.signers)).signer, SIGNER.address);
  assert.ok(wrap("a ".repeat(500), 58, 4).every((l) => l.length <= 58));
  assert.equal(wrap("a ".repeat(500), 58, 4).length, 4);
  assert.ok(shareCard(p).includes("Small amount only"));
  assert.ok(sharePage(p, { url: `${ORIGIN}/v/token/${token}`, imageUrl: `${ORIGIN}/v/token/${token}/card.svg`, signer: SIGNER.address, signature: "0x", origin: ORIGIN }).includes("can be sold, with limits"));
});

// The width and height of a PNG, from its IHDR chunk (right after the 8-byte signature).
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const pngSize = (b) => (b.subarray(12, 16).toString("latin1") === "IHDR" ? [b.readUInt32BE(16), b.readUInt32BE(20)] : null);

test("PNG card: the same verified link rendered by resvg to a 1200x630 PNG, cached headers as the SVG; a changed link is a 400", async () => {
  const s = await boot();
  try {
    const a = await (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: HOSTILE })).json();
    const path = sharePath(a.share.png_url);
    const r = await fetch(`${s.base}${path}`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "image/png");
    const svg = await fetch(`${s.base}${sharePath(a.share.image_url)}`);
    for (const h of ["cache-control", "content-security-policy"]) assert.equal(r.headers.get(h), svg.headers.get(h), h);
    const png = Buffer.from(await r.arrayBuffer());
    assert.ok(png.subarray(0, 8).equals(PNG_SIGNATURE), "starts with the PNG signature");
    assert.deepEqual(pngSize(png), [1200, 630]);
    assert.ok(png.length > 10000 && png.length < 300000, `${png.length} bytes`);
    const again = Buffer.from(await (await fetch(`${s.base}${path}`)).arrayBuffer());
    assert.ok(again.equals(png), "the same bytes from the cache");

    const [payload, sig] = path.split("/")[3].split(".");
    const tampered = Buffer.from(canonicalJson({ ...JSON.parse(Buffer.from(payload, "base64url").toString()), grade: "AVOID", verdict: "red" })).toString("base64url");
    const bad = await fetch(`${s.base}/v/token/${tampered}.${sig}/card.png`);
    assert.equal(bad.status, 400);
    assert.equal(bad.headers.get("cache-control"), "no-store");
  } finally { s.close(); }
});

test("PNG card: a render that fails is a 500 that says nothing about why, and is logged", async () => {
  const s = await boot({ png: async () => { throw new Error("wasm exploded at /srv/secret/path"); } });
  const logged = [];
  const realError = console.error;
  console.error = (...args) => logged.push(args.join(" "));
  try {
    const a = await (await paidPost(`${s.base}/v1/token/verdict`, { tokenAddress: GOOD })).json();
    const r = await fetch(`${s.base}${sharePath(a.share.png_url)}`);
    assert.equal(r.status, 500);
    assert.equal(r.headers.get("cache-control"), "no-store");
    const body = await r.text();
    assert.doesNotMatch(body, /wasm|secret|exploded/);
    assert.ok(logged.some((l) => l.includes("PNG card failed") && l.includes("wasm exploded")));
  } finally { console.error = realError; s.close(); }
});

test("PNG cache: least recently used out first, a hit doesn't render again", async () => {
  const lru = createLru(2);
  lru.set("a", 1); lru.set("b", 2); lru.get("a"); lru.set("c", 3);
  assert.deepEqual([lru.get("a"), lru.get("b"), lru.get("c"), lru.size], [1, undefined, 3, 2]);
  let renders = 0;
  const cards = createPngCards({ render: async (svg) => (renders++, Buffer.from(svg)), max: 2 });
  for (const key of ["x", "x", "y", "x", "z", "y"]) await cards(key, `<svg>${key}</svg>`);
  assert.equal(renders, 4, "x once, y twice (pushed out by z), z once");
});

test("usage log: the POST is logged with its decision and sell check, never the requestKey; share views by kind", () => {
  const req = { method: "POST", path: "/v1/token/verdict", body: { tokenAddress: GOOD, requestKey: "secret-ish" }, get: () => undefined };
  const d = describePresignCall(req, { statusCode: 200 }, { verdict: "green", grade: "SAFE", decision: "buy", reasons: [], sell_check: { can_sell: "yes", simulated: true } });
  assert.deepEqual(d, { route: "token_verdict", via: "api", input: { chain: "base", target: GOOD }, result: { verdict: "green", grade: "SAFE", decision: "buy", canSell: "yes", simulated: true, reasons: undefined, error: undefined } });
  assert.doesNotMatch(JSON.stringify(d), /secret-ish/);
  assert.deepEqual(describePresignCall({ method: "GET", path: "/v/token/abc.def/card.svg" }, { statusCode: 200 }, null), { route: "token_share", via: "web", input: { kind: "card" }, result: { status: 200 } });
  assert.deepEqual(describePresignCall({ method: "GET", path: "/v/token/abc.def/card.png" }, { statusCode: 200 }, null).input, { kind: "card_png" });
});
