// $AFUEL holder tiers (src/afuel-holders.js): a signed wallet that holds Bronze or more gets a few paid calls a day
// free, counted per wallet and capped for all holders together; everything else still reaches the paywall.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import express from "express";
import { b58decode, createHolders, tierFor, verifyWalletSignature } from "../src/afuel-holders.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (buf) => {
  let n = BigInt(`0x${Buffer.from(buf).toString("hex") || "0"}`);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of buf) { if (b !== 0) break; out = `1${out}`; }
  return out;
};
function wallet() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const address = b58(publicKey.export({ format: "der", type: "spki" }).subarray(-32));
  const sign = (ts = Math.floor(Date.now() / 1000)) => ({
    "x-wallet": address,
    "x-wallet-timestamp": String(ts),
    "x-wallet-signature": b58(crypto.sign(null, Buffer.from(`agent-coin-api:${ts}`), privateKey)),
  });
  return { address, sign };
}

const holdings = new Map();
let rpcCalls = 0;
const fetchImpl = async (_url, init) => {
  rpcCalls += 1;
  const { params } = JSON.parse(init.body);
  const whole = holdings.get(params[0]) ?? 0n;
  const value = whole ? [{ account: { data: { parsed: { info: { tokenAmount: { amount: String(whole * 10n ** 6n) } } } } } }] : [];
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { value } }), { headers: { "content-type": "application/json" } });
};

const servers = [];
test.after(() => servers.forEach((s) => s.close()));
// A tiny app like server.js: holders before a paywall that answers 402 unless the call is already paid for.
async function start(env = {}) {
  const holders = createHolders({ env: { AFUEL_PAYMENTS: "on", ...env }, fetchImpl });
  const app = express();
  app.get("/v1/afuel/holder", holders.statusHandler());
  app.use(holders.payWithHolding((req) => ({ "POST /v1/check": 0.01, "POST /v1/check/explain": 0.05 })[`${req.method} ${req.path}`] ?? null));
  app.use((req, res, next) => (req.fizzlCredits ? next() : res.status(402).json({ error: "payment required" })));
  app.post(["/v1/check", "/v1/check/explain"], (req, res) => res.json({ ok: true, via: req.fizzlCredits }));
  return new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${s.address().port}`));
    servers.push(s);
  });
}
const check = (base, headers, path = "/v1/check") => fetch(`${base}${path}`, { method: "POST", headers });

test("signature, base58 and tiers", () => {
  const w = wallet();
  const h = w.sign(1_700_000_000);
  assert.equal(b58decode(w.address).length, 32);
  assert.ok(verifyWalletSignature(h["x-wallet"], h["x-wallet-timestamp"], h["x-wallet-signature"], 1_700_000_100));
  assert.ok(!verifyWalletSignature(h["x-wallet"], h["x-wallet-timestamp"], h["x-wallet-signature"], 1_700_000_400));
  assert.ok(!verifyWalletSignature(wallet().address, h["x-wallet-timestamp"], h["x-wallet-signature"], 1_700_000_100));
  assert.equal(tierFor(99_999n * 10n ** 6n), null);
  assert.equal(tierFor(100_000n * 10n ** 6n).name, "bronze");
  assert.equal(tierFor(1_000_000n * 10n ** 6n).name, "gold");
});

test("Gold gets the check free; the dearer explain stays paid; below Bronze and forged signatures get the 402", async () => {
  const gold = wallet(); holdings.set(gold.address, 2_000_000n);
  const small = wallet(); holdings.set(small.address, 10n);
  const base = await start();
  const free = await check(base, gold.sign());
  assert.equal(free.status, 200);
  assert.deepEqual((await free.json()).via, { holder: "gold", wallet: gold.address, cost: 0 });
  assert.equal(free.headers.get("x-afuel-free-remaining"), "499");
  assert.equal((await check(base, gold.sign(), "/v1/check/explain")).status, 402);
  const below = await check(base, small.sign());
  assert.equal(below.status, 402);
  assert.equal(below.headers.get("x-afuel-holder"), "below_bronze");
  const forged = await check(base, { ...gold.sign(), "x-wallet-signature": small.sign()["x-wallet-signature"] });
  assert.equal(forged.headers.get("x-afuel-holder"), "invalid_signature");
  assert.equal((await check(base, {})).status, 402);
});

test("Bronze has 20 a day; all holders together stop at the daily cap; the balance is cached", async () => {
  const bronze = wallet(); holdings.set(bronze.address, 150_000n);
  const silver = wallet(); holdings.set(silver.address, 300_000n);
  const base = await start({ AFUEL_HOLDER_DAILY_CAP: "21" });
  const before = rpcCalls;
  for (let i = 0; i < 20; i++) assert.equal((await check(base, bronze.sign())).status, 200);
  assert.equal(rpcCalls - before, 1, "one balance read for 20 calls");
  assert.equal((await check(base, bronze.sign())).headers.get("x-afuel-holder"), "used_up");
  assert.equal((await check(base, silver.sign())).status, 200);
  assert.equal((await check(base, silver.sign())).headers.get("x-afuel-holder"), "daily_cap");
});

test("GET /v1/afuel/holder and the off switch", async () => {
  const w = wallet(); holdings.set(w.address, 260_000n);
  const base = await start();
  const info = await (await fetch(`${base}/v1/afuel/holder`)).json();
  assert.deepEqual(info.tiers.map((t) => t.free_calls_per_day), [500, 100, 20]);
  const mine = await (await fetch(`${base}/v1/afuel/holder`, { headers: w.sign() })).json();
  assert.equal(mine.tier, "silver");
  assert.equal(mine.free_calls_left_today, 100);
  for (const env of [{ AFUEL_PAYMENTS: "" }, { AFUEL_HOLDERS: "off" }]) {
    const off = await start(env);
    assert.equal((await check(off, w.sign())).status, 402);
  }
});
