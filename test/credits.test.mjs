import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import express from "express";
import { creditCosts, creditsRouter, describeRedisUrl, normalizeRedisUrl, hashKey, isKey, memoryStore, newKey, packRoutes, payWithCredits, redisStore, CREDIT_HEADER, PACKS } from "../src/credits.js";
import { x402Routes } from "../src/presign-guard.js";

const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const COSTS = creditCosts(x402Routes(PAY_TO));

test("credit costs follow the x402 prices in cents", () => {
  assert.deepEqual(COSTS, { "POST /v1/check": 1, "POST /v1/check/explain": 3, "GET /v1/token": 1, "GET /v1/approvals": 2 });
});

test("pack routes: 100 for $0.80 and 1000 for $7.00, on Base and Solana", () => {
  const routes = packRoutes("eip155:8453", PAY_TO, { network: "solana:x", payTo: "So1ana" });
  assert.deepEqual(Object.keys(routes), ["GET /v1/credits/100", "GET /v1/credits/1000"]);
  assert.equal(routes["GET /v1/credits/100"].accepts[0].price, "$0.80");
  assert.equal(routes["GET /v1/credits/1000"].accepts[1].price, "$7.00");
  assert.equal(routes["GET /v1/credits/1000"].accepts[1].network, "solana:x");
  assert.equal(PACKS["1000"].credits, 1000);
});

test("keys: random, well-formed, stored only as a hash", () => {
  const a = newKey(), b = newKey();
  assert.ok(isKey(a) && isKey(b) && a !== b);
  assert.ok(!isKey("pgc_short") && !isKey(undefined));
  assert.match(hashKey(a), /^[0-9a-f]{64}$/);
});

// A tiny app like server.js: credits before a fake paywall, then the routes.
function app(store) {
  const a = express();
  a.use(express.json());
  a.use(payWithCredits({ store, costs: COSTS }));
  a.use((req, res, next) => (req.fizzlCredits || !COSTS[`${req.method} ${req.path}`] ? next() : res.status(402).json({ error: "payment required" })));
  a.post("/v1/check", (req, res) => (req.body.bad ? res.status(400).json({ error: "invalid_request" }) : res.json({ verdict: "green" })));
  a.get("/v1/approvals", (_req, res) => res.json({ verdict: "green" }));
  a.use(creditsRouter(express, { store, costs: COSTS, publicUrl: "https://pg.test" }));
  return a;
}

async function withServer(store, fn) {
  const server = app(store).listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { server.close(); }
}

async function flow(store) {
  await withServer(store, async (base) => {
    // Buying (the paywall in front is skipped here) returns a key and the pack size.
    const bought = await (await fetch(`${base}/v1/credits/100`)).json();
    assert.equal(bought.credits, 100);
    assert.ok(isKey(bought.credit_key));
    const H = { [CREDIT_HEADER]: bought.credit_key, "content-type": "application/json" };

    let r = await fetch(`${base}/v1/check`, { method: "POST", headers: H, body: "{}" });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-credit-status"), "paid");
    assert.equal(r.headers.get("x-credits-remaining"), "99");

    r = await fetch(`${base}/v1/approvals?chain=base&address=0x1`, { headers: H });
    assert.equal(r.headers.get("x-credits-remaining"), "97");

    // A failed call gives its credits back.
    r = await fetch(`${base}/v1/check`, { method: "POST", headers: H, body: JSON.stringify({ bad: true }) });
    assert.equal(r.status, 400);
    await new Promise((ok) => setTimeout(ok, 50));
    let bal = await (await fetch(`${base}/v1/credits`, { headers: H })).json();
    assert.equal(bal.credits, 97);
    assert.ok(bal.expires_at);

    // No key, a malformed key or an unknown key: the normal 402.
    r = await fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(r.status, 402);
    r = await fetch(`${base}/v1/check`, { method: "POST", headers: { ...H, [CREDIT_HEADER]: "nope" }, body: "{}" });
    assert.equal(r.status, 402);
    assert.equal(r.headers.get("x-credit-status"), "invalid");
    r = await fetch(`${base}/v1/check`, { method: "POST", headers: { ...H, [CREDIT_HEADER]: newKey() }, body: "{}" });
    assert.equal(r.headers.get("x-credit-status"), "unknown");

    // Free info without a key; 404 for an unknown key.
    const info = await (await fetch(`${base}/v1/credits`)).json();
    assert.equal(info.packs["1000"].price_usd, "7.00");
    assert.equal((await fetch(`${base}/v1/credits`, { headers: { [CREDIT_HEADER]: newKey() } })).status, 404);
  });
}

test("credits flow with the memory store", () => flow(memoryStore()));

test("too few credits: 402 and the balance stays", async () => {
  const store = memoryStore();
  const key = newKey();
  await store.issue(hashKey(key), 2, 365);
  await withServer(store, async (base) => {
    const H = { [CREDIT_HEADER]: key, "content-type": "application/json" };
    const r = await fetch(`${base}/v1/approvals?chain=base&address=0x1`, { headers: H });
    assert.equal(r.status, 200);
    const r2 = await fetch(`${base}/v1/check`, { method: "POST", headers: H, body: "{}" });
    assert.equal(r2.status, 402);
    assert.equal(r2.headers.get("x-credit-status"), "insufficient");
    assert.equal(r2.headers.get("x-credits-remaining"), "0");
  });
});

test("expired credits are gone", async () => {
  let t = 0;
  const store = memoryStore({ now: () => t });
  await store.issue("h", 10, 1);
  t = 86400_000 + 1;
  assert.equal(await store.balance("h"), null);
});

const hasRedis = spawnSync("redis-server", ["--version"]).status === 0;
test("credits flow against a real Redis", { skip: !hasRedis && "redis-server not installed" }, async () => {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const proc = spawn("redis-server", ["--port", String(port), "--save", "", "--appendonly", "no"], { stdio: "ignore" });
  try {
    await new Promise((ok) => setTimeout(ok, 400));
    const store = await redisStore(`redis://127.0.0.1:${port}`);
    await flow(store);
    // Atomic: two parallel takes of 1 on a balance of 1, only one succeeds.
    await store.issue("race", 1, 1);
    const both = await Promise.all([store.take("race", 1), store.take("race", 1)]);
    assert.deepEqual(both.map((x) => x.ok).sort(), [false, true]);
    await store.close?.();
  } finally { proc.kill(); }
});

test("redis URL: forgiving about what gets pasted, never logs the password", () => {
  const good = "rediss://default:abc123@exact-chipmunk-1.upstash.io:6379";
  assert.equal(normalizeRedisUrl(good), good);
  assert.equal(normalizeRedisUrl(` "${good}" \n`), good);
  assert.equal(normalizeRedisUrl(`redis-cli --tls -u redis://default:abc123@exact-chipmunk-1.upstash.io:6379`), good);
  assert.equal(normalizeRedisUrl(`new Redis("${good}")`), good);
  assert.equal(normalizeRedisUrl("redis://127.0.0.1:6399"), "redis://127.0.0.1:6399");
  assert.equal(normalizeRedisUrl("https://exact-chipmunk-1.upstash.io"), null);
  assert.equal(normalizeRedisUrl("gQAAAAtoken"), null);
  assert.equal(describeRedisUrl(good), "rediss://exact-chipmunk-1.upstash.io:6379 (with password)");
  assert.doesNotMatch(describeRedisUrl(good), /abc123/);
});

test("redis store gives up quickly when it cannot connect", async () => {
  const t = Date.now();
  await assert.rejects(redisStore("redis://127.0.0.1:1", { timeoutMs: 1500 }), /no connection|ECONNREFUSED/);
  assert.ok(Date.now() - t < 5000);
});
