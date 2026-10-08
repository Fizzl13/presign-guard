// MPP sessions (src/mpp-session.js): the session challenge rides along on every 402, a session credential is
// checked before the charge middleware and the x402 paywall, and channel state is kept in an atomic store.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createRequire } from "node:module";
import express from "express";
import { generatePrivateKey } from "viem/accounts";
import { createMppSession, credentialIntent, redisAtomic, sessionStore } from "../src/mpp-session.js";

const require = createRequire(import.meta.url);
const { createMppPay } = require("../src/mpp-pay.cjs");
const RECIPIENT = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const ROUTES = { "POST /v1/check": "$0.005" };
const quiet = { warn() {} };
const session = (over = {}) => createMppSession({ operatorKey: generatePrivateKey(), recipient: RECIPIENT, secret: "s", realm: "presign.test", publicUrl: "https://presign.test", routes: ROUTES, store: sessionStore(null), log: quiet, ...over });
const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

async function serve(...middleware) {
  const app = express();
  app.use(express.json());
  for (const m of middleware) app.use(m);
  let ran = 0;
  app.post("/v1/check", (req, res) => (req.mppPaid ? (ran++, res.json({ ok: true })) : res.status(402).json({ error: "pay" })));
  const server = await new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
  return { url: `http://127.0.0.1:${server.address().port}`, ran: () => ran, close: () => new Promise((r) => server.close(r)) };
}

test("off without an operator key, a recipient, a secret or a store", () => {
  for (const missing of ["operatorKey", "recipient", "secret", "store"]) assert.equal(session({ [missing]: undefined }), null, missing);
  assert.throws(() => session({ chainId: 1 }), /unknown Tempo chain/);
  const s = session();
  assert.match(s.operator, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(s.recipient, RECIPIENT);
  assert.equal(s.chainId, 4217);
});

test("credentialIntent reads the intent without verifying anything", () => {
  assert.equal(credentialIntent(`Payment ${encode({ challenge: { intent: "session" } })}`), "session");
  assert.equal(credentialIntent(`Payment ${encode({ challenge: { intent: "charge" } })}`), "charge");
  assert.equal(credentialIntent("Bearer abc"), null);
  assert.equal(credentialIntent("Payment !!!"), null);
  assert.equal(credentialIntent(undefined), null);
});

test("a 402 carries the session challenge next to the MPP charge one", async () => {
  const s = session();
  const charge = createMppPay({ secret: "s", realm: "presign.test", recipient: RECIPIENT, routes: ROUTES, facilitator: { verify() {}, settle() {} }, log: quiet });
  const srv = await serve(s.middleware, (req, res, next) => (req.mppPaid ? next() : charge.middleware(req, res, next)));
  try {
    const res = await fetch(`${srv.url}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(res.status, 402);
    const www = res.headers.get("www-authenticate");
    assert.match(www, /intent="charge"/);
    assert.match(www, /intent="session"/);
    assert.match(www, /method="tempo"/);
    // The session request names the payee (not the operator) and the price in USDC.e base units.
    const sessionPart = www.split(/,\s*(?=Payment )/).find((p) => /intent="session"/.test(p));
    const request = JSON.parse(Buffer.from(/request="([^"]+)"/.exec(sessionPart)[1], "base64url").toString("utf8"));
    assert.equal(request.recipient.toLowerCase(), RECIPIENT.toLowerCase());
    assert.equal(request.amount, "5000");
    assert.equal(request.suggestedDeposit, "1000000", "a $1 deposit, so a channel covers many calls");
    // Unpaid routes are left alone.
    const free = await fetch(`${srv.url}/healthz`);
    assert.equal(free.headers.get("www-authenticate"), null);
  } finally { await srv.close(); }
});

test("a session credential that doesn't check out is refused before the route runs", async () => {
  const srv = await serve(session().middleware);
  try {
    const bogus = encode({ challenge: { id: "x", realm: "presign.test", method: "tempo", intent: "session", request: "e30" }, payload: { action: "voucher", channelId: `0x${"ab".repeat(32)}`, cumulativeAmount: "5000", signature: "0x00" } });
    const res = await fetch(`${srv.url}/v1/check`, { method: "POST", headers: { "content-type": "application/json", authorization: `Payment ${bogus}` }, body: "{}" });
    assert.equal(res.status, 402);
    assert.equal(srv.ran(), 0);
  } finally { await srv.close(); }
});

test("sweep: nothing to settle without channels, finalized channels are dropped", async () => {
  const store = sessionStore(null);
  const s = session({ store });
  assert.deepEqual(await s.sweep(), []);
  const id = `0x${"cd".repeat(32)}`;
  await store.put("fizzl:channels", [id]);
  await store.put(id, { channelId: id, finalized: true, highestVoucher: null, highestVoucherAmount: 0n, settledOnChain: 0n });
  assert.deepEqual(await s.sweep(), []);
  assert.deepEqual(await store.get("fizzl:channels"), []);
});

test("redisAtomic: updates to one key run in order, replay markers expire", async () => {
  const data = new Map();
  const sets = [];
  const client = {
    async get(k) { await new Promise((r) => setTimeout(r, Math.random() * 5)); return data.get(k) ?? null; },
    async set(k, v, opts) { sets.push(opts ?? null); await new Promise((r) => setTimeout(r, Math.random() * 5)); data.set(k, v); },
    async del(k) { data.delete(k); },
  };
  const a = redisAtomic(client);
  const bump = () => a.update("n", (cur) => ({ op: "set", value: String(Number(cur ?? 0) + 1), result: Number(cur ?? 0) + 1 }));
  const results = await Promise.all(Array.from({ length: 20 }, bump));
  assert.deepEqual(results, Array.from({ length: 20 }, (_, i) => i + 1));
  assert.equal(data.get("n"), "20");
  assert.equal(await a.update("n", () => ({ op: "delete", result: "gone" })), "gone");
  assert.equal(data.has("n"), false);
  // A throwing update doesn't block the next one.
  await assert.rejects(a.update("n", () => { throw new Error("boom"); }));
  assert.equal(await bump(), 1);
  sets.length = 0;
  const expires = Date.now() + 60_000;
  await a.set("r", JSON.stringify({ type: "mppx:replay", expires }));
  await a.set("plain", JSON.stringify({ a: 1 }));
  assert.deepEqual(sets, [{ PXAT: expires }, null]);
});
