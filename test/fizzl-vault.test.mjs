// Fizzl Pass phase 3 (src/fizzl-vault.js, the same as x402-doctor's lib/fizzl-vault.js): part of a paid check comes back
// as credit in the pass's vault, and a check with the pass proof and no payment is paid from the vault.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import express from "express";
import { createClient } from "redis";
import { createPassVerifier } from "../src/fizzl-pass.js";
import { createVault, memoryVault, redisVault, paidOf, VAULT_SHARE } from "../src/fizzl-vault.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const AGENT = "0x2222222222222222222222222222222222222222";
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const jwks = { keys: [{ kty: "OKP", crv: "Ed25519", kid: "testkid", x: publicKey.export({ format: "jwk" }).x }] };
function proof(claims) {
  const body = `fzp1.${Buffer.from(JSON.stringify({ kid: "testkid", iss: "wallet.fizzl.eu", tier: "bronze", until: Date.now() + 86400000, ...claims })).toString("base64url")}`;
  return `${body}.${crypto.sign(null, Buffer.from(body), privateKey).toString("base64url")}`;
}
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64");

// A tiny app like server.js: credit back, the vault before a fake paywall that settles, then the check.
async function app(store, { fetchImpl } = {}) {
  const vault = createVault({ store, pass: createPassVerifier({ keys: jwks }), fetchImpl: fetchImpl ?? (async () => ({ ok: true, json: async () => ({ pass: null }) })) });
  const a = express();
  a.use(vault.creditBack());
  a.get("/v1/vault", vault.balanceHandler());
  a.use(vault.payFromVault((req) => (req.method === "POST" && req.path === "/v1/check" ? 0.01 : null)));
  a.use((req, res, next) => {
    if (req.fizzlCredits) return next();
    const sig = req.headers["payment-signature"];
    if (!sig) return res.status(402).json({ error: "payment required" });
    res.set("PAYMENT-RESPONSE", b64({ success: true, payer: JSON.parse(Buffer.from(sig, "base64")).from, transaction: "0x1" }));
    next();
  });
  a.post("/v1/check", express.json(), (req, res) => (req.body?.bad ? res.status(400).json({ error: "bad" }) : res.json({ verdict: "green" })));
  const server = a.listen(0, "127.0.0.1");
  await new Promise((ok) => server.once("listening", ok));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}
const post = (base, headers, body = {}) => fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const settle = () => new Promise((ok) => setTimeout(ok, 30));

test("a pass wallet pays a check, gets 10% back; the vault then pays a check; a failed one gives it back", async () => {
  const store = memoryVault();
  const { base, close } = await app(store);
  try {
    const pass = proof({ wallets: [OWNER, AGENT] });
    const empty = await post(base, { "x-fizzl-pass": pass });
    assert.equal(empty.status, 402);
    assert.equal(empty.headers.get("x-fizzl-vault"), "insufficient");
    // Ten paid checks of $0.01 by the agent's wallet, with the proof: $0.01 back.
    const payment = b64({ accepted: { network: "eip155:8453", amount: "10000" }, from: AGENT });
    for (let i = 0; i < 10; i++) assert.equal((await post(base, { "x-fizzl-pass": pass, "payment-signature": payment })).status, 200);
    await settle();
    assert.equal(await store.balance([AGENT]), 10000);
    const paid = await post(base, { "x-fizzl-pass": pass });
    assert.equal(paid.status, 200);
    assert.equal(paid.headers.get("x-fizzl-vault"), "paid");
    await settle();
    assert.equal(await store.balance([OWNER, AGENT]), 0, "nothing back on a call paid from the vault");
    await store.credit(OWNER, 10000, 100);
    assert.equal((await post(base, { "x-fizzl-pass": pass }, { bad: true })).status, 400);
    await settle();
    assert.equal(await store.balance([OWNER, AGENT]), 10000);
    const bal = await (await fetch(`${base}/v1/vault`, { headers: { "x-fizzl-pass": pass } })).json();
    assert.equal(bal.balance_usd, 0.01);
    assert.equal(bal.wallets, 2);
  } finally { close(); }
});

test("without the proof, the Agent Wallet's pass check decides; no pass, no credit", async () => {
  const store = memoryVault();
  const fetchImpl = async (url) => ({ ok: true, json: async () => ({ pass: new URL(url).searchParams.get("wallet") === AGENT ? { tier: "silver", until: Date.now() + 1e6 } : null }) });
  const { base, close } = await app(store, { fetchImpl });
  try {
    assert.equal((await post(base, { "payment-signature": b64({ accepted: { network: "eip155:8453", amount: "10000" }, from: AGENT }) })).status, 200);
    assert.equal((await post(base, { "payment-signature": b64({ accepted: { network: "eip155:8453", amount: "10000" }, from: OWNER }) })).status, 200);
    await settle();
    assert.equal(await store.balance([AGENT]), 10000 * VAULT_SHARE.silver);
    assert.equal(await store.balance([OWNER]), 0);
  } finally { close(); }
});

test("paidOf: only a settled, successful call counts", () => {
  const req = { headers: { "x-payment": b64({ accepted: { network: "eip155:8453", amount: "30000" } }) } };
  const res = (h, statusCode = 200) => ({ statusCode, locals: {}, getHeader: (n) => (n === "X-PAYMENT-RESPONSE" ? h : undefined) });
  assert.deepEqual(paidOf(req, res(b64({ success: true, payer: OWNER }))), { payer: OWNER, usd: 0.03 });
  assert.equal(paidOf(req, res(b64({ success: false, payer: OWNER }))), null);
  assert.equal(paidOf(req, res(b64({ success: true, payer: OWNER }), 502)), null);
});

const hasRedis = spawnSync("redis-server", ["--version"]).status === 0;
test("the vault shares the credits store's Redis connection (atomic take over the pass wallets)", { skip: !hasRedis && "redis-server not installed" }, async () => {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const proc = spawn("redis-server", ["--port", String(port), "--save", "", "--appendonly", "no"], { stdio: "ignore" });
  try {
    await new Promise((ok) => setTimeout(ok, 400));
    const client = createClient({ url: `redis://127.0.0.1:${port}` });
    await client.connect();
    const v = redisVault(null, { client });
    assert.equal(v.ready, true);
    await v.credit(OWNER, 300, 100);
    await v.credit(AGENT, 500, 0);
    assert.equal(await client.ttl(`fizzl-vault:${AGENT}`), -1, "Gold credit does not end");
    assert.ok((await client.ttl(`fizzl-vault:${OWNER}`)) > 0);
    const both = await Promise.all([v.take([OWNER, AGENT], 600), v.take([OWNER, AGENT], 600)]);
    assert.deepEqual(both.map((x) => x.ok).sort(), [false, true]);
    assert.equal(await v.balance([OWNER, AGENT]), 200);
    await client.quit();
    assert.equal(v.ready, false);
  } finally { proc.kill(); }
});
