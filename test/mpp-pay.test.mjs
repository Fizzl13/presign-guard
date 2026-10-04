// MPP payment (src/mpp-pay.cjs, same module as x402 Doctor) on a POST route like /v1/check.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createRequire } from "node:module";
import express from "express";
import { keccak256, stringToHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const require = createRequire(import.meta.url);
const { createMppPay, unlessMppPaid } = require("../src/mpp-pay.cjs");
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const agent = privateKeyToAccount(generatePrivateKey());

async function serve({ status = 200 } = {}) {
  const calls = { verify: 0, settle: 0 };
  const facilitator = {
    async verify() { calls.verify++; return { isValid: true }; },
    async settle() { calls.settle++; return { success: true, transaction: "0xabc" }; },
  };
  const mpp = createMppPay({ secret: "s", realm: "presign.test", recipient: PAY_TO, routes: { "POST /v1/check": "$0.005" }, facilitator, log: { warn() {} } });
  const app = express();
  app.use(express.json());
  app.use(mpp.middleware);
  app.use(unlessMppPaid((req, res, next) => (req.path === "/v1/check" ? res.status(402).json({}) : next())));
  app.post("/v1/check", (req, res) => res.status(status).json({ verdict: "green", got: req.body }));
  const server = await new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
  return { base: `http://127.0.0.1:${server.address().port}`, calls, close: () => server.close() };
}

function challengeOf(res) {
  const h = res.headers.get("www-authenticate");
  const p = (n) => new RegExp(`${n}="([^"]*)"`).exec(h)[1];
  const c = { id: p("id"), realm: p("realm"), method: p("method"), intent: p("intent"), request: p("request"), expires: p("expires"), opaque: p("opaque") };
  return { c, request: JSON.parse(Buffer.from(c.request, "base64url").toString()) };
}

async function credential({ c, request }, { value = request.amount } = {}) {
  const nonce = keccak256(stringToHex(JSON.stringify([c.id, c.realm])));
  const validBefore = String(Math.floor(Date.parse(c.expires) / 1000));
  const signature = await agent.signTypedData({
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: request.currency },
    types: { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
    primaryType: "TransferWithAuthorization",
    message: { from: agent.address, to: request.recipient, value: BigInt(value), validAfter: 0n, validBefore: BigInt(validBefore), nonce },
  });
  const wire = { challenge: c, payload: { type: "authorization", from: agent.address, to: request.recipient, value, validAfter: "0", validBefore, nonce, signature } };
  return `Payment ${Buffer.from(JSON.stringify(wire)).toString("base64url")}`;
}

const post = (base, headers = {}) => fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ to: "0x1" }) });

test("POST /v1/check: 402 with an MPP evm challenge; a signed credential is served and settled once", async (t) => {
  const s = await serve(); t.after(s.close);
  const unpaid = await post(s.base);
  assert.equal(unpaid.status, 402);
  const ch = challengeOf(unpaid);
  assert.equal(ch.c.method, "evm");
  assert.equal(ch.request.amount, "5000");
  const res = await post(s.base, { authorization: await credential(ch) });
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).got, { to: "0x1" });
  assert.equal(s.calls.settle, 1);
  assert.equal(JSON.parse(Buffer.from(res.headers.get("payment-receipt"), "base64url").toString()).reference, "0xabc");
});

test("a wrong amount is refused before the facilitator; a failed answer is never settled", async (t) => {
  const s = await serve({ status: 500 }); t.after(s.close);
  const ch = challengeOf(await post(s.base));
  let res = await post(s.base, { authorization: await credential(ch, { value: "1" }) });
  assert.equal(res.status, 402);
  assert.equal(s.calls.verify, 0);
  res = await post(s.base, { authorization: await credential(ch) });
  assert.equal(res.status, 500);
  assert.equal(s.calls.settle, 0);
});
