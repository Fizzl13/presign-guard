// src/payment-retry.js: x402's payment-identifier, end to end through @x402/express with a signed Base payment.
import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactEvmScheme as ExactEvmClient } from "@x402/evm/exact/client";
import { x402Client } from "@x402/core/client";
import { appendPaymentIdentifierToExtensions } from "@x402/extensions/payment-identifier";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { createPaymentRetry, paymentIdentifierExtension } from "../src/payment-retry.js";

const BASE = "eip155:8453";
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";

async function boot({ settleOk = () => true } = {}) {
  let settled = 0, served = 0;
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: BASE }], extensions: [], signers: {} }),
    verify: async (payload) => ({ isValid: true, payer: payload.payload.authorization.from }),
    settle: async (payload) => (settleOk() ? (settled++, { success: true, transaction: `0x${String(settled).padStart(64, "0")}`, network: BASE, payer: payload.payload.authorization.from }) : { success: false, errorReason: "insufficient_funds", transaction: "", network: BASE }),
  };
  const server = new x402ResourceServer(facilitator).register(BASE, new ExactEvmScheme());
  const retry = createPaymentRetry();
  const app = express();
  app.use(retry.middleware);
  app.use(paymentMiddleware({ "GET /signal/:pair": { accepts: [{ scheme: "exact", price: "$0.01", network: BASE, payTo: PAY_TO }], description: "test", mimeType: "application/json", extensions: { ...paymentIdentifierExtension } } }, server));
  app.get("/signal/:pair", (req, res) => { served++; res.json({ pair: req.params.pair, n: served }); });
  const http = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  return { base: `http://127.0.0.1:${http.address().port}`, close: () => http.close(), counts: () => ({ settled, served }), retry };
}

// A signed payment for the 402 at url, with the given payment id (or none).
async function pay(url, account, id) {
  const challenge = JSON.parse(Buffer.from((await fetch(url)).headers.get("payment-required"), "base64").toString());
  const client = new x402Client().register(BASE, new ExactEvmClient(account));
  const payload = await client.createPaymentPayload(challenge);
  if (id) appendPaymentIdentifierToExtensions(payload.extensions, id);
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}
const get = (url, header) => fetch(url, { headers: { "payment-signature": header } });

test("the 402 declares payment-identifier (optional)", async () => {
  const s = await boot();
  try {
    const challenge = JSON.parse(Buffer.from((await fetch(`${s.base}/signal/BTC-USDT`)).headers.get("payment-required"), "base64").toString());
    assert.deepEqual(challenge.extensions["payment-identifier"].info, { required: false });
  } finally { s.close(); }
});

test("a retry with the same id gets the stored answer and is not settled again; a new id is a new purchase", async () => {
  const s = await boot();
  try {
    const url = `${s.base}/signal/BTC-USDT`;
    const buyer = privateKeyToAccount(generatePrivateKey());
    const first = await get(url, await pay(url, buyer, "pay_0123456789abcdef"));
    assert.equal(first.status, 200);
    const receipt = first.headers.get("payment-response");
    assert.ok(receipt);
    assert.deepEqual(await first.json(), { pair: "BTC-USDT", n: 1 });
    // The answer got lost; the buyer signs again (a new authorization) with the same id.
    const again = await get(url, await pay(url, buyer, "pay_0123456789abcdef"));
    assert.equal(again.status, 200);
    assert.deepEqual(await again.json(), { pair: "BTC-USDT", n: 1 }, "the stored answer");
    assert.equal(again.headers.get("payment-response"), receipt, "with the first settlement's receipt");
    assert.deepEqual(s.counts(), { settled: 1, served: 1 }, "not settled, not served again");
    const other = await get(url, await pay(url, buyer, "pay_fedcba9876543210"));
    assert.deepEqual(await other.json(), { pair: "BTC-USDT", n: 2 });
    const noId = await get(url, await pay(url, buyer));
    assert.deepEqual(await noId.json(), { pair: "BTC-USDT", n: 3 }, "no id: an ordinary purchase");
    assert.deepEqual(s.counts(), { settled: 3, served: 3 });
  } finally { s.close(); }
});

test("the same id from another payer, or for another input, is not answered from the store", async () => {
  const s = await boot();
  try {
    const url = `${s.base}/signal/BTC-USDT`;
    const id = "pay_0123456789abcdef";
    await (await get(url, await pay(url, privateKeyToAccount(generatePrivateKey()), id))).json();
    const stranger = await get(url, await pay(url, privateKeyToAccount(generatePrivateKey()), id));
    assert.deepEqual(await stranger.json(), { pair: "BTC-USDT", n: 2 });
    const eth = `${s.base}/signal/ETH-USDT`;
    const otherPair = await get(eth, await pay(eth, privateKeyToAccount(generatePrivateKey()), id));
    assert.deepEqual(await otherPair.json(), { pair: "ETH-USDT", n: 3 });
    assert.equal(s.counts().settled, 3);
  } finally { s.close(); }
});

test("an answer whose settlement failed is not kept: the retry is a new attempt", async () => {
  let ok = false;
  const s = await boot({ settleOk: () => ok });
  try {
    const url = `${s.base}/signal/BTC-USDT`;
    const buyer = privateKeyToAccount(generatePrivateKey());
    const failed = await get(url, await pay(url, buyer, "pay_0123456789abcdef"));
    assert.equal(failed.status, 402);
    assert.equal(s.retry.size(), 0);
    ok = true;
    const retried = await get(url, await pay(url, buyer, "pay_0123456789abcdef"));
    assert.equal(retried.status, 200);
    assert.equal(s.counts().settled, 1);
  } finally { s.close(); }
});
