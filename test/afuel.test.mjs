// $AFUEL as an extra Solana payment option (src/afuel.js): in the 402 next to USDC on Solana, discounted, and left
// out (USDC unchanged) while there is no fresh AFUEL price.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { AFUEL_MINT, afuelAmount, createAfuel, curvePriceSol, usdOf } from "../src/afuel.js";

const BASE = "eip155:8453";
const SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const PAY_TO_SOLANA = "ATWJ82T8nRdQwZnaysB68N5EpaSvLRsQP4h6eWmaJBH9";
const USDC_SOLANA = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

const servers = [];
const listen = (handler) => new Promise((resolve) => {
  const s = http.createServer(handler).listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${s.address().port}`));
  servers.push(s);
});
after(() => servers.forEach((s) => s.close()));

test("afuelAmount converts a dollar price with the discount, in 6-decimal base units", () => {
  // $0.01 minus 25% = $0.0075; at $0.00002 per AFUEL that is 375 AFUEL.
  assert.equal(afuelAmount(0.01, 0.00002, 25), "375000000");
  assert.equal(afuelAmount(0.01, 0.00002, 0), "500000000");
  assert.equal(afuelAmount(0.000001, 1e9, 25), "1", "never zero");
  assert.equal(usdOf("$0.005"), 0.005);
  assert.equal(usdOf({ amount: "1", asset: "x" }), null);
});

test("curvePriceSol reads the virtual reserves and stops once the curve is complete", () => {
  const data = Buffer.alloc(49);
  data.writeBigUInt64LE(1_000_000_000n * 10n ** 6n, 8); // 1e9 tokens
  data.writeBigUInt64LE(30n * 10n ** 9n, 16); // 30 SOL
  assert.equal(curvePriceSol(data), 30 / 1e9);
  data.writeUInt8(1, 48);
  assert.equal(curvePriceSol(data), null);
});

test("withAfuel is a no-op unless AFUEL_PAYMENTS=on", () => {
  const routes = { "GET /x": { accepts: [{ scheme: "exact", price: "$0.01", network: SOLANA, payTo: PAY_TO_SOLANA }] } };
  assert.equal(createAfuel({ env: {} }).withAfuel(routes), routes);
});

async function paywalled(afuel, { pay = null } = {}) {
  const seen = [];
  const facilitatorUrl = await listen(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.method === "POST") {
      let body = "";
      for await (const c of req) body += c;
      seen.push({ path: req.url, body: JSON.parse(body) });
      if (req.url.endsWith("/verify")) return res.end(JSON.stringify({ isValid: true, payer: "Payer111111111111111111111111111111111111111" }));
      return res.end(JSON.stringify({ success: true, transaction: "5xTx", network: SOLANA, payer: "Payer111111111111111111111111111111111111111" }));
    }
    res.end(JSON.stringify({
      kinds: [{ x402Version: 2, scheme: "exact", network: BASE }, { x402Version: 2, scheme: "exact", network: SOLANA, extra: { feePayer: "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4" } }],
      extensions: [],
      signers: {},
    }));
  });
  const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient({ url: facilitatorUrl }))
    .register(BASE, new ExactEvmScheme())
    .register(SOLANA, new ExactSvmScheme());
  afuel.attach(resourceServer);
  const routes = afuel.withAfuel({
    "GET /paid": {
      accepts: [
        { scheme: "exact", price: "$0.01", network: BASE, payTo: PAY_TO },
        { scheme: "exact", price: "$0.01", network: SOLANA, payTo: PAY_TO_SOLANA },
      ],
      description: "test",
      mimeType: "application/json",
    },
  });
  const app = express();
  app.use(paymentMiddleware(routes, resourceServer));
  app.get("/paid", (_req, res) => res.json({ ok: true }));
  const base = await listen(app);
  const res = await fetch(`${base}/paid`);
  assert.equal(res.status, 402);
  const accepts = JSON.parse(Buffer.from(res.headers.get("payment-required"), "base64").toString("utf8")).accepts;
  if (!pay) return accepts;
  const accepted = pay(accepts);
  const paid = await fetch(`${base}/paid`, { headers: { "payment-signature": Buffer.from(JSON.stringify({ x402Version: 2, accepted, payload: { transaction: "AAAA" } })).toString("base64") } });
  return { status: paid.status, seen };
}

test("the 402 offers AFUEL on Solana next to USDC, discounted, to the same payout wallet", async () => {
  const afuel = createAfuel({ env: { AFUEL_PAYMENTS: "on" } });
  afuel.setPriceForTest(0.00002);
  const accepts = await paywalled(afuel);
  assert.equal(accepts.length, 3);
  const [, usdc, token] = accepts;
  assert.equal(usdc.asset, USDC_SOLANA);
  assert.equal(usdc.amount, "10000");
  assert.equal(token.network, SOLANA);
  assert.equal(token.asset, AFUEL_MINT);
  assert.equal(token.amount, "375000000");
  assert.equal(token.payTo, PAY_TO_SOLANA);
  assert.equal(token.extra.feePayer, "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4");
});

test("without a fresh AFUEL price the 402 still works, with USDC only", async () => {
  const fetchImpl = async () => { throw new Error("offline"); };
  const afuel = createAfuel({ env: { AFUEL_PAYMENTS: "on" }, fetchImpl });
  const accepts = await paywalled(afuel);
  assert.deepEqual(accepts.map((a) => a.asset), ["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", USDC_SOLANA]);
});

test("a price older than five minutes is not used", async () => {
  let t = 1_000_000;
  const afuel = createAfuel({ env: { AFUEL_PAYMENTS: "on" }, now: () => t, fetchImpl: async () => { throw new Error("offline"); } });
  afuel.setPriceForTest(0.00002);
  assert.equal(afuel.usdPrice(), 0.00002);
  t += 5 * 60_000 + 1;
  assert.equal(afuel.usdPrice(), null);
  assert.equal(await afuel.priceFor(0.01), null);
});

test("the live price comes from Jupiter when it lists AFUEL", async () => {
  const fetchImpl = async (url) => {
    assert.match(String(url), /api\.jup\.ag\/price\/v3/);
    return new Response(JSON.stringify({ [AFUEL_MINT]: { usdPrice: 0.00004 }, So11111111111111111111111111111111111111112: { usdPrice: 150 } }));
  };
  const afuel = createAfuel({ env: { AFUEL_PAYMENTS: "on" }, fetchImpl });
  assert.deepEqual(await afuel.priceFor(0.01), { asset: AFUEL_MINT, amount: "187500000" });
  assert.equal(afuel.status().source, "jupiter");
});

test("a payment in AFUEL is verified and settled against the AFUEL option", async () => {
  const afuel = createAfuel({ env: { AFUEL_PAYMENTS: "on" } });
  afuel.setPriceForTest(0.00002);
  const { status, seen } = await paywalled(afuel, { pay: (accepts) => accepts.find((a) => a.asset === AFUEL_MINT) });
  assert.equal(status, 200);
  const verify = seen.find((s) => s.path.endsWith("/verify"));
  assert.equal(verify.body.paymentRequirements.asset, AFUEL_MINT);
  assert.equal(verify.body.paymentRequirements.amount, "375000000");
  assert.ok(seen.some((s) => s.path.endsWith("/settle")));
});
