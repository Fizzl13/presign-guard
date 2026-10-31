// POST /v1/check/quick (src/check-quick.js): the free pre-sign verdict only, the shared hourly limit, the same
// validation as POST /v1/check, and nothing of the content in the usage log.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createCheckQuickRouter } from "../src/check-quick.js";
import { createRateLimiter } from "../src/mcp.js";
import { describePresignCall } from "../src/usage.js";

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAYER = "0x2222222222222222222222222222222222222222";
const SELLER = "0x3333333333333333333333333333333333333333";
// The payment authorization an agent signs for a seller's 402 (EIP-3009), with the seller's requirements.
const payment = {
  type: "signature", chainId: 8453,
  typedData: {
    primaryType: "TransferWithAuthorization",
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC },
    message: { from: PAYER, to: SELLER, value: "1000", validAfter: "0", validBefore: String(Math.floor(Date.now() / 1000) + 60), nonce: "0x" + "ab".repeat(32) },
  },
  x402: { scheme: "exact", network: "eip155:8453", amount: "1000", asset: USDC, payTo: SELLER },
};

let server, base, calls, down = false;
before(async () => {
  calls = [];
  const limiter = createRateLimiter(3, 60 * 60 * 1000);
  const app = express();
  app.use(createCheckQuickRouter({
    allowFree: (ip) => limiter(ip),
    check: async (request) => {
      if (down) throw new Error("RPC down");
      calls.push(request);
      return { verdict: "green", reasons: [{ code: "PAYMENT_AUTHORIZATION", severity: "info" }] };
    },
  }));
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
  base = `http://127.0.0.1:${server.address().port}/v1/check/quick`;
});
after(() => server.close());

const post = (body) => fetch(base, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

test("free quick check: a real x402 payment authorization is parsed like POST /v1/check; the verdict only", async () => {
  const res = await post(payment);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(Object.keys(body).sort(), ["note", "verdict"]);
  assert.equal(body.verdict, "green");
  assert.equal(calls[0].kind, "transfer_authorization");
  assert.ok(calls[0].x402, "the seller's requirements go along, so a payment that differs from them is red");
  const bad = await post({ type: "signature", chainId: 8453 });
  assert.equal(bad.status, 400);
  assert.equal(calls.length, 1, "an invalid request never reaches the check");
});

test("check down: 502 with the reason; the hourly limit: 429 pointing to the paid check", async () => {
  down = true;
  const r = await post(payment);
  down = false;
  assert.equal(r.status, 502);
  assert.match((await r.json()).error, /could not check: RPC down/);
  assert.equal((await post(payment)).status, 200, "the third free call of the hour");
  const over = await post(payment);
  assert.equal(over.status, 429);
  assert.match((await over.json()).error, /POST \/v1\/check \(\$0\.01/);
});

test("usage log: the type, chain and verdict, never the transaction", () => {
  const req = { method: "POST", path: "/v1/check/quick", body: payment, get: (h) => (h === "origin" ? "https://fizzl.eu" : undefined) };
  const d = describePresignCall(req, { statusCode: 200 }, { verdict: "green", note: "Verdict only." });
  assert.deepEqual(d, { route: "check_quick", via: "web", input: { type: "signature", chainId: 8453 }, result: { verdict: "green", error: undefined } });
});
