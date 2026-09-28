import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createTokenQuickRouter } from "../src/token-quick.js";
import { createRateLimiter } from "../src/mcp.js";
import { fizzlCors } from "../src/fizzl-cors.js";
import { describePresignCall } from "../src/usage.js";

let server, base, calls;
before(async () => {
  calls = [];
  const limiter = createRateLimiter(3, 60 * 60 * 1000);
  const app = express();
  app.use("/v1/token/quick", fizzlCors);
  app.use(createTokenQuickRouter({
    allowFree: (ip) => limiter(ip),
    verdict: async (request) => { calls.push(request); return { verdict: "green", grade: "SAFE", reasons: [{ code: "SECRET" }], market: { price: 1 } }; },
  }));
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

test("free quick verdict: verdict and grade only, nothing from the paid answer", async () => {
  const res = await fetch(`${base}/v1/token/quick?chain=base&address=${USDC}`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.verdict, "green");
  assert.equal(body.grade, "SAFE");
  assert.equal(body.chain, "base");
  assert.equal(body.reasons, undefined);
  assert.equal(body.market, undefined);
  assert.equal(calls.at(-1).address, USDC.toLowerCase(), "same parsing as the paid route");
});

test("invalid input is 400 and does not use the free limit", async () => {
  const before = calls.length;
  const res = await fetch(`${base}/v1/token/quick?chain=base&address=nope`);
  assert.equal(res.status, 400);
  assert.equal(calls.length, before);
});

test("CORS for fizzl.eu only", async () => {
  const ok = await fetch(`${base}/v1/token/quick?chain=base&address=${USDC}`, { headers: { origin: "https://fizzl.eu" } });
  assert.equal(ok.headers.get("access-control-allow-origin"), "https://fizzl.eu");
  const other = await fetch(`${base}/v1/token/quick?chain=base&address=${USDC}`, { headers: { origin: "https://evil.example" } });
  assert.equal(other.headers.get("access-control-allow-origin"), null);
});

test("the free limit applies, then 429 pointing at the paid route", async () => {
  // 3 per hour in this test; earlier tests used 3 (one 400 did not count, CORS test used 2).
  const res = await fetch(`${base}/v1/token/quick?chain=base&address=${USDC}`);
  assert.equal(res.status, 429);
  assert.match((await res.json()).error, /GET \/v1\/token \(\$0\.01/);
});

test("usage log names the free route", () => {
  const req = { method: "GET", path: "/v1/token/quick", query: { chain: "base", address: USDC }, get: (h) => (h === "origin" ? "https://fizzl.eu" : undefined) };
  const d = describePresignCall(req, null, { verdict: "green", grade: "SAFE" });
  assert.equal(d.route, "token_quick");
  assert.equal(d.via, "web");
  assert.equal(d.result.verdict, "green");
});
