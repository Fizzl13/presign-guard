// The refusal extension (src/refusal.js, the same as x402-doctor's lib/refusal.js; draft x402-foundation/x402#4087):
// presign-guard's 402s name where a buyer that doesn't pay can say why, and that endpoint takes the report.
import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { x402Routes } from "../src/presign-guard.js";
import { createRefusalRoutes, refusalReport, offerHash, PATH } from "../src/refusal.js";

const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";

test("every paid route's 402 names presign-guard's refusal endpoint", () => {
  for (const [key, r] of Object.entries(x402Routes(EVM, "eip155:8453"))) {
    assert.equal(r.extensions.refusal.info.url, "https://presign-guard.fizzl.eu/.well-known/x402-refusal", key);
  }
});

test("the offer hash matches x402-doctor's (the same canonical JSON)", () => {
  // Doctor's test/refusal.test.js uses this entry too; both must hash it alike, whatever the key order.
  const a = { scheme: "exact", network: "eip155:8453", amount: "10000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: EVM, maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } };
  const b = { extra: { version: "2", name: "USD Coin" }, payTo: EVM, maxTimeoutSeconds: 60, amount: "10000", asset: a.asset, network: a.network, scheme: "exact" };
  assert.equal(offerHash(a), offerHash(b));
});

test("the endpoint takes a report about presign-guard and refuses one about another seller", async () => {
  const routes = createRefusalRoutes({ publicUrl: "https://presign-guard.fizzl.eu", routes: ["/v1/check"] });
  const app = express();
  app.get(PATH, routes.get);
  app.post(PATH, express.json(), routes.post);
  const server = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
  const url = `http://127.0.0.1:${server.address().port}${PATH}`;
  const accept = x402Routes(EVM, "eip155:8453")["POST /v1/check"].accepts[0];
  const post = (body) => fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  try {
    assert.equal((await post(refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check", accept, acceptIndex: 0, reason: "price_above_limit" }))).status, 204);
    assert.equal((await post(refusalReport({ resource: "https://other.example/v1/check", accept, reason: "price_above_limit" }))).status, 400);
    // Lucian's report: the buyer's query or path never reaches the public counts, and a repost counts once.
    const marked = refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check?wallet=marker-3e9a", accept, reason: "price_above_limit" });
    assert.equal((await post(marked)).status, 204);
    assert.equal((await post(marked)).status, 204);
    assert.equal((await post(refusalReport({ resource: "https://presign-guard.fizzl.eu/u/marker-77b1", accept, reason: "price_above_limit" }))).status, 204);
    const text = await (await fetch(url)).text();
    assert.ok(!text.includes("marker-"), "no buyer input in the public counts");
    assert.equal(JSON.parse(text).received.by_resource.other.total, 1);
    assert.equal(JSON.parse(text).received.by_resource["/v1/check"].total, 2);
    const info = await (await fetch(url)).json();
    assert.deepEqual(info.received.by_resource["/v1/check"], { total: 2, signed: 0, reasons: { price_above_limit: 2 } });
  } finally {
    server.close();
  }
});
