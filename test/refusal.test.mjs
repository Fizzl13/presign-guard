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
  app.set("trust proxy", 1); // as behind Render: the address is the one its proxy hop supplies
  app.get(PATH, routes.get);
  app.post(PATH, express.json(), routes.post);
  const server = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
  const url = `http://127.0.0.1:${server.address().port}${PATH}`;
  const accept = x402Routes(EVM, "eip155:8453")["POST /v1/check"].accepts[0];
  // `from`: the sending address as the proxy hop supplies it (unsigned reports count once per address a day).
  const post = (body, from) => fetch(url, { method: "POST", headers: { "content-type": "application/json", ...(from ? { "x-forwarded-for": from } : {}) }, body: JSON.stringify(body) });
  try {
    assert.equal((await post(refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check", accept, acceptIndex: 0, reason: "price_above_limit" }))).status, 204);
    assert.equal((await post(refusalReport({ resource: "https://other.example/v1/check", accept, reason: "price_above_limit" }))).status, 400);
    // Lucian's report: the buyer's query or path never reaches the public counts, and a repost counts once.
    const marked = refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check?wallet=marker-3e9a", accept, reason: "price_above_limit" });
    assert.equal((await post(marked, "203.0.113.2")).status, 204);
    assert.equal((await post(marked, "203.0.113.2")).status, 204);
    assert.equal((await post(refusalReport({ resource: "https://presign-guard.fizzl.eu/u/marker-77b1", accept, reason: "price_above_limit" }))).status, 204);
    const text = await (await fetch(url)).text();
    assert.ok(!text.includes("marker-"), "no buyer input in the public counts");
    assert.equal(JSON.parse(text).received.by_resource.other.total, 1);
    assert.equal(JSON.parse(text).received.by_resource["/v1/check"].total, 2);
    const info = await (await fetch(url)).json();
    assert.deepEqual(info.received.by_resource["/v1/check"], { total: 2, signed: 0, reasons: { price_above_limit: 2 } });

    // Lucian's counting policy: one address varying checkedAt and detail counts once per day, route and reason.
    const t = Date.now();
    for (let i = 1; i <= 5; i++) {
      const r = refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check", accept, reason: "trust_low", detail: i % 2 ? "score" : "unknown", now: new Date(t - i * 60000) });
      assert.equal((await post(r, "198.51.100.7")).status, 204);
    }
    assert.equal((await post(refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check", accept, reason: "trust_low" }), "198.51.100.8")).status, 204);
    const capped = await (await fetch(url)).json();
    assert.equal(capped.received.by_resource["/v1/check"].reasons.trust_low, 2, "one per address, not five");
    assert.match(capped.received.counted_by, /capped at one per sending address, UTC day, route and reason/);
    assert.ok(!JSON.stringify(capped).includes("198.51.100"), "no address in the public counts");
  } finally {
    server.close();
  }
});

test("the counts survive a restart: counted reports go to their own log and are read back at the start", async () => {
  const { createRefusalLog } = await import("../src/refusal-log.js");
  const accept = x402Routes(EVM, "eip155:8453")["POST /v1/check"].accepts[0];
  const written = [];
  const lines = [];
  const asked = [];
  const reader = { configured: true, load: async ({ service } = {}) => { asked.push(service); return { events: lines }; } };
  const serve = async (log) => {
    const routes = createRefusalRoutes({ publicUrl: "https://presign-guard.fizzl.eu", routes: ["/v1/check"], record: log.record, history: log.history });
    await routes.ready;
    const app = express();
    app.set("trust proxy", 1);
    app.get(PATH, routes.get);
    app.post(PATH, express.json(), routes.post);
    const server = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
    const url = `http://127.0.0.1:${server.address().port}${PATH}`;
    const post = (body, from) => fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": from }, body: JSON.stringify(body) });
    return { server, url, post };
  };
  // First process: one report counted, written to the log without the URL as sent.
  const first = await serve(createRefusalLog({ service: "presign-refusals", log: { record: (e) => written.push(e) }, reader: { configured: false } }));
  const report = refusalReport({ resource: "https://presign-guard.fizzl.eu/v1/check?wallet=marker-71c0", accept, reason: "price_above_limit" });
  try {
    assert.equal((await first.post(report, "203.0.113.4")).status, 204);
    assert.equal((await (await fetch(first.url)).json()).received.since_restart, true);
  } finally { first.server.close(); }
  assert.equal(written.length, 1);
  assert.deepEqual(Object.keys(written[0].input).sort(), ["key", "reason", "route", "signed"]);
  assert.equal(written[0].input.route, "/v1/check");
  assert.ok(!JSON.stringify(written).includes("marker-71c0"));
  // After a restart the log is read back: the count is there, and the same report posted again still counts once.
  lines.push({ t: new Date(Date.now() - 60000).toISOString(), service: "presign-refusals", ...written[0] });
  const second = await serve(createRefusalLog({ service: "presign-refusals", log: { record: (e) => written.push(e) }, reader }));
  try {
    let info = await (await fetch(second.url)).json();
    assert.deepEqual(asked, ["presign-refusals"]);
    assert.equal(info.received.since_restart, false);
    assert.equal(info.received.by_resource["/v1/check"].total, 1);
    assert.equal((await second.post(report, "203.0.113.5")).status, 204);
    info = await (await fetch(second.url)).json();
    assert.equal(info.received.by_resource["/v1/check"].total, 1, "a restored report still counts once");
    assert.equal(written.length, 1);
  } finally { second.server.close(); }
  assert.throws(() => createRefusalLog({}), /service/);
});
