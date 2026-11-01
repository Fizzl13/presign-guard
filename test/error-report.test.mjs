// Error reports to Sentry (src/error-report.js, the same as x402-doctor's lib/error-report.js): the envelope carries
// the error and the request path, never headers, query or body; a 5xx is answered as JSON.
import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createErrorReporter, parseDsn } from "../src/error-report.js";

const DSN = "https://abc123@o1.ingest.de.sentry.io/4507";

test("off without a DSN; a report has the error and the path, never secrets", async () => {
  assert.equal(createErrorReporter({ service: "presign-guard" }).enabled, false);
  assert.equal(parseDsn(DSN).url, "https://o1.ingest.de.sentry.io/api/4507/envelope/");
  const sent = [];
  const r = createErrorReporter({ dsn: DSN, service: "presign-guard", fetchImpl: async (_u, i) => { sent.push(i.body); return { ok: true }; } });
  await r.report(new Error("boom"), { req: { method: "POST", hostname: "presign-guard.fizzl.eu", path: "/v1/check", url: "/v1/check?x=secret", headers: { "payment-signature": "SIG" }, body: { tx: "SECRET" } } });
  assert.match(sent[0], /"value":"boom"/);
  assert.match(sent[0], /presign-guard\.fizzl\.eu\/v1\/check"/);
  for (const s of ["SIG", "SECRET", "x=secret"]) assert.ok(!sent[0].includes(s), s);
});

test("Express: a 5xx is reported and answered as JSON", async () => {
  const sent = [];
  const r = createErrorReporter({ dsn: DSN, service: "presign-guard", fetchImpl: async (_u, i) => { sent.push(i.body); return { ok: true }; } });
  const app = express();
  app.get("/boom", () => { throw new Error("kaput"); });
  app.use(r.expressHandler());
  const server = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
  const quiet = console.error; console.error = () => {};
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/boom`);
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { error: "internal error" });
    await new Promise((ok) => setTimeout(ok, 30));
    assert.equal(sent.length, 1);
  } finally { console.error = quiet; server.close(); }
});
