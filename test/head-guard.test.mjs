import { test } from "node:test";
import assert from "node:assert/strict";
import { headGuard } from "../src/head-guard.js";

test("headGuard: every HEAD is handled as GET (paid paths then get the 402, also /PAID and /paid/); with a payment it is refused", () => {
  const guard = headGuard();
  const run = (method, path, headers = {}) => {
    const req = { method, path, headers };
    const res = { code: null, headers: {}, ended: false, status(c) { this.code = c; return this; }, set(k, v) { this.headers[k] = v; return this; }, end() { this.ended = true; } };
    let nexted = false;
    guard(req, res, () => { nexted = true; });
    return { req, res, nexted };
  };
  const a = run("HEAD", "/paid");
  assert.equal(a.req.method, "GET");
  assert.ok(a.nexted);
  const b = run("HEAD", "/paid", { "payment-signature": "abc" });
  assert.equal(b.res.code, 405);
  assert.ok(!b.nexted);
  for (const p of ["/free", "/PAID", "/paid/"]) assert.equal(run("HEAD", p).req.method, "GET", p);
  const d = run("GET", "/paid");
  assert.equal(d.req.method, "GET");
});
