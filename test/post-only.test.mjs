// GET on a POST-only paid route (src/post-only.js): the POST's 402 with Allow: POST, never a payment on a GET.
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { headGuard } from "../src/head-guard.js";
import { postOnlyTerms } from "../src/post-only.js";

function server() {
  const seen = [];
  const paywall = (req, res, next) => {
    seen.push(`${req.method} ${req.path}`);
    if (req.method === "POST" && req.path === "/v1/check") return res.status(402).set("PAYMENT-REQUIRED", "terms").json({});
    next();
  };
  const app = express();
  app.use(headGuard());
  app.use(postOnlyTerms({ paths: ["/v1/check", "/v1/other"], paywall }));
  app.post("/v1/check", (_req, res) => res.json({ paid: true }));
  app.get("/v1/token", (_req, res) => res.json({ token: true }));
  return { app, seen };
}

async function call(app, path, { method = "GET", headers = {} } = {}) {
  const s = app.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${s.address().port}${path}`, { method, headers });
    return { status: res.status, allow: res.headers.get("allow"), terms: res.headers.get("payment-required"), body: method === "HEAD" ? "" : await res.text() };
  } finally { s.close(); }
}

test("an unpaid GET or HEAD gets the POST's 402, with Allow: POST", async () => {
  const { app, seen } = server();
  const get = await call(app, "/v1/check");
  assert.equal(get.status, 402);
  assert.equal(get.terms, "terms");
  assert.equal(get.allow, "POST");
  assert.deepEqual(seen, ["POST /v1/check"], "the paywall saw the POST the GET stands for");
  const head = await call(app, "/v1/check/", { method: "HEAD" });
  assert.equal(head.status, 402);
  assert.equal(head.allow, "POST");
});

test("a GET with a payment, an MPP credential or a credit key is refused, without reaching the paywall", async () => {
  for (const headers of [{ "payment-signature": "x" }, { "x-payment": "x" }, { authorization: "Payment abc" }, { "x-credit-key": "k" }]) {
    const { app, seen } = server();
    const r = await call(app, "/v1/check", { headers });
    assert.equal(r.status, 405);
    assert.equal(r.allow, "POST");
    assert.match(r.body, /takes POST/);
    assert.deepEqual(seen, []);
  }
});

test("a path the paywall doesn't guard gets 405; other routes and POST are untouched", async () => {
  const { app } = server();
  assert.equal((await call(app, "/v1/other")).status, 405);
  assert.equal((await call(app, "/v1/token")).status, 200);
  assert.equal((await call(app, "/v1/check", { method: "POST" })).status, 200);
});
