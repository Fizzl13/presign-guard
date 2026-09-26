import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { nohumansClaim, CLAIMS } from "../src/nohumans-claim.js";

test("nohumans claim: a pending token as plain text; per-endpoint headers; 404 when none", async () => {
  const app = express();
  assert.match(String(CLAIMS.wellKnown ?? ""), /^([0-9a-f]{48})?$/, "a pending token is 48 hex characters");
  app.use("/pending", nohumansClaim({ headers: {}, wellKnown: "tok" }));
  app.use("/none", nohumansClaim({ headers: { "/v1/token": "tok" }, wellKnown: null }));
  app.use((_req, res) => res.status(404).end());
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const res = await fetch(`${base}/pending/.well-known/nohumans-claim`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /^text\/plain/);
    assert.equal(await res.text(), "tok");
    assert.equal((await fetch(`${base}/none/.well-known/nohumans-claim`)).status, 404);
    assert.equal((await fetch(`${base}/none/v1/token`)).headers.get("x-nohumans-claim"), "tok");
    assert.equal((await fetch(`${base}/none/v1/check`)).headers.get("x-nohumans-claim"), null);
  } finally {
    server.close();
  }
});
