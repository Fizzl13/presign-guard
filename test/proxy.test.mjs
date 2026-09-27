import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { trustProxyHops } from "../src/proxy.js";

test("TRUST_PROXY_HOPS: 3 by default, a whole number from 0 to 10 overrides it", () => {
  assert.equal(trustProxyHops({}), 3);
  assert.equal(trustProxyHops({ TRUST_PROXY_HOPS: "1" }), 1);
  assert.equal(trustProxyHops({ TRUST_PROXY_HOPS: "0" }), 0);
  for (const bad of ["", " ", "x", "11", "-1", "2.5"]) assert.equal(trustProxyHops({ TRUST_PROXY_HOPS: bad }), 3, bad);
});

test("req.ip is the caller behind Render's three proxy hops, and a faked entry changes nothing", async () => {
  const app = express();
  app.set("trust proxy", trustProxyHops({}));
  app.get("/ip", (req, res) => res.send(req.ip));
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const ip = async (chain) => (await fetch(`http://127.0.0.1:${server.address().port}/ip`, { headers: { "x-forwarded-for": chain } })).text();
  try {
    assert.equal(await ip("203.0.113.7, 104.16.0.1, 10.0.0.5"), "203.0.113.7");
    assert.equal(await ip("93.184.216.34, 104.16.0.1, 10.0.0.5"), "93.184.216.34");
    assert.equal(await ip("1.2.3.4, 203.0.113.7, 104.16.0.1, 10.0.0.5"), "203.0.113.7");
  } finally {
    server.close();
  }
});
