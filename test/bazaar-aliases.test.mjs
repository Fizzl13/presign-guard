// Search-word paths (src/bazaar-aliases.js): the same paid route, with the alias as the 402's resource URL.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { bazaarAliases, PRESIGN_ALIASES } from "../src/bazaar-aliases.js";
import { x402Routes } from "../src/presign-guard.js";

const BASE = "eip155:8453";
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const servers = [];
const listen = (handler) => new Promise((resolve) => {
  const s = http.createServer(handler).listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${s.address().port}`));
  servers.push(s);
});
after(() => servers.forEach((s) => s.close()));

test("an alias is rewritten to its route, the query kept; other paths untouched", () => {
  const mw = bazaarAliases(PRESIGN_ALIASES);
  const run = (url) => { const req = { url }; mw(req, {}, () => {}); return req.url; };
  assert.equal(run("/v1/sanctions-screening?address=0x1"), "/v1/screen?address=0x1");
  assert.equal(run("/v1/transaction-check/"), "/v1/check");
  assert.equal(run("/v1/token-approval-check?chain=base&address=0x1"), "/v1/approvals?chain=base&address=0x1");
  assert.equal(run("/v1/screen"), "/v1/screen");
  assert.equal(run("/v1/sanctions-screening-x"), "/v1/sanctions-screening-x");
});

test("every alias goes to a paid route, and server.js puts the rewrite before the paywall", () => {
  const paid = Object.keys(x402Routes(PAY_TO, BASE)).map((k) => k.split(" ")[1]);
  for (const target of Object.values(PRESIGN_ALIASES)) assert.ok(paid.includes(target), target);
  const src = readFileSync(new URL("../server.js", import.meta.url), "utf8");
  const at = src.indexOf("app.use(bazaarAliases(PRESIGN_ALIASES))");
  assert.ok(at > 0 && at < src.indexOf("paymentMiddleware(PAYWALL_ROUTES"), "before the paywall");
});

test("402: /v1/sanctions-screening is /v1/screen's price, under its own resource URL", async () => {
  const facilitatorUrl = await listen((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ kinds: [{ x402Version: 2, scheme: "exact", network: BASE }], extensions: [], signers: {} }));
  });
  const rs = new x402ResourceServer(new HTTPFacilitatorClient({ url: facilitatorUrl })).register(BASE, new ExactEvmScheme());
  const all = x402Routes(PAY_TO, BASE);
  const key = Object.keys(all).find((k) => k.endsWith(" /v1/screen"));
  const route = { ...all[key], accepts: all[key].accepts.filter((a) => a.network === BASE) };
  const app = express();
  app.use(bazaarAliases(PRESIGN_ALIASES));
  app.use(paymentMiddleware({ [key]: route }, rs));
  app.get("/v1/screen", (_req, res) => res.json({ ok: true }));
  const base = await listen(app);
  const decode = (r) => JSON.parse(Buffer.from(r.headers.get("payment-required"), "base64").toString("utf8"));
  const plain = decode(await fetch(`${base}/v1/screen?address=0x1`));
  const res = await fetch(`${base}/v1/sanctions-screening?address=0x1`);
  assert.equal(res.status, 402);
  const c = decode(res);
  assert.deepEqual(c.accepts.map((a) => [a.network, a.amount, a.payTo]), plain.accepts.map((a) => [a.network, a.amount, a.payTo]));
  assert.equal(new URL(c.resource.url).pathname, "/v1/sanctions-screening");
});
