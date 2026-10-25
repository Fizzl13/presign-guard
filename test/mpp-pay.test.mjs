// MPP payment (src/mpp-pay.cjs, same module as x402 Doctor) on a POST route like /v1/check.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createRequire } from "node:module";
import express from "express";
import { keccak256, stringToHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const require = createRequire(import.meta.url);
const { createMppPay, unlessMppPaid } = require("../src/mpp-pay.cjs");
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const agent = privateKeyToAccount(generatePrivateKey());

async function serve({ status = 200 } = {}) {
  const calls = { verify: 0, settle: 0 };
  const facilitator = {
    async verify() { calls.verify++; return { isValid: true }; },
    async settle() { calls.settle++; return { success: true, transaction: "0xabc" }; },
  };
  const mpp = createMppPay({ secret: "s", realm: "presign.test", recipient: PAY_TO, routes: { "POST /v1/check": "$0.005" }, facilitator, log: { warn() {} } });
  const app = express();
  app.use(express.json());
  app.use(mpp.middleware);
  app.use(unlessMppPaid((req, res, next) => (req.path === "/v1/check" ? res.status(402).json({}) : next())));
  app.post("/v1/check", (req, res) => res.status(status).json({ verdict: "green", got: req.body }));
  const server = await new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
  return { base: `http://127.0.0.1:${server.address().port}`, calls, close: () => server.close() };
}

function challengeOf(res) {
  const h = res.headers.get("www-authenticate");
  const p = (n) => new RegExp(`${n}="([^"]*)"`).exec(h)[1];
  const c = { id: p("id"), realm: p("realm"), method: p("method"), intent: p("intent"), request: p("request"), expires: p("expires"), opaque: p("opaque") };
  return { c, request: JSON.parse(Buffer.from(c.request, "base64url").toString()) };
}

async function credential({ c, request }, { value = request.amount } = {}) {
  const nonce = keccak256(stringToHex(JSON.stringify([c.id, c.realm])));
  const validBefore = String(Math.floor(Date.parse(c.expires) / 1000));
  const signature = await agent.signTypedData({
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: request.currency },
    types: { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
    primaryType: "TransferWithAuthorization",
    message: { from: agent.address, to: request.recipient, value: BigInt(value), validAfter: 0n, validBefore: BigInt(validBefore), nonce },
  });
  const wire = { challenge: c, payload: { type: "authorization", from: agent.address, to: request.recipient, value, validAfter: "0", validBefore, nonce, signature } };
  return `Payment ${Buffer.from(JSON.stringify(wire)).toString("base64url")}`;
}

const post = (base, headers = {}) => fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ to: "0x1" }) });

test("POST /v1/check: 402 with an MPP evm challenge; a signed credential is served and settled once", async (t) => {
  const s = await serve(); t.after(s.close);
  const unpaid = await post(s.base);
  assert.equal(unpaid.status, 402);
  const ch = challengeOf(unpaid);
  assert.equal(ch.c.method, "evm");
  assert.equal(ch.request.amount, "5000");
  const res = await post(s.base, { authorization: await credential(ch) });
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).got, { to: "0x1" });
  assert.equal(s.calls.settle, 1);
  assert.equal(JSON.parse(Buffer.from(res.headers.get("payment-receipt"), "base64url").toString()).reference, "0xabc");
});

test("a wrong amount is refused before the facilitator; a failed answer is never settled", async (t) => {
  const s = await serve({ status: 500 }); t.after(s.close);
  const ch = challengeOf(await post(s.base));
  let res = await post(s.base, { authorization: await credential(ch, { value: "1" }) });
  assert.equal(res.status, 402);
  assert.equal(s.calls.verify, 0);
  res = await post(s.base, { authorization: await credential(ch) });
  assert.equal(res.status, 500);
  assert.equal(s.calls.settle, 0);
});

test("openapi.json gets an evm offer on the routes MPP sells, not on the credit packs", async () => {
  const { openApi } = await import("../src/discovery.js");
  const { x402Routes } = await import("../src/presign-guard.js");
  const { addMppOffers } = require("../src/mpp-pay.cjs");
  const ROUTES = x402Routes(PAY_TO, "eip155:8453", null);
  const spec = addMppOffers(openApi("https://p.test", "eip155:8453", ["eip155:8453"], { credits: true }), { include: (p, m) => `${m} ${p}` in ROUTES });
  const info = spec.paths["/v1/check"].post["x-payment-info"];
  assert.deepEqual(info.protocols.map((p) => Object.keys(p)[0]), ["x402", "mpp"]);
  assert.deepEqual(spec.paths["/v1/credits/100"].get["x-payment-info"].protocols, [{ x402: {} }]);
  assert.equal(info.offers[0].method, "evm");
  assert.equal(info.offers[0].amount, String(Math.round(Number(info.price.amount) * 1e6)));
  assert.equal(spec.paths["/v1/credits/100"].get["x-payment-info"].offers, undefined);
});

test("openapi.json gets a tempo session offer when sessions are on", async () => {
  const { openApi } = await import("../src/discovery.js");
  const { x402Routes } = await import("../src/presign-guard.js");
  const { addMppOffers } = require("../src/mpp-pay.cjs");
  const ROUTES = x402Routes(PAY_TO, "eip155:8453", null);
  const USDCE = "0x20C000000000000000000000b9537d11c60E8b50";
  const spec = addMppOffers(openApi("https://p.test", "eip155:8453", ["eip155:8453"], {}), { include: (p, m) => `${m} ${p}` in ROUTES, tempo: { currency: USDCE }, session: { currency: USDCE } });
  const info = spec.paths["/v1/check"].post["x-payment-info"];
  assert.deepEqual(info.offers.map((o) => `${o.method}/${o.intent}`), ["evm/charge", "tempo/charge", "tempo/session"]);
  assert.equal(info.offers[2].unitType, "request");
  assert.equal(info.offers[2].amount, info.offers[0].amount);
  assert.deepEqual(info.protocols.at(-1), { mpp: { method: "tempo", intent: "session", currency: USDCE } });
});

// The xrpl method (Ripple's xrpl-mpp-sdk, pull mode): RLUSD, verified and settled by an x402 XRPL facilitator.
// Tested end to end on testnet with the SDK's own client (25 Oct 2026); here with a stand-in facilitator.
const XRPL_TO = "r9xmBsRr8Ao7jRgjjxreMiAwGiCK2FGwqw";
const PAYER = "rUVHd9p3uKPqJGshyfcLtE195MhDmwSwMZ";
async function serveXrpl({ status = 200 } = {}) {
  const calls = { verify: [], settle: [] };
  const facilitator = {
    async verify(payload, req) { calls.verify.push({ payload, req }); return { isValid: true, payer: PAYER }; },
    async settle(payload, req) { calls.settle.push({ payload, req }); return { success: true, transaction: "57CF68FC", payer: PAYER }; },
  };
  const mpp = createMppPay({ secret: "s", realm: "presign.test", routes: { "POST /v1/check": "$0.005" }, xrpl: { recipient: XRPL_TO, facilitator }, log: { warn() {} } });
  const app = express();
  app.use(express.json());
  app.use(mpp.middleware);
  app.use(unlessMppPaid((req, res, next) => (req.path === "/v1/check" ? res.status(402).json({}) : next())));
  app.post("/v1/check", (req, res) => res.status(status).json({ verdict: "green", paidBy: req.mppPaid }));
  const server = await new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
  return { base: `http://127.0.0.1:${server.address().port}`, calls, mpp, close: () => server.close() };
}
const xrplCredential = ({ c }, payload, extra = {}) => `Payment ${Buffer.from(JSON.stringify({ challenge: c, payload, ...extra })).toString("base64url")}`;

test("xrpl: an RLUSD challenge bound to an InvoiceID; a signed Payment is verified, served, then settled", async (t) => {
  const { createHash } = await import("node:crypto");
  const { RLUSD_HEX } = require("../src/mpp-pay.cjs");
  const s = await serveXrpl(); t.after(s.close);
  const ch = challengeOf(await post(s.base));
  assert.equal(ch.c.method, "xrpl");
  const { amount, currency, recipient, methodDetails } = ch.request;
  assert.deepEqual([amount, JSON.parse(currency), recipient, methodDetails.network], ["0.005", { currency: RLUSD_HEX, issuer: "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De" }, XRPL_TO, "mainnet"]);
  assert.match(methodDetails.reference, /^[0-9a-f-]{36}$/);
  // The Payment must carry this InvoiceID: x402's facilitator expects sha256(extra.invoiceId).
  assert.equal(methodDetails.invoiceId, createHash("sha256").update(`presign.test mpp ${methodDetails.reference}`).digest("hex").toUpperCase());
  assert.notEqual(challengeOf(await post(s.base)).request.methodDetails.reference, methodDetails.reference); // one per challenge

  const res = await post(s.base, { authorization: xrplCredential(ch, { type: "transaction", blob: "12000022" }, { source: `did:pkh:xrpl:mainnet:${PAYER}` }) });
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).paidBy, { payer: PAYER, amount: "0.005" });
  const { payload, req } = s.calls.verify[0];
  assert.deepEqual(req, { scheme: "exact", network: "xrpl:0", amount: "0.005", asset: RLUSD_HEX, payTo: XRPL_TO, maxTimeoutSeconds: 300, extra: { issuer: "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De", invoiceId: `presign.test mpp ${methodDetails.reference}`, areFeesSponsored: false } });
  assert.deepEqual(payload, { x402Version: 2, accepted: req, payload: { signedTxBlob: "12000022" } });
  assert.equal(s.calls.settle.length, 1);
  assert.deepEqual(JSON.parse(Buffer.from(res.headers.get("payment-receipt"), "base64url").toString()).method, "xrpl");
});

test("xrpl: push mode, a tampered challenge, another signer and a failed answer are refused or never settled", async (t) => {
  const s = await serveXrpl({ status: 500 }); t.after(s.close);
  const ch = challengeOf(await post(s.base));
  let res = await post(s.base, { authorization: xrplCredential(ch, { type: "hash", hash: "A".repeat(64) }) });
  assert.equal(res.status, 402);
  assert.match((await res.json()).detail, /pull mode/);
  const tampered = { c: { ...ch.c, request: Buffer.from(JSON.stringify({ ...ch.request, methodDetails: { ...ch.request.methodDetails, reference: "00000000-0000-4000-8000-000000000000" } })).toString("base64url") } };
  res = await post(s.base, { authorization: xrplCredential(tampered, { type: "transaction", blob: "12" }) });
  assert.match((await res.json()).detail, /wasn't issued here/);
  res = await post(s.base, { authorization: xrplCredential(ch, { type: "transaction", blob: "12" }, { source: "did:pkh:xrpl:mainnet:rMqtK5JB73Ks4nTtc58oJpK6LqgHHPXmoY" }) });
  assert.match((await res.json()).detail, /another account/);
  assert.equal(s.calls.verify.length, 1);
  res = await post(s.base, { authorization: xrplCredential(ch, { type: "transaction", blob: "12" }) });
  assert.equal(res.status, 500);
  assert.equal(s.calls.settle.length, 0);
});

test("openapi.json gets an xrpl offer priced in RLUSD when the xrpl method is on", async () => {
  const { openApi } = await import("../src/discovery.js");
  const { x402Routes } = await import("../src/presign-guard.js");
  const { addMppOffers } = require("../src/mpp-pay.cjs");
  const ROUTES = x402Routes(PAY_TO, "eip155:8453", null);
  const s = await serveXrpl(); s.close();
  const spec = addMppOffers(openApi("https://p.test", "eip155:8453", ["eip155:8453"], {}), { include: (p, m) => `${m} ${p}` in ROUTES, xrpl: s.mpp.xrpl });
  const info = spec.paths["/v1/check"].post["x-payment-info"];
  const offer = info.offers.find((o) => o.method === "xrpl");
  assert.equal(offer.amount, info.price.amount.replace(/^\$/, "").replace(/0+$/, ""));
  assert.deepEqual(info.protocols.at(-1), { mpp: { method: "xrpl", intent: "charge", currency: s.mpp.xrpl.currency } });
});
