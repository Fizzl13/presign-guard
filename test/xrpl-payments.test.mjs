// Paying presign-guard in RLUSD on the XRP Ledger: every paid route and credit pack offers it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402ResourceServer } from "@x402/core/server";
import { ExactXrplScheme } from "@x402/xrpl/exact/server";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { createXrplFacilitator, XRPL_NETWORK } from "../src/xrpl-facilitator.js";
import usageLog from "../src/usage-log.cjs";

const XRPL = { network: XRPL_NETWORK, payTo: "r9xmBsRr8Ao7jRgjjxreMiAwGiCK2FGwqw" };
const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";

test("every paid route has an RLUSD option bound to its route; without xrpl nothing changes", () => {
  const routes = x402Routes(EVM, "eip155:8453", null, XRPL);
  for (const [key, r] of Object.entries(routes)) {
    const x = r.accepts.find((a) => a.network === XRPL_NETWORK);
    assert.ok(x, key);
    assert.equal(x.payTo, XRPL.payTo);
    assert.equal(x.extra.invoiceId, `presign-guard.fizzl.eu ${key}`);
  }
  for (const r of Object.values(x402Routes(EVM, "eip155:8453"))) assert.ok(!r.accepts.some((a) => a.network === XRPL_NETWORK));
  for (const [key, r] of Object.entries(packRoutes("eip155:8453", EVM, null, XRPL))) assert.equal(r.accepts.at(-1).extra.invoiceId, `presign-guard.fizzl.eu ${key}`);
});

test("the $0.01 check becomes 0.01 RLUSD from Ripple's issuer, without touching the network", async () => {
  const server = new x402ResourceServer([createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9" })]).register(XRPL_NETWORK, new ExactXrplScheme());
  await server.initialize();
  const accept = x402Routes(EVM, "eip155:8453", null, XRPL)["POST /v1/check"].accepts[1];
  const [req] = await server.buildPaymentRequirements(accept);
  assert.equal(req.amount, "0.01");
  assert.equal(req.asset, "524C555344000000000000000000000000000000");
  assert.equal(req.extra.issuer, "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De");
  assert.equal(req.extra.invoiceId, "presign-guard.fizzl.eu POST /v1/check");
});

test("usage log counts RLUSD in dollars", () => {
  assert.equal(usageLog.usdOf({ network: "xrpl:0", asset: "524C555344000000000000000000000000000000", amount: "0.01" }), 0.01);
  assert.equal(usageLog.usdOf({ network: "eip155:8453", amount: "10000" }), 0.01);
});

test("t54-format payments (invoiceId in the payload) go to t54; accepts carry the x402 SourceTag", async () => {
  const { isT54Payload, X402_SOURCE_TAG } = await import("../src/xrpl-facilitator.js");
  const calls = [];
  const t54 = { verify: async () => (calls.push("t54 verify"), { isValid: true }), settle: async () => (calls.push("t54 settle"), { success: true }) };
  const fac = createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9", t54 });
  await fac.verify({ x402Version: 2, payload: { signedTxBlob: "AB", invoiceId: "x" } }, {});
  await fac.settle({ x402Version: 2, payload: { signedTxBlob: "AB", invoiceId: "x" } }, {});
  assert.deepEqual(calls, ["t54 verify", "t54 settle"]);
  assert.equal(isT54Payload({ payload: { signedTxBlob: "AB" } }), false);
  assert.equal(x402Routes(EVM, "eip155:8453", null, XRPL)["GET /v1/token"].accepts.at(-1).extra.sourceTag, X402_SOURCE_TAG);
});
