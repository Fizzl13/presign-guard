// Paying presign-guard in RLUSD on the XRP Ledger: every paid route and credit pack offers it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402ResourceServer } from "@x402/core/server";
import { ExactXrplScheme } from "@x402/xrpl/exact/server";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { createXrplFacilitator, XRPL_NETWORK, txHash } from "../src/xrpl-facilitator.js";
import http from "node:http";
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

test("a t54 payment settles once: the same signed blob again is a duplicate (t54's /settle is idempotent), a failed settle can be retried", async () => {
  let t = 0;
  let fail = false;
  const settled = [];
  const t54 = { verify: async () => ({ isValid: true }), settle: async (p) => { settled.push(p.payload.signedTxBlob); return fail ? { success: false, errorReason: "tefPAST_SEQ" } : { success: true, transaction: "ABC" }; } };
  const fac = createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9", t54, now: () => t });
  const pay = (blob) => ({ x402Version: 2, accepted: { network: "xrpl:0" }, payload: { signedTxBlob: blob, invoiceId: "presign-guard.fizzl.eu GET /v1/screen" } });
  assert.equal((await fac.settle(pay("AA"), {})).success, true);
  const again = await fac.settle(pay("AA"), {});
  assert.deepEqual([again.success, again.errorReason], [false, "duplicate_settlement"], "a replayed blob buys nothing");
  assert.deepEqual(settled, ["AA"], "the replay never reaches t54");
  assert.equal((await fac.settle(pay("BB"), {})).success, true, "another payment settles");
  fail = true;
  assert.equal((await fac.settle(pay("CC"), {})).success, false);
  fail = false;
  assert.equal((await fac.settle(pay("CC"), {})).success, true, "a failed settle frees the blob for a retry");
  t += 8 * 24 * 3600 * 1000;
  assert.equal((await fac.settle(pay("AA"), {})).success, true, "after a week the claim is gone");
  const parallel = await Promise.all([fac.settle(pay("DD"), {}), fac.settle(pay("DD"), {})]);
  assert.deepEqual(parallel.map((r) => r.success).sort(), [false, true], "two at once: one settles");
});

// A t54 payment signed on testnet (13 Oct 2026) and the id the ledger gave it.
const TESTNET_BLOB = "120000232FF676FC2401482F00201B01482F3F50118D33D3DD43B9E4F4C3360F499765BF00C90F302CB7AFB9545FA67F79DDFF9072614000000000004E2068400000000000000A7321ED17C5501C694D47A4944A4552C61EF6E164EDD54F86D4216CF9D6CB98F992542A74405456FA9362161C17565A68893F3CFCFA3623F56C48DA0047C67A1BB6CD30F5DCA5D3F046FE250901574F1A1256548346409ECFCD00D573766309F43445ED6C0F81147731F4DF42A63D35BB8A06341856FE28535F197083140C8A850AAB95254D89763620F3DEC18E86F471F4F9EA7D2A696368696D6F6B752D7369676E616C2E66697A7A6C2E657520474554202F7369676E616C2F3A70616972E1F1";
const TESTNET_HASH = "1266EDE7843F07B65D172AB8C74F09A36F784CE499A3087E8E95C538DA3B1E46";

test("a t54 payment whose transaction is already on the ledger is a replay, even after a restart; a failed settle may still be retried", async () => {
  assert.equal(txHash(TESTNET_BLOB), TESTNET_HASH, "the id is SHA-512Half of TXN\\0 + the blob");
  const onLedger = new Set(["OLD"]);
  const asked = [];
  const verified = [];
  let fail = false;
  const t54 = { verify: async (p) => (verified.push(p.payload.signedTxBlob), { isValid: true }), settle: async () => (fail ? { success: false, errorReason: "timeout" } : { success: true, transaction: "ABC" }) };
  const fac = createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9", t54, onLedger: async (blob) => (asked.push(blob), onLedger.has(blob)) });
  const pay = (blob) => ({ x402Version: 2, accepted: { network: XRPL_NETWORK }, payload: { signedTxBlob: blob, invoiceId: "presign-guard.fizzl.eu POST /v1/check" } });
  assert.deepEqual(await fac.verify(pay("OLD"), {}), { isValid: false, invalidReason: "duplicate_settlement", payer: "" }, "a fresh process still refuses an old payment");
  assert.equal((await fac.verify(pay("NEW"), {})).isValid, true);
  assert.deepEqual(verified, ["NEW"], "the replay never reaches t54");
  fail = true;
  assert.equal((await fac.settle(pay("NEW"), {})).success, false);
  onLedger.add("NEW");
  fail = false;
  asked.length = 0;
  assert.equal((await fac.verify(pay("NEW"), {})).isValid, true, "t54 may have submitted it before the failure: the retry goes on");
  assert.deepEqual(asked, [], "no ledger lookup for a retry");
  assert.equal((await fac.settle(pay("NEW"), {})).success, true);
});

test("the ledger lookup asks rippled for the transaction by id; not found or no answer lets the payment through", async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params } = JSON.parse(body);
      seen.push([method, params[0].transaction]);
      const found = params[0].transaction === TESTNET_HASH;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ result: found ? { status: "success", hash: TESTNET_HASH, validated: true } : { status: "error", error: "txnNotFound" } }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const rpcUrl = `http://127.0.0.1:${srv.address().port}`;
  const t54 = { verify: async () => ({ isValid: true }), settle: async () => ({ success: true }) };
  const pay = (blob) => ({ x402Version: 2, payload: { signedTxBlob: blob, invoiceId: "x" } });
  try {
    const fac = createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9", rpcUrl, t54 });
    assert.equal((await fac.verify(pay(TESTNET_BLOB), {})).invalidReason, "duplicate_settlement");
    assert.equal((await fac.verify(pay("1200"), {})).isValid, true);
    assert.deepEqual(seen, [["tx", TESTNET_HASH], ["tx", txHash("1200")]]);
  } finally {
    srv.close();
  }
  const down = createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9", rpcUrl: "http://127.0.0.1:9", t54 });
  assert.equal((await down.verify(pay(TESTNET_BLOB), {})).isValid, true, "rippled unreachable: the in-memory claims still hold");
});
