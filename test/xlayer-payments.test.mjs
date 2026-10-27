// Paying presign-guard in USD₮0 on X Layer: every paid route and credit pack offers it, to PAY_TO by default.
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { xlayerConfig, usdt0Amount, XLAYER_NETWORK, XLAYER_USDT0 } from "../src/xlayer.js";
import usageLog from "../src/usage-log.cjs";

const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const OTHER = "0x551faCB18b3f173F300c944a3BDcbe1A2847A6AF";
const XL = { network: XLAYER_NETWORK, payTo: EVM };

test("xlayerConfig: PAY_TO by default, XLAYER_PAY_TO overrides it, \"off\" turns it off", () => {
  assert.deepEqual(xlayerConfig({}, EVM), XL);
  assert.deepEqual(xlayerConfig({ XLAYER_PAY_TO: OTHER }, EVM), { network: XLAYER_NETWORK, payTo: OTHER });
  assert.equal(xlayerConfig({ XLAYER_PAY_TO: "off" }, EVM), null);
  assert.equal(xlayerConfig({}, "not-an-address"), null);
});

test("dollar prices become USD₮0 amounts (6 decimals)", () => {
  assert.equal(usdt0Amount("$0.01"), "10000");
  assert.equal(usdt0Amount("$0.002"), "2000");
  assert.equal(usdt0Amount("$7.00"), "7000000");
  assert.throws(() => usdt0Amount("$0.0000001"));
});

test("every paid route and credit pack has a USD₮0-on-X-Layer option at the same dollar price; without it nothing changes", () => {
  for (const [key, r] of Object.entries(x402Routes(EVM, "eip155:8453", null, null, null, null, null, XL))) {
    const a = r.accepts.find((x) => x.network === XLAYER_NETWORK);
    assert.ok(a, key);
    assert.equal(a.payTo, EVM);
    assert.equal(a.price.asset, XLAYER_USDT0);
    assert.deepEqual(a.price.extra, { name: "USD₮0", version: "1" });
    assert.equal(a.price.amount, usdt0Amount(r.accepts[0].price), `${key}: same dollar price as Base`);
  }
  for (const r of Object.values(x402Routes(EVM, "eip155:8453"))) assert.ok(!r.accepts.some((a) => a.network === XLAYER_NETWORK));
  for (const r of Object.values(packRoutes("eip155:8453", EVM, null, null, null, null, XL))) assert.equal(r.accepts.at(-1).network, XLAYER_NETWORK);
});

test("the $0.01 check becomes 10000 units of USD₮0 with its EIP-712 domain, through the exact EVM scheme", async () => {
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: XLAYER_NETWORK }], extensions: [], signers: {} }),
    verify: async () => ({ isValid: false }),
    settle: async () => ({ success: false }),
  };
  const server = new x402ResourceServer([facilitator]).register(XLAYER_NETWORK, new ExactEvmScheme());
  await server.initialize();
  const accept = x402Routes(EVM, "eip155:8453", null, null, null, null, null, XL)["POST /v1/check"].accepts.at(-1);
  const [req] = await server.buildPaymentRequirements(accept);
  assert.equal(req.network, XLAYER_NETWORK);
  assert.equal(req.asset, XLAYER_USDT0);
  assert.equal(req.amount, "10000");
  assert.equal(req.payTo, EVM);
  assert.deepEqual(req.extra, { name: "USD₮0", version: "1" });
});

test("usage log names X Layer and counts USD₮0 in dollars", () => {
  assert.equal(usageLog.usdOf({ network: XLAYER_NETWORK, asset: XLAYER_USDT0, amount: "10000" }), 0.01);
});
