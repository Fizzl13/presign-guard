// Paying presign-guard in USDC on Algorand: every paid route and credit pack offers it when ALGORAND_PAY_TO is set.
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402ResourceServer } from "@x402/core/server";
import { ExactAvmScheme } from "@x402/avm/exact/server";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { algorandConfig, ALGORAND_NETWORK } from "../src/algorand.js";
import usageLog from "../src/usage-log.cjs";

const PAY_TO = "SGLTUPAC7TKGKNNXKNPQ2QZCC7NJSLAKYZ7O7NOGGAPXWBFZTOLTPMSPPI";
const FEE_PAYER = "ZMFK2OI7ZBD2U27ISERZC4S6LKM6WMFJPZQ4MYNJDZ2VNBNMBA67RA22AA";
const ALGO = { network: ALGORAND_NETWORK, payTo: PAY_TO };
const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";

test("algorandConfig: only with ALGORAND_PAY_TO, \"off\" turns it off", () => {
  assert.equal(algorandConfig({}), null);
  assert.equal(algorandConfig({ ALGORAND_PAY_TO: "off" }), null);
  assert.deepEqual(algorandConfig({ ALGORAND_PAY_TO: ` ${PAY_TO} ` }), ALGO);
});

test("every paid route and credit pack has a USDC-on-Algorand option; without it nothing changes", () => {
  for (const [key, r] of Object.entries(x402Routes(EVM, "eip155:8453", null, null, ALGO))) {
    const a = r.accepts.find((x) => x.network === ALGORAND_NETWORK);
    assert.ok(a, key);
    assert.equal(a.payTo, PAY_TO);
    assert.equal(a.price, r.accepts[0].price, `${key}: same dollar price as Base`);
  }
  for (const r of Object.values(x402Routes(EVM, "eip155:8453"))) assert.ok(!r.accepts.some((a) => a.network === ALGORAND_NETWORK));
  for (const r of Object.values(packRoutes("eip155:8453", EVM, null, null, ALGO))) assert.equal(r.accepts.at(-1).network, ALGORAND_NETWORK);
});

test("the $0.01 check becomes 10000 units of USDC (ASA 31566704) with the facilitator's fee payer", async () => {
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: ALGORAND_NETWORK, extra: { feePayer: FEE_PAYER } }], extensions: [], signers: {} }),
    verify: async () => ({ isValid: false }),
    settle: async () => ({ success: false }),
  };
  const server = new x402ResourceServer([facilitator]).register(ALGORAND_NETWORK, new ExactAvmScheme());
  await server.initialize();
  const accept = x402Routes(EVM, "eip155:8453", null, null, ALGO)["POST /v1/check"].accepts.at(-1);
  const [req] = await server.buildPaymentRequirements(accept);
  assert.equal(req.asset, "31566704");
  assert.equal(req.amount, "10000");
  assert.equal(req.extra.feePayer, FEE_PAYER);
});

test("usage log counts Algorand USDC in dollars", () => {
  assert.equal(usageLog.usdOf({ network: ALGORAND_NETWORK, asset: "31566704", amount: "10000" }), 0.01);
});
