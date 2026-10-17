// Paying presign-guard in USDC on Stellar: every paid route and credit pack offers it when a Stellar facilitator is
// configured (STELLAR_FACILITATOR_KEY for OpenZeppelin's), paid to Frits's account unless STELLAR_PAY_TO says otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402ResourceServer } from "@x402/core/server";
import { ExactStellarScheme } from "@x402/stellar/exact/server";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { stellarConfig, STELLAR_NETWORK } from "../src/stellar.js";
import usageLog from "../src/usage-log.cjs";

const FRITS = "GCH2J5UAY24YNKA65MPAATVKWRCZZRZNF3JZKYYS5MIBZPG6U7WJ6CDQ";
const OTHER = "GABUG2A7VT3DRJ32WJB4EVSVYRKBZBMBU5GUIJOO5ESUV5UQEYNCPSVR";
const USDC_SAC = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";
const STELLAR = { network: STELLAR_NETWORK, payTo: FRITS };
const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";

test("stellarConfig: only with a Stellar facilitator; Frits's account by default, STELLAR_PAY_TO or \"off\" otherwise", () => {
  assert.equal(stellarConfig({}), null);
  assert.equal(stellarConfig({ STELLAR_PAY_TO: OTHER }), null, "no facilitator, no option");
  assert.deepEqual(stellarConfig({ STELLAR_FACILITATOR_KEY: "k" }), STELLAR);
  assert.deepEqual(stellarConfig({ STELLAR_FACILITATOR_URL: "https://facilitator.example" }), STELLAR);
  assert.deepEqual(stellarConfig({ STELLAR_FACILITATOR_KEY: "k", STELLAR_PAY_TO: ` ${OTHER} ` }), { network: STELLAR_NETWORK, payTo: OTHER });
  assert.equal(stellarConfig({ STELLAR_FACILITATOR_KEY: "k", STELLAR_PAY_TO: "off" }), null);
});

test("every paid route and credit pack has a USDC-on-Stellar option; without it nothing changes", () => {
  for (const [key, r] of Object.entries(x402Routes(EVM, "eip155:8453", null, null, null, null, STELLAR))) {
    const a = r.accepts.find((x) => x.network === STELLAR_NETWORK);
    assert.ok(a, key);
    assert.equal(a.payTo, FRITS);
    assert.equal(a.price, r.accepts[0].price, `${key}: same dollar price as Base`);
  }
  for (const r of Object.values(x402Routes(EVM, "eip155:8453"))) assert.ok(!r.accepts.some((a) => a.network === STELLAR_NETWORK));
  for (const r of Object.values(packRoutes("eip155:8453", EVM, null, null, null, STELLAR))) assert.equal(r.accepts.at(-1).network, STELLAR_NETWORK);
});

test("the $0.01 check becomes 100000 units of USDC (the Stellar Asset Contract) with sponsored fees", async () => {
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: STELLAR_NETWORK, extra: { areFeesSponsored: true } }], extensions: [], signers: {} }),
    verify: async () => ({ isValid: false }),
    settle: async () => ({ success: false }),
  };
  const server = new x402ResourceServer([facilitator]).register(STELLAR_NETWORK, new ExactStellarScheme());
  await server.initialize();
  const accept = x402Routes(EVM, "eip155:8453", null, null, null, null, STELLAR)["POST /v1/check"].accepts.at(-1);
  const [req] = await server.buildPaymentRequirements(accept);
  assert.equal(req.asset, USDC_SAC);
  assert.equal(req.amount, "100000");
  assert.equal(req.extra.areFeesSponsored, true);
});

test("usage log counts Stellar USDC in dollars (7 decimals)", () => {
  assert.equal(usageLog.usdOf({ network: STELLAR_NETWORK, asset: USDC_SAC, amount: "100000" }), 0.01);
  assert.equal(usageLog.usdOf({ network: "eip155:8453", amount: "10000" }), 0.01);
});
