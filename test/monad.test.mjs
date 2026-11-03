// Monad (eip155:143): paying presign-guard in USDC on Monad (every paid route and credit pack, to PAY_TO by default),
// and checking Monad transactions before signing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { x402Routes, parseRequest } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { monadConfig, monadFacilitator, MONAD_NETWORK, MONAD_USDC, MONAD_FACILITATOR } from "../src/monad.js";
import usageLog from "../src/usage-log.cjs";

const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const OTHER = "0x551faCB18b3f173F300c944a3BDcbe1A2847A6AF";
const MON = { network: MONAD_NETWORK, payTo: EVM };
const routesWithMonad = () => x402Routes(EVM, "eip155:8453", null, null, null, null, null, null, MON);

test("monadConfig: PAY_TO by default, MONAD_PAY_TO overrides it, \"off\" turns it off", () => {
  assert.deepEqual(monadConfig({}, EVM), MON);
  assert.deepEqual(monadConfig({ MONAD_PAY_TO: OTHER }, EVM), { network: MONAD_NETWORK, payTo: OTHER });
  assert.equal(monadConfig({ MONAD_PAY_TO: "off" }, EVM), null);
  assert.equal(monadConfig({}, "not-an-address"), null);
});

test("monadFacilitator: the one in Monad's x402 guide by default, MONAD_FACILITATOR_URL or \"off\"", () => {
  assert.equal(MONAD_FACILITATOR, "https://x402-facilitator.molandak.org");
  assert.ok(monadFacilitator({}));
  assert.equal(monadFacilitator({ MONAD_FACILITATOR_URL: "off" }), null);
});

test("every paid route and credit pack has a USDC-on-Monad option at the same dollar price; without it nothing changes", () => {
  for (const [key, r] of Object.entries(routesWithMonad())) {
    const a = r.accepts.find((x) => x.network === MONAD_NETWORK);
    assert.ok(a, key);
    assert.equal(a.payTo, EVM);
    assert.equal(a.price, r.accepts[0].price, `${key}: same dollar price as Base`);
    assert.equal(r.accepts[0].network, "eip155:8453", `${key}: Base stays first`);
  }
  for (const r of Object.values(x402Routes(EVM, "eip155:8453"))) assert.ok(!r.accepts.some((a) => a.network === MONAD_NETWORK));
  for (const r of Object.values(packRoutes("eip155:8453", EVM, null, null, null, null, null, MON))) assert.equal(r.accepts.at(-1).network, MONAD_NETWORK);
});

test("the $0.01 check becomes 10000 units of Circle's USDC on Monad (domain USDC, version 2), through the exact EVM scheme", async () => {
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: MONAD_NETWORK }], extensions: [] }),
    verify: async () => ({ isValid: false }),
    settle: async () => ({ success: false }),
  };
  const server = new x402ResourceServer([facilitator]).register(MONAD_NETWORK, new ExactEvmScheme());
  await server.initialize();
  const accept = routesWithMonad()["POST /v1/check"].accepts.at(-1);
  const [req] = await server.buildPaymentRequirements(accept);
  assert.equal(req.network, MONAD_NETWORK);
  assert.equal(req.asset.toLowerCase(), MONAD_USDC);
  assert.equal(req.amount, "10000");
  assert.equal(req.payTo, EVM);
  assert.equal(req.extra.name, "USDC");
  assert.equal(req.extra.version, "2");
});

test("usage log names Monad and counts USDC in dollars", () => {
  assert.equal(usageLog.usdOf({ network: MONAD_NETWORK, asset: MONAD_USDC, amount: "10000" }), 0.01);
});

test("Monad (143) is a supported EVM chain for /v1/check", () => {
  const tx = { type: "transaction", chainId: 143, to: "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", data: "0x", value: "0" };
  assert.equal(parseRequest(tx).chainId, 143);
  assert.throws(() => parseRequest({ ...tx, chainId: 999 }), /Unsupported chainId\. Supported: .*143/);
});

test("Monad's USDC is a known official token, and /v1/token takes chain=monad", async () => {
  const { isOfficialToken } = await import("../src/jev.js");
  assert.equal(isOfficialToken(143, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603"), true);
  const { TOKEN_CHAINS } = await import("../src/token-verdict.js");
  assert.deepEqual(TOKEN_CHAINS.monad, { chainId: 143, dexscreener: "monad", approvals: false });
  const { TOKEN_INPUT_SCHEMA } = await import("../src/discovery.js");
  assert.ok(TOKEN_INPUT_SCHEMA.properties.chain.enum.includes("monad"));
});
