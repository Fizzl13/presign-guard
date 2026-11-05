// presign-guard takes USDC on Polygon, Arbitrum and Avalanche too (src/extra-evm.js), and the 402 stays small.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extraEvmConfig, extraEvmAccept, EXTRA_EVM } from "../src/extra-evm.js";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";

const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const OTHER = "0x551faCB18b3f173F300c944a3BDcbe1A2847A6AF";
const NETWORKS = ["eip155:137", "eip155:42161", "eip155:43114"];

test("extraEvmConfig: the three networks to PAY_TO; <NAME>_PAY_TO overrides, off leaves one out", () => {
  assert.deepEqual(Object.values(EXTRA_EVM), NETWORKS);
  assert.deepEqual(extraEvmConfig({}, PAY_TO), NETWORKS.map((network) => ({ network, payTo: PAY_TO })));
  const env = { ARBITRUM_PAY_TO: OTHER, POLYGON_PAY_TO: "off" };
  assert.deepEqual(extraEvmConfig(env, PAY_TO), [{ network: "eip155:42161", payTo: OTHER }, { network: "eip155:43114", payTo: PAY_TO }]);
  assert.deepEqual(extraEvmConfig({}, "not-an-address"), []);
  assert.deepEqual(extraEvmAccept(null, "$0.01"), []);
});

test("every paid route and credit pack offers the three networks at the same dollar price", () => {
  const extra = extraEvmConfig({}, PAY_TO);
  const routes = x402Routes(PAY_TO, "eip155:8453", null, null, null, null, null, null, null, extra);
  for (const [name, route] of Object.entries(routes)) {
    const base = route.accepts.find((a) => a.network === "eip155:8453");
    for (const n of NETWORKS) {
      const a = route.accepts.find((x) => x.network === n);
      assert.ok(a, `${name}: ${n}`);
      assert.equal(a.price, base.price, `${name}: ${n} price`);
      assert.equal(a.payTo, PAY_TO);
    }
    assert.equal(route.accepts[0].network, "eip155:8453", `${name}: Base stays first`);
  }
  for (const [name, pack] of Object.entries(packRoutes("eip155:8453", PAY_TO, null, null, null, null, null, null, extra))) {
    for (const n of NETWORKS) assert.ok(pack.accepts.some((a) => a.network === n), `${name}: ${n}`);
  }
  // Without extraEvm (local and test runs): only Base.
  assert.deepEqual(x402Routes(PAY_TO)["POST /v1/check"].accepts.map((a) => a.network), ["eip155:8453"]);
});

test("the usage log names the three networks", async () => {
  const { createRequire } = await import("node:module");
  const src = (await import("node:fs")).readFileSync(new URL("../src/usage-log.cjs", import.meta.url), "utf8");
  for (const [n, name] of [["eip155:137", "polygon"], ["eip155:42161", "arbitrum"], ["eip155:43114", "avalanche"]]) assert.match(src, new RegExp(`'${n}': '${name}'`));
  const { usdOf } = createRequire(import.meta.url)("../src/usage-log.cjs");
  assert.equal(usdOf({ network: "eip155:43114", amount: "10000" }), 0.01);
});
