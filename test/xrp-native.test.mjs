// XRP next to RLUSD on the XRP Ledger: drops at the pool's rate in the 402, none without a rate, never over MCP.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { x402ResourceServer } from "@x402/core/server";
import { ExactXrplScheme } from "@x402/xrpl/exact/server";
import { createXrplFacilitator, xrplAccept } from "../src/xrpl-facilitator.js";

const require = createRequire(import.meta.url);
const { createFacilitatorStart } = require("../src/facilitator-start.cjs");
const { createXrpRate, dropsFor, sharedXrpRate, RLUSD_HEX } = require("../src/xrp-rate.cjs");
const { usdOf } = require("../src/usage-log.cjs");

const XRPL = { network: "xrpl:0", payTo: "r9xmBsRr8Ao7jRgjjxreMiAwGiCK2FGwqw" };
const quiet = { warn() {} };

test("xrplAccept: RLUSD and an XRP price function; xrp false leaves XRP out", () => {
  const both = xrplAccept(XRPL, "$0.01", "POST /v1/check");
  assert.equal(both.length, 2);
  assert.equal(both[0].price, "$0.01");
  assert.equal(typeof both[1].price, "function");
  assert.equal(both[1].extra.invoiceId, "presign-guard.fizzl.eu POST /v1/check");
  assert.equal(xrplAccept({ ...XRPL, xrp: false }, "$0.01", "mcp presign_check").length, 1);
  assert.deepEqual(xrplAccept(null, "$0.01", "x"), []);
});

test("402: XRP in drops once there is a rate, the same amount on return", async () => {
  let pool = null;
  const rate = createXrpRate({ read: async () => pool, log: quiet });
  const start = createFacilitatorStart([createXrplFacilitator({ wsUrl: "wss://127.0.0.1:9", t54Url: "off" })], { log: quiet });
  const server = new x402ResourceServer(start.clients).register("xrpl:0", new ExactXrplScheme());
  await start.attach(server, ["xrpl:0"]).ready;
  const [rlusd, xrp] = xrplAccept(XRPL, "$0.02", "GET /v1/approvals");
  const options = [rlusd, { ...xrp, price: rate.price("$0.02") }];
  assert.equal((await server.buildPaymentRequirementsFromOptions(options, {})).length, 1, "no rate: RLUSD only");
  pool = 0.92;
  await rate.refresh();
  const reqs = await server.buildPaymentRequirementsFromOptions(options, {});
  const x = reqs.find((r) => r.asset === "XRP");
  assert.equal(x.amount, dropsFor("$0.02", 0.92));
  assert.equal(x.amount, "21800");
  assert.deepEqual((await server.buildPaymentRequirementsFromOptions(options, {})).find((r) => r.asset === "XRP"), x);
});

test("usage log: XRP's dollars only with a rate", () => {
  assert.equal(usdOf({ network: "xrpl:0", asset: RLUSD_HEX, amount: "0.01" }), 0.01);
  assert.equal(sharedXrpRate().usdOfDrops("10000") === null, true);
  assert.equal(usdOf({ network: "xrpl:0", asset: "XRP", amount: "10000" }), null);
});
