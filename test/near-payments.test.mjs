// Paying presign-guard in USDC on NEAR (src/near-pay.js): every paid route and credit pack offers it when a relayer
// is configured, paid to x402fizzl.near unless NEAR_PAY_TO says otherwise. A buyer signs a real NEP-366
// SignedDelegate with @x402/near's own client; the in-process facilitator verifies and settles it against a
// stand-in chain (no network, no money).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { KeyPair } from "@near-js/crypto";
import { x402ResourceServer } from "@x402/core/server";
import { ExactNearScheme as NearServer } from "@x402/near/exact/server";
import { ExactNearScheme as NearClient } from "@x402/near/exact/client";
import { ExactNearScheme as NearFacilitatorScheme } from "@x402/near/exact/facilitator";
import { createClientNearSigner } from "@x402/near";
import { x402Routes } from "../src/presign-guard.js";
import { packRoutes } from "../src/credits.js";
import { nearConfig, nearFacilitator, nearAccept, nearStatus, NEAR_NETWORK, NEAR_USDC } from "../src/near-pay.js";
import usageLog from "../src/usage-log.cjs";

const EVM = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const KEY = KeyPair.fromRandom("ed25519").toString();
const ENV = { NEAR_RELAYER_ACCOUNT: "relay.x402fizzl.near", NEAR_RELAYER_KEY: KEY };
const NEAR = { network: NEAR_NETWORK, payTo: "x402fizzl.near", relayer: "relay.x402fizzl.near" };

test("nearConfig: only with a relayer account and key; x402fizzl.near by default, NEAR_PAY_TO or \"off\" otherwise", () => {
  assert.equal(nearConfig({}), null);
  assert.equal(nearConfig({ NEAR_RELAYER_ACCOUNT: "relay.x402fizzl.near" }), null, "no key, no option");
  assert.deepEqual(nearConfig(ENV), NEAR);
  assert.equal(nearConfig({ ...ENV, NEAR_PAY_TO: " shop.near " }).payTo, "shop.near");
  assert.equal(nearConfig({ ...ENV, NEAR_PAY_TO: "off" }), null);
  assert.throws(() => nearConfig({ ...ENV, NEAR_PAY_TO: "Not An Account" }), /not a NEAR account id/);
  assert.throws(() => nearConfig({ ...ENV, NEAR_RELAYER_KEY: "hunter2" }), /secret key like ed25519/);
  assert.throws(() => nearConfig({ ...ENV, NEAR_PAY_TO: "relay.x402fizzl.near" }), /must not be the payout account/);
});

test("every paid route and credit pack has a USDC-on-NEAR option at the same dollar price; without it nothing changes", () => {
  for (const [key, r] of Object.entries(x402Routes(EVM, "eip155:8453", null, null, null, null, null, null, null, [], NEAR))) {
    const a = r.accepts.find((x) => x.network === NEAR_NETWORK);
    assert.ok(a, key);
    assert.equal(a.payTo, "x402fizzl.near");
    assert.equal(a.price, r.accepts[0].price, `${key}: same dollar price as Base`);
  }
  for (const r of Object.values(x402Routes(EVM, "eip155:8453"))) assert.ok(!r.accepts.some((a) => a.network === NEAR_NETWORK));
  for (const r of Object.values(packRoutes("eip155:8453", EVM, null, null, null, null, null, null, [], NEAR))) assert.equal(r.accepts.at(-1).network, NEAR_NETWORK);
  assert.deepEqual(nearAccept(null, "$0.01"), []);
});

test("usage log counts NEAR USDC in dollars (6 decimals)", () => {
  assert.equal(usageLog.usdOf({ network: NEAR_NETWORK, asset: NEAR_USDC, amount: "10000" }), 0.01);
});

// A stand-in NEAR chain: the buyer's access key and balance, the payout account's USDC registration, and what the
// relayer submitted.
function chain({ registered = true, balance = 1_000_000n, slowMs = 0 } = {}) {
  const state = { height: 200_000_000n, nonce: 41n, submitted: [], inFlight: 0, maxInFlight: 0 };
  const signer = {
    getRelayerIds: () => ["relay.x402fizzl.near"],
    getCurrentBlockHeight: async () => state.height,
    viewAccount: async ({ accountId }) => (accountId === NEAR_USDC ? { codeHash: "9xEfaCt" } : { codeHash: "11111111111111111111111111111111" }),
    viewAccessKey: async () => ({ nonce: state.nonce, permissionKind: "FullAccess" }),
    ftBalanceOf: async () => balance,
    storageBalanceOf: async () => ({ supported: true, registered }),
    submitSignedDelegateAction: async (input) => {
      state.inFlight++;
      state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
      await new Promise((r) => setTimeout(r, slowMs));
      state.inFlight--;
      state.submitted.push(input);
      return { transaction: state.submitted.length === 1 ? "9rTxHashOnNear111" : `9rTxHashOnNear${state.submitted.length}`, innerReceipt: { kind: "success", value: "" } };
    },
  };
  // The buyer's client reads its access key and the latest block over JSON-RPC: a local server answers.
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { id, method, params } = JSON.parse(body);
      const result = method === "block"
        ? { header: { height: Number(state.height), hash: "GJ2rWJ6b5o3Qpt8ZJG9FVDdLzA5eJ8tR3W4aBk1C7nHx" } }
        : params?.request_type === "view_access_key"
          ? { nonce: Number(state.nonce), permission: "FullAccess", block_height: Number(state.height), block_hash: "GJ2rWJ6b5o3Qpt8ZJG9FVDdLzA5eJ8tR3W4aBk1C7nHx" }
          : null;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
    });
  });
  return { state, signer, server };
}

async function pay({ registered = true, tamper } = {}) {
  const { state, signer, server } = chain({ registered });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const facilitator = nearFacilitator(ENV, { scheme: new NearFacilitatorScheme(signer) });
    const resource = new x402ResourceServer([facilitator]).register(NEAR_NETWORK, new NearServer());
    await resource.initialize();
    const accept = x402Routes(EVM, "eip155:8453", null, null, null, null, null, null, null, [], NEAR)["POST /v1/check"].accepts.at(-1);
    const [req] = await resource.buildPaymentRequirements(accept);
    const buyer = createClientNearSigner({ accountId: "buyer.near", secretKey: KeyPair.fromRandom("ed25519").toString(), rpcUrls: { [NEAR_NETWORK]: `http://127.0.0.1:${server.address().port}` } });
    const partial = await new NearClient(buyer).createPaymentPayload(2, req);
    const payload = { x402Version: 2, accepted: req, payload: partial.payload };
    const checked = tamper ? { ...req, ...tamper } : req;
    return { req, state, verify: await facilitator.verify(payload, checked), settle: () => facilitator.settle(payload, checked) };
  } finally {
    server.close();
  }
}

test("the $0.01 check is 10000 units of USDC on NEAR; a buyer's signed delegate verifies and settles through our relayer", async () => {
  const { req, state, verify, settle } = await pay();
  assert.equal(req.asset, NEAR_USDC);
  assert.equal(req.amount, "10000");
  assert.equal(req.payTo, "x402fizzl.near");
  assert.equal(verify.isValid, true, JSON.stringify(verify));
  assert.equal(verify.payer, "buyer.near");
  const settled = await settle();
  assert.equal(settled.success, true, JSON.stringify(settled));
  assert.equal(settled.transaction, "9rTxHashOnNear111");
  assert.equal(state.submitted.length, 1);
  assert.equal(state.submitted[0].relayerId, "relay.x402fizzl.near");
  const again = await settle();
  assert.equal(again.success, false, "the same payment does not settle twice");
});

test("a payout account not registered on USDC, or a payment for another amount, is refused before anything is sent", async () => {
  const unregistered = await pay({ registered: false });
  assert.equal(unregistered.verify.isValid, false);
  assert.equal(unregistered.state.submitted.length, 0);
  const more = await pay({ tamper: { amount: "20000" } });
  assert.equal(more.verify.isValid, false);
});

test("nearStatus: reads the payout account's USDC registration and the relayer's NEAR, never throws", async () => {
  const replies = {
    storage_balance_of: { result: { result: [...Buffer.from(JSON.stringify(null))] } },
    view_account: { result: { amount: "2500000000000000000000000" } },
  };
  const fetchImpl = async (_url, { body }) => {
    const { params } = JSON.parse(body);
    const r = params.request_type === "view_account" ? replies.view_account : replies.storage_balance_of;
    return { json: async () => ({ jsonrpc: "2.0", id: 1, ...r }) };
  };
  assert.deepEqual(await nearStatus(NEAR, { fetchImpl }), { network: NEAR_NETWORK, pay_to: "x402fizzl.near", relayer: "relay.x402fizzl.near", pay_to_registered: false, relayer_near: 2.5 });
  const down = await nearStatus(NEAR, { fetchImpl: async () => { throw new Error("offline"); } });
  assert.equal(down.pay_to_registered, null);
  assert.equal(down.relayer_near, null);
  assert.equal(await nearStatus(null), null);
});

test("settles go one at a time (the relayer's nonce), and a payment sent twice at once settles once", async () => {
  const { state, signer, server } = chain({ slowMs: 40 });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const facilitator = nearFacilitator(ENV, { scheme: new NearFacilitatorScheme(signer) });
    const resource = new x402ResourceServer([facilitator]).register(NEAR_NETWORK, new NearServer());
    await resource.initialize();
    const accept = x402Routes(EVM, "eip155:8453", null, null, null, null, null, null, null, [], NEAR)["POST /v1/check"].accepts.at(-1);
    const [req] = await resource.buildPaymentRequirements(accept);
    const rpcUrls = { [NEAR_NETWORK]: `http://127.0.0.1:${server.address().port}` };
    const payloads = await Promise.all([1, 2, 3].map(async () => {
      const buyer = createClientNearSigner({ accountId: "buyer.near", secretKey: KeyPair.fromRandom("ed25519").toString(), rpcUrls });
      return { x402Version: 2, accepted: req, payload: (await new NearClient(buyer).createPaymentPayload(2, req)).payload };
    }));
    const outs = await Promise.all([...payloads, payloads[0]].map((p) => facilitator.settle(p, req)));
    assert.deepEqual(outs.map((o) => o.success), [true, true, true, false]);
    assert.equal(outs[3].errorReason, "duplicate_settlement");
    assert.equal(state.submitted.length, 3);
    assert.equal(state.maxInFlight, 1, "never two settles on the chain at once");
  } finally {
    server.close();
  }
});
