// Algorand transaction checks (src/algorand-tx.js) against a stand-in node: no network, no money.
import { test } from "node:test";
import assert from "node:assert/strict";
import algosdk from "algosdk";
import { parseAlgorandRequest, algorandReasons, simulateAlgorand, algorandSimulationReasons } from "../src/algorand-tx.js";
import { analyze, parseRequest } from "../src/presign-guard.js";

const W = algosdk.generateAccount().addr.toString();
const OTHER = algosdk.generateAccount().addr.toString();
const THIRD = algosdk.generateAccount().addr.toString();
const MAINNET = Buffer.from("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=", "base64");
const sp = (genesisHash = MAINNET) => ({ fee: 1000, minFee: 1000, flatFee: true, firstValid: 1000, lastValid: 2000, genesisHash, genesisID: "mainnet-v1.0" });
const b64 = (t) => Buffer.from(algosdk.encodeUnsignedTransaction(t)).toString("base64");
const pay = (o = {}) => algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: W, receiver: OTHER, amount: 1_000_000, suggestedParams: sp(), ...o });
const axfer = (o = {}) => algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: W, receiver: OTHER, amount: 5, assetIndex: 31566704, suggestedParams: sp(), ...o });
const appl = (onComplete, appIndex = 123) => algosdk.makeApplicationCallTxnFromObject({ sender: W, appIndex, onComplete, suggestedParams: sp() });
const codes = (reasons) => reasons.map((r) => r.code);
const sev = (reasons, code) => reasons.find((r) => r.code === code)?.severity;

const ASSETS = {
  31566704: { "unit-name": "USDC", name: "USDC", creator: THIRD, freeze: THIRD, decimals: 6 },
  999: { "unit-name": "USDC", name: "USD Coin", creator: THIRD, decimals: 6 },
  777: { "unit-name": "GAME", name: "Game token", creator: THIRD, clawback: THIRD, decimals: 0 },
  555: { "unit-name": "OWN", name: "Own token", creator: W, manager: W, reserve: W, freeze: W, clawback: W, decimals: 0 },
};
// A stand-in algod: assets, holdings, accounts and simulate. sim: what simulate answers.
function fakeNode({ holdings = {}, rekeyed = {}, sim = { ok: true }, down = false } = {}) {
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push(url);
    if (down) throw new Error("connect ECONNREFUSED");
    const u = new URL(url);
    let m;
    if ((m = u.pathname.match(/^\/v2\/assets\/(\d+)$/))) return ASSETS[m[1]] ? Response.json({ index: Number(m[1]), params: ASSETS[m[1]] }) : new Response("{}", { status: 404 });
    if ((m = u.pathname.match(/^\/v2\/accounts\/([A-Z2-7]+)\/assets\/(\d+)$/))) {
      const h = holdings[`${m[1]}:${m[2]}`];
      return h === undefined ? new Response("{}", { status: 404 }) : Response.json({ "asset-holding": { amount: h, "asset-id": Number(m[2]) } });
    }
    if ((m = u.pathname.match(/^\/v2\/accounts\/([A-Z2-7]+)$/))) return Response.json({ address: m[1], amount: 5_000_000, ...(rekeyed[m[1]] && { "auth-addr": rekeyed[m[1]] }) });
    if (u.pathname === "/v2/transactions/simulate") {
      assert.equal(opts.headers["content-type"], "application/msgpack");
      return Response.json({ "txn-groups": [{ ...(sim.ok ? {} : { "failure-message": sim.error, "failed-at": [0] }), "txn-results": sim.results ?? [{ "txn-result": {} }] }] });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, calls };
}
async function check(body, node = fakeNode()) {
  const req = parseAlgorandRequest(body);
  const rules = await algorandReasons(req, { fetchImpl: node.fetchImpl });
  const sim = await simulateAlgorand(req, { fetchImpl: node.fetchImpl });
  return [...rules.reasons, ...algorandSimulationReasons(sim, req, rules.reasons)];
}

test("parse: the network from the genesis hash, the wallet (first sender, or from), unsigned and signed transactions; bad input is refused", () => {
  const req = parseAlgorandRequest({ transaction: b64(pay()) });
  assert.equal(req.network, "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=");
  assert.equal(req.wallet, W);
  assert.equal(req.group, "none");
  const signed = Buffer.from(algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn: pay() }))).toString("base64");
  assert.equal(parseAlgorandRequest({ transaction: signed }).txns[0].type, "pay");
  assert.equal(parseAlgorandRequest({ transaction: b64(pay()), from: OTHER }).wallet, OTHER);
  assert.equal(parseAlgorandRequest({ transaction: b64(pay()), network: "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k" }).network, req.network, "the short CAIP-2 form");
  assert.throws(() => parseAlgorandRequest({}), /transaction .* is required/);
  assert.throws(() => parseAlgorandRequest({ transaction: "not base64!" }), /base64 msgpack/);
  assert.throws(() => parseAlgorandRequest({ transaction: Buffer.from("hello").toString("base64") }), /could not be decoded/);
  assert.throws(() => parseAlgorandRequest({ transaction: b64(pay({ suggestedParams: sp(Buffer.alloc(32, 7)) })) }), /unsupported Algorand network/);
  assert.throws(() => parseAlgorandRequest({ transaction: b64(pay()), network: "testnet" }), /does not match/);
  assert.throws(() => parseAlgorandRequest({ transaction: b64(pay()), from: "nope" }), /valid Algorand address/);
  assert.throws(() => parseAlgorandRequest({ transactions: Array(17).fill(b64(pay())) }), /at most 16/);
  assert.throws(() => parseRequest({ type: "algorand" }), (e) => e.status === 400);
});

test("a plain payment is green; it is simulated", async () => {
  const reasons = await check({ transaction: b64(pay()) });
  assert.deepEqual(reasons.filter((r) => r.severity !== "info"), []);
  assert.ok(codes(reasons).includes("SIMULATED"));
});

test("rekey to another key and closing the account are red; the simulation adds what a close would send", async () => {
  assert.equal(sev(await check({ transaction: b64(pay({ rekeyTo: OTHER })) }), "ALGORAND_REKEY"), "red");
  assert.equal(sev(await check({ transaction: b64(pay({ rekeyTo: W })) }), "ALGORAND_REKEY_BACK"), "info");
  const reasons = await check({ transaction: b64(pay({ closeRemainderTo: OTHER })) }, fakeNode({ sim: { ok: true, results: [{ "txn-result": { "closing-amount": 12_500_000 } }] } }));
  const close = reasons.find((r) => r.code === "ALGORAND_CLOSE_ACCOUNT");
  assert.equal(close.severity, "red");
  assert.equal(close.subject, OTHER);
  assert.equal(close.details.closingAlgo, 12.5);
});

test("asset close: red when there is a balance, an opt-out when there is none, orange when the node can't say", async () => {
  const id = 777;
  const t = () => b64(axfer({ assetIndex: id, receiver: W, amount: 0, closeRemainderTo: OTHER }));
  const full = await check({ transaction: t() }, fakeNode({ holdings: { [`${W}:${id}`]: 40 } }));
  assert.equal(sev(full, "ALGORAND_ASSET_CLOSE"), "red");
  assert.equal(full.find((r) => r.code === "ALGORAND_ASSET_CLOSE").details.balance, "40");
  const empty = await check({ transaction: t() }, fakeNode({ holdings: { [`${W}:${id}`]: 0 } }));
  assert.ok(codes(empty).includes("ALGORAND_ASSET_OPT_OUT"));
  assert.ok(!codes(empty).includes("ALGORAND_ASSET_CLOSE"));
  const down = await check({ transaction: t() }, fakeNode({ down: true }));
  assert.equal(sev(down, "ALGORAND_ASSET_CLOSE"), "orange");
  assert.ok(codes(down).includes("ALGORAND_NODE_UNAVAILABLE"));
  assert.ok(codes(down).includes("SIMULATION_UNAVAILABLE"));
});

test("assets: fake USDC is red, the real one is fine; opting in to an asset with a clawback is orange; a clawback transfer is orange", async () => {
  const fake = await check({ transaction: b64(axfer({ assetIndex: 999, receiver: W, amount: 0 })) });
  assert.equal(sev(fake, "ALGORAND_FAKE_STABLECOIN"), "red");
  const real = await check({ transaction: b64(axfer({ assetIndex: 31566704, receiver: W, amount: 0 })) });
  assert.deepEqual(real.filter((r) => r.severity !== "info"), [], "opting in to Circle's USDC");
  assert.equal(sev(await check({ transaction: b64(axfer({ assetIndex: 777, receiver: W, amount: 0 })) }), "ALGORAND_ASSET_CLAWBACK"), "orange");
  assert.equal(sev(await check({ transaction: b64(axfer({ assetIndex: 777, assetSender: OTHER, receiver: W })) }), "ALGORAND_CLAWBACK_TRANSFER"), "orange");
});

test("apps: update, delete and clear-state are orange; a normal call is information", async () => {
  const OC = algosdk.OnApplicationComplete;
  assert.equal(sev(await check({ transaction: b64(appl(OC.ClearStateOC)) }), "ALGORAND_APP_CLEAR_STATE"), "orange");
  assert.equal(sev(await check({ transaction: b64(appl(OC.DeleteApplicationOC)) }), "ALGORAND_APP_UPDATE_OR_DELETE"), "orange");
  const call = await check({ transaction: b64(appl(OC.NoOpOC)) });
  assert.equal(sev(call, "ALGORAND_APP_CALL"), "info");
  assert.deepEqual(call.filter((r) => r.severity !== "info"), []);
});

test("asset config, key registration and fees", async () => {
  const destroy = algosdk.makeAssetDestroyTxnWithSuggestedParamsFromObject({ sender: W, assetIndex: 555, suggestedParams: sp() });
  assert.equal(sev(await check({ transaction: b64(destroy) }), "ALGORAND_ASSET_DESTROY"), "orange");
  const handOver = algosdk.makeAssetConfigTxnWithSuggestedParamsFromObject({ sender: W, assetIndex: 555, manager: OTHER, reserve: W, freeze: W, clawback: undefined, strictEmptyAddressChecking: false, suggestedParams: sp() });
  const cfg = await check({ transaction: b64(handOver) });
  assert.ok(cfg.some((r) => r.code === "ALGORAND_ASSET_CONTROL_CHANGE" && r.details.field === "manager"));
  assert.ok(cfg.some((r) => r.code === "ALGORAND_ASSET_CONTROL_CLEARED" && r.details.field === "clawback"));
  const kr = algosdk.makeKeyRegistrationTxnWithSuggestedParamsFromObject({ sender: W, nonParticipation: true, suggestedParams: sp() });
  assert.equal(sev(await check({ transaction: b64(kr) }), "ALGORAND_KEYREG_NONPARTICIPATION"), "orange");
  const fee = pay({ suggestedParams: { ...sp(), fee: 2_000_000 } });
  assert.equal(sev(await check({ transaction: b64(fee) }), "ALGORAND_HIGH_FEE"), "orange");
});

test("groups: a whole group is checked, only the wallet's own transactions count, and a partial or tampered group is orange", async () => {
  const [mine, theirs] = algosdk.assignGroupID([pay(), algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: OTHER, receiver: W, amount: 5, rekeyTo: THIRD, suggestedParams: sp() })]);
  const whole = await check({ transactions: [b64(mine), b64(theirs)] });
  assert.ok(!codes(whole).includes("ALGORAND_REKEY"), "the other sender's rekey is theirs to sign");
  assert.ok(codes(whole).includes("ALGORAND_GROUP_OTHER_SENDERS"));
  assert.deepEqual(whole.filter((r) => r.severity !== "info"), []);
  assert.equal(sev(await check({ transaction: b64(mine) }), "ALGORAND_GROUP_UNSEEN"), "orange");
  const [a] = algosdk.assignGroupID([pay(), pay({ amount: 2 })]);
  const [, b] = algosdk.assignGroupID([pay(), pay({ amount: 3 })]);
  assert.equal(sev(await check({ transactions: [b64(a), b64(b)] }), "ALGORAND_GROUP_MISMATCH"), "orange");
});

test("simulation: a failing group is orange, and a rekeyed sender is simulated with its signing key", async () => {
  const fails = await check({ transaction: b64(pay()) }, fakeNode({ sim: { ok: false, error: "overspend" } }));
  assert.equal(sev(fails, "SIMULATION_FAILS"), "orange");
  assert.equal(fails.find((r) => r.code === "SIMULATION_FAILS").details.error, "overspend");
  const node = fakeNode({ rekeyed: { [W]: THIRD } });
  const reasons = await check({ transaction: b64(pay()) }, node);
  assert.ok(codes(reasons).includes("ALGORAND_ACCOUNT_REKEYED"));
  assert.ok(codes(reasons).includes("SIMULATED"));
});

test("POST /v1/check with type algorand: the verdict, the network and what each transaction does", async () => {
  const real = globalThis.fetch;
  globalThis.fetch = fakeNode().fetchImpl;
  try {
    const result = await analyze(parseRequest({ type: "algorand", transaction: b64(pay({ rekeyTo: OTHER })) }));
    assert.equal(result.verdict, "red");
    assert.equal(result.subject.kind, "algorand_transaction");
    assert.equal(result.subject.network, "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=");
    assert.equal(result.subject.transactions[0].rekeyTo, OTHER);
    assert.equal(result.subject.transactions[0].amountAlgo, 1);
    assert.ok(result.sources.includes("algod"));
    const green = await analyze(parseRequest({ type: "algorand", transaction: b64(pay()) }));
    assert.equal(green.verdict, "green");
  } finally {
    globalThis.fetch = real;
  }
});
