// Stellar transaction checks (src/stellar-tx.js) against a stand-in Horizon and Soroban RPC: no network, no money.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, Account, TransactionBuilder, Networks, Operation, Asset, Memo, Address, StrKey, xdr, nativeToScVal } from "@stellar/stellar-sdk";
import { parseStellarRequest, stellarReasons, simulateStellar, stellarSimulationReasons, StellarValidationError } from "../src/stellar-tx.js";
import { analyze, parseRequest } from "../src/presign-guard.js";

const W = Keypair.random().publicKey();
const OTHER = Keypair.random().publicKey();
const FACILITATOR = Keypair.random().publicKey();
const EXCHANGE = Keypair.random().publicKey();
const MISSING = Keypair.random().publicKey();
const CIRCLE = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const FAKE_ISSUER = Keypair.random().publicKey();
const USDC = new Asset("USDC", CIRCLE);
const FAKE_USDC = new Asset("USDC", FAKE_ISSUER);
const USDC_SAC = USDC.contractId(Networks.PUBLIC);
const FAKE_SAC = FAKE_USDC.contractId(Networks.PUBLIC);
const codes = (reasons) => reasons.map((r) => r.code);
const sev = (reasons, code) => reasons.find((r) => r.code === code)?.severity;

// A transaction from `source` with these operations, as base64 XDR.
function build(ops, { source = W, memo, fee = "100" } = {}) {
  const b = new TransactionBuilder(new Account(source, "100"), { fee, networkPassphrase: Networks.PUBLIC });
  for (const op of ops) b.addOperation(op);
  if (memo) b.addMemo(memo);
  return b.setTimeout(300).build();
}
const b64 = (ops, o) => build(ops, o).toXDR();

// A Soroban authorization signed by `who` for contract.fn(args), with sub-calls.
const invocation = (contract, fn, args, subs = []) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({ contractAddress: Address.fromString(contract).toScAddress(), functionName: fn, args })),
  subInvocations: subs,
});
const authBy = (who, root) => new xdr.SorobanAuthorizationEntry({
  credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({ address: Address.fromString(who).toScAddress(), nonce: xdr.Int64.fromString("7"), signatureExpirationLedger: 1000, signature: xdr.ScVal.scvVoid() })),
  rootInvocation: root,
});
const addr = (a) => nativeToScVal(a, { type: "address" });
const i128 = (n) => nativeToScVal(BigInt(n), { type: "i128" });
const call = (contract, fn, args, auth) => Operation.invokeContractFunction({ contract, function: fn, args, auth });

// An x402 payment as the facilitator sends it: the facilitator's transaction, the buyer's authorization of the USDC
// transfer, wrapped in a fee bump.
function x402Payment({ amount = 100000, token = USDC_SAC } = {}) {
  const args = [addr(W), addr(OTHER), i128(amount)];
  const inner = build([call(token, "transfer", args, [authBy(W, invocation(token, "transfer", args))])], { source: FACILITATOR });
  const kp = Keypair.random();
  inner.sign(kp);
  return TransactionBuilder.buildFeeBumpTransaction(Keypair.random(), "20000", inner, Networks.PUBLIC).toXDR();
}

// A contract event as the RPC returns it: base64 DiagnosticEvent.
function event(contract, topics, data) {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: true,
    event: new xdr.ContractEvent({
      ext: new xdr.ExtensionPoint(0),
      contractId: StrKey.decodeContract(contract),
      type: xdr.ContractEventType.contract(),
      body: new xdr.ContractEventBody(0, new xdr.ContractEventV0({ topics, data })),
    }),
  }).toXDR("base64");
}
const transferEvent = (token, from, to, amount, asset) => event(token, [nativeToScVal("transfer", { type: "symbol" }), addr(from), addr(to), ...(asset ? [nativeToScVal(asset)] : [])], i128(amount));
const approveEvent = (token, from, spender, amount, asset) => event(token, [nativeToScVal("approve", { type: "symbol" }), addr(from), addr(spender), ...(asset ? [nativeToScVal(asset)] : [])], nativeToScVal([i128(amount), nativeToScVal(5000, { type: "u32" })]));

// A stand-in Horizon and Soroban RPC. accounts: id → Horizon account (missing ones are 404). sim: the RPC's result.
function fakeNode({ accounts = {}, sim = { events: [] }, down = false } = {}) {
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, body: opts.body });
    if (down) throw new Error("connect ECONNREFUSED");
    const u = new URL(url);
    let m;
    if ((m = u.pathname.match(/^\/accounts\/(G[A-Z2-7]{55})$/))) {
      if (m[1] === W) return Response.json({ id: W, signers: [{ key: W, weight: 1 }], data: {} });
      return accounts[m[1]] ? Response.json(accounts[m[1]]) : new Response("{}", { status: 404 });
    }
    if (opts.method === "POST") {
      const body = JSON.parse(opts.body);
      assert.equal(body.method, "simulateTransaction");
      return Response.json({ jsonrpc: "2.0", id: 1, result: sim });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, calls };
}
const live = { [OTHER]: { id: OTHER, data: {} }, [EXCHANGE]: { id: EXCHANGE, data: { "config.memo_required": "MQ==" } } };
async function check(body, node = fakeNode({ accounts: live })) {
  const req = parseStellarRequest({ type: "stellar", ...body });
  const rules = await stellarReasons(req, { fetchImpl: node.fetchImpl });
  const sim = await simulateStellar(req, { fetchImpl: node.fetchImpl });
  return [...rules.reasons, ...stellarSimulationReasons(sim, req, rules.reasons)];
}

test("parse: network, wallet (source, the one authorizing account, or from), fee bumps; bad input is refused", () => {
  const plain = parseStellarRequest({ transaction: b64([Operation.payment({ destination: OTHER, asset: Asset.native(), amount: "1" })]) });
  assert.equal(plain.network, "pubnet");
  assert.equal(plain.wallet, W);
  assert.equal(plain.feeSource, null);
  const pay = parseStellarRequest({ transaction: x402Payment(), network: "stellar:pubnet" });
  assert.equal(pay.wallet, W, "the buyer who authorizes the transfer, not the facilitator that sends it");
  assert.ok(pay.feeSource);
  assert.equal(parseStellarRequest({ transaction: x402Payment(), from: OTHER }).wallet, OTHER);
  for (const bad of [{}, { transaction: "" }, { transaction: "not base64!" }, { transaction: "AAAA" }, { transaction: "A".repeat(12004) }]) {
    assert.throws(() => parseStellarRequest(bad), StellarValidationError);
  }
  assert.throws(() => parseStellarRequest({ transaction: x402Payment(), network: "futurenet" }), /unsupported Stellar network/);
  assert.throws(() => parseStellarRequest({ transaction: x402Payment(), from: "0xabc" }), /from must be/);
  // A testnet transaction read as pubnet still decodes (the passphrase only matters for signatures).
  assert.equal(parseStellarRequest({ transaction: x402Payment(), network: "testnet" }).network, "testnet");
});

test("an x402 payment in Circle's USDC is green: a transfer the buyer authorizes, simulated", async () => {
  const node = fakeNode({ accounts: live, sim: { events: [transferEvent(USDC_SAC, W, OTHER, 100000, `USDC:${CIRCLE}`)] } });
  const reasons = await check({ transaction: x402Payment() }, node);
  assert.ok(!reasons.some((r) => r.severity !== "info"), JSON.stringify(reasons));
  assert.ok(codes(reasons).includes("STELLAR_FEE_BUMP"));
  assert.ok(codes(reasons).includes("STELLAR_TOKEN_TRANSFER"));
  const simulated = reasons.find((r) => r.code === "SIMULATED");
  assert.deepEqual(simulated.details.outgoing, [{ to: OTHER, token: USDC_SAC, asset: `USDC:${CIRCLE}`, amount: "100000" }]);
  // The RPC got the call without the authorizations, so the signatures don't matter.
  const sent = JSON.parse(node.calls.find((c) => c.body).body).params.transaction;
  const op = TransactionBuilder.fromXDR(sent, Networks.PUBLIC).operations[0];
  assert.equal(op.type, "invokeHostFunction");
  assert.equal(op.auth.length, 0);
});

test("a payment in a fake USDC is red, in the operation and in a simulated token transfer", async () => {
  const reasons = await check({ transaction: b64([Operation.payment({ destination: OTHER, asset: FAKE_USDC, amount: "10" })]) });
  assert.equal(sev(reasons, "STELLAR_FAKE_STABLECOIN"), "red");
  assert.equal(reasons.find((r) => r.code === "STELLAR_FAKE_STABLECOIN").details.real, `USDC:${CIRCLE}`);
  const node = fakeNode({ accounts: live, sim: { events: [transferEvent(FAKE_SAC, W, OTHER, 5, `USDC:${FAKE_ISSUER}`)] } });
  const sim = await check({ transaction: x402Payment({ token: FAKE_SAC }) }, node);
  assert.equal(sev(sim, "STELLAR_FAKE_STABLECOIN"), "red");
  // Circle's own USDC, a trustline to it and a DEX offer with it are fine.
  const ok = await check({ transaction: b64([Operation.changeTrust({ asset: USDC }), Operation.manageSellOffer({ selling: Asset.native(), buying: USDC, amount: "1", price: "0.1" })]) });
  assert.ok(!ok.some((r) => r.severity !== "info"), JSON.stringify(ok));
  assert.equal(sev(await check({ transaction: b64([Operation.changeTrust({ asset: FAKE_USDC })]) }), "STELLAR_FAKE_STABLECOIN"), "red");
});

test("handing the account over is red: merge, another signer, master key off; thresholds orange", async () => {
  assert.equal(sev(await check({ transaction: b64([Operation.accountMerge({ destination: OTHER })]) }), "STELLAR_ACCOUNT_MERGE"), "red");
  assert.equal(sev(await check({ transaction: b64([Operation.setOptions({ signer: { ed25519PublicKey: OTHER, weight: 1 } })]) }), "STELLAR_SIGNER_ADDED"), "red");
  assert.equal(sev(await check({ transaction: b64([Operation.setOptions({ signer: { ed25519PublicKey: OTHER, weight: 0 } })]) }), "STELLAR_SIGNER_REMOVED"), "info");
  assert.equal(sev(await check({ transaction: b64([Operation.setOptions({ masterWeight: 0 })]) }), "STELLAR_MASTER_KEY_DISABLED"), "red");
  assert.equal(sev(await check({ transaction: b64([Operation.setOptions({ highThreshold: 2 })]) }), "STELLAR_THRESHOLDS_CHANGED"), "orange");
  // Another account's operation in the same transaction is that account's to sign.
  const theirs = await check({ transaction: b64([Operation.accountMerge({ destination: W, source: OTHER })]) });
  assert.ok(!codes(theirs).includes("STELLAR_ACCOUNT_MERGE"));
  assert.ok(codes(theirs).includes("STELLAR_OTHER_SOURCE"));
});

test("payments: a missing memo for an exchange, a destination that doesn't exist, a path payment without minimum", async () => {
  const toExchange = (memo) => b64([Operation.payment({ destination: EXCHANGE, asset: Asset.native(), amount: "5" })], { memo });
  assert.equal(sev(await check({ transaction: toExchange() }), "STELLAR_MEMO_REQUIRED"), "orange");
  assert.ok(!codes(await check({ transaction: toExchange(Memo.id("42")) })).includes("STELLAR_MEMO_REQUIRED"));
  assert.equal(sev(await check({ transaction: b64([Operation.payment({ destination: MISSING, asset: Asset.native(), amount: "5" })]) }), "STELLAR_DESTINATION_MISSING"), "orange");
  const path = b64([Operation.pathPaymentStrictSend({ sendAsset: Asset.native(), sendAmount: "100", destination: OTHER, destAsset: USDC, destMin: "0.0000001", path: [] })]);
  assert.equal(sev(await check({ transaction: path }), "STELLAR_PATH_NO_MINIMUM"), "orange");
  assert.equal(sev(await check({ transaction: b64([Operation.bumpSequence({ bumpTo: "200" })], { fee: "60000000" }) }), "STELLAR_HIGH_FEE"), "orange");
});

test("Soroban approvals the wallet authorizes are orange, also hidden in a sub-call or only in the simulation", async () => {
  const unlimited = (2n ** 127n - 1n).toString();
  const approveArgs = [addr(W), addr(OTHER), i128(unlimited), nativeToScVal(5000, { type: "u32" })];
  const direct = b64([call(USDC_SAC, "approve", approveArgs, [authBy(W, invocation(USDC_SAC, "approve", approveArgs))])]);
  const r1 = await check({ transaction: direct });
  assert.equal(sev(r1, "STELLAR_TOKEN_APPROVE"), "orange");
  assert.equal(r1.find((r) => r.code === "STELLAR_TOKEN_APPROVE").details.amount, "unlimited");

  // A "claim" on some contract whose authorization also covers an approve to someone else.
  const DAPP = StrKey.encodeContract(Buffer.alloc(32, 9));
  const claim = [addr(W)];
  const hidden = b64([call(DAPP, "claim", claim, [authBy(W, invocation(DAPP, "claim", claim, [invocation(USDC_SAC, "approve", [addr(W), addr(OTHER), i128(1000), nativeToScVal(5000, { type: "u32" })])]))])]);
  const r2 = await check({ transaction: hidden });
  assert.equal(sev(r2, "STELLAR_HIDDEN_APPROVE"), "orange");
  assert.equal(r2.find((r) => r.code === "STELLAR_HIDDEN_APPROVE").subject, OTHER);

  // Nothing in the authorization, but the simulation shows an approval from the wallet.
  const plainClaim = b64([call(DAPP, "claim", claim, [authBy(W, invocation(DAPP, "claim", claim))])]);
  const node = fakeNode({ accounts: live, sim: { events: [approveEvent(USDC_SAC, W, OTHER, 50, `USDC:${CIRCLE}`)] } });
  assert.equal(sev(await check({ transaction: plainClaim }, node), "STELLAR_HIDDEN_APPROVE"), "orange");
  // Someone else's authorization in the same call is not the wallet's.
  const theirs = b64([call(USDC_SAC, "approve", approveArgs, [authBy(OTHER, invocation(USDC_SAC, "approve", [addr(OTHER), addr(W), i128(1), nativeToScVal(5000, { type: "u32" })]))])]);
  assert.ok(!codes(await check({ transaction: theirs, from: W })).includes("STELLAR_TOKEN_APPROVE"));
});

test("a call that fails in simulation is orange; no RPC or Horizon is info, never a guessed green", async () => {
  const failing = fakeNode({ accounts: live, sim: { error: "HostError: Error(Contract, #10)\nmore" } });
  const r1 = await check({ transaction: x402Payment() }, failing);
  assert.equal(sev(r1, "SIMULATION_FAILS"), "orange");
  assert.equal(r1.find((r) => r.code === "SIMULATION_FAILS").details.error, "HostError: Error(Contract, #10)");
  const r2 = await check({ transaction: x402Payment() }, fakeNode({ down: true }));
  assert.ok(codes(r2).includes("SIMULATION_UNAVAILABLE"));
  assert.ok(codes(r2).includes("STELLAR_NODE_UNAVAILABLE"));
  // A classic-only transaction isn't simulated.
  const node = fakeNode({ accounts: live });
  await check({ transaction: b64([Operation.payment({ destination: OTHER, asset: USDC, amount: "1" })]) }, node);
  assert.ok(!node.calls.some((c) => c.body));
});

test("POST /v1/check type stellar: parsed, analyzed, subject lists the operations", async () => {
  const req = parseRequest({ type: "stellar", transaction: b64([Operation.accountMerge({ destination: OTHER })]) });
  assert.equal(req.kind, "stellar");
  const realFetch = globalThis.fetch;
  globalThis.fetch = fakeNode({ accounts: live }).fetchImpl;
  try {
    const answer = await analyze(req);
    assert.equal(answer.verdict, "red");
    assert.equal(answer.subject.kind, "stellar_transaction");
    assert.equal(answer.subject.network, "stellar:pubnet");
    assert.equal(answer.subject.wallet, W);
    assert.deepEqual(answer.subject.operations, [{ type: "accountMerge", source: W, destination: OTHER }]);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.throws(() => parseRequest({ type: "stellar" }), (e) => e.status === 400);
});
