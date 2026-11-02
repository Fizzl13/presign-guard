// NEAR transaction checks (src/near-tx.js) against a stand-in NEAR RPC: no network, no money.
import { test } from "node:test";
import assert from "node:assert/strict";
import { actionCreators, createTransaction, encodeTransaction, buildDelegateAction, SignedDelegate, Signature } from "@near-js/transactions";
import { KeyPair } from "@near-js/crypto";
import { parseNearRequest, nearReasons, nearLookalike, NearValidationError } from "../src/near-tx.js";
import { analyze, parseRequest } from "../src/presign-guard.js";

const W = "alice.near";
const KEY = KeyPair.fromRandom("ed25519").getPublicKey();
const OTHER_KEY = KeyPair.fromRandom("ed25519").getPublicKey();
const USDC = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const codes = (reasons) => reasons.map((r) => r.code);
const sev = (reasons, code) => reasons.find((r) => r.code === code)?.severity;

// A borsh transaction from the wallet to `receiver`, base64.
const b64 = (receiver, actions, signer = W) =>
  Buffer.from(encodeTransaction(createTransaction(signer, KEY, receiver, 1n, actions, new Uint8Array(32)))).toString("base64");
const fc = (method, args, deposit = 0n) => actionCreators.functionCall(method, args, 30_000_000_000_000n, deposit);

// A stand-in RPC: ft_metadata per contract, the wallet's access keys; `down` makes every call fail.
function rpcStub({ metadata = {}, keys = [], down = false } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const { params } = JSON.parse(init.body);
    calls.push(params.request_type === "call_function" ? `${params.account_id}.${params.method_name}` : params.request_type);
    if (down) throw new TypeError("fetch failed");
    if (params.request_type === "view_access_key_list") {
      return Response.json({ jsonrpc: "2.0", id: 1, result: { keys: keys.map(([k, full]) => ({ public_key: k, access_key: { nonce: 1, permission: full ? "FullAccess" : { FunctionCall: { receiver_id: "app.near", method_names: [], allowance: null } } } })) } });
    }
    if (params.request_type === "call_function" && params.method_name === "ft_metadata") {
      const m = metadata[params.account_id];
      if (!m) return Response.json({ jsonrpc: "2.0", id: 1, error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_ACCOUNT" } } });
      return Response.json({ jsonrpc: "2.0", id: 1, result: { result: [...Buffer.from(JSON.stringify(m))] } });
    }
    return Response.json({ jsonrpc: "2.0", id: 1, error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN" } } });
  };
  return { fetchImpl, calls };
}
const judge = (body, stub = rpcStub()) => nearReasons(parseNearRequest({ type: "near", ...body }), { fetchImpl: stub.fetchImpl });

test("near: a full-access key added to the wallet is red, from borsh and from wallet-selector JSON", async () => {
  const fromBorsh = await judge({ transaction: b64(W, [actionCreators.addKey(OTHER_KEY, actionCreators.fullAccessKey())]) });
  assert.equal(sev(fromBorsh.reasons, "NEAR_FULL_ACCESS_KEY_ADDED"), "red");
  assert.equal(fromBorsh.reasons[0].subject, OTHER_KEY.toString());
  const fromJson = await judge({ tx: { signerId: W, receiverId: W, actions: [{ type: "AddKey", params: { publicKey: OTHER_KEY.toString(), accessKey: { permission: "FullAccess" } } }] } });
  assert.equal(sev(fromJson.reasons, "NEAR_FULL_ACCESS_KEY_ADDED"), "red");
});

test("near: a function-call key is the agent sandbox: info with its scope, orange only with an unlimited allowance", async () => {
  const limited = await judge({ transaction: b64(W, [actionCreators.addKey(OTHER_KEY, actionCreators.functionCallAccessKey("game.near", ["play"], 250_000_000_000_000_000_000_000n))]) });
  assert.deepEqual(codes(limited.reasons), ["NEAR_FUNCTION_CALL_KEY_ADDED"]);
  assert.deepEqual(limited.reasons[0].details, { contract: "game.near", methods: ["play"], allowanceNear: "0.25" });
  const unlimited = await judge({ transaction: b64(W, [actionCreators.addKey(OTHER_KEY, actionCreators.functionCallAccessKey("game.near", [], null))]) });
  assert.equal(sev(unlimited.reasons, "NEAR_KEY_UNLIMITED_ALLOWANCE"), "orange");
  assert.equal(unlimited.reasons[0].details.methods, "any method");
});

test("near: deleting the account and deploying code over the wallet are red; a new sub-account with its own code is not", async () => {
  assert.equal(sev((await judge({ transaction: b64(W, [actionCreators.deleteAccount("thief.near")]) })).reasons, "NEAR_ACCOUNT_DELETED"), "red");
  assert.equal(sev((await judge({ transaction: b64(W, [actionCreators.deployContract(new Uint8Array([0, 97, 115, 109]))]) })).reasons, "NEAR_CONTRACT_DEPLOYED_ON_WALLET"), "red");
  const sub = await judge({ transaction: b64("bot.alice.near", [actionCreators.createAccount(), actionCreators.transfer(10n ** 24n), actionCreators.addKey(OTHER_KEY, actionCreators.fullAccessKey()), actionCreators.deployContract(new Uint8Array([0, 97, 115, 109]))]) });
  assert.deepEqual(sub.reasons.map((r) => [r.code, r.severity]), [["NEAR_KEY_ON_OTHER_ACCOUNT", "info"]]);
});

test("near: deleting the last full-access key is red, another one orange, and unread keys orange with the RPC noted", async () => {
  const del = { transaction: b64(W, [actionCreators.deleteKey(KEY)]) };
  const last = await judge(del, rpcStub({ keys: [[KEY.toString(), true], [OTHER_KEY.toString(), false]] }));
  assert.equal(sev(last.reasons, "NEAR_LAST_FULL_ACCESS_KEY_DELETED"), "red");
  const another = await judge(del, rpcStub({ keys: [[KEY.toString(), true], [OTHER_KEY.toString(), true]] }));
  assert.deepEqual(another.reasons.map((r) => [r.code, r.severity, r.details?.fullAccessKeysLeft]), [["NEAR_FULL_ACCESS_KEY_DELETED", "orange", 1]]);
  const down = await judge(del, rpcStub({ down: true }));
  assert.deepEqual(codes(down.reasons), ["NEAR_ACCESS_KEY_DELETED", "NEAR_RPC_UNAVAILABLE"]);
  // A key rotation (add a new full-access key, delete the old one) is red for the added key, not for the deletion.
  const rotate = await judge({ transaction: b64(W, [actionCreators.addKey(OTHER_KEY, actionCreators.fullAccessKey()), actionCreators.deleteKey(KEY)]) }, rpcStub({ keys: [[KEY.toString(), true]] }));
  assert.deepEqual(codes(rotate.reasons), ["NEAR_FULL_ACCESS_KEY_ADDED", "NEAR_FULL_ACCESS_KEY_DELETED"]);
});

test("near: a token that calls itself USDC but isn't Circle's is red; the real USDC is read from the list, not the chain", async () => {
  const stub = rpcStub({ metadata: { "usdc-token.near": { symbol: "USDC", decimals: 6 }, "meme.near": { symbol: "MEME", decimals: 18 } } });
  const fake = await judge({ transaction: b64("usdc-token.near", [fc("ft_transfer", { receiver_id: "bob.near", amount: "5" }, 1n)]) }, stub);
  assert.equal(sev(fake.reasons, "NEAR_FAKE_TOKEN"), "red");
  assert.deepEqual(fake.reasons[0].details, { symbol: "USDC", real: [USDC, "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.factory.bridge.near"] });
  const meme = await judge({ transaction: b64("meme.near", [fc("ft_transfer", { receiver_id: "bob.near", amount: "5" }, 1n)]) }, stub);
  assert.deepEqual(meme.reasons, []);
  const before = stub.calls.length;
  const real = await judge({ transaction: b64(USDC, [fc("ft_transfer", { receiver_id: "bob.near", amount: "5" }, 1n)]) }, stub);
  assert.deepEqual(real.reasons, []);
  assert.equal(stub.calls.length, before, "no RPC call for a listed token");
});

test("near: look-alike accounts of well-known contracts are red, the real ones are not", async () => {
  assert.equal(nearLookalike("wrap-near.near"), "wrap.near");
  assert.equal(nearLookalike("intents-near.near"), "intents.near");
  assert.equal(nearLookalike("usdt.tether-tokens.near"), "usdt.tether-token.near");
  assert.equal(nearLookalike("wrap.near"), null);
  assert.equal(nearLookalike("bob.near"), null);
  assert.equal(nearLookalike(USDC), null);
  const r = await judge({ transaction: b64(USDC, [fc("ft_transfer", { receiver_id: "intents-near.near", amount: "5" }, 1n)]) });
  assert.deepEqual(r.reasons.map((x) => [x.code, x.subject]), [["NEAR_LOOKALIKE_ACCOUNT", "intents-near.near"]]);
});

test("near: NEAR Intents: a key added to intents.near is red, a deposit credited to someone else orange", async () => {
  const key = await judge({ transaction: b64("intents.near", [fc("add_public_key", { public_key: OTHER_KEY.toString() }, 1n)]) });
  assert.equal(sev(key.reasons, "NEAR_INTENTS_KEY_ADDED"), "red");
  const deposit = await judge({ transaction: b64(USDC, [fc("ft_transfer_call", { receiver_id: "intents.near", amount: "5", msg: JSON.stringify({ receiver_id: "mallory.near" }) }, 1n)]) });
  assert.deepEqual(deposit.reasons.map((x) => [x.code, x.severity, x.subject]), [["NEAR_INTENTS_DEPOSIT_FOR_OTHER", "orange", "mallory.near"]]);
  const own = await judge({ transaction: b64(USDC, [fc("ft_transfer_call", { receiver_id: "intents.near", amount: "5", msg: "" }, 1n)]) });
  assert.deepEqual(own.reasons, []);
});

test("near: a forced storage_unregister burns the balance (red); an NFT approval and a large unknown deposit are orange", async () => {
  assert.equal(sev((await judge({ transaction: b64("wrap.near", [fc("storage_unregister", { force: true }, 1n)]) })).reasons, "NEAR_STORAGE_UNREGISTER_FORCE"), "red");
  assert.equal(sev((await judge({ transaction: b64("nft.near", [fc("nft_approve", { token_id: "7", account_id: "market.near" }, 10n ** 21n)]) })).reasons, "NEAR_NFT_APPROVAL"), "orange");
  assert.equal(sev((await judge({ transaction: b64("game.near", [fc("buy", {}, 50n * 10n ** 24n)]) })).reasons, "NEAR_LARGE_DEPOSIT"), "orange");
  assert.deepEqual((await judge({ transaction: b64("wrap.near", [fc("near_deposit", {}, 50n * 10n ** 24n)]) })).reasons, []);
});

test("near: a meta transaction is judged by its inner actions, for the delegate's sender", async () => {
  const delegate = buildDelegateAction({ senderId: "bob.near", receiverId: "bob.near", actions: [actionCreators.addKey(OTHER_KEY, actionCreators.fullAccessKey())], nonce: 1n, maxBlockHeight: 100n, publicKey: KEY });
  const signed = actionCreators.signedDelegate({ delegateAction: delegate, signature: new Signature({ keyType: 0, data: new Uint8Array(64) }) });
  const r = await judge({ transaction: b64("bob.near", [signed], "relayer.near"), from: "bob.near" });
  assert.equal(sev(r.reasons, "NEAR_FULL_ACCESS_KEY_ADDED"), "red");
  assert.equal(r.operations[0].delegated, true);
});

test("near: invalid requests are 400s", () => {
  assert.throws(() => parseNearRequest({ type: "near" }), NearValidationError);
  assert.throws(() => parseNearRequest({ type: "near", transaction: "not base64!" }), /base64 borsh/);
  assert.throws(() => parseNearRequest({ type: "near", tx: { receiverId: W, actions: [{ type: "Transfer", params: { deposit: "1" } }] } }), /wallet is unknown/);
  assert.throws(() => parseNearRequest({ type: "near", network: "near:betanet", transaction: b64(W, [actionCreators.transfer(1n)]) }), /unsupported NEAR network/);
  assert.throws(() => parseNearRequest({ type: "near", tx: { signerId: W, receiverId: "Bad Name", actions: [{ type: "Transfer", params: {} }] } }), /receiverId/);
  assert.equal(new NearValidationError("x").status, 400);
});

test("near: the full check through /v1/check's parser: verdict, subject and scope", async () => {
  const r = await analyze(parseRequest({ type: "near", tx: { signerId: W, receiverId: W, actions: [{ type: "DeleteAccount", params: { beneficiaryId: "thief.near" } }] } }));
  assert.equal(r.verdict, "red");
  assert.equal(r.subject.kind, "near_transaction");
  assert.equal(r.subject.network, "near:mainnet");
  assert.equal(r.subject.actions[0].beneficiary, "thief.near");
  const ok = await analyze(parseRequest({ type: "near", tx: { signerId: W, receiverId: "bob.near", actions: [{ type: "Transfer", params: { deposit: "1000000000000000000000000" } }] } }));
  assert.equal(ok.verdict, "green");
  assert.equal(ok.subject.actions[0].amountNear, "1");
});

// ---------- NEAR Intents: signed intents (NEP-413) ----------

const intentsMsg = (intents, { signer = W, verifier = "intents.near", recipient = "intents.near", deadline = new Date(Date.now() + 10 * 60 * 1000).toISOString() } = {}) => ({
  message: JSON.stringify({ signer_id: signer, verifying_contract: verifier, deadline, nonce: "AAAAAA==", intents }),
  recipient,
  nonce: "AAAAAA==",
});

test("near intents: a normal swap is green, with what is given and received", async () => {
  const r = await judge({ nep413: intentsMsg([{ intent: "token_diff", diff: { [`nep141:${USDC}`]: "-10000000", "nep141:wrap.near": "3000000000000000000000000" } }]) });
  assert.deepEqual(r.reasons.map((x) => [x.code, x.severity]), [["NEAR_INTENTS_SWAP", "info"]]);
  assert.equal(r.operations[0].intent, "token_diff");
});

test("near intents: giving for nothing, a key added to NEAR Intents and fake tokens received are red", async () => {
  const give = await judge({ nep413: intentsMsg([{ intent: "token_diff", diff: { [`nep141:${USDC}`]: "-10000000" } }]) });
  assert.equal(sev(give.reasons, "NEAR_INTENTS_GIVES_FOR_NOTHING"), "red");
  const key = await judge({ nep413: intentsMsg([{ intent: "add_public_key", public_key: OTHER_KEY.toString() }]) });
  assert.equal(sev(key.reasons, "NEAR_INTENTS_KEY_ADDED"), "red");
  const stub = rpcStub({ metadata: { "usdc-token.near": { symbol: "USDC", decimals: 6 } } });
  const fake = await judge({ nep413: intentsMsg([{ intent: "token_diff", diff: { "nep141:wrap.near": "-1000000000000000000000000", "nep141:usdc-token.near": "3000000" } }]) }, stub);
  assert.equal(sev(fake.reasons, "NEAR_FAKE_TOKEN"), "red");
});

test("near intents: transfers and withdrawals to others are shown; look-alikes, another verifier and long deadlines are flagged", async () => {
  const pay = await judge({ nep413: intentsMsg([{ intent: "transfer", receiver_id: "bob.near", tokens: { [`nep141:${USDC}`]: "5000000" } }, { intent: "ft_withdraw", token: USDC, receiver_id: "carol.near", amount: "1" }]) });
  assert.deepEqual(pay.reasons.map((x) => [x.code, x.severity]), [["NEAR_INTENTS_TRANSFER", "info"], ["NEAR_INTENTS_WITHDRAW_TO_OTHER", "info"]]);
  const like = await judge({ nep413: intentsMsg([{ intent: "transfer", receiver_id: "intents-near.near", tokens: { "nep141:wrap.near": "1" } }]) });
  assert.equal(sev(like.reasons, "NEAR_LOOKALIKE_ACCOUNT"), "red");
  const verifier = await judge({ nep413: intentsMsg([], { verifier: "intents.fake.near", recipient: "intents.fake.near" }) });
  assert.equal(sev(verifier.reasons, "NEAR_INTENTS_UNKNOWN_VERIFIER"), "orange");
  const late = await judge({ nep413: intentsMsg([], { deadline: new Date(Date.now() + 7 * 86400000).toISOString() }) });
  assert.equal(sev(late.reasons, "NEAR_INTENTS_LONG_DEADLINE"), "orange");
  const unknown = await judge({ nep413: intentsMsg([{ intent: "auth_call", contract_id: "x.near" }]) });
  assert.equal(sev(unknown.reasons, "NEAR_INTENT_NOT_ANALYZED"), "orange");
  // The signed form (standard nep413 with payload) is read the same way.
  const signed = await judge({ nep413: { standard: "nep413", payload: intentsMsg([{ intent: "add_public_key", public_key: "ed25519:x" }]), public_key: "ed25519:y", signature: "ed25519:z" } });
  assert.equal(sev(signed.reasons, "NEAR_INTENTS_KEY_ADDED"), "red");
});

test("near intents: signed intents sent on chain with execute_intents are judged too", async () => {
  const signed = { standard: "nep413", payload: intentsMsg([{ intent: "token_diff", diff: { "nep141:wrap.near": "-5" } }]), public_key: "ed25519:y", signature: "ed25519:z" };
  const r = await judge({ transaction: b64("intents.near", [fc("execute_intents", { signed: [signed] })]) });
  assert.equal(sev(r.reasons, "NEAR_INTENTS_GIVES_FOR_NOTHING"), "red");
  assert.throws(() => parseNearRequest({ type: "near", nep413: { message: "not json" } }), /not JSON/);
  assert.throws(() => parseNearRequest({ type: "near", nep413: { message: JSON.stringify({ intents: [] }) } }), /wallet is unknown/);
});
