// OWS policy support (src/ows.js): a PolicyContext becomes the matching /v1/check body per chain and request type,
// and a verdict becomes the PolicyResult OWS reads. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encode as encodeXrpl } from "ripple-binary-codec";
import { serializeTransaction } from "viem";
import * as k from "@solana/kit";
import { isOwsContext, owsToCheck, owsResult, OwsUnchecked } from "../src/ows.js";

const TO = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ctx = (chain_id, request_type, extra = {}) => ({ chain_id, request_type, wallet_id: "w", api_key_id: "k", spending: { daily_total: "0", date: "2026-10-24" }, timestamp: "2026-10-24T18:00:00Z", ...extra });
const hex = (s) => s.replace(/^0x/, "");

test("isOwsContext: a PolicyContext has chain_id and a known request_type", () => {
  assert.equal(isOwsContext(ctx("eip155:8453", "sign_transaction")), true);
  assert.equal(isOwsContext({ chain_id: "eip155:8453", request_type: "sign_something" }), false);
  assert.equal(isOwsContext({ type: "transaction", chainId: 8453 }), false);
  assert.equal(isOwsContext(null), false);
});

test("owsToCheck: an EVM transaction envelope (unsigned, with or without 0x) becomes a transaction check", () => {
  const data = `0x095ea7b3${"11".repeat(32)}${"ff".repeat(32)}`;
  const raw = serializeTransaction({ chainId: 8453, type: "eip1559", to: TO, data, value: 5n, nonce: 1, gas: 60000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n });
  for (const raw_hex of [hex(raw), raw]) {
    const { body, options } = owsToCheck(ctx("eip155:8453", "sign_transaction", { transaction: { raw_hex, effects: [] }, policy_config: { address: "0x1111111111111111111111111111111111111111" } }));
    assert.deepEqual({ ...body, to: body.to.toLowerCase() }, { type: "transaction", chainId: 8453, to: TO.toLowerCase(), data, value: "5", from: "0x1111111111111111111111111111111111111111" });
    assert.deepEqual(options, { allowOrange: false, allowUnchecked: false });
  }
  const legacy = serializeTransaction({ chainId: 1, to: TO, value: 1n, nonce: 0, gas: 21000n, gasPrice: 1n });
  assert.equal(owsToCheck(ctx("eip155:1", "sign_transaction", { transaction: { raw_hex: hex(legacy) } })).body.value, "1");
});

test("owsToCheck: an EIP-7702 transaction is judged by its delegation", () => {
  const raw = serializeTransaction({ chainId: 8453, type: "eip7702", to: TO, nonce: 1, gas: 60000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n,
    authorizationList: [{ address: "0x2222222222222222222222222222222222222222", chainId: 8453, nonce: 3, r: `0x${"01".repeat(32)}`, s: `0x${"02".repeat(32)}`, yParity: 0 }] });
  const { body } = owsToCheck(ctx("eip155:8453", "sign_transaction", { transaction: { raw_hex: hex(raw) } }));
  assert.equal(body.type, "authorization");
  assert.equal(body.address.toLowerCase(), "0x2222222222222222222222222222222222222222");
  assert.deepEqual([body.chainId, body.authorizationChainId, body.nonce], [8453, 8453, "3"]);
});

test("owsToCheck: typed data, messages and hashes on EVM", () => {
  const td = JSON.stringify({ domain: { name: "Permit2", chainId: 8453, verifyingContract: TO }, primaryType: "PermitSingle", types: {}, message: {} });
  assert.deepEqual(owsToCheck(ctx("eip155:8453", "sign_typed_data", { typed_data: { primary_type: "PermitSingle", raw_json: td } })).body, { type: "signature", chainId: 8453, typedData: td });
  const msg = Buffer.from("Sign in to example.com").toString("hex");
  assert.deepEqual(owsToCheck(ctx("eip155:8453", "sign_message", { transaction: { raw_hex: msg } })).body, { type: "message", method: "personal_sign", message: `0x${msg}`, chainId: 8453 });
  assert.equal(owsToCheck(ctx("eip155:8453", "sign_hash", { transaction: { raw_hex: "ab".repeat(32) } })).body.method, "eth_sign");
  assert.throws(() => owsToCheck(ctx("eip155:8453", "sign_typed_data", {})), OwsUnchecked);
});

test("owsToCheck: a Solana wire transaction goes as base64; XRPL binary is decoded to JSON", () => {
  const wire = Buffer.from([1, ...new Array(64).fill(0), 7, 7, 7]);
  assert.deepEqual(owsToCheck(ctx("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "sign_transaction", { transaction: { raw_hex: wire.toString("hex") } })).body, { type: "solana", transaction: wire.toString("base64") });
  const tx = { TransactionType: "Payment", Account: "rfryheo6yzFdLWj8qUQtZc7zG9MKkBkUEy", Destination: "rMnHeutYALco8RYFVcmuU4BCgSzBpPEh32", Amount: "1000", Fee: "12", Sequence: 5, Flags: 0 };
  const { body } = owsToCheck(ctx("xrpl:mainnet", "sign_transaction", { transaction: { raw_hex: encodeXrpl(tx).toLowerCase() } }));
  assert.equal(body.type, "xrpl");
  assert.equal(body.network, "xrpl:0");
  assert.deepEqual(body.tx, tx);
  assert.equal(owsToCheck(ctx("xrpl:testnet", "sign_transaction", { transaction: { raw_hex: encodeXrpl(tx) } })).body.network, "xrpl:1");
});

// A Solana transaction message (what a transaction's signatures sign), and an XRPL transaction, as message bytes.
function solanaMessageHex() {
  const W = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9", OTHER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", SYSTEM = "11111111111111111111111111111111";
  const data = new Uint8Array(12); new DataView(data.buffer).setUint32(0, 2, true); new DataView(data.buffer).setBigUint64(4, 1000000n, true);
  let m = k.createTransactionMessage({ version: 0 });
  m = k.setTransactionMessageFeePayer(k.address(W), m);
  m = k.setTransactionMessageLifetimeUsingBlockhash({ blockhash: SYSTEM, lastValidBlockHeight: 0n }, m);
  m = k.appendTransactionMessageInstruction({ programAddress: k.address(SYSTEM), accounts: [{ address: k.address(W), role: k.AccountRole.WRITABLE_SIGNER }, { address: k.address(OTHER), role: k.AccountRole.WRITABLE }], data }, m);
  return Buffer.from(k.compileTransaction(m).messageBytes).toString("hex");
}
const XRPL_TX = { TransactionType: "Payment", Account: "rfryheo6yzFdLWj8qUQtZc7zG9MKkBkUEy", Destination: "rMnHeutYALco8RYFVcmuU4BCgSzBpPEh32", Amount: "1000", Fee: "12", Sequence: 5, Flags: 0 };

test("owsToCheck: a Solana or XRPL message is a message; one whose bytes are a whole transaction is marked", () => {
  const sol = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  const signIn = Buffer.from("app.example wants you to sign in with your Solana account:\n5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9").toString("hex");
  assert.deepEqual(owsToCheck(ctx(sol, "sign_message", { transaction: { raw_hex: signIn } })).body, { type: "message", method: "personal_sign", message: `0x${signIn}` });
  assert.equal(owsToCheck(ctx(sol, "sign_message", { transaction: { raw_hex: solanaMessageHex() } })).body.disguisedTransaction, "solana");
  assert.equal(owsToCheck(ctx(sol, "sign_message", { transaction: { raw_hex: "deadbeef".repeat(8) } })).body.disguisedTransaction, undefined); // binary, not a transaction
  assert.equal(owsToCheck(ctx("xrpl:mainnet", "sign_message", { transaction: { raw_hex: encodeXrpl(XRPL_TX) } })).body.disguisedTransaction, "xrpl");
  assert.equal(owsToCheck(ctx("xrpl:mainnet", "sign_message", { transaction: { raw_hex: signIn } })).body.disguisedTransaction, undefined);
});

test("OWS messages end to end: plain text allowed, binary needs a person, a disguised transaction is refused", async () => {
  const express = (await import("express")).default;
  const { createCheckRouter } = await import("../src/presign-guard.js");
  const app = express(); app.use(createCheckRouter());
  const server = app.listen(0);
  const post = async (body) => (await fetch(`http://127.0.0.1:${server.address().port}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
  const sol = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  try {
    let r = await post(ctx(sol, "sign_message", { transaction: { raw_hex: Buffer.from("Sign in to app.example").toString("hex") } }));
    assert.deepEqual([r.verdict, r.allow], ["green", true]);
    r = await post(ctx(sol, "sign_message", { transaction: { raw_hex: "deadbeef".repeat(8) } }));
    assert.deepEqual([r.verdict, r.allow], ["orange", false]);
    r = await post(ctx(sol, "sign_message", { transaction: { raw_hex: solanaMessageHex() }, policy_config: { allow_orange: true } }));
    assert.deepEqual([r.verdict, r.allow], ["red", false]);
    assert.match(r.reason, /MESSAGE_IS_TRANSACTION \(signing this message signs a Solana transaction\)/);
    r = await post(ctx("xrpl:mainnet", "sign_message", { transaction: { raw_hex: encodeXrpl(XRPL_TX) } }));
    assert.deepEqual([r.verdict, r.allow], ["red", false]);
    assert.match(r.reason, /signs an XRPL transaction/);
  } finally { server.close(); }
});

test("owsToCheck: what presign-guard can't judge is refused (the handler denies it unless allow_unchecked)", () => {
  assert.throws(() => owsToCheck(ctx("bip122:000000000019d6689c085ae165831e93", "sign_transaction", { transaction: { raw_hex: "00" } })), /doesn't check bip122/);
  assert.throws(() => owsToCheck(ctx("xrpl:mainnet", "sign_hash", { transaction: { raw_hex: "00" } })), /isn't checked, only transactions and messages/);
  assert.throws(() => owsToCheck(ctx("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "sign_hash", { transaction: { raw_hex: "00" } })), OwsUnchecked);
  assert.throws(() => owsToCheck(ctx("eip155:8453", "sign_transaction", { transaction: { raw_hex: "zz" } })), /raw_hex must be/);
  assert.throws(() => owsToCheck(ctx("eip155:8453", "sign_transaction", { transaction: { raw_hex: "0102" } })), /not an EVM transaction/);
});

test("owsResult: green allows, orange only with allow_orange, red never; the reason names the codes", () => {
  const r = (verdict, reasons = []) => ({ verdict, reasons });
  assert.deepEqual(owsResult(r("green", [{ code: "SANCTIONS_SCREENED", severity: "info" }])), { allow: true, reason: "presign-guard green" });
  const orange = r("orange", [{ code: "XRPL_CHECK_TO_OTHER", severity: "orange", details: { effect: "the destination can cash up to SendMax" } }]);
  assert.deepEqual(owsResult(orange), { allow: false, reason: "presign-guard orange: XRPL_CHECK_TO_OTHER (the destination can cash up to SendMax)" });
  assert.equal(owsResult(orange, { allowOrange: true }).allow, true);
  assert.equal(owsResult(r("red", [{ code: "XRPL_REGULAR_KEY_CHANGE", severity: "red" }]), { allowOrange: true }).allow, false);
  assert.equal(owsResult(r(null)).allow, false);
});

test("owsPaymentRequired: an unpaid PolicyContext gets allow:false and what to do in its 402; others are untouched", async () => {
  const express = (await import("express")).default;
  const { memoryStore, payWithCredits, hashKey, newKey, CREDIT_HEADER } = await import("../src/credits.js");
  const { createCheckRouter } = await import("../src/presign-guard.js");
  const { owsPaymentRequired } = await import("../src/ows.js");
  const store = memoryStore();
  const rich = newKey(), poor = newKey();
  await store.issue(hashKey(rich), 100, 365);
  await store.issue(hashKey(poor), 0, 365);
  // Like server.js: parse, credits, the 402 hint, a paywall (here a fake one), then the check router.
  const app = express();
  const checkJson = express.json({ limit: "64kb" });
  app.post("/v1/check", (req, res, next) => checkJson(req, res, (err) => { if (err) req.fizzlJsonError = err; next(); }), owsPaymentRequired("https://pg.test"));
  app.use(payWithCredits({ store, costs: { "POST /v1/check": 1 } }));
  app.use((req, res, next) => (req.fizzlCredits ? next() : res.status(402).json({ x402Version: 2, error: "Payment required" })));
  app.use(createCheckRouter());
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (body, key) => fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json", ...(key ? { [CREDIT_HEADER]: key } : {}) }, body: typeof body === "string" ? body : JSON.stringify(body) });
  const owsCtx = ctx("bip122:000000000019d6689c085ae165831e93", "sign_transaction", { transaction: { raw_hex: "00" } });
  try {
    let r = await post(owsCtx);
    assert.equal(r.status, 402);
    let b = await r.json();
    assert.equal(b.x402Version, 2); // the challenge stays
    assert.equal(b.allow, false);
    assert.match(b.reason, /^presign-guard: no credit key was sent\. .*https:\/\/pg\.test\/v1\/credits\/100$/);
    assert.match((await (await post(owsCtx, poor)).json()).reason, /too few credits left/);
    assert.match((await (await post(owsCtx, "nope")).json()).reason, /not a credit key/);
    assert.match((await (await post(owsCtx, newKey())).json()).reason, /has no credits/);
    // An ordinary check's 402 is untouched.
    b = await (await post({ type: "transaction", chainId: 8453, to: TO, data: "0x" })).json();
    assert.equal("allow" in b, false);
    // Paid, the PolicyContext reaches the check (bip122 isn't checked: denied with the reason, credits refunded).
    r = await post(owsCtx, rich);
    assert.equal(r.status, 400);
    assert.match((await r.json()).reason, /doesn't check bip122/);
    // A body that isn't JSON: the 402 first, as before; once paid, the check router's 400.
    assert.equal((await post("{not json", null)).status, 402);
    assert.equal((await post("{not json", rich)).status, 400);
  } finally { server.close(); }
});
