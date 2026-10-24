// OWS policy support (src/ows.js): a PolicyContext becomes the matching /v1/check body per chain and request type,
// and a verdict becomes the PolicyResult OWS reads. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encode as encodeXrpl } from "ripple-binary-codec";
import { serializeTransaction } from "viem";
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

test("owsToCheck: what presign-guard can't judge is refused (the handler denies it unless allow_unchecked)", () => {
  assert.throws(() => owsToCheck(ctx("bip122:000000000019d6689c085ae165831e93", "sign_transaction", { transaction: { raw_hex: "00" } })), /doesn't check bip122/);
  assert.throws(() => owsToCheck(ctx("xrpl:mainnet", "sign_message", { transaction: { raw_hex: "00" } })), /isn't checked, only transactions/);
  assert.throws(() => owsToCheck(ctx("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "sign_message", { transaction: { raw_hex: "00" } })), OwsUnchecked);
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
