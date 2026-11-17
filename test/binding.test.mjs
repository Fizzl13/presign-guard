// A verdict bound to the exact transaction: the signed receipt carries the checked tx and a short validity, and
// checkBinding (in the wallet, offline) answers MATCH / CHANGED (with the field) / EXPIRED / UNTRUSTED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeFunctionData, parseAbi } from "viem";
import { createSigner } from "../src/receipt.js";
import { bindingFor, checkBinding, txSha256 } from "../src/binding.js";

const signer = createSigner({ RECEIPT_SIGNER_SECRET: "binding-test-secret-long-enough-0123456789" });
const pinned = signer.signers;
const ERC20 = parseAbi(["function approve(address spender,uint256 amount)"]);
const V2 = parseAbi(["function swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to,uint256 deadline)"]);
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ROUTER = "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24";
const WETH = "0x4200000000000000000000000000000000000006";
const FROM = "0xF03b86caDe7764026182a62019474abE738D5fc0";
const approve = (spender, amount) => encodeFunctionData({ abi: ERC20, functionName: "approve", args: [spender, amount] });
const swap = (recipient, minOut) => encodeFunctionData({ abi: V2, functionName: "swapExactTokensForTokens", args: [5_000_000_000n, minOut, [USDC, WETH], recipient, 1_900_000_000n] });

const request = (to, data, extra = {}) => ({ type: "transaction", chainId: 8453, to, data, value: "0", from: FROM, ...extra });
const checked = (input, verdict = "green") => signer.sign({ verdict, reasons: [] }, { route: "POST /v1/check", input });

test("binding: an EVM transaction check is signed with the exact tx, its hash and a short validity", async () => {
  const t0 = Date.parse("2026-11-17T20:00:00.000Z");
  const a = bindingFor(request(USDC, approve(ROUTER, 5_000_000_000n)), t0);
  assert.equal(a.scope, "evm-tx-v1");
  assert.deepEqual(a.tx, { chainId: 8453, from: FROM.toLowerCase(), to: USDC.toLowerCase(), value: "0", data: approve(ROUTER, 5_000_000_000n).toLowerCase() });
  assert.equal(a.tx_sha256, txSha256(a.tx));
  assert.equal(a.valid_until, "2026-11-17T20:10:00.000Z", "10 minutes for an approval");
  assert.equal(bindingFor(request(ROUTER, swap(FROM, 1n)), t0).valid_until, "2026-11-17T20:02:00.000Z", "2 minutes for a swap");
  assert.equal(bindingFor({ type: "solana", transaction: "AQAA" }), null, "only EVM transactions are bound");

  const signed = await checked(request(USDC, approve(ROUTER, 5_000_000_000n)));
  assert.equal(signed.receipt.binding.tx.to, USDC.toLowerCase());
  const other = await signer.sign({ verdict: "green" }, { route: "GET /v1/screen", input: { address: FROM } });
  assert.equal(other.receipt.binding, undefined, "other routes are not bound");
});

test("checkBinding: MATCH for the same tx (wallet fields ignored), CHANGED names the field", async () => {
  const input = request(USDC, approve(ROUTER, 5_000_000_000n));
  const signed = await checked(input);
  const same = await checkBinding({ chainId: 8453, to: USDC, value: "0x0", data: input.data, from: FROM, gas: "0x5208", nonce: 7, maxFeePerGas: "1000" }, signed, { signers: pinned });
  assert.equal(same.result, "MATCH");
  assert.equal(same.sign_ok, true);

  const spender = await checkBinding({ ...input, data: approve("0x5555555555555555555555555555555555555555", 5_000_000_000n) }, signed, { signers: pinned });
  assert.deepEqual([spender.result, spender.changed, spender.sign_ok], ["CHANGED", ["spender"], false]);
  const amount = await checkBinding({ ...input, data: approve(ROUTER, 2n ** 256n - 1n) }, signed, { signers: pinned });
  assert.deepEqual(amount.changed, ["amount"]);
  const token = await checkBinding({ ...input, to: "0x6666666666666666666666666666666666666666" }, signed, { signers: pinned });
  assert.deepEqual(token.changed, ["to"]);
  const value = await checkBinding({ ...input, value: "1" }, signed, { signers: pinned });
  assert.deepEqual(value.changed, ["value"]);
  const chain = await checkBinding({ ...input, chainId: 1 }, signed, { signers: pinned });
  assert.deepEqual(chain.changed, ["chainId"]);

  const swapIn = request(ROUTER, swap(FROM, 2_000_000n));
  const swapSigned = await checked(swapIn);
  const recipient = await checkBinding({ ...swapIn, data: swap("0x7777777777777777777777777777777777777777", 2_000_000n) }, swapSigned, { signers: pinned });
  assert.deepEqual(recipient.changed, ["recipient"], "the swap's recipient argument");
  const minOut = await checkBinding({ ...swapIn, data: swap(FROM, 1n) }, swapSigned, { signers: pinned });
  assert.deepEqual(minOut.changed, ["amountOutMin"]);
  const unknown = await checkBinding({ ...input, data: "0xdeadbeef" }, signed, { signers: pinned });
  assert.deepEqual(unknown.changed, ["data"], "a call we can't decode is named data");
});

test("checkBinding: EXPIRED after valid_until; UNTRUSTED when tampered, not ours or not bound", async () => {
  const input = request(USDC, approve(ROUTER, 5_000_000_000n));
  const signed = await checked(input);
  const later = Date.parse(signed.receipt.binding.valid_until);
  assert.equal((await checkBinding(input, signed, { signers: pinned, now: later - 1 })).result, "MATCH");
  const old = await checkBinding(input, signed, { signers: pinned, now: later });
  assert.deepEqual([old.result, old.sign_ok], ["EXPIRED", false]);

  const red = await checked(input, "red");
  const redFlipped = { ...structuredClone(red), verdict: "green" };
  assert.equal((await checkBinding(input, redFlipped, { signers: pinned })).result, "UNTRUSTED", "a red verdict flipped to green");
  const extended = structuredClone(signed);
  extended.receipt.binding.valid_until = "2099-01-01T00:00:00.000Z";
  assert.equal((await checkBinding(input, extended, { signers: pinned })).result, "UNTRUSTED", "validity extended");
  const moved = structuredClone(signed);
  moved.receipt.binding.tx.to = "0x6666666666666666666666666666666666666666";
  assert.equal((await checkBinding({ ...input, to: moved.receipt.binding.tx.to }, moved, { signers: pinned })).result, "UNTRUSTED", "binding moved to another tx");

  const stranger = createSigner({ RECEIPT_SIGNER_SECRET: "someone-else-entirely-0123456789-abcdef" });
  const theirs = await stranger.sign({ verdict: "green" }, { route: "POST /v1/check", input });
  const notOurs = await checkBinding(input, theirs, { signers: pinned });
  assert.equal(notOurs.result, "UNTRUSTED");
  assert.equal((await checkBinding(input, { verdict: "green" }, { signers: pinned })).result, "UNTRUSTED", "unsigned");
  const solana = await signer.sign({ verdict: "green" }, { route: "POST /v1/check", input: { type: "solana", transaction: "AQAA" } });
  assert.match((await checkBinding(input, solana, { signers: pinned })).reason, /no transaction binding/);
  // A red verdict on the same tx is a MATCH but never sign_ok.
  const redMatch = await checkBinding(input, red, { signers: pinned });
  assert.deepEqual([redMatch.result, redMatch.sign_ok], ["MATCH", false]);
});
