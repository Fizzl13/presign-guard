// ERC-4337 user operations and signed EVM transactions (src/userop.js), with Incentiv's two x402 schemes built as
// their protocol spec describes them (docs/SPEC.md in IncentivNetwork/incentiv-x402-public): executeBatch with an
// optional paymaster fee, the nonce lane of (paymentId, validUntil), and an EIP-1559 USDC transfer with the deadline
// marker in its access list.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeFunctionData, keccak256, parseAbi, hexToBigInt, maxUint256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { getUserOperationHash } from "viem/account-abstraction";
import { parseRequest, analyze } from "../src/presign-guard.js";
import { USEROP_CHAINS, laneKey } from "../src/userop.js";

const INC = USEROP_CHAINS[24101];
const USDC = "0x16e43840d8D79896A389a3De85aB0B0210C05685";
const EP = "0x3eC61c5633BBD7Afa9144C6610930489736a72d4";
const PAYMASTER = "0x43000f785EB43BcB4961C5c70276eD00e088972c";
const SELLER = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const OTHER = "0x1111111111111111111111111111111111111111";
const ACCOUNT = "0x2222222222222222222222222222222222222222";
const NOW = Math.floor(Date.now() / 1000);
const ERC20 = parseAbi(["function transfer(address to, uint256 amount)", "function approve(address spender, uint256 amount)"]);
const BATCH = parseAbi(["function executeBatch(address[] dest, uint256[] value, bytes[] func)"]);
const transfer = (to, amount) => encodeFunctionData({ abi: ERC20, functionName: "transfer", args: [to, amount] });
const hex = (n) => `0x${BigInt(n).toString(16)}`;

const quote = (over = {}) => ({ accepted: { scheme: "incentiv-userop", network: "eip155:24101", amount: "10000", asset: USDC, payTo: SELLER, maxTimeoutSeconds: 120, extra: { entryPoint: EP }, ...over } });

// A payment the way Incentiv's smart-account client builds it.
function userop({ calls = [[USDC, transfer(PAYMASTER, 30_000n)], [USDC, transfer(SELLER, 10_000n)]], paymaster = PAYMASTER, paymentId = keccak256("0x01"), validUntil = NOW + 120, nonceKey, entryPoint = EP } = {}) {
  const key = nonceKey ?? laneKey(paymentId, validUntil);
  const userOperation = {
    sender: ACCOUNT, nonce: hex((key << 64n) + 0n),
    callData: encodeFunctionData({ abi: BATCH, functionName: "executeBatch", args: [calls.map((c) => c[0]), calls.map(() => 0n), calls.map((c) => c[1])] }),
    callGasLimit: hex(90_000), verificationGasLimit: hex(150_000), preVerificationGas: hex(50_000),
    maxFeePerGas: hex(1_000_000_000), maxPriorityFeePerGas: hex(1_000_000_000), signature: "0x" + "11".repeat(65),
    ...(paymaster && { paymaster, paymasterVerificationGasLimit: hex(60_000), paymasterPostOpGasLimit: hex(40_000), paymasterData: "0x" }),
  };
  const big = (h) => hexToBigInt(h);
  const userOpHash = getUserOperationHash({
    userOperation: {
      ...userOperation, nonce: big(userOperation.nonce), callGasLimit: big(userOperation.callGasLimit), verificationGasLimit: big(userOperation.verificationGasLimit),
      preVerificationGas: big(userOperation.preVerificationGas), maxFeePerGas: big(userOperation.maxFeePerGas), maxPriorityFeePerGas: big(userOperation.maxPriorityFeePerGas),
      ...(paymaster && { paymasterVerificationGasLimit: 60_000n, paymasterPostOpGasLimit: 40_000n }),
    },
    entryPointAddress: entryPoint, entryPointVersion: "0.7", chainId: 24101,
  });
  return { type: "userop", chainId: 24101, entryPoint, userOperation, userOpHash, paymentId, validUntil };
}
const check = async (body) => analyze(parseRequest(body));
const codes = (r) => r.reasons.map((x) => `${x.severity}:${x.code}`);

test("an honest incentiv-userop payment with the paymaster fee: green, and the answer says what it pays", async () => {
  const r = await check({ ...userop(), x402: quote() });
  assert.equal(r.verdict, "green", JSON.stringify(r.reasons));
  assert.deepEqual(r.subject.actions, [`pay 0.03 USDC to ${PAYMASTER.toLowerCase()}`, `pay 0.01 USDC to ${SELLER.toLowerCase()}`]);
  assert.equal(r.subject.chain, "Incentiv");
  assert.equal(r.subject.gas.paidBy, PAYMASTER.toLowerCase());
  assert.ok(codes(r).includes("info:PAYMASTER_FEE"));
  assert.equal(r.subject.userOpHash, userop().userOpHash.toLowerCase());
  // Without a paymaster (gas in CENT): only the payment.
  const plain = await check({ ...userop({ calls: [[USDC, transfer(SELLER, 10_000n)]], paymaster: null }), x402: quote() });
  assert.equal(plain.verdict, "green", JSON.stringify(plain.reasons));
  assert.ok(plain.subject.gas.maxCostWei);
});

test("a hash that isn't this operation's, a foreign EntryPoint or nonce lane: red", async () => {
  const op = userop();
  assert.ok(codes(await check({ ...op, userOpHash: keccak256("0x02"), x402: quote() })).includes("red:USEROP_HASH_MISMATCH"));
  assert.ok(codes(await check({ ...userop({ entryPoint: OTHER }), x402: quote() })).includes("red:USEROP_ENTRYPOINT_UNKNOWN"));
  const lane = await check({ ...userop({ nonceKey: 7n }), x402: quote() });
  assert.ok(codes(lane).includes("red:USEROP_NONCE_LANE_MISMATCH"));
});

test("what the quote doesn't allow: another payee, more than asked, another token, extra calls", async () => {
  const swapped = await check({ ...userop({ calls: [[USDC, transfer(PAYMASTER, 30_000n)], [USDC, transfer(OTHER, 10_000n)]] }), x402: quote() });
  assert.equal(swapped.verdict, "red");
  assert.ok(codes(swapped).includes("red:X402_RECIPIENT_MISMATCH"));
  const more = await check({ ...userop({ calls: [[USDC, transfer(SELLER, 1_000_000n)]], paymaster: null }), x402: quote() });
  assert.ok(codes(more).includes("red:X402_AMOUNT_ABOVE_REQUIRED"));
  const token = await check({ ...userop({ calls: [[OTHER, transfer(SELLER, 10_000n)]], paymaster: null }), x402: quote() });
  assert.ok(codes(token).includes("red:X402_ASSET_MISMATCH"));
  const extra = await check({ ...userop({ calls: [[USDC, transfer(SELLER, 10_000n)], [USDC, encodeFunctionData({ abi: ERC20, functionName: "approve", args: [OTHER, maxUint256] })]], paymaster: null }), x402: quote() });
  assert.ok(codes(extra).includes("red:UNLIMITED_APPROVAL"));
  assert.ok(codes(extra).includes("red:X402_EXTRA_CALLS"));
  const wrongEp = await check({ ...userop(), x402: quote({ extra: { entryPoint: OTHER } }) });
  assert.ok(codes(wrongEp).includes("red:X402_ENTRYPOINT_MISMATCH"));
});

test("a paymaster fee above the client's 0.25 USDC cap, a long deadline, an unknown call: orange", async () => {
  const fee = await check({ ...userop({ calls: [[USDC, transfer(PAYMASTER, 900_000n)], [USDC, transfer(SELLER, 10_000n)]] }), x402: quote() });
  assert.equal(fee.verdict, "orange", JSON.stringify(fee.reasons));
  assert.ok(codes(fee).includes("orange:PAYMASTER_FEE_HIGH"));
  const long = await check({ ...userop({ validUntil: NOW + 86_400 }), x402: quote() });
  assert.ok(codes(long).includes("orange:X402_VALIDITY_TOO_LONG"));
  const unknown = await check({ ...userop({ calls: [[OTHER, "0xdeadbeef"]], paymaster: null }) });
  assert.ok(codes(unknown).includes("orange:UNKNOWN_CALL"));
});

test("malformed requests are refused, not judged", () => {
  assert.throws(() => parseRequest({ type: "userop", chainId: 24101 }), /userOperation/);
  assert.throws(() => parseRequest({ ...userop(), userOpHash: "0x12" }), /userOpHash/);
  assert.throws(() => parseRequest({ type: "signed_transaction", signedTransaction: "nope" }), /signedTransaction/);
});

// incentiv-eoa-tx: a type-2 USDC transfer, gas <= 120,000, the deadline in the access list.
const marker = (validUntil) => `0x78343032${BigInt(validUntil).toString(16).padStart(16, "0")}0000000000000000`;
async function eoaTx({ to = SELLER, amount = 10_000n, gas = 100_000n, validUntil = NOW + 120, accessList } = {}) {
  const account = privateKeyToAccount(keccak256("0x99")); // a throwaway test key
  const tx = { type: "eip1559", chainId: 24101, nonce: 0, to: USDC, value: 0n, data: transfer(to, amount), gas, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, accessList: accessList ?? [{ address: marker(validUntil), storageKeys: [] }] };
  return { type: "signed_transaction", signedTransaction: await account.signTransaction(tx), payer: account.address };
}

test("incentiv-eoa-tx: an honest signed transfer is green; another payee red; too much gas or no deadline orange", async () => {
  const ok = await eoaTx();
  const r = await check({ ...ok, x402: quote({ scheme: "incentiv-eoa-tx", extra: {} }) });
  assert.equal(r.verdict, "green", JSON.stringify(r.reasons));
  assert.equal(r.subject.account, ok.payer.toLowerCase());
  assert.equal(r.subject.validUntil, NOW + 120);
  const swapped = await check({ ...(await eoaTx({ to: OTHER })), x402: quote({ scheme: "incentiv-eoa-tx", extra: {} }) });
  assert.ok(codes(swapped).includes("red:X402_RECIPIENT_MISMATCH"));
  const gas = await check({ ...(await eoaTx({ gas: 500_000n })), x402: quote({ scheme: "incentiv-eoa-tx", extra: {} }) });
  assert.ok(codes(gas).includes("orange:TX_GAS_ABOVE_LIMIT"));
  const noDeadline = await check({ ...(await eoaTx({ accessList: [] })), x402: quote({ scheme: "incentiv-eoa-tx", extra: {} }) });
  assert.ok(codes(noDeadline).includes("orange:TX_DEADLINE_MISSING"));
  assert.equal(INC.maxEoaGas, 120_000n);
});
