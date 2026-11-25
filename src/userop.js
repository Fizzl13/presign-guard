// What an agent is about to authorize when it pays from a smart account (an ERC-4337 v0.7 user operation) or with a
// signed EVM transaction, read from what it signs, never from a claim.
//
// Built for x402 on Incentiv (eip155:24101, https://x402.incentiv.io; protocol spec: github.com/IncentivNetwork/
// incentiv-x402-public docs/SPEC.md), whose two schemes are exactly these:
//   incentiv-userop   the smart account's executeBatch: [USDC.transfer(paymaster, fee)], USDC.transfer(payTo, amount);
//                     the nonce key is the lane of keccak256(abi.encode(paymentId, validUntil)), the owner signs
//                     userOpHash (EIP-191).
//   incentiv-eoa-tx   a type-2 transaction: USDC.transfer(payTo, amount), gas <= 120,000, one access-list entry whose
//                     address is "x402" + validUntil (uint64) + 8 zero bytes: the signed deadline.
// userOpHash is opaque, so a wallet that signs it signs whatever the operation does. Every check here decodes the
// operation itself: its hash, its calls (to whom, how much, what else), its paymaster and gas, its deadline, and with
// the x402 requirements (`x402`: the accepts entry being paid) whether it pays exactly that and nothing more.
//
// Requests:
//   { type: "userop", chainId, entryPoint?, userOperation, userOpHash?, paymentId?, validUntil?, x402? }
//     userOperation: unpacked v0.7 fields as hex strings (sender, nonce, factory?, factoryData?, callData,
//     callGasLimit, verificationGasLimit, preVerificationGas, maxFeePerGas, maxPriorityFeePerGas, paymaster?,
//     paymasterVerificationGasLimit?, paymasterPostOpGasLimit?, paymasterData?, signature?).
//   { type: "signed_transaction", signedTransaction, x402? }   an EIP-1559 transaction, signed or not.
// Offline: no RPC is asked (no simulation, no balances); the parties are screened against the OFAC SDN list by the
// caller (presign-guard.js analyzeUserOp).

import {
  decodeFunctionData, encodeAbiParameters, isAddress, isHex, keccak256, parseAbi, parseTransaction,
  recoverTransactionAddress, hexToBigInt, getAddress,
} from "viem";
import { getUserOperationHash } from "viem/account-abstraction";

// Chains whose x402 smart-account and transaction payments we know by their contracts (SPEC.md section 1).
export const USEROP_CHAINS = {
  24101: {
    name: "Incentiv",
    caip2: "eip155:24101",
    entryPoint: "0x3ec61c5633bbd7afa9144c6610930489736a72d4",
    factory: "0xfed842f3c1d054361a840ae863c0b72db5cb2a32",
    paymaster: "0x43000f785eb43bcb4961c5c70276ed00e088972c",
    transferGate: "0x66f51d740d0ab781bc525b52d0d35d0585086aa1",
    usdc: "0x16e43840d8d79896a389a3de85ab0b0210c05685",
    // The reference client's default cap on the paymaster fee: 0.25 USDC (6 decimals).
    maxPaymasterFee: 250_000n,
    // incentiv-eoa-tx: the gas limit the facilitator accepts (SPEC 3.3).
    maxEoaGas: 120_000n,
    schemes: { userop: "incentiv-userop", eoa: "incentiv-eoa-tx" },
  },
};
// The canonical ERC-4337 v0.7 EntryPoint on other chains.
const ENTRYPOINT_V07 = "0x0000000071727de22e5e9d8baf0edac6f37da032";

const lc = (s) => String(s ?? "").toLowerCase();

const ACCOUNT_ABI = parseAbi([
  "function executeBatch(address[] dest, uint256[] value, bytes[] func)",
  "function executeBatch((address target, uint256 value, bytes data)[] calls)",
  "function execute(address dest, uint256 value, bytes func)",
  "function execute(address target, uint256 value, bytes data, uint8 operation)",
]);
const TOKEN_ABI = parseAbi([
  "function transfer(address to, uint256 amount)",
  "function transferFrom(address from, address to, uint256 amount)",
  "function approve(address spender, uint256 amount)",
  "function increaseAllowance(address spender, uint256 addedValue)",
  "function setApprovalForAll(address operator, bool approved)",
  "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)",
]);
const UNLIMITED = 2n ** 255n;
const AMOUNT_RE = /^(0|[1-9][0-9]*)$/;

export class UserOpError extends Error {}
const fail = (msg) => { throw new UserOpError(msg); };

const hexField = (v, name, { optional = false } = {}) => {
  if (v === undefined || v === null || v === "") {
    if (optional) return undefined;
    fail(`userOperation.${name} is required (a 0x hex string)`);
  }
  if (typeof v === "number" || typeof v === "bigint") return `0x${BigInt(v).toString(16)}`;
  if (typeof v !== "string" || !isHex(v)) fail(`userOperation.${name} must be a 0x hex string`);
  return v.toLowerCase();
};
const addrField = (v, name, { optional = false } = {}) => {
  if (v === undefined || v === null || v === "") {
    if (optional) return undefined;
    fail(`${name} is required (a 0x address)`);
  }
  if (typeof v !== "string" || !isAddress(v, { strict: false })) fail(`${name} must be a 0x address`);
  return v.toLowerCase();
};
const big = (h) => (h === undefined ? 0n : hexToBigInt(h));

// The x402 requirements being paid (one accepts entry, or { accepted }). Light checks; the comparison is below.
function parseQuote(raw) {
  if (raw === undefined || raw === null) return undefined;
  const a = typeof raw === "object" && !Array.isArray(raw) && raw.accepted && typeof raw.accepted === "object" ? raw.accepted : raw;
  if (!a || typeof a !== "object" || Array.isArray(a)) fail("x402 must be the payment requirements you are paying: { accepted: { scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra } }");
  const amount = a.amount ?? a.maxAmountRequired;
  if (amount !== undefined && !AMOUNT_RE.test(String(amount))) fail("x402 amount must be an integer in base units");
  for (const k of ["asset", "payTo"]) if (a[k] !== undefined && !isAddress(String(a[k]), { strict: false })) fail(`x402 ${k} must be a 0x address`);
  if (a.maxTimeoutSeconds !== undefined && !(Number.isInteger(a.maxTimeoutSeconds) && a.maxTimeoutSeconds >= 0)) fail("x402 maxTimeoutSeconds must be a whole number of seconds");
  return {
    scheme: typeof a.scheme === "string" ? a.scheme.slice(0, 40) : undefined,
    network: typeof a.network === "string" ? a.network.slice(0, 64) : undefined,
    amount: amount !== undefined ? BigInt(amount) : undefined,
    asset: a.asset !== undefined ? lc(a.asset) : undefined,
    payTo: a.payTo !== undefined ? lc(a.payTo) : undefined,
    maxTimeoutSeconds: a.maxTimeoutSeconds,
    entryPoint: a.extra && typeof a.extra.entryPoint === "string" ? lc(a.extra.entryPoint) : undefined,
  };
}

const chainIdOf = (body) => {
  const id = Number(body.chainId ?? (typeof body.network === "string" && /^eip155:\d+$/.test(body.network) ? body.network.slice(7) : NaN));
  if (!Number.isInteger(id) || id <= 0) fail("chainId must be the chain id number (24101 for Incentiv)");
  return id;
};

// { type: "userop", … } -> the request analyzeUserOp reads.
export function parseUserOpRequest(body) {
  const chainId = chainIdOf(body);
  const known = USEROP_CHAINS[chainId];
  const u = body.userOperation ?? body.userOp;
  if (!u || typeof u !== "object" || Array.isArray(u)) fail("userOperation must be the unpacked v0.7 user operation (sender, nonce, callData, gas fields, …)");
  const op = {
    sender: addrField(u.sender, "userOperation.sender"),
    nonce: hexField(u.nonce, "nonce"),
    factory: addrField(u.factory, "userOperation.factory", { optional: true }),
    factoryData: hexField(u.factoryData, "factoryData", { optional: true }),
    callData: hexField(u.callData, "callData"),
    callGasLimit: hexField(u.callGasLimit, "callGasLimit"),
    verificationGasLimit: hexField(u.verificationGasLimit, "verificationGasLimit"),
    preVerificationGas: hexField(u.preVerificationGas, "preVerificationGas"),
    maxFeePerGas: hexField(u.maxFeePerGas, "maxFeePerGas"),
    maxPriorityFeePerGas: hexField(u.maxPriorityFeePerGas, "maxPriorityFeePerGas"),
    paymaster: addrField(u.paymaster, "userOperation.paymaster", { optional: true }),
    paymasterVerificationGasLimit: hexField(u.paymasterVerificationGasLimit, "paymasterVerificationGasLimit", { optional: true }),
    paymasterPostOpGasLimit: hexField(u.paymasterPostOpGasLimit, "paymasterPostOpGasLimit", { optional: true }),
    paymasterData: hexField(u.paymasterData, "paymasterData", { optional: true }),
    signature: hexField(u.signature, "signature", { optional: true }) ?? "0x",
  };
  if (op.callData.length > 2 + 2 * 64 * 1024) fail("callData is longer than 64 KB");
  const entryPoint = addrField(body.entryPoint ?? body.x402?.accepted?.extra?.entryPoint ?? body.x402?.extra?.entryPoint ?? known?.entryPoint ?? ENTRYPOINT_V07, "entryPoint");
  const userOpHash = body.userOpHash !== undefined && body.userOpHash !== null && body.userOpHash !== ""
    ? (typeof body.userOpHash === "string" && /^0x[0-9a-fA-F]{64}$/.test(body.userOpHash) ? body.userOpHash.toLowerCase() : fail("userOpHash must be 0x + 64 hex characters"))
    : undefined;
  const paymentId = body.paymentId !== undefined && body.paymentId !== null && body.paymentId !== ""
    ? (typeof body.paymentId === "string" && /^0x[0-9a-fA-F]{64}$/.test(body.paymentId) ? body.paymentId.toLowerCase() : fail("paymentId must be 0x + 64 hex characters"))
    : undefined;
  const validUntil = body.validUntil !== undefined && body.validUntil !== null && body.validUntil !== ""
    ? (Number.isInteger(Number(body.validUntil)) && Number(body.validUntil) > 0 ? Number(body.validUntil) : fail("validUntil must be a unix time in seconds"))
    : undefined;
  return { kind: "userop", chainId, entryPoint, userOperation: op, userOpHash, paymentId, validUntil, quote: parseQuote(body.x402) };
}

// { type: "signed_transaction", signedTransaction, x402? } -> the request analyzeUserOp reads.
export function parseSignedTxRequest(body) {
  const raw = body.signedTransaction ?? body.serializedTransaction;
  if (typeof raw !== "string" || !isHex(raw) || raw.length < 10) fail("signedTransaction must be the 0x hex of an EIP-1559 transaction");
  if (raw.length > 2 + 2 * 64 * 1024) fail("signedTransaction is longer than 64 KB");
  let tx;
  try { tx = parseTransaction(raw); } catch (err) { fail(`signedTransaction could not be decoded: ${String(err.shortMessage || err.message).slice(0, 160)}`); }
  return { kind: "signed_transaction", raw: raw.toLowerCase(), tx, chainId: tx.chainId, quote: parseQuote(body.x402) };
}

// The calls an account call makes: [{ to, value, data }]. Null when callData is no batch/execute we know.
function accountCalls(callData) {
  let d;
  try { d = decodeFunctionData({ abi: ACCOUNT_ABI, data: callData }); } catch { return null; }
  if (d.functionName === "executeBatch" && d.args.length === 3) {
    const [dest, value, func] = d.args;
    if (value.length && value.length !== dest.length) return null;
    if (func.length !== dest.length) return null;
    return { method: "executeBatch", calls: dest.map((to, i) => ({ to: lc(to), value: value.length ? value[i] : 0n, data: lc(func[i]) })) };
  }
  if (d.functionName === "executeBatch") return { method: "executeBatch", calls: d.args[0].map((c) => ({ to: lc(c.target), value: c.value, data: lc(c.data) })) };
  if (d.functionName === "execute") {
    const [to, value, data, operation] = d.args;
    return { method: "execute", calls: [{ to: lc(to), value, data: lc(data), ...(operation !== undefined && { delegatecall: Number(operation) === 1 }) }] };
  }
  return null;
}

// One call, in words: a token transfer, an approval, or something else.
function describeCall(call) {
  if (!call.data || call.data === "0x") return { kind: "native", to: call.to, value: call.value };
  try {
    const d = decodeFunctionData({ abi: TOKEN_ABI, data: call.data });
    const [a, b, c] = d.args;
    switch (d.functionName) {
      case "transfer": return { kind: "transfer", token: call.to, to: lc(a), amount: b, value: call.value };
      case "transferFrom": return { kind: "transferFrom", token: call.to, from: lc(a), to: lc(b), amount: c, value: call.value };
      case "approve": return { kind: "approve", token: call.to, spender: lc(a), amount: b, value: call.value };
      case "increaseAllowance": return { kind: "approve", token: call.to, spender: lc(a), amount: b, value: call.value, increase: true };
      case "setApprovalForAll": return { kind: "approveAll", token: call.to, operator: lc(a), approved: b, value: call.value };
      case "permit": return { kind: "permit", token: call.to, spender: lc(b), amount: c, value: call.value };
    }
  } catch { /* not a token call */ }
  return { kind: "call", to: call.to, value: call.value, selector: call.data.slice(0, 10) };
}

// The nonce key a payment's lane uses (SPEC 4.3 item 2): the top 192 bits of keccak256(abi.encode(paymentId, validUntil)).
export function laneKey(paymentId, validUntil) {
  const h = keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint64" }], [paymentId, BigInt(validUntil)]));
  return hexToBigInt(h) >> 64n;
}

// incentiv-eoa-tx's deadline marker: "x402" (0x78343032) + validUntil (uint64, big-endian) + 8 zero bytes.
function deadlineOf(accessList) {
  if (!Array.isArray(accessList)) return null;
  for (const e of accessList) {
    const a = lc(e.address);
    if (a.startsWith("0x78343032") && a.endsWith("0000000000000000")) return Number(BigInt(`0x${a.slice(10, 26)}`));
  }
  return null;
}

const fmtUnits = (v, d) => {
  const s = v.toString().padStart(d + 1, "0");
  const whole = s.slice(0, -d), frac = s.slice(-d).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole;
};

// The rules. Returns { reasons, effects, subject }.
export function userOpReasons(req, { now = Math.floor(Date.now() / 1000) } = {}) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject && JSON.stringify(r.details ?? null) === JSON.stringify(details ?? null))) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };
  const known = USEROP_CHAINS[req.chainId];
  const usdc = known?.usdc;
  const tokenName = (t) => (usdc && t === usdc ? "USDC" : t);
  const amountText = (t, a) => (usdc && t === usdc ? `${fmtUnits(a, 6)} USDC` : `${a} base units of ${t}`);

  let calls, method, payer, gas = null, deadline = null;
  if (req.kind === "userop") {
    const op = req.userOperation;
    payer = op.sender;
    // The hash the owner signs: is it this operation?
    try {
      const userOperation = {
        sender: getAddress(op.sender), nonce: big(op.nonce), callData: op.callData,
        callGasLimit: big(op.callGasLimit), verificationGasLimit: big(op.verificationGasLimit), preVerificationGas: big(op.preVerificationGas),
        maxFeePerGas: big(op.maxFeePerGas), maxPriorityFeePerGas: big(op.maxPriorityFeePerGas), signature: op.signature,
        ...(op.factory && { factory: getAddress(op.factory), factoryData: op.factoryData ?? "0x" }),
        ...(op.paymaster && {
          paymaster: getAddress(op.paymaster), paymasterData: op.paymasterData ?? "0x",
          paymasterVerificationGasLimit: big(op.paymasterVerificationGasLimit), paymasterPostOpGasLimit: big(op.paymasterPostOpGasLimit),
        }),
      };
      const hash = getUserOperationHash({ userOperation, entryPointAddress: getAddress(req.entryPoint), entryPointVersion: "0.7", chainId: req.chainId });
      if (req.userOpHash && lc(hash) !== req.userOpHash) add("USEROP_HASH_MISMATCH", "red", payer, { given: req.userOpHash, computed: lc(hash), effect: "the hash you would sign is not this operation's: you would authorize something else than what you see" });
      req.computedHash = lc(hash);
    } catch (err) {
      add("USEROP_UNREADABLE", "red", payer, { error: String(err.shortMessage || err.message).slice(0, 160) });
    }
    if (known && req.entryPoint !== known.entryPoint) add("USEROP_ENTRYPOINT_UNKNOWN", "red", req.entryPoint, { expected: known.entryPoint, chain: known.name });
    else if (!known && req.entryPoint !== ENTRYPOINT_V07) add("USEROP_ENTRYPOINT_UNKNOWN", "orange", req.entryPoint, { expected: ENTRYPOINT_V07 });
    if (op.factory) {
      if (known && op.factory !== known.factory) add("USEROP_FACTORY_UNKNOWN", "red", op.factory, { expected: known.factory, effect: "this operation deploys the account from a factory that isn't the chain's account factory" });
      else add("USEROP_DEPLOYS_ACCOUNT", "info", op.sender, { factory: op.factory });
    }
    const decoded = accountCalls(op.callData);
    if (!decoded) { add("USEROP_CALLS_UNREADABLE", "red", payer, { selector: op.callData.slice(0, 10), effect: "the account call isn't execute or executeBatch: what it does can't be read" }); calls = []; }
    else { calls = decoded.calls; method = decoded.method; }
    // Gas: what the operation may cost at most, in the native coin (without a paymaster) or through the paymaster.
    const limits = big(op.callGasLimit) + big(op.verificationGasLimit) + big(op.preVerificationGas) + big(op.paymasterVerificationGasLimit) + big(op.paymasterPostOpGasLimit);
    gas = { limits, maxFeePerGas: big(op.maxFeePerGas), maxCostWei: limits * big(op.maxFeePerGas), paymaster: op.paymaster ?? null };
    if (op.paymaster && known && op.paymaster !== known.paymaster) add("USEROP_PAYMASTER_UNKNOWN", "orange", op.paymaster, { expected: known.paymaster });
    else if (op.paymaster && !known) add("USEROP_PAYMASTER", "info", op.paymaster);
    // The deadline and the nonce lane (Incentiv): the signature covers the nonce, so the lane binds the deadline.
    if (req.paymentId && req.validUntil) {
      const key = laneKey(req.paymentId, req.validUntil);
      if ((big(op.nonce) >> 64n) !== key) add("USEROP_NONCE_LANE_MISMATCH", "red", payer, { effect: "the nonce isn't this payment's lane: the signed operation is not bound to the paymentId and deadline it claims" });
      deadline = req.validUntil;
    } else if (known) add("USEROP_DEADLINE_NOT_SENT", "info", payer, { send: "paymentId and validUntil from the payload, to check the deadline the nonce lane binds" });
  } else {
    const tx = req.tx;
    payer = req.signer ?? null;
    if (tx.type !== "eip1559") add("TX_NOT_EIP1559", known ? "red" : "info", null, { type: tx.type });
    calls = tx.to ? [{ to: lc(tx.to), value: tx.value ?? 0n, data: lc(tx.data ?? "0x") }] : [];
    if (!tx.to) add("TX_DEPLOYS_CONTRACT", "red", null, { effect: "this transaction deploys a contract" });
    gas = { limits: tx.gas ?? 0n, maxFeePerGas: tx.maxFeePerGas ?? tx.gasPrice ?? 0n, maxCostWei: (tx.gas ?? 0n) * (tx.maxFeePerGas ?? tx.gasPrice ?? 0n), paymaster: null };
    if (known && tx.gas > known.maxEoaGas) add("TX_GAS_ABOVE_LIMIT", "orange", null, { gas: tx.gas.toString(), limit: known.maxEoaGas.toString() });
    deadline = deadlineOf(tx.accessList);
    if (known && deadline === null) add("TX_DEADLINE_MISSING", "orange", null, { effect: "no x402 deadline marker in the access list: a signed transfer without a deadline can be sent any time until its nonce is used" });
  }

  // Each call, by what it does.
  const effects = calls.map(describeCall);
  for (const e of effects) {
    if (e.value > 0n) add("CALL_SENDS_NATIVE", "orange", e.to, { value: e.value.toString() });
    if (e.kind === "approve") add(e.amount >= UNLIMITED ? "UNLIMITED_APPROVAL" : "APPROVAL", e.amount >= UNLIMITED ? "red" : "orange", e.spender, { token: e.token, amount: e.amount.toString() });
    if (e.kind === "approveAll" && e.approved) add("APPROVAL_FOR_ALL", "red", e.operator, { token: e.token });
    if (e.kind === "permit") add("PERMIT", "orange", e.spender, { token: e.token, amount: e.amount.toString() });
    if (e.kind === "transferFrom") add("TRANSFER_FROM", "orange", e.to, { token: e.token, from: e.from, amount: e.amount.toString() });
    if (e.kind === "call") add("UNKNOWN_CALL", "orange", e.to, { selector: e.selector });
  }
  for (const c of calls) if (c.delegatecall) add("DELEGATECALL", "red", c.to, { effect: "the account runs another contract's code as itself: it can do anything with the account" });

  // The quoted payment: exactly one transfer of amount of asset to payTo, plus at most the paymaster's fee.
  const q = req.quote;
  if (q) {
    const scheme = known && (req.kind === "userop" ? known.schemes.userop : known.schemes.eoa);
    if (q.network && q.network !== `eip155:${req.chainId}`) add("X402_NETWORK_MISMATCH", "red", null, { asked: q.network, signing: `eip155:${req.chainId}` });
    if (scheme && q.scheme && q.scheme !== scheme) add("X402_SCHEME_UNEXPECTED", "orange", null, { asked: q.scheme, signing: scheme });
    if (req.kind === "userop" && q.entryPoint && q.entryPoint !== req.entryPoint) add("X402_ENTRYPOINT_MISMATCH", "red", req.entryPoint, { asked: q.entryPoint });
    const transfers = effects.filter((e) => e.kind === "transfer");
    const toPayee = transfers.filter((e) => q.payTo === undefined || e.to === q.payTo);
    const fee = req.kind === "userop" && req.userOperation.paymaster ? transfers.filter((e) => e.to === req.userOperation.paymaster) : [];
    const rest = effects.filter((e) => !toPayee.includes(e) && !fee.includes(e));
    if (q.payTo !== undefined && toPayee.length === 0) {
      const other = transfers.find((e) => !fee.includes(e));
      add("X402_RECIPIENT_MISMATCH", "red", other?.to ?? null, { asked: q.payTo, effect: other ? `this pays ${other.to}, not the seller's payTo ${q.payTo}` : "nothing in it pays the seller's payTo" });
    }
    if (toPayee.length > 1) add("X402_PAYS_TWICE", "red", q.payTo, { transfers: toPayee.length });
    for (const e of toPayee) {
      if (q.asset !== undefined && e.token !== q.asset) add("X402_ASSET_MISMATCH", "red", e.token, { asked: q.asset });
      if (q.amount !== undefined && e.amount > q.amount) add("X402_AMOUNT_ABOVE_REQUIRED", "red", q.payTo, { asked: q.amount.toString(), signing: e.amount.toString() });
      else if (q.amount !== undefined && e.amount < q.amount) add("X402_AMOUNT_BELOW_REQUIRED", "info", q.payTo, { asked: q.amount.toString(), signing: e.amount.toString() });
    }
    if (rest.length) add("X402_EXTRA_CALLS", "red", null, { calls: rest.map((e) => ({ kind: e.kind, to: e.to ?? e.spender ?? e.operator, ...(e.token && { token: e.token }) })), effect: "the payment does more than pay the seller (and the paymaster's fee)" });
    if (q.maxTimeoutSeconds !== undefined && deadline !== null) {
      const left = deadline - now;
      if (left > Math.min(q.maxTimeoutSeconds, 300) + 5 && left > 0) add("X402_VALIDITY_TOO_LONG", "orange", null, { validForSeconds: left, sellerTimeout: q.maxTimeoutSeconds });
    }
  }
  if (deadline !== null && deadline <= now) add("PAYMENT_EXPIRED", "info", null, { validUntil: deadline, effect: "the deadline has passed: a facilitator refuses it, but nothing on chain stops it until its nonce is used" });

  // The paymaster fee (Incentiv: a USDC transfer to the paymaster before the payment).
  if (req.kind === "userop" && req.userOperation.paymaster) {
    for (const e of effects.filter((x) => x.kind === "transfer" && x.to === req.userOperation.paymaster)) {
      if (known && e.token === known.usdc && e.amount > known.maxPaymasterFee) add("PAYMASTER_FEE_HIGH", "orange", e.to, { fee: e.amount.toString(), cap: known.maxPaymasterFee.toString() });
      else add("PAYMASTER_FEE", "info", e.to, { token: e.token, fee: e.amount.toString() });
    }
  }

  const actions = effects.map((e) => {
    switch (e.kind) {
      case "transfer": return `pay ${amountText(e.token, e.amount)} to ${e.to}`;
      case "approve": return `let ${e.spender} spend ${e.amount >= UNLIMITED ? "unlimited" : amountText(e.token, e.amount)} of ${tokenName(e.token)}`;
      case "approveAll": return `${e.approved ? "let" : "stop"} ${e.operator} move every token of ${e.token}`;
      case "transferFrom": return `move ${amountText(e.token, e.amount)} from ${e.from} to ${e.to}`;
      case "permit": return `sign a permit for ${e.spender} on ${tokenName(e.token)}`;
      case "native": return `send ${e.value} wei to ${e.to}`;
      default: return `call ${e.to} (${e.selector})`;
    }
  });
  const subject = {
    kind: req.kind === "userop" ? "user_operation" : "signed_transaction",
    chainId: req.chainId,
    chain: known?.name ?? `eip155:${req.chainId}`,
    ...(payer && { account: payer }),
    ...(req.kind === "userop" && { entryPoint: req.entryPoint, userOpHash: req.computedHash ?? null, method }),
    actions,
    gas: gas && {
      limit: gas.limits.toString(), maxFeePerGas: gas.maxFeePerGas.toString(),
      ...(gas.paymaster ? { paidBy: gas.paymaster } : { maxCostWei: gas.maxCostWei.toString() }),
    },
    ...(deadline !== null && { validUntil: deadline }),
  };
  return { reasons, effects, subject };
}

// Every party a payment touches, for the sanctions screen.
export function userOpParties(effects) {
  const out = new Set();
  for (const e of effects) for (const a of [e.to, e.spender, e.operator, e.from]) if (a) out.add(a);
  return [...out];
}

export const USEROP_SCOPE = "ERC-4337 v0.7 user operations and signed EVM transactions before signing, with Incentiv's x402 schemes (incentiv-userop, incentiv-eoa-tx) known by their contracts: whether userOpHash is this operation, what the account's execute/executeBatch calls do (token transfers, approvals, unknown calls, native value, delegatecall), the EntryPoint, factory and paymaster, the paymaster fee and the gas limits, the nonce lane that binds the payment id and deadline, the deadline marker of an incentiv-eoa-tx transfer, and with the x402 requirements whether it pays exactly the quoted amount of the quoted asset to the payTo and nothing else; every party against the OFAC SDN list. Not covered: simulation and balances (no RPC is asked), TransferGate approvals, and the account's own code beyond execute/executeBatch.";
