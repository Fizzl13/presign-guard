// A verdict bound to the exact transaction (Frits, 17 Nov 2026: "Doe maar", after the TAT Risk review).
//
// A green verdict is only worth something for the transaction that was checked. If an agent (or anything between
// the agent and the wallet) changes the recipient, the spender or the amount after the check, the old "green" must
// not count. So the signed receipt of an EVM transaction check carries a `binding`:
//
//   { scope: "evm-tx-v1", tx: {chainId, from, to, value, data}, tx_sha256, valid_until }
//
// - `tx` holds the checked fields, normalised: addresses and data lowercase, value as a decimal string, from null
//   when the request had none. `tx_sha256` is the SHA-256 of their canonical JSON (keys by UTF-16 code units, the
//   same canonicalJson as the receipt), so any language can recompute it.
// - `valid_until`: 2 minutes for a swap (prices and pools move), 10 minutes for anything else.
// - It sits inside the receipt, so our signature covers it: it cannot be moved to another transaction or extended.
//
// checkBinding(tx, signedAnswer) runs in the wallet, offline, right before it signs, and answers:
//   MATCH      same transaction, still valid, signed by us: sign if the verdict is green
//   CHANGED    a field changed since the check; `changed` names it (to, value, data, or decoded: spender, amount,
//              recipient, amountOutMin, path, deadline, operator, ...)
//   EXPIRED    the verdict is older than valid_until: ask for a fresh one
//   UNTRUSTED  not signed by presign-guard, the signature does not match, or no binding in it
// Standard wallet fields (gas, nonce, maxFeePerGas, type, ...) are ignored, not refused: they don't change what the
// transaction does. A positive MATCH is never an authorisation on its own: `sign_ok` is MATCH and a green verdict.

import { decodeFunctionData, parseAbi } from "viem";
import { canonicalJson, sha256, verifyReceipt } from "./receipt.js";

export const BINDING_SCOPE = "evm-tx-v1";
export const SWAP_VALID_MS = 2 * 60_000;
export const OTHER_VALID_MS = 10 * 60_000;

// Calls whose fields we can name when the data changed. Swaps also get the short validity.
const ABI = parseAbi([
  "function approve(address spender,uint256 amount)",
  "function increaseAllowance(address spender,uint256 addedValue)",
  "function transfer(address recipient,uint256 amount)",
  "function transferFrom(address owner,address recipient,uint256 amount)",
  "function setApprovalForAll(address operator,bool approved)",
  "function swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address recipient,uint256 deadline)",
  "function swapTokensForExactTokens(uint256 amountOut,uint256 amountInMax,address[] path,address recipient,uint256 deadline)",
  "function swapExactETHForTokens(uint256 amountOutMin,address[] path,address recipient,uint256 deadline)",
  "function swapExactTokensForETH(uint256 amountIn,uint256 amountOutMin,address[] path,address recipient,uint256 deadline)",
  "function swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address recipient,uint256 deadline)",
  "function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
  "function exactInput((bytes path,address recipient,uint256 amountIn,uint256 amountOutMinimum) params)",
  "function execute(bytes commands,bytes[] inputs,uint256 deadline)",
  "function execute(bytes commands,bytes[] inputs)",
]);
const SWAPS = new Set(["swapExactTokensForTokens", "swapTokensForExactTokens", "swapExactETHForTokens", "swapExactTokensForETH",
  "swapExactTokensForTokensSupportingFeeOnTransferTokens", "exactInputSingle", "exactInput", "execute"]);

const HEX = /^0x[0-9a-fA-F]*$/;
const ADDR = /^0x[0-9a-fA-F]{40}$/;

function decimal(v) {
  if (v === undefined || v === null || v === "") return "0";
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return String(v);
  if (typeof v === "bigint" && v >= 0n) return v.toString();
  if (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v)) return v;
  if (typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v).toString();
  return null;
}

/** The fields a signer signs, normalised; null when they are not a valid EVM transaction. */
export function normaliseTx(tx, chainId = tx?.chainId) {
  if (!tx || typeof tx !== "object") return null;
  const cid = typeof chainId === "string" && /^[0-9]+$/.test(chainId) ? Number(chainId) : typeof chainId === "string" && /^0x[0-9a-fA-F]+$/.test(chainId) ? Number(BigInt(chainId)) : chainId;
  const value = decimal(tx.value);
  const data = tx.data ?? tx.input ?? "0x";
  if (!Number.isSafeInteger(cid) || cid <= 0 || typeof tx.to !== "string" || !ADDR.test(tx.to) || value === null || typeof data !== "string" || !HEX.test(data)) return null;
  if (tx.from !== undefined && tx.from !== null && (typeof tx.from !== "string" || !ADDR.test(tx.from))) return null;
  return { chainId: cid, from: tx.from ? tx.from.toLowerCase() : null, to: tx.to.toLowerCase(), value, data: data.toLowerCase() };
}

export const txSha256 = (tx) => sha256(canonicalJson(tx));

function decode(data) {
  try {
    return decodeFunctionData({ abi: ABI, data });
  } catch {
    return null;
  }
}

/** The binding for a checked request, or null when it is not an EVM transaction check. */
export function bindingFor(input, now = Date.now()) {
  if (!input || input.type !== "transaction") return null;
  const tx = normaliseTx(input, input.chainId);
  if (!tx) return null;
  const call = decode(tx.data);
  const ms = call && SWAPS.has(call.functionName) ? SWAP_VALID_MS : OTHER_VALID_MS;
  return { scope: BINDING_SCOPE, tx, tx_sha256: txSha256(tx), valid_until: new Date(now + ms).toISOString() };
}

// Flatten decoded arguments to named fields (struct params included) so a change can be named.
function fields(call) {
  const out = {};
  const item = ABI.find((x) => x.type === "function" && x.name === call.functionName && x.inputs.length === call.args.length);
  (item?.inputs ?? []).forEach((input, i) => {
    const v = call.args[i];
    if (input.type === "tuple" && v && typeof v === "object") for (const c of input.components) out[c.name] = v[c.name];
    else out[input.name] = v;
  });
  const norm = (v) => (typeof v === "bigint" ? v.toString() : Array.isArray(v) ? v.map(norm).join(",") : typeof v === "string" ? v.toLowerCase() : String(v));
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, norm(v)]));
}

/** Which fields changed between the checked data and the data about to be signed. */
export function changedData(checked, actual) {
  if (checked === actual) return [];
  const a = decode(checked), b = decode(actual);
  if (!a || !b || a.functionName !== b.functionName) return ["data"];
  const fa = fields(a), fb = fields(b);
  const names = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].filter((k) => fa[k] !== fb[k]);
  return names.length ? names : ["data"];
}

/**
 * Before signing: is this the transaction presign-guard checked, still valid, signed by us?
 * `signers` (from GET /.well-known/presign-guard-signers or the published list) pins our keys; a certified rotated
 * key also counts (see verifyReceipt).
 */
export async function checkBinding(tx, signedAnswer, { signers = [], now = Date.now() } = {}) {
  const verdict = signedAnswer?.verdict ?? null;
  const base = { result: "UNTRUSTED", changed: [], verdict, valid_until: null, sign_ok: false };
  const sig = await verifyReceipt(signedAnswer, { signers });
  if (!sig.valid) return { ...base, reason: sig.reason };
  if (sig.known_signer === false) return { ...base, reason: "signed, but not by a presign-guard signer" };
  const b = signedAnswer.receipt?.binding;
  if (!b || b.scope !== BINDING_SCOPE || !b.tx || typeof b.valid_until !== "string") return { ...base, reason: "no transaction binding in this answer (only EVM transaction checks carry one)" };
  if (txSha256(b.tx) !== b.tx_sha256) return { ...base, reason: "the binding's tx_sha256 does not match its tx" };
  const actual = normaliseTx(tx, tx?.chainId ?? b.tx.chainId);
  if (!actual) return { ...base, valid_until: b.valid_until, reason: "the transaction about to be signed is not a valid EVM transaction (chainId, to, value, data)" };
  const changed = [];
  if (actual.chainId !== b.tx.chainId) changed.push("chainId");
  if (b.tx.from && actual.from && actual.from !== b.tx.from) changed.push("from");
  if (actual.to !== b.tx.to) changed.push("to");
  if (actual.value !== b.tx.value) changed.push("value");
  changed.push(...changedData(b.tx.data, actual.data));
  const expired = !(now < Date.parse(b.valid_until));
  const result = changed.length ? "CHANGED" : expired ? "EXPIRED" : "MATCH";
  return {
    result,
    changed,
    expired,
    verdict,
    valid_until: b.valid_until,
    sign_ok: result === "MATCH" && verdict === "green",
    next: result === "MATCH" ? (verdict === "green" ? "sign" : "ask the owner (the verdict is not green)") : result === "CHANGED" ? "do not sign: check the changed transaction again" : "ask presign-guard for a fresh verdict",
  };
}
