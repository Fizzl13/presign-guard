// Open Wallet Standard (OWS) policy support: POST /v1/check also takes the PolicyContext an OWS custom executable
// policy receives on stdin, and answers with the PolicyResult OWS reads from stdout ({ allow, reason }) next to the
// usual verdict. So an OWS policy can be one curl command: OWS evaluates it before it decrypts the key, for agent
// tokens (ows_key_…), and denies on a non-zero exit, output without a boolean "allow", or no answer within 5 s.
// https://github.com/open-wallet-standard/core/blob/main/docs/03-policy-engine.md
//
// What each chain's transaction.raw_hex holds (OWS signers, Oct 2026): EVM the unsigned transaction envelope (RLP,
// typed or legacy), Solana the full wire transaction with its signature slots, XRPL the binary-encoded unsigned
// transaction (no STX\0 prefix). sign_typed_data brings typed_data.raw_json; sign_message and sign_hash bring the
// bytes. Chains presign-guard doesn't check (Bitcoin, Cosmos, Sui, …) are denied unless the policy's config says
// allow_unchecked; so are request types it can't judge (a Solana or XRPL hash or typed data).
//
// A Solana or XRPL message (a dApp sign-in, say) is judged like a personal_sign message: readable text is green, binary
// orange. Bytes that decode as a whole transaction are red (MESSAGE_IS_TRANSACTION): the signature over them is a
// signature over that transaction, the drainer's way around a wallet that shows transactions.
//
// policy_config (the policy file's "config"): allow_orange (default false: "orange" means a person should look, and
// an agent token has no person, so it is denied), allow_unchecked (default false), address (the wallet's address,
// for simulating EVM transactions and as the Solana signer).

import { getCompiledTransactionMessageDecoder } from "@solana/kit";
import { decode as decodeXrplBinary } from "ripple-binary-codec";
import { parseTransaction } from "viem";

const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const XRPL_IDS = { "xrpl:mainnet": "xrpl:0", "xrpl:0": "xrpl:0", "xrpl:testnet": "xrpl:1", "xrpl:1": "xrpl:1" };
const REQUEST_TYPES = new Set(["sign_transaction", "sign_message", "sign_hash", "sign_typed_data"]);

export class OwsUnchecked extends Error {
  constructor(message) {
    super(message);
    this.status = 400;
  }
}

// An OWS PolicyContext: chain_id and request_type, the two fields it always carries.
export function isOwsContext(body) {
  return Boolean(body && typeof body === "object" && typeof body.chain_id === "string" && REQUEST_TYPES.has(body.request_type));
}

const hexOf = (raw) => {
  const s = String(raw ?? "").trim();
  const h = s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s;
  if (!h || h.length % 2 || !/^[0-9a-fA-F]+$/.test(h)) throw new OwsUnchecked("transaction.raw_hex must be the hex payload OWS is about to sign");
  return h.toLowerCase();
};

// Whether message bytes are a transaction: a Solana transaction message (legacy or v0) using all of them, with a
// signer and an instruction; or a binary-encoded XRPL transaction with its type and account.
function solanaTransactionIn(hex) {
  const bytes = Buffer.from(hex, "hex");
  try {
    const [m, end] = getCompiledTransactionMessageDecoder().read(bytes, 0);
    return end === bytes.length && m.header.numSignerAccounts > 0 && m.staticAccounts.length > 0 && m.instructions.length > 0;
  } catch { return false; }
}
function xrplTransactionIn(hex) {
  try { const tx = decodeXrplBinary(hex.toUpperCase()); return typeof tx.TransactionType === "string" && typeof tx.Account === "string"; } catch { return false; }
}
const messageBody = (hex, chain, isTransaction) => ({ type: "message", method: "personal_sign", message: `0x${hex}`, ...(isTransaction(hex) && { disguisedTransaction: chain }) });

// The /v1/check body for an OWS PolicyContext, and the policy's options.
export function owsToCheck(ctx) {
  const config = ctx.policy_config && typeof ctx.policy_config === "object" ? ctx.policy_config : {};
  const options = { allowOrange: config.allow_orange === true, allowUnchecked: config.allow_unchecked === true };
  const address = typeof config.address === "string" && config.address ? config.address : undefined;
  const chain = ctx.chain_id;
  const type = ctx.request_type;
  const raw = () => hexOf(ctx.transaction?.raw_hex);

  if (chain.startsWith("eip155:")) {
    const chainId = Number(chain.slice("eip155:".length));
    if (type === "sign_typed_data") {
      const json = ctx.typed_data?.raw_json;
      if (typeof json !== "string" || !json) throw new OwsUnchecked("typed_data.raw_json is missing");
      return { body: { type: "signature", chainId, typedData: json }, options };
    }
    if (type === "sign_message") return { body: { type: "message", method: "personal_sign", message: `0x${raw()}`, chainId, ...(address && { from: address }) }, options };
    if (type === "sign_hash") return { body: { type: "message", method: "eth_sign", message: `0x${raw()}`, chainId, ...(address && { from: address }) }, options };
    const envelope = `0x${raw()}`;
    let tx;
    try { tx = parseTransaction(envelope); } catch { throw new OwsUnchecked("transaction.raw_hex is not an EVM transaction envelope"); }
    // An EIP-7702 transaction: the delegation is what hands the account over, so that is what is judged.
    const auth = tx.authorizationList?.[0];
    if (auth) {
      const authAddress = auth.address ?? auth.contractAddress;
      return { body: { type: "authorization", chainId, address: authAddress, authorizationChainId: Number(auth.chainId), nonce: auth.nonce !== undefined ? String(auth.nonce) : undefined, ...(address && { from: address }) }, options };
    }
    if (!tx.to) throw new OwsUnchecked("contract creation (a transaction without a recipient) isn't checked");
    return { body: { type: "transaction", chainId, to: tx.to, data: tx.data ?? "0x", value: String(tx.value ?? 0n), ...(address && { from: address }) }, options };
  }

  if (chain === SOLANA_MAINNET || chain === "solana:mainnet") {
    if (type === "sign_message") return { body: messageBody(raw(), "solana", solanaTransactionIn), options };
    if (type !== "sign_transaction") throw new OwsUnchecked(`${type} on Solana isn't checked, only transactions and messages`);
    return { body: { type: "solana", transaction: Buffer.from(raw(), "hex").toString("base64"), ...(address && { from: address }) }, options };
  }

  if (XRPL_IDS[chain]) {
    if (type === "sign_message") return { body: messageBody(raw(), "xrpl", xrplTransactionIn), options };
    if (type !== "sign_transaction") throw new OwsUnchecked(`${type} on the XRP Ledger isn't checked, only transactions and messages`);
    const binary = raw().toUpperCase();
    let tx;
    try { tx = decodeXrplBinary(binary); } catch { throw new OwsUnchecked("transaction.raw_hex is not a binary-encoded XRPL transaction"); }
    return { body: { type: "xrpl", network: XRPL_IDS[chain], tx }, options };
  }

  throw new OwsUnchecked(`presign-guard doesn't check ${chain}`);
}

// A PolicyContext that arrives unpaid (no credit key, a wrong one, or one without credits) gets its 402 as usual, with
// the PolicyResult OWS reads added. Without `allow`, OWS 1.4.3 denies with "invalid JSON from executable: missing field
// `allow`", which doesn't say what to do. Mounted before the paywall on POST /v1/check(/explain), after parsing the body.
const CREDIT_PROBLEMS = {
  invalid: "the x-credit-key header is not a credit key",
  unknown: "this credit key has no credits (used up, expired or mistyped)",
  insufficient: "this credit key has too few credits left",
  unavailable: "credits can't be checked right now; try again",
};
export function owsPaymentRequired(publicUrl) {
  return (req, res, next) => {
    if (!isOwsContext(req.body)) return next();
    const json = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode === 402 && body && typeof body === "object" && !("allow" in body)) {
        const problem = CREDIT_PROBLEMS[res.getHeader("x-credit-status")] ?? "no credit key was sent";
        body = { ...body, allow: false, reason: `presign-guard: ${problem}. Send one in the x-credit-key header (examples/ows/presign-guard.sh reads ~/.ows/presign-guard.key): 100 checks for $0.80 at ${publicUrl}/v1/credits/100` };
      }
      return json(body);
    };
    next();
  };
}

// The PolicyResult for a verdict: green allows; orange only with allow_orange; red never. The reason names the verdict
// and the reason codes that aren't just information.
export function owsResult(result, options = {}) {
  const verdict = result?.verdict;
  const allow = verdict === "green" || (verdict === "orange" && options.allowOrange === true);
  const codes = (result?.reasons ?? []).filter((r) => r && r.severity !== "info").map((r) => r.code);
  const effect = (result?.reasons ?? []).find((r) => r?.severity !== "info" && r?.details?.effect)?.details?.effect;
  const reason = `presign-guard ${verdict}${codes.length ? `: ${codes.slice(0, 6).join(", ")}` : ""}${effect ? ` (${effect})` : ""}`;
  return { allow, reason: reason.slice(0, 500) };
}
