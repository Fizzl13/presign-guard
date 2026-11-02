// near-tx.js — the pre-sign check for NEAR transactions (POST /v1/check with type "near").
//
//   { type: "near", transaction: "<base64 borsh Transaction or SignedTransaction>", network?, from?, origin?, intent? }
//   { type: "near", tx: { signerId, receiverId, actions: [...] }, ... }            // wallet-selector JSON
//   { type: "near", transactions: [<base64> | { signerId, receiverId, actions }], ... }  // several, as signAndSendTransactions
//   { type: "near", nep413: { message, recipient: "intents.near", nonce } }       // a NEAR Intents message to sign
//
// On NEAR an account is controlled by its access keys. A full-access key can do everything: move every token,
// delete the account, deploy code over it. A function-call key can only call the methods it names on one contract,
// without attaching a deposit, and spend a gas allowance. That is the sandbox NEAR gives an AI agent, and it is what
// the riskiest NEAR transactions take apart:
//
// - AddKey with full access on the wallet: whoever holds that key owns the account (red).
// - DeleteAccount: the remaining NEAR goes to the beneficiary and every token on the account is lost (red).
// - DeployContract or UseGlobalContract on the wallet itself: the account's behaviour is replaced by that code (red).
// - DeleteKey of the wallet's last full-access key: nobody can control the account any more (red); of another
//   full-access key: orange.
// - intents.near add_public_key: that key can sign intents that move everything the wallet holds in NEAR Intents (red).
// - NEP-145 storage_unregister with force: the token balance is burned (red).
// - ft_transfer / ft_transfer_call in a token that calls itself USDC, USDT or wNEAR but isn't the real contract (red).
// - A receiver that looks like a well-known account but isn't it (wrap-near.near for wrap.near) (red).
// - nft_approve to another account, a function-call key with an unlimited gas allowance, a deposit into NEAR Intents
//   credited to someone else, and a large deposit to a contract that isn't a known one (orange).
//
// Meta transactions (SignedDelegate) are judged by their inner actions. Read-only RPC (view calls, access-key list);
// when it can't be reached the field rules still apply and the check says so (info). Fail-closed as in
// presign-guard.js: errors are non-2xx, never "green".
import { decodeTransaction, decodeSignedTransaction } from "@near-js/transactions";
import { baseEncode } from "@near-js/utils";

export const NEAR_NETWORKS = {
  mainnet: {
    caip2: "near:mainnet", name: "NEAR",
    rpc: process.env.NEAR_RPC_URL || "https://free.rpc.fastnear.com",
    // The real contracts of the tokens most often copied. Read from ft_metadata on 2 Nov 2026.
    tokens: {
      "wrap.near": "wNEAR",
      "usdt.tether-token.near": "USDt",
      "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1": "USDC",
      "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.factory.bridge.near": "USDC.e",
      "dac17f958d2ee523a2206206994597c13d831ec7.factory.bridge.near": "USDT.e",
    },
    known: ["wrap.near", "intents.near", "usdt.tether-token.near", "aurora", "v2.ref-finance.near", "dclv2.ref-labs.near", "contract.main.burrow.near", "meta-pool.near", "linear-protocol.near", "relay.aurora", "factory.bridge.near", "social.near", "near", "lockup.near", "poolv1.near"],
  },
  testnet: {
    caip2: "near:testnet", name: "NEAR testnet",
    rpc: process.env.NEAR_TESTNET_RPC_URL || "https://rpc.testnet.fastnear.com",
    tokens: { "wrap.testnet": "wNEAR" },
    known: ["wrap.testnet", "intents.testnet", "testnet"],
  },
};
const INTENTS = { mainnet: "intents.near", testnet: "intents.testnet" };
const MAX_TX_CHARS = 12000;
const MAX_TXS = 10;
const RPC_TIMEOUT_MS = 5000;
const YOCTO = 10n ** 24n;
const LARGE_DEPOSIT = 10n * YOCTO; // 10 NEAR attached to a call
// A token that calls itself one of these must be one of the real contracts above.
const COPIED_SYMBOLS = /^(usdc|usdc\.e|usdt|usdt\.e|usd₮|wnear|near)$/i;

export class NearValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

// NEAR account ids: 2–64 characters of lowercase letters, digits and - _ separated by dots; implicit accounts are
// 64 hex characters (ed25519) or 0x + 40 hex (ETH-implicit).
const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
export const isNearAccount = (a) => typeof a === "string" && a.length >= 2 && a.length <= 64 && ACCOUNT_RE.test(a);
const isImplicit = (a) => /^[0-9a-f]{64}$/.test(a) || /^0x[0-9a-f]{40}$/.test(a);

function pickNetwork(n) {
  if (n === undefined || n === null || n === "") return "mainnet";
  const s = String(n).toLowerCase();
  if (s === "mainnet" || s === "near:mainnet" || s === "near") return "mainnet";
  if (s === "testnet" || s === "near:testnet") return "testnet";
  throw new NearValidationError(`unsupported NEAR network ${n}: mainnet and testnet are checked`);
}

const big = (v) => { try { return BigInt(v ?? 0); } catch { return 0n; } };
const nearAmount = (yocto) => {
  const whole = yocto / YOCTO;
  const frac = (yocto % YOCTO).toString().padStart(24, "0").slice(0, 4).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
};

// A borsh public key ({ ed25519Key: { data } } or { secp256k1Key: { data } }) or "ed25519:…" as a string.
function keyString(pk) {
  if (typeof pk === "string") return pk;
  if (pk?.ed25519Key?.data) return `ed25519:${baseEncode(Uint8Array.from(pk.ed25519Key.data))}`;
  if (pk?.secp256k1Key?.data) return `secp256k1:${baseEncode(Uint8Array.from(pk.secp256k1Key.data))}`;
  return null;
}

// Function-call arguments as an object when they are JSON, else null (and how many bytes they were).
function parseArgs(args) {
  if (args === undefined || args === null) return { args: null };
  if (typeof args === "object" && !Array.isArray(args) && !(args instanceof Uint8Array)) return { args };
  let bytes;
  if (typeof args === "string") {
    try { bytes = Buffer.from(args, "base64"); } catch { return { args: null }; }
  } else {
    bytes = Buffer.from(Uint8Array.from(args));
  }
  try { return { args: JSON.parse(bytes.toString("utf8")) }; } catch { return { args: null, argsBytes: bytes.length }; }
}

// One action, from borsh ({ transfer: { deposit } }) or wallet-selector JSON ({ type: "Transfer", params: { deposit } }),
// as { kind, … } with plain values.
export function normalizeAction(a) {
  if (!a || typeof a !== "object") throw new NearValidationError("every action must be an object");
  if (typeof a.type === "string") {
    const p = a.params ?? {};
    switch (a.type) {
      case "CreateAccount": return { kind: "createAccount" };
      case "Transfer": return { kind: "transfer", deposit: big(p.deposit) };
      case "FunctionCall": return { kind: "functionCall", methodName: String(p.methodName ?? ""), ...parseArgs(p.args), gas: big(p.gas), deposit: big(p.deposit) };
      case "AddKey": {
        const perm = p.accessKey?.permission;
        const full = perm === "FullAccess" || perm?.fullAccess !== undefined;
        return { kind: "addKey", publicKey: keyString(p.publicKey), fullAccess: full, ...(!full && {
          receiverId: perm?.receiverId ?? null,
          methodNames: Array.isArray(perm?.methodNames) ? perm.methodNames.map(String) : [],
          allowance: perm?.allowance === undefined || perm?.allowance === null ? null : big(perm.allowance),
        }) };
      }
      case "DeleteKey": return { kind: "deleteKey", publicKey: keyString(p.publicKey) };
      case "DeleteAccount": return { kind: "deleteAccount", beneficiaryId: String(p.beneficiaryId ?? "") };
      case "DeployContract": return { kind: "deployContract" };
      case "DeployGlobalContract": return { kind: "deployGlobalContract" };
      case "UseGlobalContract": return { kind: "useGlobalContract" };
      case "Stake": return { kind: "stake", stake: big(p.stake), publicKey: keyString(p.publicKey) };
      default: throw new NearValidationError(`unknown NEAR action type ${a.type}`);
    }
  }
  if (a.createAccount) return { kind: "createAccount" };
  if (a.transfer) return { kind: "transfer", deposit: big(a.transfer.deposit) };
  if (a.functionCall) return { kind: "functionCall", methodName: String(a.functionCall.methodName ?? ""), ...parseArgs(a.functionCall.args), gas: big(a.functionCall.gas), deposit: big(a.functionCall.deposit) };
  if (a.addKey) {
    const perm = a.addKey.accessKey?.permission ?? {};
    const fc = perm.functionCall;
    return { kind: "addKey", publicKey: keyString(a.addKey.publicKey), fullAccess: !fc, ...(fc && {
      receiverId: fc.receiverId ?? null,
      methodNames: Array.isArray(fc.methodNames) ? fc.methodNames.map(String) : [],
      allowance: fc.allowance === undefined || fc.allowance === null ? null : big(fc.allowance),
    }) };
  }
  if (a.deleteKey) return { kind: "deleteKey", publicKey: keyString(a.deleteKey.publicKey) };
  if (a.deleteAccount) return { kind: "deleteAccount", beneficiaryId: String(a.deleteAccount.beneficiaryId ?? "") };
  if (a.deployContract) return { kind: "deployContract" };
  if (a.deployGlobalContract) return { kind: "deployGlobalContract" };
  if (a.useGlobalContract) return { kind: "useGlobalContract" };
  if (a.stake) return { kind: "stake", stake: big(a.stake.stake), publicKey: keyString(a.stake.publicKey) };
  if (a.signedDelegate) {
    const d = a.signedDelegate.delegateAction ?? {};
    return {
      kind: "signedDelegate",
      senderId: String(d.senderId ?? ""),
      receiverId: String(d.receiverId ?? ""),
      actions: (d.actions ?? []).map(normalizeAction),
    };
  }
  throw new NearValidationError("unknown NEAR action");
}

function fromBase64(raw) {
  const s = String(raw).trim();
  if (!s || s.length > MAX_TX_CHARS || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    throw new NearValidationError("transaction must be a base64 borsh NEAR transaction (unsigned or signed)");
  }
  const bytes = Buffer.from(s, "base64");
  let tx;
  try { tx = decodeTransaction(bytes); } catch {
    try { tx = decodeSignedTransaction(bytes).transaction; } catch {
      throw new NearValidationError("transaction could not be decoded as a NEAR transaction");
    }
  }
  return { signerId: tx.signerId, receiverId: tx.receiverId, publicKey: keyString(tx.publicKey), actions: tx.actions.map(normalizeAction) };
}

function fromJson(t) {
  if (!t || typeof t !== "object") throw new NearValidationError("tx must be an object with signerId, receiverId and actions");
  if (!isNearAccount(t.receiverId)) throw new NearValidationError("tx.receiverId must be a NEAR account id");
  if (t.signerId !== undefined && t.signerId !== null && !isNearAccount(t.signerId)) throw new NearValidationError("tx.signerId must be a NEAR account id");
  if (!Array.isArray(t.actions) || !t.actions.length) throw new NearValidationError("tx.actions must be a non-empty list");
  return { signerId: t.signerId ?? null, receiverId: t.receiverId, publicKey: null, actions: t.actions.map(normalizeAction) };
}

// The request decoded: network, wallet (from, else the signer), and the transactions as plain values.
export function parseNearRequest(body) {
  const network = pickNetwork(body.network);
  let txs;
  const signed = body.nep413 !== undefined ? [parseIntentsMessage(body.nep413, network)] : [];
  if (signed.length && body.transaction === undefined && body.tx === undefined && body.transactions === undefined) txs = [];
  else if (body.transaction !== undefined) txs = [fromBase64(body.transaction)];
  else if (body.tx !== undefined) txs = [fromJson(body.tx)];
  else if (Array.isArray(body.transactions)) {
    if (!body.transactions.length || body.transactions.length > MAX_TXS) throw new NearValidationError(`transactions must hold 1 to ${MAX_TXS} transactions`);
    txs = body.transactions.map((t) => (typeof t === "string" ? fromBase64(t) : fromJson(t)));
  } else {
    throw new NearValidationError("send transaction (base64 borsh), tx (signerId, receiverId, actions), transactions, or nep413 (a NEAR Intents message)");
  }
  if (!txs.every((t) => t.actions.length)) throw new NearValidationError("a transaction has no actions");
  let wallet = txs.find((t) => t.signerId)?.signerId ?? signed[0]?.signerId ?? null;
  if (body.from !== undefined && body.from !== null && body.from !== "") {
    if (!isNearAccount(body.from)) throw new NearValidationError("from must be a NEAR account id");
    wallet = body.from;
  }
  if (!wallet) throw new NearValidationError("the wallet is unknown: send from, or tx.signerId");
  for (const t of txs) if (!t.signerId) t.signerId = wallet;
  return { network, wallet, txs, signed };
}

// ---------- NEAR Intents (signed intents, NEP-413) ----------

// A NEAR Intents message as an agent passes it to signMessage ({ message, recipient, nonce }), or the signed form
// ({ standard: "nep413", payload: { message, recipient, nonce }, public_key, signature }). message is the JSON
// { signer_id, verifying_contract, deadline, nonce, intents: [...] } as a string.
export function parseIntentsMessage(raw, network = "mainnet") {
  const env = raw && typeof raw === "object" ? (raw.payload && typeof raw.payload === "object" ? raw.payload : raw) : null;
  if (!env || typeof env.message !== "string" || env.message.length > MAX_TX_CHARS) {
    throw new NearValidationError("nep413 must be { message, recipient, nonce } with the intents payload as a JSON string in message");
  }
  let payload;
  try { payload = JSON.parse(env.message); } catch { throw new NearValidationError("nep413.message is not JSON"); }
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.intents)) {
    throw new NearValidationError("nep413.message must hold { signer_id, verifying_contract, deadline, nonce, intents: [...] }");
  }
  if (payload.intents.length > 32) throw new NearValidationError("at most 32 intents in one message");
  const signerId = typeof payload.signer_id === "string" ? payload.signer_id : null;
  if (signerId !== null && !isNearAccount(signerId)) throw new NearValidationError("signer_id must be a NEAR account id");
  return {
    signerId,
    recipient: typeof env.recipient === "string" ? env.recipient : null,
    verifyingContract: typeof payload.verifying_contract === "string" ? payload.verifying_contract : null,
    deadline: typeof payload.deadline === "string" ? payload.deadline : null,
    intents: payload.intents.filter((i) => i && typeof i === "object"),
    network,
  };
}

const tokenContract = (id) => (typeof id === "string" ? id.replace(/^nep141:/, "") : null);

// The intents of one signed message, judged: who gets what, keys added to NEAR Intents, swaps that only give,
// fake tokens received, a verifier that isn't intents.near, and deadlines far in the future.
async function intentsReasons(msg, req, add, metaOf, now) {
  const intents = INTENTS[req.network];
  const signer = msg.signerId ?? req.wallet;
  if (msg.signerId && msg.signerId !== req.wallet) add("NEAR_INTENTS_OTHER_SIGNER", "orange", msg.signerId, { wallet: req.wallet });
  for (const v of [msg.recipient, msg.verifyingContract]) {
    if (!v || v === intents) continue;
    const like = nearLookalike(v, req.network);
    add(like ? "NEAR_LOOKALIKE_ACCOUNT" : "NEAR_INTENTS_UNKNOWN_VERIFIER", like ? "red" : "orange", v, like ? { looksLike: like } : { expected: intents });
  }
  const deadline = msg.deadline ? Date.parse(msg.deadline) : NaN;
  if (Number.isFinite(deadline) && deadline - now > 24 * 3600 * 1000) add("NEAR_INTENTS_LONG_DEADLINE", "orange", msg.deadline, { hours: Math.round((deadline - now) / 3600000) });
  if (Number.isFinite(deadline) && deadline < now) add("NEAR_INTENTS_EXPIRED", "info", msg.deadline);

  const fakeCheck = async (contract) => {
    if (!contract || contract in NEAR_NETWORKS[req.network].tokens) return;
    const meta = await metaOf(contract);
    if (meta && typeof meta.symbol === "string" && COPIED_SYMBOLS.test(meta.symbol.trim())) add("NEAR_FAKE_TOKEN", "red", contract, { symbol: meta.symbol });
  };
  const receiverCheck = (to) => {
    if (typeof to !== "string") return;
    const like = nearLookalike(to, req.network);
    if (like) add("NEAR_LOOKALIKE_ACCOUNT", "red", to, { looksLike: like });
  };

  for (const i of msg.intents) {
    switch (i.intent) {
      case "transfer":
        receiverCheck(i.receiver_id);
        if (i.receiver_id !== signer) add("NEAR_INTENTS_TRANSFER", "info", i.receiver_id, { tokens: i.tokens ?? {} });
        for (const t of Object.keys(i.tokens ?? {})) await fakeCheck(tokenContract(t));
        break;
      case "ft_withdraw":
      case "nft_withdraw":
      case "mt_withdraw":
      case "native_withdraw":
        receiverCheck(i.receiver_id);
        if (i.receiver_id !== signer) add("NEAR_INTENTS_WITHDRAW_TO_OTHER", "info", i.receiver_id, { intent: i.intent, ...(i.token && { token: i.token }), ...(i.amount && { amount: String(i.amount) }) });
        if (i.intent === "ft_withdraw") await fakeCheck(tokenContract(i.token));
        break;
      case "token_diff": {
        const diff = Object.entries(i.diff ?? {});
        const gives = diff.filter(([, v]) => String(v).trim().startsWith("-"));
        const gets = diff.filter(([, v]) => !String(v).trim().startsWith("-") && big(String(v).trim()) > 0n);
        if (gives.length && !gets.length) add("NEAR_INTENTS_GIVES_FOR_NOTHING", "red", "token_diff", { gives: Object.fromEntries(gives) });
        for (const [t] of gets) await fakeCheck(tokenContract(t));
        if (gives.length && gets.length) add("NEAR_INTENTS_SWAP", "info", "token_diff", { gives: Object.fromEntries(gives), gets: Object.fromEntries(gets) });
        break;
      }
      case "add_public_key":
        add("NEAR_INTENTS_KEY_ADDED", "red", typeof i.public_key === "string" ? i.public_key : "add_public_key");
        break;
      case "remove_public_key":
        add("NEAR_INTENTS_KEY_REMOVED", "orange", typeof i.public_key === "string" ? i.public_key : "remove_public_key");
        break;
      case "storage_deposit":
        if (i.account_id !== signer) add("NEAR_INTENTS_STORAGE_FOR_OTHER", "info", String(i.account_id ?? ""), { contract: i.contract_id ?? null });
        break;
      default:
        add("NEAR_INTENT_NOT_ANALYZED", "orange", String(i.intent ?? "unknown"));
    }
  }
}

// ---------- RPC (read-only) ----------

async function rpc(network, params, { fetchImpl = globalThis.fetch } = {}) {
  const res = await fetchImpl(NEAR_NETWORKS[network].rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query", params: { finality: "final", ...params } }),
    signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`NEAR RPC HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) {
    const name = body.error?.cause?.name ?? body.error?.name ?? "error";
    const err = new Error(name); err.rpcName = name; throw err;
  }
  return body.result;
}

async function viewCall(network, accountId, method, args, opts) {
  const r = await rpc(network, { request_type: "call_function", account_id: accountId, method_name: method, args_base64: Buffer.from(JSON.stringify(args ?? {})).toString("base64") }, opts);
  return JSON.parse(Buffer.from(r.result).toString("utf8"));
}

// ---------- rules ----------

// Edit distance, for look-alike account ids (cheap: ids are at most 64 characters).
function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  }
  return d[a.length][b.length];
}

// A receiver that is not a well-known account but looks like one: close in spelling, or the known name with its
// dots turned into dashes (wrap-near.near), or the known name under another top-level account.
export function nearLookalike(account, network = "mainnet") {
  const net = NEAR_NETWORKS[network];
  const known = [...net.known, ...Object.keys(net.tokens).filter((t) => !isImplicit(t) && !t.endsWith(".factory.bridge.near"))];
  if (!account || known.includes(account) || isImplicit(account)) return null;
  for (const k of known) {
    if (k.length < 6) continue;
    const flat = k.replace(/\./g, "-");
    if (account === `${flat}.near` || account.startsWith(`${flat}.`) || account === `${k}.near`) return k;
    if (Math.abs(account.length - k.length) <= 2 && distance(account, k) <= 2) return k;
  }
  return null;
}

// The actions each account signs: a SignedDelegate's inner actions are the delegate sender's, to its receiver.
function flatten(txs) {
  const out = [];
  for (const t of txs) {
    for (const a of t.actions) {
      if (a.kind === "signedDelegate") for (const inner of a.actions) out.push({ signer: a.senderId, receiver: a.receiverId, action: inner, delegated: true });
      else out.push({ signer: t.signerId, receiver: t.receiverId, action: a });
    }
  }
  return out;
}

// What one action does, as plain values (for the answer's subject, the intent check and the usage log).
export function describeNearAction({ signer, receiver, action: a, delegated }) {
  const base = { signer, receiver, action: a.kind, ...(delegated && { delegated: true }) };
  switch (a.kind) {
    case "transfer": return { ...base, amountNear: nearAmount(a.deposit) };
    case "functionCall": return { ...base, method: a.methodName, ...(a.deposit > 0n && { depositNear: nearAmount(a.deposit) }), ...(a.args && { args: a.args }) };
    case "addKey": return { ...base, publicKey: a.publicKey, fullAccess: a.fullAccess, ...(!a.fullAccess && { contract: a.receiverId, methods: a.methodNames, allowanceNear: a.allowance === null ? "unlimited" : nearAmount(a.allowance) }) };
    case "deleteKey": return { ...base, publicKey: a.publicKey };
    case "deleteAccount": return { ...base, beneficiary: a.beneficiaryId };
    case "stake": return { ...base, stakeNear: nearAmount(a.stake) };
    default: return base;
  }
}

export async function nearReasons(req, { fetchImpl = globalThis.fetch } = {}) {
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };
  const net = NEAR_NETWORKS[req.network];
  const intents = INTENTS[req.network];
  const flat = flatten(req.txs);
  let rpcUsed = false;
  let rpcFailed = false;
  const ask = async (fn) => { try { const r = await fn(); rpcUsed = true; return r; } catch (err) { if (err.rpcName) { rpcUsed = true; throw err; } rpcFailed = true; return undefined; } };

  // The wallet's full-access keys, when a key is deleted.
  let fullKeys;
  const deletes = flat.filter((f) => f.action.kind === "deleteKey" && f.receiver === f.signer);
  if (deletes.length) {
    const list = await ask(() => rpc(req.network, { request_type: "view_access_key_list", account_id: req.wallet }, { fetchImpl })).catch(() => undefined);
    if (list) fullKeys = list.keys.filter((k) => k.access_key?.permission === "FullAccess").map((k) => k.public_key);
  }
  const addsFullKey = flat.some((f) => f.action.kind === "addKey" && f.action.fullAccess && f.receiver === f.signer);
  const created = new Set(flat.filter((f) => f.action.kind === "createAccount").map((f) => f.receiver));
  const metadata = new Map();
  const metaOf = async (contract) => {
    if (!metadata.has(contract)) metadata.set(contract, await ask(() => viewCall(req.network, contract, "ft_metadata", {}, { fetchImpl })).catch(() => null));
    return metadata.get(contract);
  };
  const now = Date.now();
  for (const msg of req.signed ?? []) await intentsReasons(msg, req, add, metaOf, now);

  for (const f of flat) {
    const { signer, receiver, action: a } = f;
    const onWallet = receiver === signer;
    switch (a.kind) {
      case "addKey":
        if (!onWallet) { add("NEAR_KEY_ON_OTHER_ACCOUNT", created.has(receiver) ? "info" : "orange", a.publicKey, { account: receiver }); break; }
        if (a.fullAccess) { add("NEAR_FULL_ACCESS_KEY_ADDED", "red", a.publicKey, { account: receiver }); break; }
        add("NEAR_FUNCTION_CALL_KEY_ADDED", "info", a.publicKey, { contract: a.receiverId, methods: a.methodNames.length ? a.methodNames : "any method", allowanceNear: a.allowance === null ? "unlimited" : nearAmount(a.allowance) });
        if (a.allowance === null) add("NEAR_KEY_UNLIMITED_ALLOWANCE", "orange", a.publicKey, { contract: a.receiverId });
        break;
      case "deleteKey":
        if (!onWallet) break;
        if (!fullKeys) { add("NEAR_ACCESS_KEY_DELETED", "orange", a.publicKey, { note: "the wallet's keys could not be read" }); break; }
        if (fullKeys.includes(a.publicKey)) {
          const left = fullKeys.filter((k) => !deletes.some((d) => d.action.publicKey === k));
          if (!left.length && !addsFullKey) add("NEAR_LAST_FULL_ACCESS_KEY_DELETED", "red", a.publicKey);
          else add("NEAR_FULL_ACCESS_KEY_DELETED", "orange", a.publicKey, { fullAccessKeysLeft: left.length });
        }
        break;
      case "deleteAccount":
        add("NEAR_ACCOUNT_DELETED", "red", receiver, { beneficiary: a.beneficiaryId });
        break;
      case "deployContract":
      case "useGlobalContract":
        if (onWallet) add("NEAR_CONTRACT_DEPLOYED_ON_WALLET", "red", receiver);
        else if (!created.has(receiver)) add("NEAR_CONTRACT_DEPLOYED_ON_OTHER_ACCOUNT", "orange", receiver);
        break;
      case "stake":
        add("NEAR_STAKE", "info", receiver, { stakeNear: nearAmount(a.stake), validatorKey: a.publicKey });
        break;
      case "transfer": {
        const like = nearLookalike(receiver, req.network);
        if (like) add("NEAR_LOOKALIKE_ACCOUNT", "red", receiver, { looksLike: like });
        break;
      }
      case "functionCall": {
        const args = a.args ?? {};
        const like = nearLookalike(receiver, req.network);
        if (like) add("NEAR_LOOKALIKE_ACCOUNT", "red", receiver, { looksLike: like });
        if (a.methodName === "ft_transfer" || a.methodName === "ft_transfer_call") {
          const to = typeof args.receiver_id === "string" ? args.receiver_id : null;
          const toLike = to ? nearLookalike(to, req.network) : null;
          if (toLike) add("NEAR_LOOKALIKE_ACCOUNT", "red", to, { looksLike: toLike });
          if (!(receiver in net.tokens)) {
            const meta = await metaOf(receiver);
            if (meta && typeof meta.symbol === "string" && COPIED_SYMBOLS.test(meta.symbol.trim())) {
              add("NEAR_FAKE_TOKEN", "red", receiver, { symbol: meta.symbol, real: Object.entries(net.tokens).filter(([, s]) => s.toLowerCase().startsWith(meta.symbol.trim().toLowerCase().slice(0, 4))).map(([c]) => c) });
            }
          }
          // A deposit into NEAR Intents credited to another account (the msg names a receiver_id).
          if (a.methodName === "ft_transfer_call" && to === intents && typeof args.msg === "string" && args.msg.trim().startsWith("{")) {
            let m; try { m = JSON.parse(args.msg); } catch { m = null; }
            if (m && typeof m.receiver_id === "string" && m.receiver_id !== signer) add("NEAR_INTENTS_DEPOSIT_FOR_OTHER", "orange", m.receiver_id, { token: receiver });
          }
        } else if (a.methodName === "storage_unregister" && args.force === true) {
          add("NEAR_STORAGE_UNREGISTER_FORCE", "red", receiver);
        } else if (a.methodName === "nft_approve" && typeof args.account_id === "string" && args.account_id !== signer) {
          add("NEAR_NFT_APPROVAL", "orange", args.account_id, { contract: receiver, tokenId: args.token_id ?? null });
        } else if (receiver === intents && a.methodName === "add_public_key") {
          add("NEAR_INTENTS_KEY_ADDED", "red", typeof args.public_key === "string" ? args.public_key : receiver);
        } else if (receiver === intents && a.methodName === "execute_intents" && Array.isArray(args.signed)) {
          // Signed intents sent on chain (a solver or relayer does this): each one judged like a message to sign.
          for (const s of args.signed.slice(0, 16)) {
            let msg; try { msg = parseIntentsMessage(s, req.network); } catch { add("NEAR_INTENT_NOT_ANALYZED", "orange", "execute_intents"); continue; }
            await intentsReasons(msg, req, add, metaOf, now);
          }
        } else if (receiver === intents && a.methodName === "remove_public_key") {
          add("NEAR_INTENTS_KEY_REMOVED", "orange", typeof args.public_key === "string" ? args.public_key : receiver);
        }
        if (a.deposit >= LARGE_DEPOSIT && !net.known.includes(receiver) && !(receiver in net.tokens)) {
          add("NEAR_LARGE_DEPOSIT", "orange", receiver, { depositNear: nearAmount(a.deposit), method: a.methodName });
        }
        if (a.args === null && a.argsBytes) add("NEAR_ARGS_NOT_JSON", "info", receiver, { method: a.methodName, bytes: a.argsBytes });
        break;
      }
      default:
        break;
    }
  }
  if (rpcFailed) add("NEAR_RPC_UNAVAILABLE", "info", req.network);
  return {
    reasons, rpcUsed,
    operations: [
      ...flat.map(describeNearAction),
      ...(req.signed ?? []).flatMap((m) => m.intents.map((i) => ({ signer: m.signerId ?? req.wallet, receiver: m.verifyingContract ?? intents, action: "intent", intent: String(i.intent ?? "unknown"), ...(i.receiver_id && { to: i.receiver_id }), ...(i.tokens && { tokens: i.tokens }), ...(i.diff && { diff: i.diff }), ...(i.token && { token: i.token }), ...(i.amount && { amount: String(i.amount) }) }))),
    ],
  };
}

// Every account the transactions pay, approve, add as beneficiary or send tokens to (for the sanctions screen).
export function nearParties(req) {
  const fromIntents = (req.signed ?? []).flatMap((m) => m.intents.map((i) => i.receiver_id).filter((x) => typeof x === "string"));
  return fromIntents.concat(flatten(req.txs).flatMap(({ receiver, action: a }) => [
    receiver,
    a.kind === "deleteAccount" ? a.beneficiaryId : null,
    a.kind === "functionCall" && typeof a.args?.receiver_id === "string" ? a.args.receiver_id : null,
    a.kind === "functionCall" && typeof a.args?.account_id === "string" ? a.args.account_id : null,
  ])).filter((x) => typeof x === "string" && x);
}
