// algorand-tx.js — the pre-sign check for Algorand transactions (POST /v1/check with type "algorand").
//
//   { type: "algorand", transaction: "<base64 msgpack>" | transactions: ["<base64>", …], from?, origin?, intent? }
//
// Algorand has no token approvals; what loses people an account is one field on an ordinary-looking transaction.
// rekeyTo hands the account's signing power to another key for good; a payment's closeRemainderTo sends all its
// ALGO to someone and closes it; an asset transfer's closeRemainderTo sends the whole balance of that asset. Those
// are red when they go to someone else. Orange: a clawback transfer, an app being updated, deleted or cleared, an
// asset's control addresses handed over or cleared, giving up consensus participation for good, a fee far above
// normal, a transaction that belongs to a group this check didn't see, or one that would fail. A token called USDC
// or USDt that isn't the real one is red. Every transaction is also simulated on a public node (algod simulate,
// signatures not checked) to see whether it would fail and how much a close would send.
// The node is read without a key; when it can't be reached the check says so (info) and the rules that need no
// node still apply. Fail-closed as in presign-guard.js: errors are non-2xx, never "green".
import algosdk from "algosdk";

export const ALGORAND_NETWORKS = {
  "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=": {
    caip2: "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=", name: "Algorand", api: process.env.ALGORAND_ALGOD_URL || "https://mainnet-api.algonode.cloud",
    stablecoins: { 31566704: "USDC", 312769: "USDt" },
  },
  "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=": {
    caip2: "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=", name: "Algorand testnet", api: process.env.ALGORAND_TESTNET_ALGOD_URL || "https://testnet-api.algonode.cloud",
    stablecoins: { 10458941: "USDC" },
  },
};
// Names a fake stablecoin uses (unit name or asset name, letters only, any case).
const STABLE_NAMES = new Set(["USDC", "USDT", "USD"]);
const MAX_TXNS = 16; // an atomic group holds at most 16 transactions
const MAX_TX_CHARS = 12000; // an app call with its programs and pages fits; a payment is ~250 characters
const HIGH_FEE = 100_000n; // microAlgos (0.1 ALGO): the minimum is 0.001; a fee this high is spent, not needed
const NODE_TIMEOUT_MS = 5000;
const ON_COMPLETE = ["NoOp", "OptIn", "CloseOut", "ClearState", "UpdateApplication", "DeleteApplication"];

export class AlgorandValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

export const isAlgorandRequest = (body) => Boolean(body && typeof body === "object" && body.type === "algorand");

const addr = (a) => (a ? a.toString() : undefined);
export const ALGORAND_ZERO = algosdk.ALGORAND_ZERO_ADDRESS_STRING;
const ZERO = ALGORAND_ZERO;
const set = (a) => { const s = addr(a); return s && s !== ZERO ? s : undefined; };
const algo = (micro) => Number(micro) / 1e6;

// One base64 transaction, unsigned (encodeUnsignedTransaction) or signed (a wallet's SignedTxn): the transaction.
function decodeOne(raw, i) {
  if (typeof raw !== "string" || !raw.trim() || raw.length > MAX_TX_CHARS || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw.trim())) {
    throw new AlgorandValidationError(`transaction${i === null ? "" : `s[${i}]`} must be a base64 msgpack Algorand transaction (algosdk.encodeUnsignedTransaction, or a signed one)`);
  }
  const bytes = Buffer.from(raw.trim(), "base64");
  try { return algosdk.decodeUnsignedTransaction(bytes); } catch { /* maybe signed */ }
  try { return algosdk.decodeSignedTransaction(bytes).txn; } catch { /* neither */ }
  throw new AlgorandValidationError(`transaction${i === null ? "" : `s[${i}]`} could not be decoded as an Algorand transaction`);
}

// The request decoded: the network (from the genesis hash), the wallet whose funds are at stake (from, or the sender
// of the first transaction) and every transaction with its fields as plain values.
export function parseAlgorandRequest(body) {
  const list = Array.isArray(body.transactions) ? body.transactions : body.transaction !== undefined ? [body.transaction] : null;
  if (!list || !list.length) throw new AlgorandValidationError("transaction (base64) or transactions (an array of base64, for an atomic group) is required");
  if (list.length > MAX_TXNS) throw new AlgorandValidationError(`at most ${MAX_TXNS} transactions (one atomic group)`);
  const txns = list.map((raw, i) => decodeOne(raw, Array.isArray(body.transactions) ? i : null));
  const genesis = Buffer.from(txns[0].genesisHash ?? []).toString("base64");
  const net = ALGORAND_NETWORKS[genesis];
  if (!net) throw new AlgorandValidationError(`unsupported Algorand network (genesis hash ${genesis || "missing"}): mainnet and testnet are checked`);
  if (txns.some((t) => Buffer.from(t.genesisHash ?? []).toString("base64") !== genesis)) throw new AlgorandValidationError("all transactions must be for the same network");
  if (body.network !== undefined && body.network !== null && body.network !== "") {
    const n = String(body.network);
    const ok = n === net.caip2 || net.caip2.startsWith(n) && n.length >= "algorand:".length + 32 || (n === "mainnet" && net.name === "Algorand") || (n === "testnet" && net.name === "Algorand testnet");
    if (!ok) throw new AlgorandValidationError(`network ${n} does not match the transactions (${net.caip2})`);
  }
  let wallet = addr(txns[0].sender);
  if (body.from !== undefined && body.from !== null && body.from !== "") {
    if (typeof body.from !== "string" || !algosdk.isValidAddress(body.from)) throw new AlgorandValidationError("from must be a valid Algorand address");
    wallet = body.from;
  }
  // The group: transactions sent together must all carry the group id computed over them; a single transaction
  // that carries a group id runs together with others this check didn't see.
  const ids = txns.map((t) => (t.group ? Buffer.from(t.group).toString("base64") : null));
  let group = "none";
  if (txns.length === 1 && ids[0]) group = "unseen";
  else if (txns.length > 1) {
    const bare = txns.map((t) => { const c = algosdk.decodeUnsignedTransaction(algosdk.encodeUnsignedTransaction(t)); c.group = undefined; return c; });
    const expected = Buffer.from(algosdk.computeGroupID(bare)).toString("base64");
    group = ids.every((id) => id === expected) ? "complete" : "mismatch";
  }
  return { network: genesis, wallet, txns, group, encoded: list.map((r) => r.trim()) };
}

// What a transaction does, as plain values: for the answer's subject, the intent check and the usage log.
export function describeAlgorandTxn(t) {
  const d = { type: t.type, sender: addr(t.sender), fee: algo(t.fee) };
  if (t.rekeyTo) d.rekeyTo = addr(t.rekeyTo);
  if (t.type === "pay") Object.assign(d, { receiver: addr(t.payment.receiver), amountAlgo: algo(t.payment.amount), ...(t.payment.closeRemainderTo && { closeTo: addr(t.payment.closeRemainderTo) }) });
  if (t.type === "axfer") {
    const x = t.assetTransfer;
    Object.assign(d, { assetId: Number(x.assetIndex), receiver: addr(x.receiver), amount: String(x.amount), ...(x.closeRemainderTo && { closeTo: addr(x.closeRemainderTo) }), ...(x.assetSender && { clawbackFrom: addr(x.assetSender) }) });
  }
  if (t.type === "appl") Object.assign(d, { appId: Number(t.applicationCall.appIndex), onComplete: ON_COMPLETE[t.applicationCall.onComplete] ?? String(t.applicationCall.onComplete) });
  if (t.type === "acfg") Object.assign(d, { assetId: Number(t.assetConfig.assetIndex) });
  if (t.type === "afrz") Object.assign(d, { assetId: Number(t.assetFreeze.assetIndex), freezeAccount: addr(t.assetFreeze.freezeAccount), frozen: t.assetFreeze.frozen });
  return d;
}

// The public node: asset params, an account's holding of an asset, the account itself (is it rekeyed?).
function node(net, fetchImpl) {
  const get = async (path) => {
    const res = await fetchImpl(`${net.api}${path}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`algod HTTP ${res.status}`);
    return res.json();
  };
  return {
    asset: async (id) => (await get(`/v2/assets/${id}`))?.params ?? null,
    holding: async (account, id) => { const r = await get(`/v2/accounts/${account}/assets/${id}`); return r ? BigInt(r["asset-holding"]?.amount ?? 0) : null; },
    account: (account) => get(`/v2/accounts/${account}?exclude=all`),
  };
}

const letters = (s) => String(s ?? "").replace(/[^a-z]/gi, "").toUpperCase();
// A token named like a stablecoin that isn't the network's real one, or one named ALGO (the coin is not an asset).
function impostor(net, id, params) {
  if (!params || net.stablecoins[id]) return null;
  const names = [letters(params["unit-name"]), letters(params.name)];
  if (names.some((n) => STABLE_NAMES.has(n))) return { code: "ALGORAND_FAKE_STABLECOIN", severity: "red" };
  if (names.some((n) => n === "ALGO")) return { code: "ALGORAND_FAKE_ALGO", severity: "orange" };
  return null;
}

// The rules: every transaction the wallet sends (others' transactions in a group are not the wallet's to sign).
export async function algorandReasons(req, { fetchImpl = globalThis.fetch } = {}) {
  const net = ALGORAND_NETWORKS[req.network];
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, ...(subject && { subject }), ...(details && { details }) });
  };
  const ask = node(net, fetchImpl);
  let nodeDown = false;
  let nodeUsed = false;
  const lookup = async (fn) => {
    try { const r = await fn(); nodeUsed = true; return r; } catch (err) {
      if (!nodeDown) add("ALGORAND_NODE_UNAVAILABLE", "info", net.name, { error: String(err.message).slice(0, 120) });
      nodeDown = true;
      return undefined;
    }
  };
  const assets = new Map();
  const asset = (id) => { if (!assets.has(id)) assets.set(id, lookup(() => ask.asset(id))); return assets.get(id); };

  if (req.group === "unseen") add("ALGORAND_GROUP_UNSEEN", "orange", req.wallet, { effect: "this transaction belongs to an atomic group; the other transactions run together with it and were not checked. Send them all as transactions" });
  if (req.group === "mismatch") add("ALGORAND_GROUP_MISMATCH", "orange", req.wallet, { effect: "these transactions don't carry the group id computed over them, so they are not the group that will be sent" });
  const others = req.txns.filter((t) => addr(t.sender) !== req.wallet).length;
  if (others) add("ALGORAND_GROUP_OTHER_SENDERS", "info", req.wallet, { transactions: others, note: "transactions from other accounts in the group are theirs to sign" });

  const account = await lookup(() => ask.account(req.wallet));
  if (account && account["auth-addr"]) add("ALGORAND_ACCOUNT_REKEYED", "info", account["auth-addr"], { note: "this account is already signed for by another key" });

  for (const [i, t] of req.txns.entries()) {
    if (addr(t.sender) !== req.wallet) continue;
    const sender = req.wallet;
    if (t.rekeyTo) {
      if (addr(t.rekeyTo) !== sender) add("ALGORAND_REKEY", "red", addr(t.rekeyTo), { txn: i, effect: "hands the account's signing power to this key: from then on it can move everything in the account, and you can't" });
      else add("ALGORAND_REKEY_BACK", "info", sender, { txn: i });
    }
    if (t.fee > HIGH_FEE) add("ALGORAND_HIGH_FEE", "orange", sender, { txn: i, feeAlgo: algo(t.fee), effect: "the fee is paid by you and far above the 0.001 ALGO minimum" });

    if (t.type === "pay" && t.payment.closeRemainderTo) {
      add("ALGORAND_CLOSE_ACCOUNT", "red", addr(t.payment.closeRemainderTo), { txn: i, effect: "closes the account: all its remaining ALGO goes to this address" });
    }

    if (t.type === "axfer") {
      const x = t.assetTransfer;
      const id = Number(x.assetIndex);
      if (x.assetSender) add("ALGORAND_CLAWBACK_TRANSFER", "orange", addr(x.assetSender), { txn: i, assetId: id, effect: "a clawback: takes the asset from this account, which only the asset's clawback address can do" });
      const params = await asset(id);
      const fake = impostor(net, id, params);
      if (fake) add(fake.code, fake.severity, String(id), { txn: i, assetId: id, unitName: params["unit-name"], name: params.name, real: Object.entries(net.stablecoins).map(([k, v]) => `${v} ${k}`).join(", ") });
      if (x.closeRemainderTo) {
        const to = addr(x.closeRemainderTo);
        const held = await lookup(() => ask.holding(sender, id));
        if (held === 0n) add("ALGORAND_ASSET_OPT_OUT", "info", String(id), { txn: i, assetId: id });
        else if (to !== sender) add("ALGORAND_ASSET_CLOSE", held === undefined ? "orange" : "red", to, { txn: i, assetId: id, ...(params?.["unit-name"] && { unitName: params["unit-name"] }), ...(held !== undefined && held !== null && { balance: String(held) }), effect: "sends the whole balance of this asset to this address and opts out of it" });
      }
      const optIn = addr(x.receiver) === sender && x.amount === 0n && !x.closeRemainderTo;
      if (optIn && params && !net.stablecoins[id]) {
        if (set(params.clawback)) add("ALGORAND_ASSET_CLAWBACK", "orange", set(params.clawback), { txn: i, assetId: id, effect: "the asset's clawback address can take it out of any account, also yours" });
        if (params["default-frozen"]) add("ALGORAND_ASSET_DEFAULT_FROZEN", "orange", String(id), { txn: i, assetId: id, effect: "new holdings are frozen until the freeze address releases them" });
      }
    }

    if (t.type === "appl") {
      const c = t.applicationCall;
      const oc = ON_COMPLETE[c.onComplete] ?? String(c.onComplete);
      const appId = Number(c.appIndex);
      if (oc === "UpdateApplication" || oc === "DeleteApplication") add("ALGORAND_APP_UPDATE_OR_DELETE", "orange", String(appId), { txn: i, appId, onComplete: oc, effect: oc === "UpdateApplication" ? "replaces the app's program" : "deletes the app" });
      else if (oc === "ClearState") add("ALGORAND_APP_CLEAR_STATE", "orange", String(appId), { txn: i, appId, effect: "drops your local state in this app whatever the app says, which can forfeit what it holds for you" });
      else if (appId === 0) add("ALGORAND_APP_CREATE", "info", sender, { txn: i });
      else add("ALGORAND_APP_CALL", "info", String(appId), { txn: i, appId, onComplete: oc });
    }

    if (t.type === "acfg") {
      const c = t.assetConfig;
      const id = Number(c.assetIndex);
      const controls = { manager: set(c.manager), reserve: set(c.reserve), freeze: set(c.freeze), clawback: set(c.clawback) };
      if (id === 0) add("ALGORAND_ASSET_CREATE", "info", sender, { txn: i });
      else if (!Object.values(controls).some(Boolean)) add("ALGORAND_ASSET_DESTROY", "orange", String(id), { txn: i, assetId: id, effect: "destroys the asset (or clears every control address, which can't be undone)" });
      else {
        const current = await asset(id);
        for (const [field, to] of Object.entries(controls)) {
          if (to && to !== sender && to !== set(current?.[field])) add("ALGORAND_ASSET_CONTROL_CHANGE", "orange", to, { txn: i, assetId: id, field, effect: `makes this address the asset's ${field}` });
          if (!to && current && set(current[field])) add("ALGORAND_ASSET_CONTROL_CLEARED", "orange", String(id), { txn: i, assetId: id, field, effect: `clears the asset's ${field} address for good` });
        }
      }
    }

    if (t.type === "afrz") add("ALGORAND_ASSET_FREEZE", "info", addr(t.assetFreeze.freezeAccount), { txn: i, assetId: Number(t.assetFreeze.assetIndex), frozen: t.assetFreeze.frozen });

    if (t.type === "keyreg") {
      if (t.keyreg?.nonParticipation) add("ALGORAND_KEYREG_NONPARTICIPATION", "orange", sender, { txn: i, effect: "marks the account as never taking part in consensus again; it can't be undone" });
      else add("ALGORAND_KEYREG", "info", sender, { txn: i });
    }

    if (!["pay", "axfer", "appl", "acfg", "afrz", "keyreg"].includes(t.type)) add("ALGORAND_TX_NOT_ANALYZED", "orange", sender, { txn: i, type: t.type });
  }
  return { reasons, nodeUsed };
}

// Simulate the transactions on the node (algod simulate, empty signatures allowed): would they fail, and what would a
// close send? A rekeyed sender is simulated with its signing key, so that is not reported as a failure.
export async function simulateAlgorand(req, { fetchImpl = globalThis.fetch } = {}) {
  const net = ALGORAND_NETWORKS[req.network];
  try {
    const signers = new Map();
    await Promise.all([...new Set(req.txns.map((t) => addr(t.sender)))].map(async (s) => {
      const res = await fetchImpl(`${net.api}/v2/accounts/${s}?exclude=all`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
      if (res.ok) { const a = await res.json(); if (a["auth-addr"]) signers.set(s, a["auth-addr"]); }
    }));
    const txns = req.txns.map((t) => new algosdk.SignedTransaction({ txn: t, ...(signers.has(addr(t.sender)) && { sgnr: algosdk.Address.fromString(signers.get(addr(t.sender))) }) }));
    const body = new algosdk.modelsv2.SimulateRequest({ txnGroups: [new algosdk.modelsv2.SimulateRequestTransactionGroup({ txns })], allowEmptySignatures: true });
    const res = await fetchImpl(`${net.api}/v2/transactions/simulate?format=json`, { method: "POST", headers: { "content-type": "application/msgpack", accept: "application/json" }, body: algosdk.encodeMsgpack(body), signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`algod HTTP ${res.status}`);
    const g = (await res.json())?.["txn-groups"]?.[0];
    if (!g) return null;
    const closing = (g["txn-results"] ?? []).map((r, i) => ({ txn: i, algo: r["txn-result"]?.["closing-amount"], asset: r["txn-result"]?.["asset-closing-amount"] }))
      .filter((c) => c.algo || c.asset);
    return { ok: !g["failure-message"], ...(g["failure-message"] && { error: String(g["failure-message"]).slice(0, 300), failedAt: g["failed-at"] }), closing };
  } catch (err) {
    console.warn(`[algorand-tx] simulation: ${err.message}`);
    return null;
  }
}

// Reasons from the simulation, and the amounts a close would send added to the red reasons it confirms.
export function algorandSimulationReasons(sim, req, reasons) {
  if (!sim) return [{ code: "SIMULATION_UNAVAILABLE", severity: "info", subject: req.wallet }];
  for (const c of sim.closing) {
    const r = reasons.find((x) => x.details?.txn === c.txn && (x.code === "ALGORAND_CLOSE_ACCOUNT" || x.code === "ALGORAND_ASSET_CLOSE"));
    if (r && r.code === "ALGORAND_CLOSE_ACCOUNT" && c.algo) r.details.closingAlgo = algo(c.algo);
    if (r && r.code === "ALGORAND_ASSET_CLOSE" && c.asset) r.details.closingAmount = String(c.asset);
  }
  if (!sim.ok) return [{ code: "SIMULATION_FAILS", severity: "orange", subject: req.wallet, details: { error: sim.error, ...(sim.failedAt && { failedAt: sim.failedAt }) } }];
  return [{ code: "SIMULATED", severity: "info", subject: req.wallet }];
}
