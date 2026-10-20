// xrpl.js — the pre-sign check for XRP Ledger transactions (POST /v1/check with type "xrpl").
//
//   { type: "xrpl", network?: "xrpl:0" | "xrpl:1", tx: { TransactionType, Account, ... }, origin? }
//
// What hurts people on the XRPL is rarely a token approval (there are none): it is handing over the account. A
// SetRegularKey or SignerListSet to someone else's key, or AccountSet disabling the master key, gives the account away
// for good; AccountDelete sends all its XRP to the Destination. Those are red. Orange: a payment that will fail or may
// deliver less than it says (partial payment), a destination that refuses it, a trust line to an issuer that can claw
// tokens back or has frozen them, an escrow, check, payment channel or NFT offer that hands value to someone else, a
// transaction type this check does not judge. A token called RLUSD that isn't Ripple's is red. Credentials (XLS-70):
// issuing one for another account is orange (you vouch for it); accepting one is info, or orange when there is nothing
// valid to accept and the transaction would fail. A Batch (XLS-56) is judged by every transaction inside it, so a
// takeover can't hide in one; inner transactions of other accounts without all-or-nothing are orange (your part can go
// through while theirs fails). Permission delegation (XLS-75): a DelegateSet that lets another account send payments,
// checks, escrows, channels, DEX orders or NFT trades for you is red, other permissions orange. MPTs (XLS-33): opting
// in to hold one gets the trust-line issuer checks; a ticker of RLUSD not issued by Ripple is red; a payment that would
// fail (locked, not transferable, a destination that hasn't opted in or isn't authorised) is orange.
// The ledger is read through public JSON-RPC (no key); when it can't be reached the check says so (info) and the
// rules that need no ledger still apply. Fail-closed as in presign-guard.js: errors are non-2xx, never "green".

import { createHash } from "node:crypto";
import { domainAge, hostnameReputation, NEW_DOMAIN_DAYS } from "./pg1.js";
import { secondOpinion } from "./jev.js";
import { partySanctionsReasons } from "./ofac.js";

export const XRPL_NETWORKS = {
  "xrpl:0": { name: "XRP Ledger", rpc: "https://xrplcluster.com", rlusdIssuer: "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De" },
  "xrpl:1": { name: "XRPL Testnet", rpc: "https://testnet.xrpl-labs.com", rlusdIssuer: "rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV" },
};
export const RLUSD = "524C555344000000000000000000000000000000";
const RPC_TIMEOUT_MS = 5000;
const CACHE_MS = 5 * 60 * 1000;

// AccountSet SetFlag values (asf…) and AccountRoot flags (lsf…).
export const BLACKHOLES = new Set(["rrrrrrrrrrrrrrrrrrrrrhoLvTp", "rrrrrrrrrrrrrrrrrrrrBZbvji", "rrrrrrrrrrrrrrrrrNAMEtxvNvQ", "rrrrrrrrrrrrrrrrrrrn5RM1rHd"]);
const ASF = { requireDest: 1, disableMaster: 4, defaultRipple: 8, depositAuth: 9, allowClawback: 16 };
export const LSF = { requireDestTag: 0x00020000, requireAuth: 0x00040000, disallowXrp: 0x00080000, disableMaster: 0x00100000, noFreeze: 0x00200000, globalFreeze: 0x00400000, depositAuth: 0x01000000, allowClawback: 0x80000000 };
const TF_PARTIAL_PAYMENT = 0x00020000;
const TF_SELL_NFTOKEN = 0x00000001;
const LSF_CREDENTIAL_ACCEPTED = 0x00010000;
// MPTokenIssuance flags, the MPToken (a holder's balance) flag, and MPTokenAuthorize's tfMPTUnauthorize.
const LSF_MPT = { locked: 0x01, requireAuth: 0x04, canTransfer: 0x20, canClawback: 0x40 };
const LSF_MPTOKEN_AUTHORIZED = 0x02;
const TF_MPT_UNAUTHORIZE = 0x01;
const RIPPLE_EPOCH = 946684800; // XRPL times are seconds since 2000-01-01
const rippleTime = (t) => new Date((Number(t) + RIPPLE_EPOCH) * 1000).toISOString();
// A credential type is hex; show it as text when it is readable.
export const credentialName = (hex) => {
  const text = Buffer.from(String(hex), "hex").toString("utf8");
  return /^[\x20-\x7e]+$/.test(text) ? text : String(hex);
};

// Types judged by a rule below, and everyday types with nothing to flag on their own.
const JUDGED = new Set(["Payment", "TrustSet", "SetRegularKey", "SignerListSet", "AccountSet", "AccountDelete", "EscrowCreate", "NFTokenCreateOffer", "OfferCreate", "AMMCreate", "AMMDeposit", "CredentialCreate", "CredentialAccept", "Batch", "DelegateSet", "MPTokenAuthorize", "CheckCreate", "PaymentChannelCreate", "PaymentChannelFund"]);
const BENIGN = new Set(["OfferCancel", "EscrowFinish", "EscrowCancel", "CheckCash", "CheckCancel", "NFTokenMint", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenAcceptOffer", "TicketCreate", "AMMWithdraw", "AMMVote", "AMMBid", "CredentialDelete", "PermissionedDomainSet", "PermissionedDomainDelete", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "PaymentChannelClaim", "DepositPreauth", "Clawback", "AMMClawback", "AMMDelete", "DIDSet", "DIDDelete", "OracleSet", "OracleDelete", "NFTokenModify"]);

// Batch (XLS-56): 2 to 8 inner transactions, exactly one mode flag, at most 24 batch signers.
const BATCH_MODES = [["tfAllOrNothing", 0x00010000], ["tfOnlyOne", 0x00020000], ["tfUntilFailure", 0x00040000], ["tfIndependent", 0x00080000]];
const batchModes = (flags) => BATCH_MODES.filter(([name, bit]) => (flags && typeof flags === "object" ? flags[name] === true : (Number(flags) & bit) !== 0)).map(([name]) => name);

// Permission delegation (XLS-75). A PermissionValue is a name or a number: a transaction type's code + 1, or a granular
// permission from 65537. Only the numbers this check needs to name are listed; others show as their number.
const PERMISSION_NUMBERS = { 1: "Payment", 2: "EscrowCreate", 4: "AccountSet", 6: "SetRegularKey", 8: "OfferCreate", 13: "SignerListSet", 14: "PaymentChannelCreate", 15: "PaymentChannelFund", 17: "CheckCreate", 22: "AccountDelete", 28: "NFTokenCreateOffer", 30: "NFTokenAcceptOffer", 36: "AMMCreate", 37: "AMMDeposit", 43: "XChainCommit", 45: "XChainAccountCreateCommit", 65: "DelegateSet", 72: "Batch", 65537: "TrustlineAuthorize", 65538: "TrustlineFreeze", 65539: "TrustlineUnfreeze", 65540: "AccountDomainSet", 65541: "AccountEmailHashSet", 65542: "AccountMessageKeySet", 65543: "AccountTransferRateSet", 65544: "AccountTickSizeSet", 65545: "PaymentMint", 65546: "PaymentBurn", 65547: "MPTokenIssuanceLock", 65548: "MPTokenIssuanceUnlock" };
const MAX_PERMISSIONS = 10;
// The ledger refuses these (temMALFORMED): handing them over would be handing over the account.
const NOT_DELEGABLE = new Set(["AccountSet", "SetRegularKey", "SignerListSet", "DelegateSet", "AccountDelete", "Batch", "EnableAmendment", "SetFee", "UNLModify"]);
// Permissions that let the delegate send the account's funds to itself: directly, through a check, escrow or payment
// channel it can claim, a DEX order or NFT trade against its own offer, a pool it controls, a bridge; or mint or burn
// the account's tokens (PaymentBurn could mint too before the fixCleanup3_4_0 amendment).
const MOVES_FUNDS = new Set(["Payment", "CheckCreate", "EscrowCreate", "PaymentChannelCreate", "PaymentChannelFund", "OfferCreate", "NFTokenCreateOffer", "NFTokenAcceptOffer", "AMMCreate", "AMMDeposit", "XChainCommit", "XChainAccountCreateCommit", "PaymentMint", "PaymentBurn"]);
const permissionName = (v) => (typeof v === "number" ? PERMISSION_NUMBERS[v] ?? String(v) : String(v));
const delegatedPermissions = (tx) => (Array.isArray(tx.Permissions) ? tx.Permissions.map((p) => permissionName(p?.Permission?.PermissionValue)) : []);

export class XrplValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

// XRPL classic address: base58 (XRPL alphabet), 25 bytes = 0x00 + 20-byte account id + 4-byte double-SHA-256 checksum.
const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
export function isXrplAddress(value) {
  if (typeof value !== "string" || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(value)) return false;
  let n = 0n;
  for (const ch of value) {
    const d = ALPHABET.indexOf(ch);
    if (d < 0) return false;
    n = n * 58n + BigInt(d);
  }
  const hex = n.toString(16).padStart(50, "0");
  if (hex.length !== 50) return false;
  const bytes = Buffer.from(hex, "hex");
  const sum = createHash("sha256").update(createHash("sha256").update(bytes.subarray(0, 21)).digest()).digest();
  return bytes[0] === 0 && sum.subarray(0, 4).equals(bytes.subarray(21, 25));
}

// An account ID (20 bytes) as an r-address: 0x00 + the ID + a 4-byte double-SHA-256 checksum, in base58.
function addressOf(accountId) {
  const payload = Buffer.concat([Buffer.from([0]), accountId]);
  const sum = createHash("sha256").update(createHash("sha256").update(payload).digest()).digest();
  const bytes = Buffer.concat([payload, sum.subarray(0, 4)]);
  let n = BigInt(`0x${bytes.toString("hex")}`);
  let out = "";
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = ALPHABET[0] + out; }
  return out;
}

// MPTs (XLS-33): an amount is { mpt_issuance_id, value }; the issuance ID is 24 bytes, the issuer's sequence (4) and
// its account ID (20).
const MPT_ID = /^[0-9A-Fa-f]{48}$/;
const isMpt = (a) => Boolean(a && typeof a === "object" && typeof a.mpt_issuance_id === "string");
export const mptIssuer = (id) => (MPT_ID.test(String(id)) ? addressOf(Buffer.from(String(id).slice(8), "hex")) : null);
// The ticker (or else the name) in an issuance's metadata (XLS-89: hex-encoded JSON, long or compact keys).
export function mptTicker(issuance) {
  try {
    const meta = JSON.parse(Buffer.from(String(issuance?.MPTokenMetadata ?? ""), "hex").toString("utf8"));
    const name = meta.ticker ?? meta.t ?? meta.name ?? meta.n;
    return typeof name === "string" && name.trim() ? name.trim().slice(0, 40) : null;
  } catch { return null; }
}

export const isXrplRequest = (body) => Boolean(body && typeof body === "object" && body.type === "xrpl");

// The fields of one transaction (the one signed, or one inside a Batch) that must be addresses, hex or a valid
// permission list. `at` names it in the error.
function validateTx(tx, at) {
  if (typeof tx.TransactionType !== "string" || !/^[A-Za-z]{2,40}$/.test(tx.TransactionType)) throw new XrplValidationError(`${at}.TransactionType is required`);
  if (!isXrplAddress(tx.Account)) throw new XrplValidationError(`${at}.Account must be a valid XRPL address (r…)`);
  const credential = tx.TransactionType.startsWith("Credential");
  const delegate = tx.TransactionType === "DelegateSet";
  for (const field of ["Destination", "RegularKey", "Holder", ...(credential ? ["Subject", "Issuer"] : []), ...(delegate ? ["Authorize"] : [])]) {
    if (tx[field] !== undefined && !isXrplAddress(tx[field])) throw new XrplValidationError(`${at}.${field} must be a valid XRPL address (r…)`);
  }
  if (tx.TransactionType === "PaymentChannelFund" && !/^[0-9A-Fa-f]{64}$/.test(String(tx.Channel ?? ""))) throw new XrplValidationError(`${at}.Channel must be the channel's 64-character hex ID`);
  if (tx.TransactionType === "MPTokenAuthorize" && !MPT_ID.test(String(tx.MPTokenIssuanceID ?? ""))) throw new XrplValidationError(`${at}.MPTokenIssuanceID must be 48 hex characters`);
  for (const field of ["Amount", "SendMax", "DeliverMin"]) {
    if (isMpt(tx[field]) && !MPT_ID.test(tx[field].mpt_issuance_id)) throw new XrplValidationError(`${at}.${field}.mpt_issuance_id must be 48 hex characters`);
  }
  if (credential && (typeof tx.CredentialType !== "string" || !/^([0-9A-Fa-f]{2}){1,64}$/.test(tx.CredentialType))) {
    throw new XrplValidationError(`${at}.CredentialType must be hex, 1 to 64 bytes`);
  }
  if (delegate) {
    if (tx.Authorize === undefined || tx.Authorize === tx.Account) throw new XrplValidationError(`${at}.Authorize is required: the account that gets the permissions (not Account itself)`);
    const list = tx.Permissions;
    if (!Array.isArray(list) || list.length > MAX_PERMISSIONS) throw new XrplValidationError(`${at}.Permissions must be a list of at most ${MAX_PERMISSIONS} [{ Permission: { PermissionValue } }]; an empty list removes them all`);
    const values = list.map((p) => p?.Permission?.PermissionValue);
    if (!values.every((v) => (typeof v === "string" && /^[A-Za-z0-9]{1,40}$/.test(v)) || (Number.isInteger(v) && v > 0 && v < 2 ** 32))) {
      throw new XrplValidationError(`${at}.Permissions: every PermissionValue must be a transaction type or granular permission (a name or number)`);
    }
    const names = values.map(permissionName);
    const refused = names.find((n) => NOT_DELEGABLE.has(n));
    if (refused) throw new XrplValidationError(`${at}.Permissions: ${refused} can't be delegated`);
    if (new Set(names).size !== names.length) throw new XrplValidationError(`${at}.Permissions lists a permission twice`);
  }
}

export async function parseXrplRequest(body) {
  const network = body.network ?? "xrpl:0";
  if (!XRPL_NETWORKS[network]) throw new XrplValidationError(`network must be one of ${Object.keys(XRPL_NETWORKS).join(", ")}`);
  const tx = body.tx ?? body.tx_json;
  if (!tx || typeof tx !== "object" || Array.isArray(tx)) throw new XrplValidationError("tx is required: the unsigned transaction JSON (TransactionType, Account, …)");
  validateTx(tx, "tx");
  if (tx.TransactionType === "Batch") {
    const raw = tx.RawTransactions;
    if (!Array.isArray(raw) || raw.length < 2 || raw.length > 8) throw new XrplValidationError("tx.RawTransactions must hold 2 to 8 transactions: [{ RawTransaction: { TransactionType, Account, … } }]");
    raw.forEach((r, i) => {
      const inner = r?.RawTransaction;
      const at = `tx.RawTransactions[${i}].RawTransaction`;
      if (!inner || typeof inner !== "object" || Array.isArray(inner)) throw new XrplValidationError(`${at} is required`);
      if (inner.TransactionType === "Batch") throw new XrplValidationError(`${at}: a Batch can't contain another Batch`);
      validateTx(inner, at);
    });
    if (batchModes(tx.Flags).length !== 1) throw new XrplValidationError(`tx.Flags must set exactly one batch mode: ${BATCH_MODES.map(([name, bit]) => `${name} (${bit})`).join(", ")}`);
    if (tx.BatchSigners !== undefined) {
      if (!Array.isArray(tx.BatchSigners) || tx.BatchSigners.length > 24) throw new XrplValidationError("tx.BatchSigners must be a list of at most 24 [{ BatchSigner: { Account, … } }]");
      tx.BatchSigners.forEach((s, i) => {
        if (!isXrplAddress(s?.BatchSigner?.Account)) throw new XrplValidationError(`tx.BatchSigners[${i}].BatchSigner.Account must be a valid XRPL address (r…)`);
      });
    }
  }
  let origin;
  if (body.origin !== undefined && body.origin !== null && body.origin !== "") {
    if (typeof body.origin !== "string" || body.origin.length > 2048) throw new XrplValidationError("origin must be a URL or hostname");
    try { origin = new URL(/^[a-z]+:\/\//i.test(body.origin) ? body.origin : `https://${body.origin}`).hostname.toLowerCase(); } catch { throw new XrplValidationError("origin must be a URL or hostname"); }
  }
  return { network, tx, ...(origin && { origin }) };
}

// Amount helpers: XRP is a string of drops; an issued token is { currency, issuer, value }.
const isIssued = (a) => Boolean(a && typeof a === "object" && typeof a.currency === "string" && typeof a.issuer === "string" && a.currency.toUpperCase() !== "XRP");
export const currencyName = (c) => (String(c).toUpperCase() === RLUSD ? "RLUSD" : String(c).length === 40 ? Buffer.from(String(c), "hex").toString("latin1").replace(/\0+$/, "") || c : c);
export const isRlusdCode = (c) => String(c).toUpperCase() === RLUSD || String(c).toUpperCase() === "RLUSD";

const cache = new Map();
export function ledger(network, fetchImpl = globalThis.fetch) {
  const { rpc } = XRPL_NETWORKS[network];
  const useCache = fetchImpl === globalThis.fetch; // a stand-in node (tests) is asked every time
  return async (method, params) => {
    const key = `${rpc}|${method}|${JSON.stringify(params)}`;
    const hit = useCache && cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.result;
    const res = await fetchImpl(rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ method, params: [{ ...params, ledger_index: "validated" }] }), signal: AbortSignal.timeout(RPC_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`XRPL node HTTP ${res.status}`);
    const result = (await res.json())?.result ?? {};
    if (useCache) {
      if (cache.size > 2000) cache.clear();
      cache.set(key, { at: Date.now(), result });
    }
    return result;
  };
}

// A DEX order more than this much below the best available rate is flagged.
const OFFER_MAX_BELOW_MARKET = 0.05;
const round6 = (x) => Math.round(x * 1e6) / 1e6;
// An amount in whole units: XRP drops to XRP, a token's value as a number.
const units = (a) => (isIssued(a) ? Number(a.value) : Number(a) / 1e6);
const assetOf = (a) => (isIssued(a) ? { currency: a.currency, issuer: a.issuer } : { currency: "XRP" });

// The best rate (units received per unit given) the ledger offers now for giving `give` to get `receive`: the top of
// the order book and the AMM pool's spot price, whichever is better. null = neither exists.
async function bestRate(ask, give, receive) {
  const [book, amm] = await Promise.all([
    ask("book_offers", { taker_gets: assetOf(receive), taker_pays: assetOf(give), limit: 1 }).catch(() => ({})),
    ask("amm_info", { asset: assetOf(give), asset2: assetOf(receive) }).catch(() => ({})),
  ]);
  const rates = [];
  const top = book.offers?.[0];
  if (top) {
    const gets = units(top.taker_gets_funded ?? top.TakerGets), pays = units(top.taker_pays_funded ?? top.TakerPays);
    if (gets > 0 && pays > 0) rates.push({ rate: gets / pays, source: "order book" });
  }
  if (amm.amm) {
    const a = units(amm.amm.amount), b = units(amm.amm.amount2);
    // amount is the pool's `asset` (what we give), amount2 its `asset2` (what we receive)
    if (a > 0 && b > 0) rates.push({ rate: b / a, source: "AMM pool" });
  }
  if (!rates.length) return null;
  return rates.sort((x, y) => y.rate - x.rate)[0];
}

export async function analyzeXrpl(req, { fetchImpl = globalThis.fetch } = {}) {
  const { tx, network } = req;
  const net = XRPL_NETWORKS[network];
  const reasons = [];
  // One reason per code and subject (per inner transaction of a Batch).
  const addReason = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject && r.details?.inner === details?.inner)) return;
    reasons.push({ code, severity, ...(subject && { subject }), ...(details && { details }) });
  };
  const add = addReason;
  const ask = ledger(network, fetchImpl);
  let ledgerUsed = false;
  let ledgerDown = false;
  const account = async (address) => {
    try {
      const r = await ask("account_info", { account: address });
      ledgerUsed = true;
      if (r.error === "actNotFound") return { exists: false };
      if (r.error || !r.account_data) throw new Error(r.error_message || r.error || "no account data");
      return { exists: true, flags: Number(r.account_data.Flags) || 0, transferRate: Number(r.account_data.TransferRate) || 0 };
    } catch (err) {
      if (!ledgerDown) add("XRPL_LEDGER_UNAVAILABLE", "info", net.name, { error: String(err.message).slice(0, 120) });
      ledgerDown = true;
      return null;
    }
  };
  // A ledger entry (a credential, an MPT issuance or holding): the node, null when there is none, undefined when the
  // ledger can't be read.
  const ledgerEntry = async (params) => {
    try {
      const r = await ask("ledger_entry", params);
      ledgerUsed = true;
      if (r.error === "entryNotFound") return null;
      if (r.error || !r.node) throw new Error(r.error_message || r.error || "no ledger entry");
      return r.node;
    } catch (err) {
      if (!ledgerDown) add("XRPL_LEDGER_UNAVAILABLE", "info", net.name, { error: String(err.message).slice(0, 120) });
      ledgerDown = true;
      return undefined;
    }
  };
  const credential = (subject, issuer, type) => ledgerEntry({ credential: { subject, issuer, credential_type: type } });
  const tokens = [];
  const seenTokens = new Set();
  const parties = [];
  // The rules for one transaction: the one signed, or one inside a Batch (`at` = { inner, account? }, added to the
  // details of its reasons).
  const judge = async (tx, at) => {
    const add = (code, severity, subject, details) => addReason(code, severity, subject, at ? { ...at, ...details } : details);
    const fakeRlusd = (amount, where) => {
      if (isIssued(amount) && isRlusdCode(amount.currency) && amount.issuer !== net.rlusdIssuer) {
        add("XRPL_FAKE_RLUSD", "red", amount.issuer, { where, issuer: amount.issuer, rippleIssuer: net.rlusdIssuer });
        return true;
      }
      return false;
    };
    const type = tx.TransactionType;

    if (type === "SetRegularKey") {
      if (tx.RegularKey && tx.RegularKey !== tx.Account) add("XRPL_REGULAR_KEY_CHANGE", "red", tx.RegularKey, { effect: "the regular key can sign every transaction for the account, including moving all its funds" });
      else if (!tx.RegularKey) add("XRPL_REGULAR_KEY_REMOVED", "info", tx.Account);
    }

    if (type === "SignerListSet") {
      const entries = Array.isArray(tx.SignerEntries) ? tx.SignerEntries.map((e) => e?.SignerEntry?.Account).filter(Boolean) : [];
      if (Number(tx.SignerQuorum) > 0 && entries.length) {
        add("XRPL_SIGNER_LIST_CHANGE", "red", entries.join(","), { quorum: Number(tx.SignerQuorum), signers: entries, effect: "these signers can sign for the account together; unless you control them, the account is theirs" });
      } else if (Number(tx.SignerQuorum) === 0) add("XRPL_SIGNER_LIST_REMOVED", "orange", tx.Account);
    }

    if (type === "AccountSet") {
      const f = Number(tx.SetFlag);
      if (f === ASF.disableMaster) add("XRPL_DISABLE_MASTER_KEY", "red", tx.Account, { effect: "after this only the regular key or signer list can sign; if those aren't yours, the account is lost" });
      if (f === ASF.allowClawback) add("XRPL_ENABLE_CLAWBACK", "orange", tx.Account, { effect: "lets this account claw back tokens it issues; it can't be turned off again" });
      if (f === ASF.depositAuth) add("XRPL_ENABLE_DEPOSIT_AUTH", "orange", tx.Account, { effect: "the account will refuse payments from anyone it hasn't pre-authorised" });
    }

    if (type === "AccountDelete") {
      add("XRPL_ACCOUNT_DELETE", "red", tx.Destination, { effect: "deletes the account and sends all its remaining XRP to the destination; it can't be undone" });
    }

    if (type === "Payment") {
      if (Number(tx.Flags) & TF_PARTIAL_PAYMENT) add("XRPL_PARTIAL_PAYMENT", "orange", tx.Destination, { effect: "a partial payment may deliver far less than Amount; receivers must read delivered_amount" });
      fakeRlusd(tx.Amount, "Amount");
      if (isIssued(tx.SendMax)) fakeRlusd(tx.SendMax, "SendMax");
    }

    // An MPT's issuance on the ledger, its issuer and the name to show. A ticker of RLUSD from anyone but Ripple is a
    // fake; another ticker goes to the name check below.
    const mptOf = async (id, where) => {
      const issuer = mptIssuer(id);
      const issuance = await ledgerEntry({ mpt_issuance: id });
      if (issuance === null) add("XRPL_MPT_NOT_FOUND", "orange", id, { where, effect: "there is no such MPT on the ledger, so the transaction fails" });
      if (!issuance) return null;
      const ticker = mptTicker(issuance);
      const rippleRlusd = Boolean(ticker && isRlusdCode(ticker) && issuer === net.rlusdIssuer);
      if (ticker && isRlusdCode(ticker) && !rippleRlusd) add("XRPL_FAKE_RLUSD", "red", issuer, { where, issuer, rippleIssuer: net.rlusdIssuer, mpt: id });
      else if (ticker && !rippleRlusd && !seenTokens.has(`${ticker}.${issuer}`)) { seenTokens.add(`${ticker}.${issuer}`); tokens.push({ address: `${ticker}.${issuer}`, symbol: ticker }); }
      return { issuance, issuer, flags: Number(issuance.Flags) || 0, token: ticker ?? id, rippleRlusd };
    };

    // Opting in to hold an MPT (MPTokenAuthorize without Holder, which is the issuer authorising someone, and without
    // tfMPTUnauthorize): what its issuer can do to it, as for a trust line.
    if (type === "MPTokenAuthorize" && tx.Holder === undefined && !(Number(tx.Flags) & TF_MPT_UNAUTHORIZE)) {
      const m = await mptOf(tx.MPTokenIssuanceID, "MPTokenIssuanceID");
      if (m) {
        if (m.flags & LSF_MPT.canClawback) add("XRPL_ISSUER_CAN_CLAW_BACK", m.rippleRlusd ? "info" : "orange", m.issuer, { token: m.token });
        if (m.flags & LSF_MPT.locked) add("XRPL_ISSUER_FROZEN", "orange", m.issuer, { token: m.token });
        if (Number(m.issuance.TransferFee) > 0) add("XRPL_TRANSFER_FEE", "orange", m.issuer, { feePercent: Number(m.issuance.TransferFee) / 1000 });
      }
    }

    // Paying with an MPT fails when the issuer has locked it, or doesn't let it move between holders (only to and
    // from the issuer); the destination's side is checked with the destination below.
    const mpt = type === "Payment" && isMpt(tx.Amount) ? await mptOf(tx.Amount.mpt_issuance_id, "Amount") : null;
    if (mpt) {
      if (mpt.flags & LSF_MPT.locked) add("XRPL_MPT_LOCKED", "orange", mpt.issuer, { token: mpt.token, effect: "the issuer has locked this MPT, so the payment fails" });
      if (!(mpt.flags & LSF_MPT.canTransfer) && tx.Account !== mpt.issuer && tx.Destination !== mpt.issuer) add("XRPL_MPT_NOT_TRANSFERABLE", "orange", mpt.issuer, { token: mpt.token, effect: "the issuer only lets this MPT go back to the issuer, not to other holders, so the payment fails" });
    }

    // What the issuer of a token the account is about to hold (trust line, buy, pool deposit) can do to it.
    const issuerRisks = async (amount, where) => {
      if (!isIssued(amount) || fakeRlusd(amount, where)) return;
      const issuer = amount.issuer;
      const info = await account(issuer);
      if (info && !info.exists) add("XRPL_ISSUER_NOT_FOUND", "orange", issuer, { where });
      if (!info?.exists) return;
      // Ripple's own RLUSD is a regulated stablecoin with clawback on by design: worth knowing, not a warning.
      const rippleRlusd = issuer === net.rlusdIssuer && isRlusdCode(amount.currency);
      if (info.flags & LSF.allowClawback) add("XRPL_ISSUER_CAN_CLAW_BACK", rippleRlusd ? "info" : "orange", issuer, { token: currencyName(amount.currency), ...(rippleRlusd && { note: "regulated stablecoin: Ripple can claw back RLUSD" }) });
      if (info.flags & LSF.globalFreeze) add("XRPL_ISSUER_FROZEN", "orange", issuer, { token: currencyName(amount.currency) });
      if (info.transferRate > 1_000_000_000) add("XRPL_TRANSFER_FEE", "orange", issuer, { feePercent: Math.round((info.transferRate / 1e7 - 100) * 100) / 100 });
    };

    if (type === "TrustSet" && isIssued(tx.LimitAmount) && Number(tx.LimitAmount.value) > 0) await issuerRisks(tx.LimitAmount, "LimitAmount");

    // A DEX order: TakerGets is what the account gives, TakerPays what it receives. The token bought is screened like
    // a trust line; the limit price is compared with the best the ledger offers now (order book and AMM pool). On the
    // XRPL a crossing order fills at the better book prices first, but on a thin book it keeps filling down to its
    // limit: a limit far below the market lets that happen.
    if (type === "OfferCreate" && tx.TakerGets !== undefined && tx.TakerPays !== undefined) {
      fakeRlusd(tx.TakerGets, "TakerGets");
      await issuerRisks(tx.TakerPays, "TakerPays");
      const give = units(tx.TakerGets), receive = units(tx.TakerPays);
      if (give > 0 && receive > 0) {
        const market = await bestRate(ask, tx.TakerGets, tx.TakerPays).catch(() => undefined);
        const yours = receive / give;
        if (market === null) add("XRPL_NO_MARKET", "orange", null, { effect: "no order book or AMM pool for this pair right now: the order rests until someone takes it, at your price" });
        else if (market && yours < market.rate * (1 - OFFER_MAX_BELOW_MARKET)) {
          add("XRPL_OFFER_FAR_BELOW_MARKET", "orange", null, { yourRate: round6(yours), marketRate: round6(market.rate), worseByPct: Math.round((1 - yours / market.rate) * 1000) / 10, source: market.source, effect: "you accept far less than the market gives now; on a thin book the order can fill down to this price" });
        }
      }
    }

    // Creating or funding an AMM pool: both assets are held by the pool for you; a fake or risky token loses value.
    if (type === "AMMCreate" || type === "AMMDeposit") {
      for (const field of ["Amount", "Amount2", "Asset", "Asset2"]) if (isIssued(tx[field])) await issuerRisks(tx[field], field);
    }

    if (type === "EscrowCreate" && tx.Destination && tx.Destination !== tx.Account) {
      add("XRPL_ESCROW_TO_OTHER", "orange", tx.Destination, { amount: tx.Amount, effect: "locks the XRP until it is released to the destination, not back to you", ...(tx.FinishAfter && { finishAfter: tx.FinishAfter }), ...(tx.CancelAfter && { cancelAfter: tx.CancelAfter }) });
    }

    // A check or payment channel to someone else: like an escrow, the value can then go to the destination without
    // another signature (a check up to SendMax; a channel up to Amount, with claims signed by the channel's key).
    if (type === "CheckCreate" && tx.Destination && tx.Destination !== tx.Account) {
      add("XRPL_CHECK_TO_OTHER", "orange", tx.Destination, { sendMax: tx.SendMax, ...(tx.Expiration !== undefined && { expires: rippleTime(tx.Expiration) }), effect: "the destination can cash up to SendMax from your account until the check expires or you cancel it" });
    }
    if (type === "PaymentChannelCreate" && tx.Destination && tx.Destination !== tx.Account) {
      add("XRPL_CHANNEL_TO_OTHER", "orange", tx.Destination, { amount: tx.Amount, settleDelay: tx.SettleDelay, effect: "locks the XRP in a payment channel the destination claims from with claims signed by PublicKey; if that key isn't yours, whoever holds it can let the destination take all of it" });
    }
    if (type === "PaymentChannelFund" && tx.Channel) {
      const channel = await ledgerEntry({ payment_channel: tx.Channel });
      if (channel === null) add("XRPL_CHANNEL_NOT_FOUND", "orange", tx.Channel, { effect: "there is no such payment channel, so the transaction fails" });
      else if (channel && channel.Destination && channel.Destination !== tx.Account) {
        add("XRPL_CHANNEL_TO_OTHER", "orange", channel.Destination, { amount: tx.Amount, channel: tx.Channel, effect: "adds the XRP to a payment channel this destination claims from" });
        parties.push(channel.Destination);
      }
    }

    if (type === "NFTokenCreateOffer" && Number(tx.Flags) & TF_SELL_NFTOKEN && (tx.Amount === "0" || tx.Amount === 0 || (isIssued(tx.Amount) && Number(tx.Amount.value) === 0))) {
      add("XRPL_NFT_GIVEAWAY", "orange", tx.Destination ?? null, { effect: "offers the NFT for nothing; whoever accepts it gets it for free" });
    }

    // Credentials (XLS-70): an issuer vouches for a subject, and permissioned domains and deposit authorization can let
    // holders in. Issuing one for another account lends it your name. Accepting one only takes owner reserve, but the
    // transaction fails when there is no credential, it has expired, or it was accepted already.
    if (type === "CredentialCreate" && tx.Subject && tx.Subject !== tx.Account) {
      add("XRPL_CREDENTIAL_ISSUE", "orange", tx.Subject, { credentialType: credentialName(tx.CredentialType), ...(tx.Expiration !== undefined && { expires: rippleTime(tx.Expiration) }), effect: "your account vouches for this account: services and permissioned domains that accept your credentials will treat it as having this one, until you delete it" });
    }
    if (type === "CredentialAccept" && tx.Issuer) {
      const credentialType = credentialName(tx.CredentialType);
      const issuer = await account(tx.Issuer);
      if (issuer && !issuer.exists) add("XRPL_ISSUER_NOT_FOUND", "orange", tx.Issuer, { where: "Issuer" });
      const entry = issuer?.exists ? await credential(tx.Account, tx.Issuer, tx.CredentialType) : undefined;
      if (entry === null) add("XRPL_CREDENTIAL_NOT_FOUND", "orange", tx.Issuer, { credentialType, effect: "this issuer hasn't issued that credential to you, so there is nothing to accept and the transaction fails" });
      else if (entry && Number(entry.Flags) & LSF_CREDENTIAL_ACCEPTED) add("XRPL_CREDENTIAL_ALREADY_ACCEPTED", "orange", tx.Issuer, { credentialType, effect: "you accepted it already, so the transaction fails" });
      else if (entry && entry.Expiration !== undefined && Date.parse(rippleTime(entry.Expiration)) <= Date.now()) add("XRPL_CREDENTIAL_EXPIRED", "orange", tx.Issuer, { credentialType, expired: rippleTime(entry.Expiration), effect: "the credential has expired, so the transaction fails" });
      else if (entry) add("XRPL_CREDENTIAL_ACCEPT", "info", tx.Issuer, { credentialType, ...(entry.Expiration !== undefined && { expires: rippleTime(entry.Expiration) }), effect: "the credential counts from now on, and holds one owner reserve until it is deleted" });
    }

    // Permission delegation (XLS-75): the delegate then signs these transaction types for the account, spending the
    // account's funds, until the account removes them. An empty list removes them all.
    if (type === "DelegateSet") {
      const permissions = delegatedPermissions(tx);
      const funds = permissions.filter((p) => MOVES_FUNDS.has(p));
      if (!permissions.length) add("XRPL_DELEGATE_REMOVED", "info", tx.Authorize, { effect: "removes every permission this account had to sign for yours" });
      else if (funds.length) add("XRPL_DELEGATE_FUNDS", "red", tx.Authorize, { permissions, movesFunds: funds, effect: "this account can then move your funds, to itself too, without your signature until you remove the permission; unless you control it, this gives your funds away" });
      else add("XRPL_DELEGATE_SET", "orange", tx.Authorize, { permissions, effect: "this account can sign these transaction types for yours until you remove the permission" });
      if (permissions.length) {
        const target = await account(tx.Authorize);
        if (target && !target.exists) add("XRPL_DELEGATE_NOT_FOUND", "orange", tx.Authorize, { effect: "the account doesn't exist, so the transaction fails" });
      }
    }

    if (!JUDGED.has(type) && !BENIGN.has(type)) add("XRPL_TX_NOT_ANALYZED", "orange", tx.Account, { transactionType: type });

    // The destination of a payment (or account delete) on the ledger: missing, refusing, or asking for a tag.
    if ((type === "Payment" || type === "AccountDelete") && tx.Destination) {
      const dest = await account(tx.Destination);
      const xrp = typeof tx.Amount === "string" || typeof tx.Amount === "number";
      if (dest && !dest.exists) {
        if (type === "AccountDelete") add("XRPL_DESTINATION_NOT_FOUND", "orange", tx.Destination);
        else if (xrp && Number(tx.Amount) < 1_000_000) add("XRPL_DESTINATION_NOT_ACTIVATED", "orange", tx.Destination, { effect: "the destination doesn't exist and the amount is below the 1 XRP reserve, so the payment fails" });
        else if (xrp) add("XRPL_NEW_DESTINATION", "info", tx.Destination, { effect: "this payment creates the destination account" });
        else add("XRPL_DESTINATION_NOT_ACTIVATED", "orange", tx.Destination, { effect: "the destination doesn't exist, so it can't hold this token" });
      }
      if (dest?.exists) {
        if (dest.flags & LSF.depositAuth) add("XRPL_DESTINATION_REFUSES", "orange", tx.Destination, { effect: "the destination has Deposit Authorization on and will refuse the payment unless it pre-authorised you" });
        if (dest.flags & LSF.requireDestTag && tx.DestinationTag === undefined) add("XRPL_DESTINATION_TAG_MISSING", "orange", tx.Destination, { effect: "the destination requires a destination tag (often an exchange); without one the payment is refused" });
        if (dest.flags & LSF.disallowXrp && xrp && type === "Payment") add("XRPL_DESTINATION_DISALLOWS_XRP", "orange", tx.Destination);
        if (type === "Payment" && isIssued(tx.Amount) && tx.Amount.issuer !== tx.Destination && !reasons.some((r) => r.code === "XRPL_FAKE_RLUSD")) {
          try {
            const lines = await ask("account_lines", { account: tx.Destination, peer: tx.Amount.issuer });
            const has = (lines.lines || []).some((l) => String(l.currency).toUpperCase() === String(tx.Amount.currency).toUpperCase());
            if (!has) add("XRPL_DESTINATION_NO_TRUSTLINE", "orange", tx.Destination, { token: currencyName(tx.Amount.currency), effect: "the destination has no trust line for this token, so the payment fails" });
          } catch { /* the account lookup already reported an outage, if any */ }
        }
        // An MPT payment needs the destination to hold the MPT (opted in), authorised if the issuer requires it.
        if (mpt && tx.Destination !== mpt.issuer) {
          const holding = await ledgerEntry({ mptoken: { mpt_issuance_id: tx.Amount.mpt_issuance_id, account: tx.Destination } });
          if (holding === null) add("XRPL_DESTINATION_NO_MPTOKEN", "orange", tx.Destination, { token: mpt.token, effect: "the destination hasn't opted in to hold this MPT, so the payment fails" });
          else if (holding) {
            if (mpt.flags & LSF_MPT.requireAuth && !(Number(holding.Flags) & LSF_MPTOKEN_AUTHORIZED)) add("XRPL_DESTINATION_NOT_AUTHORIZED", "orange", tx.Destination, { token: mpt.token, effect: "the issuer hasn't authorised the destination to hold this MPT, so the payment fails" });
            if (Number(holding.Flags) & LSF_MPT.locked) add("XRPL_MPT_LOCKED", "orange", tx.Destination, { token: mpt.token, effect: "the issuer has locked the destination's balance of this MPT, so the payment fails" });
          }
        }
      }
    }

    // The names of the tokens this transaction moves or trusts (not Ripple's RLUSD, not one already flagged as fake):
    // RLUSD look-alikes by rule, other famous names by Jev when the server has TypeSafe. Orange at most.
    for (const k of ["Amount", "SendMax", "DeliverMin", "LimitAmount", "TakerGets", "TakerPays", "Amount2"]) {
      const a = tx[k];
      if (!isIssued(a) || (isRlusdCode(a.currency) && (a.issuer === net.rlusdIssuer || reasons.some((r) => r.code === "XRPL_FAKE_RLUSD")))) continue;
      const name = currencyName(a.currency);
      const address = `${name}.${a.issuer}`;
      if (!seenTokens.has(address)) { seenTokens.add(address); tokens.push({ address, symbol: name }); }
    }
    // Everyone the transaction pays, hands the account or permissions to, trusts or trades with (destinations, new keys,
    // signers and delegates, token issuers), for the OFAC SDN screen below.
    parties.push(
      ...["Destination", "RegularKey", "Owner", "Authorize", "Unauthorize", "Issuer", "Holder", "Subject"].map((k) => tx[k]),
      ...["Amount", "SendMax", "DeliverMin", "LimitAmount", "TakerGets", "TakerPays"].map((k) => (isIssued(tx[k]) ? tx[k].issuer : isMpt(tx[k]) ? mptIssuer(tx[k].mpt_issuance_id) : null)),
      ...(tx.MPTokenIssuanceID ? [mptIssuer(tx.MPTokenIssuanceID)] : []),
      ...(Array.isArray(tx.SignerEntries) ? tx.SignerEntries.map((e) => e?.SignerEntry?.Account) : []),
    );
  };

  // A Batch (XLS-56) does what its inner transactions do, so each is judged as if signed on its own (`details.inner`
  // is its place in RawTransactions). Inner transactions of other accounts are signed by them (BatchSigners); unless
  // the batch is all-or-nothing, one account's part can go through while another's fails.
  if (tx.TransactionType === "Batch") {
    const inner = tx.RawTransactions.map((r) => r.RawTransaction);
    const accounts = [...new Set(inner.map((t) => t.Account))];
    const [mode] = batchModes(tx.Flags);
    add("XRPL_BATCH", "info", tx.Account, { mode, transactions: inner.map((t) => t.TransactionType), ...(accounts.some((a) => a !== tx.Account) && { accounts }) });
    if (accounts.length > 1 && mode !== "tfAllOrNothing") add("XRPL_BATCH_NOT_ATOMIC", "orange", tx.Account, { mode, accounts, effect: "the transactions of different accounts in this batch don't depend on each other: your part can go through while the other account's part fails" });
    for (const [i, t] of inner.entries()) {
      await judge(t, { inner: i, ...(t.Account !== tx.Account && { account: t.Account }) });
      parties.push(t.Account);
    }
    for (const s of tx.BatchSigners ?? []) parties.push(s.BatchSigner.Account);
  } else await judge(tx);

  // The site asking for the signature: phishing lists and domain age (PG1), as for EVM checks.
  if (req.origin) {
    const [rep, domain] = await Promise.all([hostnameReputation(req.origin).catch(() => null), domainAge(req.origin).catch(() => null)]);
    if (rep?.verdict === "listed") add("PHISHING_SITE", "red", req.origin, { flaggedBy: ["pg1"], list: "MetaMask eth-phishing-detect", matchType: rep.matchType });
    else if (rep?.lookalikeOf) add("LOOKALIKE_SITE", "orange", req.origin, { lookalikeOf: rep.lookalikeOf });
    if (domain?.found && domain.ageDays < NEW_DOMAIN_DAYS) add("NEW_DOMAIN", "orange", domain.domain, { ageDays: domain.ageDays, registered: domain.registered });
    else if (domain && !domain.found && domain.unregistered) add("DOMAIN_NOT_REGISTERED", "orange", domain.domain);
  }

  const sanctions = partySanctionsReasons(parties, { exclude: [tx.Account] });
  for (const r of sanctions.reasons) add(r.code, r.severity, r.subject, r.details);

  let aiSources = [];
  if (tokens.length) {
    const ai = await secondOpinion({ chainId: "xrpl", tokens }).catch(() => ({ reasons: [], sources: [] }));
    for (const r of ai.reasons) add(r.code, r.severity, r.subject, r.details);
    aiSources = ai.sources;
  }

  const verdict = reasons.some((r) => r.severity === "red") ? "red" : reasons.some((r) => r.severity === "orange") ? "orange" : "green";
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      network,
      kind: tx.TransactionType,
      account: tx.Account,
      ...(tx.Destination && { destination: tx.Destination }),
      ...(tx.Amount !== undefined && { amount: isIssued(tx.Amount) ? { ...tx.Amount, token: currencyName(tx.Amount.currency) } : typeof tx.Amount === "object" ? tx.Amount : String(tx.Amount) }),
      ...(req.origin && { origin: req.origin }),
    },
    scope: "XRP Ledger transactions before signing: account takeover (SetRegularKey, SignerListSet, disabling the master key), AccountDelete, partial payments, fake RLUSD (and RLUSD look-alike names; other famous token names via the AI check), destinations that refuse or need a tag, trust lines to issuers that can claw back, freeze or charge a transfer fee, escrows, checks, payment channels and NFT offers that hand value to someone else, credentials issued for another account or accepted when there is nothing valid to accept, Batch transactions (every inner transaction judged; batches of several accounts that aren't all-or-nothing), permission delegation (DelegateSet that lets another account move funds), MPTs (opting in to one whose issuer can claw back, has locked it or charges a fee; fake RLUSD tickers; payments that would fail), every destination, new key, signer, delegate and token issuer against the OFAC SDN list, plus the requesting site's phishing-list status and domain age. DEX orders are screened for the token bought and a limit far below the order book or AMM price; AMM pool funding for risky tokens. Not covered: full simulation of how an order fills.",
    sources: [...(ledgerUsed ? ["xrpl-ledger"] : []), ...(sanctions.used ? ["ofac-sdn"] : []), ...(req.origin ? ["pg1"] : []), ...aiSources],
    checkedAt: new Date().toISOString(),
  };
}
