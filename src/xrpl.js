// xrpl.js — the pre-sign check for XRP Ledger transactions (POST /v1/check with type "xrpl").
//
//   { type: "xrpl", network?: "xrpl:0" | "xrpl:1", tx: { TransactionType, Account, ... }, origin? }
//
// What hurts people on the XRPL is rarely a token approval (there are none): it is handing over the account.
// A SetRegularKey or SignerListSet to someone else's key, or AccountSet disabling the master key, gives the
// account away for good; AccountDelete sends all its XRP to the Destination. Those are red. Orange: a payment
// that will fail or may deliver less than it says (partial payment), a destination that refuses it, a trust line
// to an issuer that can claw tokens back or has frozen them, an escrow or NFT offer that hands value to someone
// else, a transaction type this check does not judge. A token called RLUSD that isn't Ripple's is red.
// The ledger is read through public JSON-RPC (no key); when it can't be reached the check says so (info) and the
// rules that need no ledger still apply. Fail-closed as in presign-guard.js: errors are non-2xx, never "green".

import { createHash } from "node:crypto";
import { domainAge, hostnameReputation, NEW_DOMAIN_DAYS } from "./pg1.js";

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

// Types judged by a rule below, and everyday types with nothing to flag on their own.
const JUDGED = new Set(["Payment", "TrustSet", "SetRegularKey", "SignerListSet", "AccountSet", "AccountDelete", "EscrowCreate", "NFTokenCreateOffer", "OfferCreate", "AMMCreate", "AMMDeposit"]);
const BENIGN = new Set(["OfferCancel", "EscrowFinish", "EscrowCancel", "CheckCash", "CheckCancel", "NFTokenMint", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenAcceptOffer", "TicketCreate", "AMMWithdraw", "AMMVote", "AMMBid"]);

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

export const isXrplRequest = (body) => Boolean(body && typeof body === "object" && body.type === "xrpl");

export async function parseXrplRequest(body) {
  const network = body.network ?? "xrpl:0";
  if (!XRPL_NETWORKS[network]) throw new XrplValidationError(`network must be one of ${Object.keys(XRPL_NETWORKS).join(", ")}`);
  const tx = body.tx ?? body.tx_json;
  if (!tx || typeof tx !== "object" || Array.isArray(tx)) throw new XrplValidationError("tx is required: the unsigned transaction JSON (TransactionType, Account, …)");
  if (typeof tx.TransactionType !== "string" || !/^[A-Za-z]{2,40}$/.test(tx.TransactionType)) throw new XrplValidationError("tx.TransactionType is required");
  if (!isXrplAddress(tx.Account)) throw new XrplValidationError("tx.Account must be a valid XRPL address (r…)");
  for (const field of ["Destination", "RegularKey"]) {
    if (tx[field] !== undefined && !isXrplAddress(tx[field])) throw new XrplValidationError(`tx.${field} must be a valid XRPL address (r…)`);
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
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, ...(subject && { subject }), ...(details && { details }) });
  };
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

  if (type === "NFTokenCreateOffer" && Number(tx.Flags) & TF_SELL_NFTOKEN && (tx.Amount === "0" || tx.Amount === 0 || (isIssued(tx.Amount) && Number(tx.Amount.value) === 0))) {
    add("XRPL_NFT_GIVEAWAY", "orange", tx.Destination ?? null, { effect: "offers the NFT for nothing; whoever accepts it gets it for free" });
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
    }
  }

  // The site asking for the signature: phishing lists and domain age (PG1), as for EVM checks.
  if (req.origin) {
    const [rep, domain] = await Promise.all([hostnameReputation(req.origin).catch(() => null), domainAge(req.origin).catch(() => null)]);
    if (rep?.verdict === "listed") add("PHISHING_SITE", "red", req.origin, { flaggedBy: ["pg1"], list: "MetaMask eth-phishing-detect", matchType: rep.matchType });
    else if (rep?.lookalikeOf) add("LOOKALIKE_SITE", "orange", req.origin, { lookalikeOf: rep.lookalikeOf });
    if (domain?.found && domain.ageDays < NEW_DOMAIN_DAYS) add("NEW_DOMAIN", "orange", domain.domain, { ageDays: domain.ageDays, registered: domain.registered });
    else if (domain && !domain.found && domain.unregistered) add("DOMAIN_NOT_REGISTERED", "orange", domain.domain);
  }

  const verdict = reasons.some((r) => r.severity === "red") ? "red" : reasons.some((r) => r.severity === "orange") ? "orange" : "green";
  return {
    version: "2",
    verdict,
    reasons,
    subject: {
      network,
      kind: type,
      account: tx.Account,
      ...(tx.Destination && { destination: tx.Destination }),
      ...(tx.Amount !== undefined && { amount: isIssued(tx.Amount) ? { ...tx.Amount, token: currencyName(tx.Amount.currency) } : String(tx.Amount) }),
      ...(req.origin && { origin: req.origin }),
    },
    scope: "XRP Ledger transactions before signing: account takeover (SetRegularKey, SignerListSet, disabling the master key), AccountDelete, partial payments, fake RLUSD, destinations that refuse or need a tag, trust lines to issuers that can claw back, freeze or charge a transfer fee, escrows and NFT offers that hand value to someone else, plus the requesting site's phishing-list status and domain age. DEX orders are screened for the token bought and a limit far below the order book or AMM price; AMM pool funding for risky tokens. Not covered: full simulation of how an order fills.",
    sources: [...(ledgerUsed ? ["xrpl-ledger"] : []), ...(req.origin ? ["pg1"] : [])],
    checkedAt: new Date().toISOString(),
  };
}
