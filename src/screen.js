// Wallet screen: may I pay, or accept money from, this address?
// GET /v1/screen?address=<any chain's address>
//
// For sellers screening who pays them, and for agents checking who they are about to pay. One address,
// any chain: the format says which one (EVM, Solana, Tron, Bitcoin, XRP Ledger, Algorand, or another
// currency OFAC lists).
//
// Sources:
// - The OFAC SDN list from the US Treasury (src/ofac.js): every digital currency address OFAC publishes,
//   exact match. PG1 stands in for EVM addresses while our copy is not loaded.
// - GoPlus address_security, EVM only (its data for other chains is empty): theft, phishing, scams,
//   laundering, mixers.
//
// Rules:
// - red: on the OFAC SDN list (SANCTIONED_ADDRESS), or GoPlus reports theft, phishing, laundering,
//   sanctions or other crime.
// - orange: GoPlus has the address on its doubt list or reports mixer use.
// - info: what was screened (SANCTIONS_SCREENED with the list's publish date), no reports
//   (NO_REPORTS), and what could not be checked (REPUTATION_NOT_COVERED, REPUTATION_UNAVAILABLE,
//   SANCTIONS_LIST_STALE).
// No sanctions list at all (ours not loaded and no PG1 answer): 503, no verdict and nothing charged.

import express from "express";
import algosdk from "algosdk";
import { ValidationError, UpstreamError, cached, goplus, flag } from "./presign-guard.js";
import { gradeOf } from "./token-verdict.js";
import { screenOfac } from "./ofac.js";
import { screenSanctions } from "./pg1.js";

// GoPlus address_security fields, as in /v1/check.
const RED_FLAGS = [
  "cybercrime", "money_laundering", "phishing_activities", "stealing_attack",
  "blackmail_activities", "sanctioned", "financial_crime", "darkweb_transactions",
  "honeypot_related_address", "fake_kyc", "malicious_mining_activities",
];
const ORANGE_FLAGS = ["blacklist_doubt", "mixer"];

const B58 = "1-9A-HJ-NP-Za-km-z";
// Most specific first: a Tron, Bitcoin or XRPL address is also valid base58.
const FORMATS = [
  ["evm", new RegExp("^0x[0-9a-fA-F]{40}$")],
  ["tron", new RegExp(`^T[${B58}]{33}$`)],
  ["bitcoin", new RegExp(`^(bc1[02-9ac-hj-np-z]{11,71}|[13][${B58}]{24,33})$`)],
  ["xrpl", new RegExp(`^r[${B58}]{24,34}$`)],
  ["algorand", /^[A-Z2-7]{58}$/],
  // A 32-byte key is 43 or 44 characters (shorter only with leading zero bytes); Litecoin and Dogecoin are 34.
  ["solana", new RegExp(`^[${B58}]{43,44}$`)],
];
export const FORMAT_NAMES = { evm: "EVM", tron: "Tron", bitcoin: "Bitcoin", xrpl: "XRP Ledger", algorand: "Algorand", solana: "Solana", other: "this chain" };

export function addressFormat(address) {
  for (const [name, re] of FORMATS) {
    if (!re.test(address)) continue;
    if (name === "algorand" && !algosdk.isValidAddress(address)) continue;
    return name;
  }
  return "other";
}

// ---------- input ----------

export function parseScreenRequest(query) {
  const address = String(query?.address ?? "").trim();
  // Any currency OFAC lists: base58, bech32, hex, Monero's 95 characters, cash addresses with a prefix.
  if (!/^[A-Za-z0-9:]{20,120}$/.test(address)) throw new ValidationError("address must be a wallet address (EVM 0x..., Solana, Tron, Bitcoin, XRP Ledger, Algorand or another chain's)");
  return { address, format: addressFormat(address) };
}

// ---------- sources ----------

// GoPlus without chain_id: one answer for the address across the EVM chains it covers.
function addressReputation(address) {
  return cached(`screen:${address.toLowerCase()}`, async () => {
    const { result } = await goplus(`/address_security/${address.toLowerCase()}`);
    return result;
  });
}

async function sanctions(address, format) {
  const own = await screenOfac(address);
  if (own) return { ...own, source: "ofac-sdn" };
  // Our copy is not loaded (just started, or the Treasury site is down): PG1 screens EVM addresses.
  if (format !== "evm") return null;
  const pg1 = await screenSanctions(address.toLowerCase());
  return pg1 && {
    listed: pg1.listed,
    matches: pg1.matches.map((m) => ({ uid: m.sdnUid, name: m.sdnName, programs: m.programs })),
    published: pg1.listSynced,
    source: "pg1",
  };
}

// ---------- verdict ----------

const PHRASES = {
  SANCTIONED_ADDRESS: (r) => `on the OFAC SDN list (${[...new Set(r.details.matches.map((m) => m.name))].slice(0, 2).join(", ")})`,
  STEALING_ATTACK: () => "reported for theft",
  PHISHING_ACTIVITIES: () => "reported for phishing",
  MONEY_LAUNDERING: () => "reported for money laundering",
  SANCTIONED: () => "reported as sanctioned",
  CYBERCRIME: () => "reported for cybercrime",
  FINANCIAL_CRIME: () => "reported for financial crime",
  BLACKMAIL_ACTIVITIES: () => "reported for blackmail",
  DARKWEB_TRANSACTIONS: () => "darkweb transactions reported",
  HONEYPOT_RELATED_ADDRESS: () => "linked to honeypot tokens",
  FAKE_KYC: () => "fake KYC reported",
  MALICIOUS_MINING_ACTIVITIES: () => "malicious mining reported",
  MIXER: () => "mixer use reported",
  BLACKLIST_DOUBT: () => "on a doubt list",
};

export function screenOneLiner({ grade, reasons, sanctions: sc, format }) {
  const bad = reasons.filter((r) => r.severity !== "info" && PHRASES[r.code]).map((r) => PHRASES[r.code](r));
  let line;
  if (bad.length) line = `${grade}: ${bad.slice(0, 3).join(", ")}`;
  else {
    line = `${grade}: not on the OFAC SDN list${sc.published ? ` (published ${sc.published})` : ""}`;
    line += format === "evm" ? (reasons.some((r) => r.code === "NO_REPORTS") ? ", no scam or theft reports" : "") : `; scam reports not covered for ${FORMAT_NAMES[format]}`;
  }
  return line.length > 140 ? `${line.slice(0, 139)}…` : line;
}

export async function screenAddress({ address, format }, now = Date.now()) {
  const [sc, rep] = await Promise.all([
    sanctions(address, format),
    format === "evm" ? addressReputation(address).catch(() => null) : Promise.resolve(undefined),
  ]);
  if (!sc) throw new UpstreamError("Sanctions list unavailable; nothing charged, try again shortly");

  const reasons = [];
  const add = (code, severity, details) => reasons.push({ code, severity, ...(details ? { details } : {}) });
  if (sc.listed) {
    add("SANCTIONED_ADDRESS", "red", { list: "OFAC SDN", matches: sc.matches, published: sc.published ?? null, ...(flag(rep?.sanctioned) && { alsoFlaggedBy: ["goplus"] }) });
  }
  if (rep) {
    for (const f of RED_FLAGS) if (flag(rep[f]) && !(f === "sanctioned" && sc.listed)) add(f.toUpperCase(), "red", rep.data_source ? { reportedBy: rep.data_source } : undefined);
    for (const f of ORANGE_FLAGS) if (flag(rep[f])) add(f.toUpperCase(), "orange", rep.data_source ? { reportedBy: rep.data_source } : undefined);
  }
  if (!sc.listed) add("SANCTIONS_SCREENED", "info", { list: "OFAC SDN", listed: false, published: sc.published ?? null, ...(sc.addresses && { addressesOnList: sc.addresses }) });
  if (sc.stale) add("SANCTIONS_LIST_STALE", "info", { checkedAt: sc.checkedAt });
  if (rep === null) add("REPUTATION_UNAVAILABLE", "info");
  else if (rep === undefined) add("REPUTATION_NOT_COVERED", "info", { format });
  else if (!reasons.some((r) => r.severity !== "info")) add("NO_REPORTS", "info");

  const ORDER = { red: 0, orange: 1, info: 2 };
  reasons.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const { verdict, grade } = gradeOf(reasons);
  return {
    version: "1",
    verdict,
    grade,
    one_liner: screenOneLiner({ grade, reasons, sanctions: sc, format }),
    reasons,
    address: { address, format },
    sanctions: { list: "OFAC SDN", listed: sc.listed, matches: sc.matches, published: sc.published ?? null, source: sc.source },
    sources: [sc.source, ...(rep ? ["goplus"] : [])],
    checkedAt: new Date(now).toISOString(),
    disclaimer: "Exact match against the addresses OFAC publishes in the SDN list, plus GoPlus reports for EVM addresses. Not legal advice; it does not cover unlisted addresses of sanctioned persons or indirect exposure.",
  };
}

// ---------- routes ----------

// Mounted before the paywall, like /v1/approvals: an invalid query gets a 400 instead of a price; a bare
// probe goes on to the 402.
export function validateScreenQuery(req, res, next) {
  if (req.method !== "GET" || req.path !== "/v1/screen") return next();
  if (req.query?.address === undefined) return next();
  try {
    req.screenRequest = parseScreenRequest(req.query);
    next();
  } catch (err) {
    res.status(400).json({ error: "invalid_request", message: err.message, verdict: null });
  }
}

export function createScreenRouter() {
  const router = express.Router();
  router.get("/v1/screen", async (req, res) => {
    try {
      const result = await screenAddress(req.screenRequest ?? parseScreenRequest(req.query));
      res.set("Cache-Control", "no-store").json(result);
    } catch (err) {
      const status = err.status ?? 500;
      if (status >= 500) console.error("[screen]", err);
      res.status(status).json({
        error: status === 400 ? "invalid_request" : status === 503 ? "upstream_unavailable" : "internal_error",
        message: status === 500 ? "Internal error" : err.message,
        verdict: null,
      });
    }
  });
  return router;
}
