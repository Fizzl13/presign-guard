// Wallet approval audit: who can still move this wallet's tokens?
// GET /v1/approvals?chain=base|ethereum|...&address=0x...
//
// The follow-up to /v1/check: that one asks "should I sign this approval?", this
// one asks "which approvals did I already give, and which should I revoke?".
// Agents with their own wallet can run it as a periodic hygiene check.
//
// Source: GoPlus token_approval_security (free, public): every open ERC-20
// allowance of the wallet, with who the spender is.
//
// Rules per approval, the same spirit as /v1/check:
// - red: the spender is flagged malicious by GoPlus.
// - orange: the spender is a plain wallet (no contract), on the GoPlus doubt list,
//   an unverified contract, or holds an unlimited allowance without being on the
//   GoPlus trust list.
// - info: context (an unlimited allowance to a trust-list spender, an approval
//   older than a year, the approved token itself flagged).
// Every approval that is not info-only is listed to revoke. No approvals is green.
// NFT approvals are not covered: GoPlus has no NFT approval data for Base.

import express from "express";
import { isAddress } from "viem";
import { ValidationError, cached, goplus, flag } from "./presign-guard.js";
import { TOKEN_CHAINS, gradeOf } from "./token-verdict.js";

// The EVM chains of the token verdict: name → GoPlus chain id.
export const APPROVAL_CHAINS = Object.fromEntries(
  Object.entries(TOKEN_CHAINS).filter(([, c]) => c.chainId).map(([name, c]) => [name, c.chainId]),
);

export const STALE_APPROVAL_SECONDS = 365 * 86400;
export const MAX_LISTED = 100;
const UNLIMITED_AMOUNT = 1e30; // 2^255 and up; GoPlus may also write "Unlimited"

// ---------- input ----------

export function parseApprovalsRequest(query) {
  const chain = String(query?.chain ?? "").trim().toLowerCase();
  if (!APPROVAL_CHAINS[chain]) {
    throw new ValidationError(`chain must be one of: ${Object.keys(APPROVAL_CHAINS).join(", ")}`);
  }
  const raw = String(query?.address ?? "").trim();
  if (!isAddress(raw, { strict: false })) throw new ValidationError("address must be a 0x-prefixed wallet address");
  return { chain, address: raw.toLowerCase() };
}

// ---------- source ----------

function getApprovals(chainId, address) {
  return cached(`approvals:${chainId}:${address}`, async () => {
    const { result, partial } = await goplus(`/token_approval_security/${chainId}?addresses=${address}`, { version: "v2", emptyOk: true });
    return { items: Array.isArray(result) ? result : [], partial };
  }, 2 * 60 * 1000); // someone may have just revoked
}

// ---------- rules ----------

const ORDER = { red: 0, orange: 1, info: 2 };
const worst = (codes) => codes.reduce((w, c) => (ORDER[c.severity] < ORDER[w] ? c.severity : w), "info");

export function isUnlimited(amount) {
  if (/unlimited/i.test(String(amount))) return true;
  const n = Number(amount);
  return Number.isFinite(n) ? n >= UNLIMITED_AMOUNT : String(amount).replace(/\D/g, "").length > 30;
}

// One allowance: what it is and what is wrong with it.
export function assessApproval(item, approval, now = Date.now()) {
  const info = approval?.address_info ?? {};
  const codes = [];
  const add = (code, severity, details) => codes.push({ code, severity, ...(details ? { details } : {}) });
  const unlimited = isUnlimited(approval?.approved_amount);
  const trusted = flag(info.trust_list);
  const behaviors = Array.isArray(info.malicious_behavior) ? info.malicious_behavior.filter(Boolean) : [];

  if (behaviors.length) add("SPENDER_MALICIOUS", "red", { behaviors: behaviors.slice(0, 5) });
  if (flag(info.doubt_list)) add("SPENDER_SUSPICIOUS", "orange");
  if (info.is_contract !== undefined && info.is_contract !== null && !flag(info.is_contract)) add("APPROVAL_TO_WALLET", "orange");
  else if (flag(info.is_contract) && info.is_open_source !== undefined && info.is_open_source !== null && !flag(info.is_open_source)) add("SPENDER_UNVERIFIED", "orange");
  if (unlimited) add(trusted ? "UNLIMITED_APPROVAL_TRUSTED" : "UNLIMITED_APPROVAL", trusted ? "info" : "orange");
  const at = Number(approval?.approved_time);
  if (Number.isFinite(at) && at > 0 && now / 1000 - at > STALE_APPROVAL_SECONDS) add("STALE_APPROVAL", "info");
  if (flag(item?.malicious_address)) add("TOKEN_FLAGGED", "info");

  const severity = worst(codes);
  return {
    token: { address: String(item?.token_address ?? "").toLowerCase(), symbol: item?.token_symbol ?? null, name: item?.token_name ?? null },
    spender: {
      address: String(approval?.approved_contract ?? "").toLowerCase(),
      name: info.contract_name || info.tag || null,
      trusted,
      contract: info.is_contract === undefined || info.is_contract === null ? null : flag(info.is_contract),
    },
    amount: unlimited ? "unlimited" : String(approval?.approved_amount ?? ""),
    unlimited,
    approvedAt: Number.isFinite(at) && at > 0 ? new Date(at * 1000).toISOString() : null,
    severity,
    codes,
    revoke: severity !== "info",
  };
}

// Wallet-level reasons: one per code, with how many approvals it hit.
function walletReasons(approvals) {
  const byCode = new Map();
  for (const a of approvals) {
    for (const c of a.codes) {
      const r = byCode.get(c.code) ?? { code: c.code, severity: c.severity, details: { count: 0, spenders: [] } };
      r.details.count += 1;
      if (r.details.spenders.length < 5 && !r.details.spenders.includes(a.spender.address)) r.details.spenders.push(a.spender.address);
      byCode.set(c.code, r);
    }
  }
  const reasons = [...byCode.values()];
  if (!approvals.length) reasons.push({ code: "NO_APPROVALS", severity: "info" });
  return reasons.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

const PHRASES = {
  SPENDER_MALICIOUS: (n) => `${n} to a flagged address`,
  APPROVAL_TO_WALLET: (n) => `${n} to a plain wallet`,
  SPENDER_SUSPICIOUS: (n) => `${n} to a suspicious spender`,
  SPENDER_UNVERIFIED: (n) => `${n} to an unverified contract`,
  UNLIMITED_APPROVAL: (n) => `${n} unlimited`,
};
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

export function approvalsOneLiner({ grade, chain, reasons, total, toRevoke }) {
  if (!total) return `${grade}: no open token approvals on ${chain}`;
  const order = Object.keys(PHRASES); // most serious kind first, whatever order GoPlus lists them in
  const phrases = reasons.filter((r) => PHRASES[r.code])
    .sort((a, b) => order.indexOf(a.code) - order.indexOf(b.code))
    .map((r) => PHRASES[r.code](r.details.count));
  let line = `${grade}: ${plural(total, "approval")}`;
  line += phrases.length ? `, ${phrases.slice(0, 3).join(", ")}; revoke ${toRevoke}` : ", none risky";
  return line.length > 140 ? `${line.slice(0, 139)}…` : line;
}

export async function walletApprovals({ chain, address }, now = Date.now()) {
  const chainId = APPROVAL_CHAINS[chain];
  const { items, partial } = await getApprovals(chainId, address);
  const approvals = items.flatMap((item) => (Array.isArray(item?.approved_list) ? item.approved_list : []).map((a) => assessApproval(item, a, now)));
  approvals.sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || Number(b.unlimited) - Number(a.unlimited));
  const reasons = walletReasons(approvals);
  const { verdict, grade } = gradeOf(reasons);
  const toRevoke = approvals.filter((a) => a.revoke).length;
  return {
    version: "1",
    verdict,
    grade,
    one_liner: approvalsOneLiner({ grade, chain, reasons, total: approvals.length, toRevoke }),
    reasons,
    wallet: { chain, address },
    summary: {
      approvals: approvals.length,
      tokens: new Set(approvals.map((a) => a.token.address)).size,
      unlimited: approvals.filter((a) => a.unlimited).length,
      toRevoke,
      ...(approvals.length > MAX_LISTED && { listed: MAX_LISTED }),
    },
    approvals: approvals.slice(0, MAX_LISTED),
    revokeUrl: `https://revoke.cash/address/${address}?chainId=${chainId}`,
    ...(partial && { partial: true }),
    sources: ["goplus"],
    checkedAt: new Date(now).toISOString(),
    disclaimer: "Automated check of open ERC-20 allowances, not a guarantee. Green means no known risky approvals; NFT approvals are not covered.",
  };
}

// ---------- routes ----------

// Mounted before the paywall, like /v1/token: an invalid query gets a 400
// instead of a price; a bare probe goes on to the 402.
export function validateApprovalsQuery(req, res, next) {
  if (req.method !== "GET" || req.path !== "/v1/approvals") return next();
  if (req.query?.chain === undefined && req.query?.address === undefined) return next();
  try {
    req.approvalsRequest = parseApprovalsRequest(req.query);
    next();
  } catch (err) {
    res.status(400).json({ error: "invalid_request", message: err.message, verdict: null });
  }
}

export function createApprovalsRouter() {
  const router = express.Router();
  router.get("/v1/approvals", async (req, res) => {
    try {
      const result = await walletApprovals(req.approvalsRequest ?? parseApprovalsRequest(req.query));
      res.set("Cache-Control", "no-store").json(result);
    } catch (err) {
      const status = err.status ?? 500;
      if (status >= 500) console.error("[approvals]", err);
      res.status(status).json({
        error: status === 400 ? "invalid_request" : status === 503 ? "upstream_unavailable" : "internal_error",
        message: status === 500 ? "Internal error" : err.message,
        verdict: null,
      });
    }
  });
  return router;
}
