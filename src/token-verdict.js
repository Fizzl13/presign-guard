// Token verdict: is this token safe to buy, hold or accept as payment?
// GET /v1/token?chain=solana|base|ethereum|...&address=...
//
// Sources, all free and public:
// - GoPlus token security (EVM and Solana): authorities, honeypot, tax, holders.
// - RugCheck (Solana only, optional): LP lock, rugged flag, its own risk list.
// - DexScreener: price, liquidity, market cap, volume and the age of the first pair.
//
// Verdict rules, the same spirit as /v1/check:
// - red: the token itself is a trap (honeypot, rugged, impersonation, can't be transferred).
// - orange: someone can still mint, freeze or change balances, or the market is thin,
//   new or held by a few wallets.
// - info: context that doesn't change the verdict.
// Missing data never makes a token red. If GoPlus or DexScreener is down, there is no
// verdict (503, nothing charged); RugCheck being down is reported and skipped.

import express from "express";
import { isAddress } from "viem";
import {
  ValidationError, UpstreamError, cached, goplus, flag, getTokenSecurity, tokenReasons,
} from "./presign-guard.js";

const DEXSCREENER_BASE = "https://api.dexscreener.com";
const RUGCHECK_BASE = "https://api.rugcheck.xyz/v1";
const FETCH_TIMEOUT_MS = 4000;
const MARKET_TTL_MS = 2 * 60 * 1000;   // prices move; security data keeps the default 10 minutes

// chain name → GoPlus chain id (EVM) and DexScreener chain id.
export const TOKEN_CHAINS = {
  solana: { dexscreener: "solana" },
  base: { chainId: 8453, dexscreener: "base" },
  ethereum: { chainId: 1, dexscreener: "ethereum" },
  arbitrum: { chainId: 42161, dexscreener: "arbitrum" },
  optimism: { chainId: 10, dexscreener: "optimism" },
  polygon: { chainId: 137, dexscreener: "polygon" },
  bsc: { chainId: 56, dexscreener: "bsc" },
};

export const LOW_LIQUIDITY_USD = 50_000;
export const NEW_TOKEN_SECONDS = 24 * 3600;
export const YOUNG_TOKEN_SECONDS = 30 * 86400; // unlocked LP matters most in the first month
export const LP_LOCKED_MIN_PCT = 50;
export const TOP_HOLDER_MAX_PCT = 20;
export const TOP10_MAX_PCT = 50;
export const HIGH_TRANSFER_FEE_PCT = 10;

// Addresses that hold burnt supply, not a person.
const BURN = new Set([
  "0x0000000000000000000000000000000000000000",
  "0x000000000000000000000000000000000000dead",
  "1nc1nerator11111111111111111111111111111111",
]);

const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

// ---------- input ----------

export function parseTokenRequest(query) {
  const chain = String(query?.chain ?? "").trim().toLowerCase();
  if (!TOKEN_CHAINS[chain]) {
    throw new ValidationError(`chain must be one of: ${Object.keys(TOKEN_CHAINS).join(", ")}`);
  }
  const raw = String(query?.address ?? "").trim();
  if (chain === "solana") {
    if (!SOLANA_ADDRESS.test(raw)) throw new ValidationError("address must be a Solana mint address (base58)");
    return { chain, address: raw };
  }
  if (!isAddress(raw, { strict: false })) throw new ValidationError("address must be a 0x-prefixed token contract address");
  return { chain, address: raw.toLowerCase() };
}

// ---------- sources ----------

async function getJson(url, source, { notFoundOk = false } = {}) {
  let res;
  try {
    res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new UpstreamError(`${source} unreachable (${err.name})`);
  }
  if (notFoundOk && res.status === 404) return null;
  if (!res.ok) throw new UpstreamError(`${source} HTTP ${res.status}`);
  const body = await res.json().catch(() => undefined);
  if (body === undefined) throw new UpstreamError(`${source} returned no JSON`);
  return body;
}

function getMarket(chain, address) {
  return cached(`dex:${chain}:${address}`, async () => {
    const body = await getJson(`${DEXSCREENER_BASE}/tokens/v1/${TOKEN_CHAINS[chain].dexscreener}/${address}`, "DexScreener");
    return Array.isArray(body) ? body : Array.isArray(body?.pairs) ? body.pairs : [];
  }, MARKET_TTL_MS);
}

function getSolanaSecurity(mint) {
  return cached(`sol-token:${mint}`, async () => {
    const { result, partial } = await goplus(`/solana/token_security?contract_addresses=${mint}`);
    const data = result?.[mint];
    return { data: data && typeof data === "object" && Object.keys(data).length ? data : null, partial };
  });
}

// Optional: null when RugCheck doesn't know the mint, { error } when it is down.
async function getRugcheck(mint) {
  try {
    return await cached(`rugcheck:${mint}`, () => getJson(`${RUGCHECK_BASE}/tokens/${mint}/report`, "RugCheck", { notFoundOk: true }));
  } catch (err) {
    return { error: err.message };
  }
}

// ---------- market data ----------

const num = (v) => (v === null || v === undefined || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const sameAddress = (a, b, chain) => (chain === "solana" ? a === b : String(a).toLowerCase() === b);

export function summarizeMarket(pairs, chain, address, now = Date.now()) {
  if (!pairs.length) return null;
  const liquidity = (p) => num(p?.liquidity?.usd) ?? 0;
  const sorted = [...pairs].sort((a, b) => liquidity(b) - liquidity(a));
  // Price and market cap from the deepest pair where this token is the base token.
  const main = sorted.find((p) => sameAddress(p?.baseToken?.address, address, chain)) ?? sorted[0];
  const created = pairs.map((p) => num(p?.pairCreatedAt)).filter((t) => t && t > 0);
  const firstPairAt = created.length ? Math.min(...created) : null;
  const info = pairs.find((p) => p?.info)?.info ?? {};
  const isBase = sameAddress(main?.baseToken?.address, address, chain);
  const token = isBase ? main.baseToken : main?.quoteToken;
  return {
    name: token?.name ?? null,
    symbol: token?.symbol ?? null,
    priceUsd: isBase ? num(main.priceUsd) : null,
    liquidityUsd: Math.round(pairs.reduce((s, p) => s + liquidity(p), 0)),
    marketCapUsd: isBase ? num(main.marketCap) ?? num(main.fdv) : null,
    volume24hUsd: Math.round(pairs.reduce((s, p) => s + (num(p?.volume?.h24) ?? 0), 0)),
    pairs: pairs.length,
    firstPairAt: firstPairAt ? new Date(firstPairAt).toISOString() : null,
    ageSeconds: firstPairAt ? Math.max(0, Math.floor((now - firstPairAt) / 1000)) : null,
    dex: main?.dexId ?? null,
    url: main?.url ?? null,
    socials: (info.socials?.length ?? 0) + (info.websites?.length ?? 0),
  };
}

// ---------- holders ----------

const pct1 = (x) => Math.round(x * 10) / 10;

// holders: [{ address, pct, excluded }] where pct is a percent of supply.
function concentration(holders) {
  const counted = holders.filter((h) => !h.excluded && !BURN.has(h.address) && Number.isFinite(h.pct));
  if (!counted.length) return null;
  const sorted = counted.map((h) => h.pct).sort((a, b) => b - a);
  return { top1Pct: pct1(sorted[0]), top10Pct: pct1(sorted.slice(0, 10).reduce((s, p) => s + p, 0)) };
}

// ---------- rules ----------

function reasonCollector() {
  const reasons = [];
  const add = (code, severity, details) => {
    if (reasons.some((r) => r.code === code)) return;
    reasons.push({ code, severity, ...(details ? { details } : {}) });
  };
  return { reasons, add };
}

// trusted: on the GoPlus trust list. DexScreener mostly returns the pairs where a token
// is the base token, so the liquidity of a quote asset (USDC, WETH) looks far too low.
function marketReasons(market, add, { lpLockedPct, trusted = false } = {}) {
  if (!market) { add("NO_DEX_MARKET", trusted ? "info" : "orange"); return; }
  if (market.liquidityUsd < LOW_LIQUIDITY_USD) add("LOW_LIQUIDITY", trusted ? "info" : "orange", { liquidityUsd: market.liquidityUsd });
  if (market.ageSeconds !== null && market.ageSeconds < NEW_TOKEN_SECONDS) add("NEW_TOKEN", "orange", { ageSeconds: market.ageSeconds });
  if (lpLockedPct !== null && lpLockedPct !== undefined && lpLockedPct < LP_LOCKED_MIN_PCT) {
    // Concentrated-liquidity pools have no LP token to lock, so only a young token is flagged.
    const young = market.ageSeconds === null || market.ageSeconds < YOUNG_TOKEN_SECONDS;
    add("LP_NOT_LOCKED", young && !trusted ? "orange" : "info", { lpLockedPct: pct1(lpLockedPct) });
  }
  if (!market.socials) add("NO_SOCIALS", "info");
}

function holderReasons(c, add) {
  if (!c) return;
  if (c.top1Pct > TOP_HOLDER_MAX_PCT || c.top10Pct > TOP10_MAX_PCT) add("TOP_HOLDERS_CONCENTRATED", "orange", c);
}

const statusOn = (v) => v && typeof v === "object" && flag(v.status);

function solanaReasons({ sec, rug, market }, add) {
  const trusted = flag(sec?.trusted_token);
  if (!sec) add("NO_SECURITY_DATA", "info");

  if (rug?.rugged === true) add("RUGGED", "red");
  if (sec) {
    if (statusOn(sec.non_transferable)) add("NON_TRANSFERABLE", "red");
    const authorities = [
      ...(sec.metadata_mutable?.metadata_upgrade_authority ?? []),
      ...(sec.balance_mutable_authority?.authority ?? []),
      ...(sec.creators ?? []),
    ];
    if (authorities.some((a) => flag(a?.malicious_address))) add("MALICIOUS_AUTHORITY", "red");

    // A trusted issuer (USDC, USDT) keeps these powers on purpose: context, not a warning.
    const power = trusted ? "info" : "orange";
    if (statusOn(sec.mintable)) add("MINT_AUTHORITY_ACTIVE", power);
    if (statusOn(sec.freezable)) add("FREEZE_AUTHORITY_ACTIVE", power);
    if (statusOn(sec.balance_mutable_authority)) add("BALANCE_MUTABLE", power);
    if (statusOn(sec.closable)) add("CLOSABLE", power);
    if (statusOn(sec.transfer_hook_upgradable) || (Array.isArray(sec.transfer_hook) && sec.transfer_hook.length)) add("TRANSFER_HOOK", power);
    if (statusOn(sec.default_account_state_upgradable)) add("DEFAULT_STATE_UPGRADABLE", "info");

    const feePct = transferFeePct(sec, rug);
    if (feePct >= HIGH_TRANSFER_FEE_PCT) add("HIGH_TRANSFER_FEE", "orange", { feePct });
    else if (feePct > 0) add("TRANSFER_FEE", "orange", { feePct });
    if (statusOn(sec.transfer_fee_upgradable)) add("TRANSFER_FEE_UPGRADABLE", power);
    if (statusOn(sec.metadata_mutable)) add("MUTABLE_METADATA", "info");
    if (trusted) add("TOKEN_ON_TRUST_LIST", "info");
  }

  const lpLockedPct = rug && !rug.error ? lpLocked(rug) : null;
  marketReasons(market, add, { lpLockedPct, trusted });
  holderReasons(solanaHolders(sec, rug), add);

  if (rug?.error) add("RUGCHECK_UNAVAILABLE", "info", { message: rug.error });
  const danger = (rug?.risks ?? []).filter((r) => r?.level === "danger").map((r) => r.name).filter(Boolean);
  if (danger.length) add("RUGCHECK_DANGER", "info", { risks: danger.slice(0, 5) });
}

function transferFeePct(sec, rug) {
  const rate = num(sec?.transfer_fee?.current_fee_rate?.fee_rate); // a fraction: "0.01" = 1%
  if (rate !== null) return pct1(rate * 100);
  const rugPct = num(rug?.transferFee?.pct);
  return rugPct ?? 0;
}

function lpLocked(rug) {
  if (num(rug.lpLockedPct) !== null) return num(rug.lpLockedPct);
  const values = (rug.markets ?? []).map((m) => num(m?.lp?.lpLockedPct)).filter((v) => v !== null);
  return values.length ? Math.max(...values) : null;
}

// GoPlus first (it tags pool and locked accounts); RugCheck's list otherwise.
function solanaHolders(sec, rug) {
  if (Array.isArray(sec?.holders) && sec.holders.length) {
    return concentration(sec.holders.map((h) => ({
      address: h.account, pct: num(h.percent) * 100, excluded: flag(h.is_locked) || Boolean(h.tag),
    })));
  }
  if (Array.isArray(rug?.topHolders) && rug.topHolders.length) {
    const pools = new Set((rug.markets ?? []).flatMap((m) => [m?.liquidityA, m?.liquidityB, m?.pubkey]).filter(Boolean));
    return concentration(rug.topHolders.map((h) => ({
      address: h.address ?? h.owner, pct: num(h.pct), excluded: pools.has(h.address) || pools.has(h.owner),
    })));
  }
  return null;
}

function evmReasons({ sec, market }, add) {
  // The same GoPlus rules as the token part of /v1/check, without a subject. On a
  // trust-list token (USDT, USDC) the issuer's powers are context, as on Solana.
  const trusted = flag(sec?.trust_list);
  tokenReasons(null, sec, (code, severity, _subject, details) => add(code, trusted && severity === "orange" ? "info" : severity, details));
  if (flag(sec?.cannot_buy)) add("TOKEN_CANNOT_BUY", "orange");
  const lp = Array.isArray(sec?.lp_holders) ? sec.lp_holders : [];
  const lpLockedPct = lp.length
    ? lp.filter((h) => flag(h.is_locked) || BURN.has(String(h.address).toLowerCase())).reduce((s, h) => s + (num(h.percent) ?? 0) * 100, 0)
    : null;
  marketReasons(market, add, { lpLockedPct, trusted });
  // Wallets only: the big contract holders of an EVM token are pools, lockers,
  // staking, vesting and bridges (veAERO holds half of AERO).
  if (Array.isArray(sec?.holders)) {
    const lpAddresses = new Set(lp.map((h) => String(h.address).toLowerCase()));
    const pairs = new Set((sec.dex ?? []).map((d) => String(d.pair).toLowerCase()));
    holderReasons(concentration(sec.holders.map((h) => {
      const address = String(h.address).toLowerCase();
      return { address, pct: num(h.percent) * 100, excluded: flag(h.is_locked) || flag(h.is_contract) || pairs.has(address) || lpAddresses.has(address) };
    })), add);
  }
}

// ---------- verdict ----------

export function gradeOf(reasons) {
  if (reasons.some((r) => r.severity === "red")) return { verdict: "red", grade: "AVOID" };
  const orange = reasons.filter((r) => r.severity === "orange").length;
  if (orange >= 2) return { verdict: "orange", grade: "RISKY" };
  if (orange === 1) return { verdict: "orange", grade: "CAUTION" };
  return { verdict: "green", grade: "SAFE" };
}

const usd = (v) => (v >= 1e9 ? `$${(v / 1e9).toFixed(1)}B` : v >= 1e6 ? `$${(v / 1e6).toFixed(1)}M` : v >= 1e3 ? `$${Math.round(v / 1e3)}k` : `$${Math.round(v)}`);
const age = (s) => (s < 3600 ? `${Math.max(1, Math.round(s / 60))} min` : s < 86400 ? `${Math.round(s / 3600)} h` : s < 365 * 86400 ? `${Math.round(s / 86400)} days` : `${(s / (365 * 86400)).toFixed(1)} years`);

// Short factual phrases, most serious first.
const PHRASES = {
  RUGGED: () => "marked rugged by RugCheck",
  TOKEN_HONEYPOT: () => "honeypot: can't be sold",
  TOKEN_AIRDROP_SCAM: () => "airdrop scam",
  TOKEN_IMPERSONATION: () => "imitates another token",
  NON_TRANSFERABLE: () => "can't be transferred",
  MALICIOUS_AUTHORITY: () => "authority address flagged malicious",
  MINT_AUTHORITY_ACTIVE: () => "supply can still be minted",
  FREEZE_AUTHORITY_ACTIVE: () => "holders can be frozen",
  BALANCE_MUTABLE: () => "balances can be changed",
  TOKEN_OWNER_CAN_CHANGE_BALANCES: () => "owner can change balances",
  HIGH_TRANSFER_FEE: (d) => `${d.feePct}% transfer fee`,
  TRANSFER_FEE: (d) => `${d.feePct}% transfer fee`,
  TOKEN_HIGH_TAX: (d) => `${pct1(Math.max(d.buyTax, d.sellTax) * 100)}% tax`,
  LP_NOT_LOCKED: (d) => `only ${d.lpLockedPct}% of LP locked`,
  LOW_LIQUIDITY: (d) => `${usd(d.liquidityUsd)} liquidity`,
  NO_DEX_MARKET: () => "no DEX market found",
  NEW_TOKEN: (d) => `${age(d.ageSeconds)} old`,
  TOP_HOLDERS_CONCENTRATED: (d) => `top holder ${d.top1Pct}%, top 10 ${d.top10Pct}%`,
};

export function oneLiner({ grade, reasons, market }) {
  const serious = reasons.filter((r) => r.severity !== "info");
  const phrases = serious.map((r) => PHRASES[r.code]?.(r.details ?? {}) ?? r.code.toLowerCase().replace(/_/g, " "));
  if (!phrases.length && reasons.some((r) => r.code === "TOKEN_ON_TRUST_LIST")) {
    // DexScreener's liquidity and age undercount quote assets (USDT showed $863): leave them out.
    phrases.push("no red flags, on the GoPlus trust list");
  } else if (!phrases.length) {
    const facts = market ? [`${usd(market.liquidityUsd)} liquidity`, market.ageSeconds !== null && `${age(market.ageSeconds)} old`].filter(Boolean) : [];
    phrases.push(["no red flags", ...facts].join(", "));
  }
  let line = `${grade}: ${phrases.slice(0, 3).join("; ")}`;
  if (phrases.length > 3) line += ` (+${phrases.length - 3} more)`;
  return line.length > 140 ? `${line.slice(0, 139)}…` : line;
}

export async function tokenVerdict({ chain, address }, now = Date.now()) {
  const { reasons, add } = reasonCollector();
  const sources = ["goplus", "dexscreener"];
  let partial = false;
  let market;

  if (chain === "solana") {
    const [sec, rug, pairs] = await Promise.all([getSolanaSecurity(address), getRugcheck(address), getMarket(chain, address)]);
    market = summarizeMarket(pairs, chain, address, now);
    partial = sec.partial;
    if (rug && !rug.error) sources.push("rugcheck");
    solanaReasons({ sec: sec.data, rug, market }, add);
  } else {
    const [sec, pairs] = await Promise.all([getTokenSecurity(TOKEN_CHAINS[chain].chainId, address), getMarket(chain, address)]);
    market = summarizeMarket(pairs, chain, address, now);
    partial = sec.partial;
    evmReasons({ sec: sec.data, market }, add);
  }

  const order = { red: 0, orange: 1, info: 2 };
  reasons.sort((a, b) => order[a.severity] - order[b.severity]);
  const { verdict, grade } = gradeOf(reasons);
  return {
    version: "1",
    verdict,
    grade,
    one_liner: oneLiner({ grade, reasons, market }),
    reasons,
    token: { chain, address, name: market?.name ?? null, symbol: market?.symbol ?? null },
    market,
    ...(partial && { partial: true }),
    sources,
    checkedAt: new Date(now).toISOString(),
    disclaimer: "Automated on-chain and market checks, not financial advice. Green means no known red flags, not that the token will hold its value.",
  };
}

// ---------- routes ----------

// Mounted before the paywall: an invalid query gets a 400 instead of a price.
// A bare /v1/token (no chain, no address) is how catalogues and health monitors
// probe an x402 endpoint: it goes on to the paywall and gets the 402 challenge.
// Paying without a query still ends in a 400, and a 400 is never settled.
export function validateTokenQuery(req, res, next) {
  if (req.method !== "GET" || req.path !== "/v1/token") return next();
  if (req.query?.chain === undefined && req.query?.address === undefined) return next();
  try {
    req.tokenRequest = parseTokenRequest(req.query);
    next();
  } catch (err) {
    res.status(400).json({ error: "invalid_request", message: err.message, verdict: null });
  }
}

export function createTokenRouter() {
  const router = express.Router();
  router.get("/v1/token", async (req, res) => {
    try {
      const result = await tokenVerdict(req.tokenRequest ?? parseTokenRequest(req.query));
      res.set("Cache-Control", "no-store").json(result);
    } catch (err) {
      const status = err.status ?? 500;
      if (status >= 500) console.error("[token-verdict]", err);
      res.status(status).json({
        error: status === 400 ? "invalid_request" : status === 503 ? "upstream_unavailable" : "internal_error",
        message: status === 500 ? "Internal error" : err.message,
        verdict: null,
      });
    }
  });
  return router;
}
