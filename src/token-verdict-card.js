// POST /v1/token/verdict: the token verdict for agents that want one answer to act on.
//
// Body: { "tokenAddress": "0x…" | "<mint>" | "CURRENCY.rIssuer" | "<asset id>", "chain"?: "base" (default) | any chain
// of GET /v1/token, "requestKey"?: "…" (echoed back) }. Synchronous: no operation id, no polling.
//
// The answer is the GET /v1/token answer (src/token-verdict.js, the same code), plus:
// - decision: buy | small_only | do_not_buy, from the grade (SAFE, CAUTION, RISKY or AVOID); null without a verdict.
// - take: one or two plain sentences for someone about to buy, built from the reasons and market data (no LLM).
// - sell_check: can a holder sell it back (src/sell-check.js), on Base with a simulated sell transfer.
// - share: { url, image_url, png_url }, a stateless signed link to a page and a card, SVG and PNG (src/token-share.js); null when the
//   service has no receipt signer.
// Same price, credits and payment networks as GET /v1/token, and the same rule: an invalid body (400) or a data source
// that is down (503) is answered with verdict null and nothing is charged.

import express from "express";
import { randomUUID } from "node:crypto";
import { ValidationError } from "./presign-guard.js";
import { parseTokenRequest, tokenVerdict, reasonPhrase, formatUsd, formatAge } from "./token-verdict.js";
import { sellCheck } from "./sell-check.js";
import { sharePayload, signShare, shareLinks } from "./token-share.js";

export const TOKEN_VERDICT_PATH = "/v1/token/verdict";
const MAX_REQUEST_KEY = 128;

export const DECISIONS = { SAFE: "buy", CAUTION: "small_only", RISKY: "do_not_buy", AVOID: "do_not_buy" };
export const decisionOf = (grade) => DECISIONS[grade] ?? null;

export function parseVerdictBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new ValidationError('send a JSON body: { "tokenAddress": "0x…", "chain": "base" }');
  const { tokenAddress, chain = "base", requestKey } = body;
  if (typeof tokenAddress !== "string" || !tokenAddress.trim()) throw new ValidationError("tokenAddress is required: an EVM token contract (0x…), a Solana mint, an XRPL CURRENCY.rIssuer or an Algorand asset id");
  if (typeof chain !== "string") throw new ValidationError("chain must be a string, e.g. base or solana");
  if (requestKey !== undefined && (typeof requestKey !== "string" || requestKey.length > MAX_REQUEST_KEY)) throw new ValidationError(`requestKey must be a string of at most ${MAX_REQUEST_KEY} characters`);
  return { ...parseTokenRequest({ chain, address: tokenAddress }), ...(requestKey !== undefined && { requestKey }) };
}

const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);

// One or two sentences: what was found, then what it means for a buyer. Deterministic, from the reasons, the market
// data and the sell check.
export function takeOf(verdict, sell = null) {
  if (!verdict?.grade) return null;
  const serious = verdict.reasons.filter((r) => r.severity !== "info");
  const red = serious.filter((r) => r.severity === "red");
  const m = verdict.market;
  // DexScreener undercounts the liquidity of quote assets (USDC, WETH), so a trusted token's take leaves it out, as the one-liner does.
  const trusted = verdict.reasons.some((r) => ["TOKEN_ON_TRUST_LIST", "KNOWN_STABLECOIN", "ISSUER_IS_RIPPLE"].includes(r.code));
  const facts = m && !trusted ? [Number.isFinite(m.liquidityUsd) && `${formatUsd(m.liquidityUsd)} liquidity`, Number.isFinite(m.ageSeconds) && `${formatAge(m.ageSeconds)} old`].filter(Boolean) : [];
  const sellBlocked = sell?.can_sell === "no";
  const simulated = sell?.checks?.find((c) => c.check === "simulated_sell");
  const simulatedFail = simulated?.result === "fail";
  const simulatedTax = simulated?.value ?? 0;
  switch (verdict.grade) {
    case "SAFE":
      if (simulatedFail) return "No known red flags in the data, but a simulated sell transfer into its pool failed. Don't buy until you know why.";
      if (simulatedTax >= 10) return `No known red flags in the data, but a simulated sell lost ${simulatedTax}% on the way to the pool. Count on getting that much less back when you sell.`;
      return `No known red flags${facts.length ? ` (${facts.join(", ")})` : ""}. Nothing found that should stop a buy, but this says nothing about where the price goes.`;
    case "CAUTION":
      return `One warning: ${reasonPhrase(serious[0])}. If you buy, keep it to an amount you can afford to lose.`;
    case "RISKY":
      return `${serious.length} warnings, including ${reasonPhrase(serious[0])} and ${reasonPhrase(serious[1])}. Don't buy unless you know why each of these is fine.`;
    default: // AVOID
      return `${cap(reasonPhrase(red[0] ?? serious[0]))}${red.length > 1 ? `, and ${red.length - 1} more red flag${red.length > 2 ? "s" : ""}` : ""}. ${sellBlocked ? "Don't buy: you may not be able to sell it." : "Don't buy it."}`;
  }
}

// Mounted before the paywall, as GET /v1/token's validateTokenQuery: an invalid body gets a 400 instead of a price.
// An empty body (no tokenAddress, chain or requestKey) is how catalogues probe an endpoint: it gets the 402.
const json = express.json({ limit: "4kb" });
export function validateTokenVerdictBody(req, res, next) {
  if (req.method !== "POST" || req.path !== TOKEN_VERDICT_PATH) return next();
  json(req, res, (err) => {
    if (err) return res.status(400).json({ error: "invalid_request", message: "the body is not valid JSON", verdict: null });
    const b = req.body;
    if (b === undefined || (b && typeof b === "object" && !Array.isArray(b) && b.tokenAddress === undefined && b.chain === undefined && b.requestKey === undefined)) return next();
    try {
      req.tokenVerdictRequest = parseVerdictBody(b);
      next();
    } catch (e) {
      res.status(400).json({ error: "invalid_request", message: e.message, verdict: null });
    }
  });
}

export function createTokenVerdictRouter({ signer = null, publicUrl, verdict = tokenVerdict, sell = sellCheck } = {}) {
  const router = express.Router();
  router.post(TOKEN_VERDICT_PATH, express.json({ limit: "4kb" }), async (req, res) => {
    try {
      const { requestKey, ...request } = req.tokenVerdictRequest ?? parseVerdictBody(req.body);
      const result = await verdict(request);
      const sellResult = await sell(request, result).catch((err) => {
        console.warn(`[token-verdict-card] sell check failed: ${err.message}`);
        return { can_sell: "unknown", simulated: false, checks: [], sources: [], note: "The sell check could not run; nothing about selling is known." };
      });
      const { version, verdict: v, grade, one_liner: oneLiner, ...rest } = result;
      const answer = { version, verdict: v, grade, decision: decisionOf(grade), take: takeOf(result, sellResult), one_liner: oneLiner, ...rest, sell_check: sellResult };
      let share = null;
      if (signer) {
        // The receipt signed onto this answer gets the same request id (src/receipt.js), so the link names it.
        const requestId = randomUUID();
        res.locals.receiptRequestId = requestId;
        share = await signShare(signer, sharePayload(answer, requestId)).then((token) => shareLinks(publicUrl, token), (err) => {
          console.warn(`[token-verdict-card] share link not signed: ${err.message}`);
          return null;
        });
      }
      res.set("Cache-Control", "no-store").json({ ...answer, share, ...(requestKey !== undefined && { requestKey }) });
    } catch (err) {
      const status = err.status ?? 500;
      if (status >= 500) console.error("[token-verdict-card]", err);
      res.status(status).json({
        error: status === 400 ? "invalid_request" : status === 503 ? "upstream_unavailable" : "internal_error",
        message: status === 500 ? "Internal error" : err.message,
        verdict: null,
        ...(typeof req.body?.requestKey === "string" && req.body.requestKey.length <= MAX_REQUEST_KEY && { requestKey: req.body.requestKey }),
      });
    }
  });
  return router;
}
