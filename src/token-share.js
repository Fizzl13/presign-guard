// Share links for POST /v1/token/verdict: a page and a 1200x630 card for one token verdict, stateless.
//
// The link carries the verdict itself: a compact payload (chain, address, name, symbol, verdict, grade, decision,
// take, the top reason codes, a few market numbers, checked_at and the receipt's request_id) as base64url canonical
// JSON (src/receipt.js, the same canonicalisation as the receipts), a dot, and presign-guard's receipt signer's
// EIP-191 personal_sign over SHARE_PREFIX + that JSON, also base64url. The server stores nothing: every request
// recovers the signer and renders only when it is one of presign-guard's signers; anything else is a 400.
//
//   GET /v/token/<payload>.<signature>            an HTML page (no scripts, OG/Twitter tags pointing at the card)
//   GET /v/token/<payload>.<signature>/card.svg   the card
//
// Names and symbols come from DexScreener and so from whoever launched the token: every string is escaped.

import express from "express";
import { recoverMessageAddress } from "viem";
import { canonicalJson } from "./receipt.js";
import { formatUsd, formatAge } from "./token-verdict.js";

export const SHARE_PREFIX = "presign-guard token share v1\n";
export const SHARE_PATH = "/v/token";
export const MAX_SHARE_CHARS = 2400; // the whole <payload>.<signature> part of the link
const MAX_TAKE = 320;

const DECISION_LABEL = { buy: "No red flags found", small_only: "Small amount only", do_not_buy: "Do not buy" };
const COLOR = { green: "#15803d", orange: "#c2410c", red: "#b91c1c" };
const GREY = "#4b5563";

const clip = (s, n) => (typeof s === "string" && s ? (s.length > n ? `${s.slice(0, n - 1)}…` : s) : null);
const finite = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);

// The payload of a POST /v1/token/verdict answer. Undefined and null members are left out (canonicalJson drops
// undefined), so the link stays short.
export function sharePayload(answer, requestId) {
  const m = answer.market ?? null;
  const serious = (answer.reasons ?? []).filter((r) => r.severity !== "info");
  const market = m ? Object.fromEntries(Object.entries({
    price: finite(m.priceUsd), liquidity: finite(m.liquidityUsd), mcap: finite(m.marketCapUsd), vol24h: finite(m.volume24hUsd), age_s: finite(m.ageSeconds),
  }).filter(([, v]) => v !== null)) : null;
  const t = answer.token ?? {};
  return {
    v: 1,
    chain: t.chain,
    address: t.address,
    name: clip(t.name, 48) ?? undefined,
    symbol: clip(t.symbol, 16) ?? undefined,
    verdict: answer.verdict,
    grade: answer.grade,
    decision: answer.decision,
    take: clip(answer.take, MAX_TAKE) ?? undefined,
    reasons: (serious.length ? serious : answer.reasons ?? []).slice(0, 5).map((r) => r.code),
    sell: answer.sell_check?.can_sell,
    simulated: answer.sell_check?.simulated || undefined,
    market: market && Object.keys(market).length ? market : undefined,
    checked_at: answer.checkedAt,
    request_id: requestId ?? undefined,
  };
}

// "<base64url canonical JSON>.<base64url signature>"
export async function signShare(signer, payload) {
  const json = canonicalJson(payload);
  const signature = await signer.signText(SHARE_PREFIX + json);
  return `${Buffer.from(json, "utf8").toString("base64url")}.${Buffer.from(signature.slice(2), "hex").toString("base64url")}`;
}

export function shareLinks(origin, token) {
  const url = `${origin}${SHARE_PATH}/${token}`;
  return { url, image_url: `${url}/card.svg` };
}

// { payload, signer, signature } when the link verifies against one of `signers`, else { error }.
export async function readShare(raw, signers = []) {
  if (typeof raw !== "string" || !raw) return { error: "empty link" };
  if (raw.length > MAX_SHARE_CHARS) return { error: "link too long" };
  const m = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{87})$/.exec(raw);
  if (!m) return { error: "not a share link" };
  const json = Buffer.from(m[1], "base64url").toString("utf8");
  let payload;
  try { payload = JSON.parse(json); } catch { return { error: "payload is not JSON" }; }
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || canonicalJson(payload) !== json) return { error: "payload is not canonical JSON" };
  const signature = `0x${Buffer.from(m[2], "base64url").toString("hex")}`;
  if (signature.length !== 132) return { error: "signature is not 65 bytes" };
  let signer;
  try { signer = await recoverMessageAddress({ message: SHARE_PREFIX + json, signature }); } catch { return { error: "signature does not parse" }; }
  if (!signers.some((s) => s.address.toLowerCase() === signer.toLowerCase())) return { error: "not signed by a presign-guard signer" };
  if (payload.v !== 1 || typeof payload.chain !== "string" || typeof payload.address !== "string") return { error: "unknown payload version" };
  return { payload, signer, signature };
}

// ---------- rendering ----------

export function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
const words = (code) => String(code).toLowerCase().replace(/_/g, " ");
const tokenLabel = (p) => [p.name, p.symbol && p.symbol !== p.name ? `(${p.symbol})` : null].filter(Boolean).join(" ") || `${p.address.slice(0, 6)}…${p.address.slice(-4)}`;
const price = (v) => (v >= 1 ? `$${v.toLocaleString("en-US", { maximumFractionDigits: 2 })}` : `$${Number(v.toPrecision(3))}`);
function marketRows(m = {}) {
  return [
    m.price !== undefined && ["Price", price(m.price)],
    m.liquidity !== undefined && ["Liquidity", formatUsd(m.liquidity)],
    m.mcap !== undefined && ["Market cap", formatUsd(m.mcap)],
    m.vol24h !== undefined && ["24h volume", formatUsd(m.vol24h)],
    m.age_s !== undefined && ["Age", formatAge(m.age_s)],
  ].filter(Boolean);
}
const SELL_LABEL = { yes: "no sign it can't be sold", limited: "can be sold, with limits", no: "selling looks blocked", unknown: "not known" };
const checkedAt = (s) => (typeof s === "string" ? s.replace("T", " ").slice(0, 16) + " UTC" : "unknown");

export function sharePage(p, { url, imageUrl, signer, signature, origin }) {
  const color = COLOR[p.verdict] ?? GREY;
  const label = tokenLabel(p);
  const decision = DECISION_LABEL[p.decision] ?? "No verdict";
  const title = `${label}: ${p.grade ?? "no grade"} – presign-guard token check`;
  const description = p.take ?? `${p.grade ?? "No grade"}: ${decision}`;
  const reasons = (p.reasons ?? []).map((c) => `<li><code>${esc(c)}</code> ${esc(words(c))}</li>`).join("");
  const market = marketRows(p.market).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("");
  const payloadPart = url.split("/").pop().split(".")[0];
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<meta property="og:type" content="website">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:url" content="${esc(url)}">
<meta property="og:image" content="${esc(imageUrl)}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="twitter:image" content="${esc(imageUrl)}">
<style>
:root{color-scheme:light dark;--fg:#111827;--muted:#4b5563;--bg:#f9fafb;--card:#fff;--line:#e5e7eb}
@media (prefers-color-scheme:dark){:root{--fg:#f3f4f6;--muted:#9ca3af;--bg:#0b0f19;--card:#111827;--line:#1f2937}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:720px;margin:0 auto;padding:24px 16px}section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:0 0 16px}
h1{font-size:1.5rem;margin:0 0 4px;overflow-wrap:anywhere}.addr{color:var(--muted);font:13px ui-monospace,monospace;overflow-wrap:anywhere}
.grade{display:inline-block;color:#fff;background:${color};border-radius:8px;padding:4px 12px;font-weight:700;margin:12px 8px 0 0}
.decision{font-weight:600}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 0;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:500;width:40%}
ul{padding-left:20px;margin:8px 0}code{font-size:13px}.small{color:var(--muted);font-size:14px}.sig{font:12px ui-monospace,monospace;overflow-wrap:anywhere}
</style>
</head><body><main>
<section>
<div class="small">presign-guard token check · ${esc(p.chain)}</div>
<h1>${esc(label)}</h1>
<div class="addr">${esc(p.address)}</div>
<span class="grade">${esc(p.grade ?? "no grade")}</span><span class="decision">${esc(decision)}</span>
${p.take ? `<p>${esc(p.take)}</p>` : ""}
${p.sell ? `<p class="small">Sell check: ${esc(SELL_LABEL[p.sell] ?? p.sell)}${p.simulated ? " (a sell transfer was simulated on chain)" : ""}.</p>` : ""}
</section>
${reasons ? `<section><strong>Reasons</strong><ul>${reasons}</ul></section>` : ""}
${market ? `<section><strong>Market</strong> <span class="small">(DexScreener, at the time of the check)</span><table>${market}</table></section>` : ""}
<section class="small">
<p>Checked at ${esc(checkedAt(p.checked_at))}${p.request_id ? `, request <code>${esc(p.request_id)}</code>` : ""}. A risk check from public data (GoPlus, DexScreener, the chain itself and others), not financial advice: green means no known red flags, not that the price will hold.</p>
<p><strong>Verify it.</strong> presign-guard stores nothing: this page is rendered from the link. The part of the link before the dot is base64url canonical JSON; the part after it is an EIP-191 personal_sign by <code>${esc(signer)}</code> over <code>presign-guard token share v1\\n</code> followed by that JSON. Recover the signer (for example with viem's <code>recoverMessageAddress</code>) and compare it with the signer list at <a href="${esc(origin)}/.well-known/presign-guard-signer.json">/.well-known/presign-guard-signer.json</a>. A changed character in the link breaks the signature, and the link stops working.</p>
<p class="sig">payload: ${esc(Buffer.from(payloadPart, "base64url").toString("utf8"))}<br>signature: ${esc(signature)}</p>
<p>Check a token yourself: <code>POST ${esc(origin)}/v1/token/verdict</code> with <code>{"tokenAddress": "…", "chain": "base"}</code> ($0.01 over x402), or the free verdict at <code>GET ${esc(origin)}/v1/token/quick</code>. <a href="${esc(origin)}/">presign-guard</a></p>
</section>
</main></body></html>`;
}

// Words into lines of at most `width` characters, at most `max` lines (the last one cut with …).
export function wrap(text, width, max) {
  const lines = [];
  let line = "";
  for (const word of String(text ?? "").split(/\s+/).filter(Boolean)) {
    const w = word.length > width ? `${word.slice(0, width - 1)}…` : word;
    if (!line) line = w;
    else if (line.length + 1 + w.length <= width) line += ` ${w}`;
    else { lines.push(line); line = w; }
  }
  if (line) lines.push(line);
  if (lines.length > max) { lines.length = max; lines[max - 1] = `${lines[max - 1].slice(0, width - 1)}…`; }
  return lines;
}

export function shareCard(p) {
  const color = COLOR[p.verdict] ?? GREY;
  const label = clip(tokenLabel(p), 30);
  const grade = String(p.grade ?? "NO GRADE");
  const box = Math.max(180, 30 * grade.length + 56);
  const decision = DECISION_LABEL[p.decision] ?? "No verdict";
  const take = wrap(p.take ?? "", 58, 4);
  const market = marketRows(p.market).filter(([k]) => k !== "Price").slice(0, 3).map(([k, v]) => `${k} ${v}`).join("   ·   ");
  const text = (x, y, size, fill, s, weight = 400) => `<text x="${x}" y="${y}" font-size="${size}" font-weight="${weight}" fill="${fill}">${esc(s)}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" font-family="system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif">
<rect width="1200" height="630" fill="#0b0f19"/>
<rect x="0" y="0" width="16" height="630" fill="${color}"/>
${text(72, 92, 28, "#9ca3af", `presign-guard token check · ${p.chain}`)}
${text(72, 172, 56, "#f9fafb", label, 700)}
<rect x="72" y="214" width="${box}" height="72" rx="14" fill="${color}"/>
${text(96, 264, 40, "#ffffff", grade, 800)}
${text(box + 100, 264, 40, "#f9fafb", decision, 600)}
${take.map((l, i) => text(72, 352 + i * 44, 32, "#e5e7eb", l)).join("\n")}
${market ? text(72, 556, 26, "#9ca3af", market) : ""}
${text(72, 598, 22, "#6b7280", `Checked ${checkedAt(p.checked_at)} · signed, verifiable · not financial advice`)}
</svg>`;
}

// Strict for these responses: no scripts, no remote content (the card is an image on our own origin).
const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const CARD_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";

export function createShareRouter({ signer, publicUrl }) {
  const router = express.Router();
  const signers = () => (signer ? signer.signers : []);
  const refuse = (res, error) => res.status(400).set("Cache-Control", "no-store").type("text/plain; charset=utf-8").send(`Not a valid presign-guard share link: ${error}.`);
  router.get(`${SHARE_PATH}/:share`, async (req, res) => {
    const r = await readShare(req.params.share, signers());
    if (r.error) return refuse(res, r.error);
    const { url, image_url: imageUrl } = shareLinks(publicUrl, req.params.share);
    res.set({ "Content-Security-Policy": PAGE_CSP, "Cache-Control": "public, max-age=86400" }).type("html")
      .send(sharePage(r.payload, { url, imageUrl, signer: r.signer, signature: r.signature, origin: publicUrl }));
  });
  router.get(`${SHARE_PATH}/:share/card.svg`, async (req, res) => {
    const r = await readShare(req.params.share, signers());
    if (r.error) return refuse(res, r.error);
    res.set({ "Content-Security-Policy": CARD_CSP, "Cache-Control": "public, max-age=86400" }).type("image/svg+xml").send(shareCard(r.payload));
  });
  return router;
}
