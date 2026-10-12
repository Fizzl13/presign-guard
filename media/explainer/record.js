// Records the explainer video's picture: drives a real browser through the
// presign-guard homepage, timed to the narration (out/durations.json), with
// burned-in captions. Writes out/screen.webm and out/timeline.json.
// SCRIPT=token.json records the token verdict video, SCRIPT=screen.json the
// wallet sanctions screen (GET /v1/screen on the Treasury's own SDN list).
//
// The page is served by engine.mjs (the same check code, no paywall, localhost),
// so the verdicts on screen are real and nobody pays. The price in the agent
// scene comes from the live service's 402.
//
//   node engine.mjs &  node record.js

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = process.env.OUT || path.join(HERE, "out");
const SITE = (process.env.SITE_URL || "http://127.0.0.1:3100").replace(/\/$/, "");
const LIVE = "https://presign-guard.fizzl.eu";
const W = 1920;
const H = 1080;
const ZOOM = 2.0;

const script = JSON.parse(fs.readFileSync(path.join(HERE, process.env.SCRIPT || "script.json"), "utf8"));
const durations = JSON.parse(fs.readFileSync(path.join(OUT, "durations.json"), "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");

// Load a generated page and wait for its web fonts, so no frame shows a fallback font.
async function setPage(page, html, opts = {}) {
  await page.setContent(html, opts);
  await page.evaluate(() => document.fonts && document.fonts.ready).catch(() => {});
}

const THEME = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Space+Grotesk:wght@500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
  :root { --bg:#020708; --panel:#041212; --line:rgba(97,245,195,.16); --text:#f4f8f7; --soft:#a8b5b2; --bull:#6ee7b7; --red:#fca5a5; --accent:#61f5c3; --warn:#fcd34d; }
  html, body { margin:0; height:100%; background:var(--bg); color:var(--text); font-family:'DM Sans',system-ui,sans-serif; }
`;

function cardHtml({ title, sub, note }) {
  return `<!doctype html><html><head><style>${THEME}
    body { display:flex; align-items:center; justify-content:center; }
    .c { text-align:center; animation: in .6s ease-out both; padding: 0 120px; }
    h1 { font-family: 'Space Grotesk','DM Sans',sans-serif; font-size: 120px; margin: 0 0 24px; letter-spacing: -0.02em; }
    p { font-size: 52px; color: var(--soft); margin: 0; }
    .note { font-family: ui-monospace, 'DejaVu Sans Mono', monospace; font-size: 30px; margin-top: 44px; color: var(--accent); }
    @keyframes in { from { opacity:0; transform: translateY(24px);} to { opacity:1; transform:none; } }
  </style></head><body><div class="c"><h1>${esc(title)}</h1><p>${esc(sub || '')}</p>${note ? `<p class="note">${esc(note)}</p>` : ''}</div></body></html>`;
}

function terminalHtml(label, lines) {
  return `<!doctype html><html><head><style>${THEME}
    body { display:flex; align-items:center; justify-content:center; }
    .t { width: 1560px; background: var(--panel); border:1px solid var(--line); border-radius: 18px; padding: 36px 44px; box-shadow: 0 30px 80px rgba(0,0,0,.5); }
    .bar { display:flex; gap:10px; margin-bottom: 26px; } .bar i { width:16px; height:16px; border-radius:50%; background:#10302b; display:block; }
    .label { color: var(--soft); font-size: 24px; margin: -8px 0 22px; }
    pre { margin:0; font: 29px/1.55 ui-monospace, 'DejaVu Sans Mono', monospace; white-space: pre-wrap; }
    .l { opacity: 0; transition: opacity .35s; } .l.on { opacity: 1; }
    .in { color: var(--warn); } .ok { color: var(--bull); } .dim { color: var(--soft); }
    .hl { background: rgba(110,231,183,.14); border-radius: 6px; outline: 2px solid var(--bull); }
  </style></head><body><div class="t"><div class="bar"><i></i><i></i><i></i></div><div class="label">${esc(label)}</div><pre>${lines
    .map((l, i) => `<div class="l ${l.cls || ''}" id="l${i}">${esc(l.text)}</div>`)
    .join('')}</pre></div></body></html>`;
}

// ---------- token video ----------

const BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
const USDC_SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const LITECAT = "qikeUfbJaWPHy7sTTYfQuBuafzmUBZAH7SjCbjZCyFA";
const usd = (v) => (v == null ? "–" : v >= 1e9 ? `$${(v / 1e9).toFixed(1)}B` : v >= 1e6 ? `$${(v / 1e6).toFixed(1)}M` : v >= 1e3 ? `$${Math.round(v / 1e3)}k` : `$${Math.round(v)}`);
const age = (s) => (s == null ? "–" : s < 3600 ? `${Math.max(1, Math.round(s / 60))} min` : s < 86400 ? `${Math.round(s / 3600)} h` : s < 365 * 86400 ? `${Math.round(s / 86400)} days` : `${(s / (365 * 86400)).toFixed(1)} years`);

async function tokenVerdictLocal(address) {
  const res = await fetch(`${SITE}/v1/token?chain=solana&address=${address}`);
  const out = await res.json();
  if (!res.ok) throw new Error(`token ${address}: HTTP ${res.status} ${JSON.stringify(out)}`);
  return out;
}

const orangeCodes = (r) => r.reasons.filter((x) => x.severity === "orange").map((x) => x.code);

// A token the narration can call "launched today, risky: hours old, thin liquidity":
// LITECAT if it still fits, else the newest Solana tokens on DexScreener.
async function pickRisky() {
  const fits = (r) => r.grade === "RISKY" && ["NEW_TOKEN", "LOW_LIQUIDITY"].every((c) => orangeCodes(r).includes(c));
  const candidates = [LITECAT];
  if (process.env.MOCK_LIVE === "1") candidates.push("Risky11111111111111111111111111111111111111");
  else try {
    const latest = await (await fetch("https://api.dexscreener.com/token-profiles/latest/v1")).json();
    for (const t of latest) if (t.chainId === "solana" && t.tokenAddress) candidates.push(t.tokenAddress);
  } catch { /* LITECAT only */ }
  for (const address of candidates.slice(0, 25)) {
    const r = await tokenVerdictLocal(address).catch(() => null);
    if (r && fits(r)) return r;
  }
  throw new Error("no fresh, thin Solana token found that grades RISKY");
}

async function tokenData() {
  const safe = await tokenVerdictLocal(BONK);
  if (safe.grade !== "SAFE") throw new Error(`Bonk: expected SAFE, got ${safe.grade} (${orangeCodes(safe)})`);
  const trusted = await tokenVerdictLocal(USDC_SOL);
  const info = trusted.reasons.filter((x) => x.severity === "info").map((x) => x.code);
  if (trusted.grade !== "SAFE" || !["FREEZE_AUTHORITY_ACTIVE", "MINT_AUTHORITY_ACTIVE", "TOKEN_ON_TRUST_LIST"].every((c) => info.includes(c))) {
    throw new Error(`USDC: expected SAFE with freeze/mint as context, got ${trusted.grade} ${info}`);
  }
  const risky = await pickRisky();
  for (const r of [safe, risky, trusted]) console.log(`${r.token.symbol}: ${r.grade} | ${r.one_liner}`);
  return { safe, risky, trusted };
}

const BADGE = { SAFE: "var(--bull)", CAUTION: "var(--warn)", RISKY: "#fdba74", AVOID: "var(--red)" };
const SEV = { red: "var(--red)", orange: "#fdba74", info: "var(--soft)" };

function verdictHtml(r) {
  const m = r.market || {};
  const serious = r.reasons.filter((x) => x.severity !== "info");
  // Info the narration mentions first; the rest only if there is room.
  const FIRST = ["MINT_AUTHORITY_ACTIVE", "FREEZE_AUTHORITY_ACTIVE", "TOKEN_ON_TRUST_LIST"];
  const rank = (x) => (FIRST.includes(x.code) ? FIRST.indexOf(x.code) : FIRST.length);
  const info = r.reasons.filter((x) => x.severity === "info").sort((a, b) => rank(a) - rank(b)).slice(0, 4 - Math.min(serious.length, 3));
  // DexScreener undercounts quote assets (USDC), so a trust-list token shows no market figures.
  const trusted = r.reasons.some((x) => x.code === "TOKEN_ON_TRUST_LIST");
  const reasons = [...serious.slice(0, 5), ...info];
  const stats = [["Price", m.priceUsd == null ? "–" : `$${Number(m.priceUsd).toPrecision(3)}`], ["Liquidity", usd(m.liquidityUsd)], ["Market cap", usd(m.marketCapUsd)], ["24h volume", usd(m.volume24hUsd)], ["Age", age(m.ageSeconds)]];
  return `<!doctype html><html><head><style>${THEME}
    body { display:flex; align-items:center; justify-content:center; }
    .v { width: 1500px; background: var(--panel); border:1px solid var(--line); border-radius: 22px; padding: 44px 56px; box-shadow: 0 30px 80px rgba(0,0,0,.5); }
    .req { font: 26px ui-monospace, 'DejaVu Sans Mono', monospace; color: var(--soft); margin-bottom: 30px; }
    .top { display:flex; align-items:center; gap: 28px; }
    h1 { font-family: 'Space Grotesk','DM Sans',sans-serif; font-size: 64px; margin: 0; } .chain { color: var(--soft); font-size: 30px; }
    .badge { margin-left:auto; font-size: 44px; font-weight: 800; padding: 10px 30px; border-radius: 14px; color:#0f1115; background:${BADGE[r.grade]}; }
    .one { font-size: 36px; margin: 26px 0 26px; color: var(--text); }
    ul { list-style:none; padding:0; margin:0 0 30px; font: 28px/1.7 ui-monospace, 'DejaVu Sans Mono', monospace; }
    li b { display:inline-block; width: 110px; font-weight: 600; }
    .stats { display:grid; grid-template-columns: repeat(5, 1fr); gap: 16px; }
    .s { background: var(--bg); border:1px solid var(--line); border-radius: 12px; padding: 16px 20px; }
    .s span { display:block; color: var(--soft); font-size: 22px; } .s strong { font-size: 34px; }
    .r { opacity: 0; transform: translateY(10px); transition: all .4s; } .r.on { opacity: 1; transform: none; }
  </style></head><body><div class="v">
    <div class="req r">GET /v1/token?chain=solana&amp;address=${esc(r.token.address.slice(0, 6))}…${esc(r.token.address.slice(-4))}</div>
    <div class="top r"><h1>${esc(r.token.symbol || "?")}</h1><span class="chain">${esc(r.token.name || "")} · Solana</span><span class="badge">${esc(r.grade)}</span></div>
    <div class="one r">${esc(r.one_liner)}</div>
    <ul class="r">${reasons.map((x) => `<li><b style="color:${SEV[x.severity]}">${esc(x.severity)}</b>${esc(x.code)}</li>`).join("")}</ul>
    ${trusted ? "" : `<div class="stats r">${stats.map(([k, v]) => `<div class="s"><span>${k}</span><strong>${esc(v)}</strong></div>`).join("")}</div>`}
  </div></body></html>`;
}

// The price an agent sees for the token verdict, from the live 402 challenge.
async function liveTokenPrice() {
  if (process.env.MOCK_LIVE === "1") return "$0.01 on Base, Solana, XRP Ledger or Algorand";
  const res = await fetch(`${LIVE}/v1/token?chain=solana&address=${BONK}`);
  if (res.status !== 402) throw new Error(`expected 402 from ${LIVE}/v1/token, got ${res.status}`);
  const challenge = JSON.parse(Buffer.from(res.headers.get("payment-required"), "base64").toString("utf8"));
  const nets = challenge.accepts.map((a) => (a.network.startsWith("solana:") ? "Solana" : a.network === "eip155:8453" ? "Base" : null)).filter(Boolean);
  if (!nets.includes("Base") || !nets.includes("Solana")) throw new Error(`live token route offers ${nets}, expected Base and Solana`);
  return `$${(Number(challenge.accepts[0].amount) / 1e6).toFixed(2)} on Base, Solana, XRP Ledger or Algorand`;
}

// ---------- sanctions video ----------

const TRON_MARKAZI = "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81";
const VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const LAZARUS = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96";
// A real $0.01 x402 payment for GET /v1/screen?address=TNiq9… on Base, settled by the CDP facilitator (12 Oct 2026).
const PAID_TX = "0xcc760f0d2af04db2b200c744aa0a7108ac12da9c8363bd31d78399c971db51e1";
const short = (a) => `${a.slice(0, 8)}…${a.slice(-4)}`;

async function screenLocal(address) {
  const res = await fetch(`${SITE}/v1/screen?address=${address}`);
  const out = await res.json();
  if (!res.ok) throw new Error(`screen ${address}: HTTP ${res.status} ${JSON.stringify(out)}`);
  return out;
}
const sdnNames = (r) => (r.sanctions?.matches || []).map((m) => m.name);

// GoPlus, the usual free source, on the same Tron address (the narration says it answers sanctioned: 0).
async function goplusTron() {
  if (process.env.MOCK_LIVE === "1") return { sanctioned: "0", stealing_attack: "0", phishing_activities: "0" };
  const j = await (await fetch(`https://api.gopluslabs.io/api/v1/address_security/${TRON_MARKAZI}?chain_id=tron`)).json();
  if (j?.result?.sanctioned !== "0") throw new Error(`GoPlus now answers sanctioned=${j?.result?.sanctioned} for ${TRON_MARKAZI}: rewrite s_goplus`);
  return j.result;
}

// The free open list and x402 Doctor's index, as they are live.
async function openNumbers() {
  if (process.env.MOCK_LIVE === "1") return { count: 1050, published: "2026-10-09", endpoints: 34474, sellers: 1847 };
  const list = await (await fetch(`${LIVE}/v1/sanctions`)).json();
  const trust = await (await fetch("https://x402-doctor.fizzl.eu/api/trust/summary")).json();
  const l = trust.latest || {};
  return { count: list.count, published: list.published, endpoints: (l.go || 0) + (l.caution || 0) + (l.no_go || 0) + (l.unreachable || 0), sellers: trust.services?.sellers };
}

// The verdicts the narration names, checked before anything is recorded.
async function screenData() {
  const tron = await screenLocal(TRON_MARKAZI);
  if (tron.verdict !== "red" || !sdnNames(tron).some((n) => /MARKAZI/i.test(n))) throw new Error(`Tron: expected red (Bank Markazi), got ${tron.verdict} ${sdnNames(tron)}`);
  const vitalik = await screenLocal(VITALIK);
  if (vitalik.verdict !== "green") throw new Error(`vitalik.eth: expected green, got ${vitalik.verdict}`);
  const lazarus = await screenLocal(LAZARUS);
  if (lazarus.verdict !== "red" || !sdnNames(lazarus).some((n) => /LAZARUS/i.test(n)) || !lazarus.reasons.some((x) => x.code === "STEALING_ATTACK")) {
    throw new Error(`Lazarus: expected red, on the list and reported for theft, got ${lazarus.verdict} ${lazarus.reasons.map((x) => x.code)}`);
  }
  for (const r of [tron, vitalik, lazarus]) console.log(`${short(r.address.address)}: ${r.verdict} | ${r.one_liner}`);
  return { tron, vitalik, lazarus, goplus: await goplusTron(), open: await openNumbers() };
}

const VERDICT_BG = { green: "var(--bull)", orange: "#fdba74", red: "var(--red)" };

// One screen result: the request, the address and chain, the verdict, the reasons and the SDN entry.
function screenCard(r, { compact = false, label = "" } = {}) {
  const m = (r.sanctions?.matches || [])[0];
  const reasons = r.reasons.filter((x) => x.severity !== "info").slice(0, 3);
  const info = reasons.length ? [] : r.reasons.filter((x) => x.severity === "info").slice(0, 2);
  return `<div class="v ${compact ? "compact" : ""}">
    <div class="req r">GET /v1/screen?address=${esc(short(r.address.address))}</div>
    <div class="top r"><h1>${esc(label || short(r.address.address))}</h1><span class="chain">${esc(FORMAT[r.address.format] || r.address.format)}</span><span class="badge" style="background:${VERDICT_BG[r.verdict]}">${esc(r.verdict)}</span></div>
    <div class="one r">${esc(r.one_liner)}</div>
    <ul class="r">${[...reasons, ...info].map((x) => `<li><b style="color:${SEV[x.severity]}">${esc(x.severity)}</b>${esc(x.code)}</li>`).join("")}</ul>
    ${m ? `<div class="sdn r"><span>OFAC SDN entry</span><strong>${esc(m.name)}</strong><em>programs ${esc(m.programs.join(", "))} · list published ${esc(r.sanctions.published)}</em></div>` : `<div class="sdn r"><span>OFAC SDN list</span><strong>not listed</strong><em>list published ${esc(r.sanctions.published)}</em></div>`}
  </div>`;
}
const FORMAT = { evm: "EVM", tron: "Tron", bitcoin: "Bitcoin", xrpl: "XRP Ledger", algorand: "Algorand", solana: "Solana", other: "other chain" };

function screenHtml(cards) {
  return `<!doctype html><html><head><style>${THEME}
    body { display:flex; align-items:center; justify-content:center; gap: 40px; box-sizing: border-box; padding-bottom: 230px; }
    .v { width: 1500px; background: var(--panel); border:1px solid var(--line); border-radius: 22px; padding: 44px 56px; box-shadow: 0 30px 80px rgba(0,0,0,.5); }
    .v.compact { width: 820px; padding: 36px 40px; box-sizing: border-box; }
    .req { font: 26px ui-monospace, 'DejaVu Sans Mono', monospace; color: var(--soft); margin-bottom: 26px; }
    .top { display:flex; align-items:center; gap: 24px; }
    h1 { font-family: 'Space Grotesk','DM Sans',sans-serif; font-size: 56px; margin: 0; } .compact h1 { font-size: 44px; }
    .chain { color: var(--soft); font-size: 30px; }
    .badge { margin-left:auto; font-size: 44px; font-weight: 800; padding: 8px 28px; border-radius: 14px; color:#0f1115; text-transform: uppercase; }
    .one { font-size: 34px; margin: 24px 0; } .compact .one { font-size: 28px; min-height: 3.9em; }
    ul { list-style:none; padding:0; margin:0 0 26px; font: 28px/1.7 ui-monospace, 'DejaVu Sans Mono', monospace; } .compact ul { font-size: 24px; min-height: 5.1em; }
    li b { display:inline-block; width: 110px; font-weight: 600; } .compact li b { width: 96px; }
    .sdn { background: var(--bg); border:1px solid var(--line); border-radius: 12px; padding: 18px 22px; }
    .sdn span { display:block; color: var(--soft); font-size: 22px; } .sdn strong { display:block; font-size: 34px; margin: 4px 0; } .compact .sdn strong { font-size: 28px; }
    .sdn em { font-style: normal; color: var(--soft); font-size: 22px; }
    .r { opacity: 0; transform: translateY(10px); transition: all .4s; } .r.on { opacity: 1; transform: none; }
  </style></head><body>${cards.join("")}</body></html>`;
}

// The price an agent sees for a wallet screen, from the live 402 challenge.
async function liveScreenPrice() {
  if (process.env.MOCK_LIVE === "1") return "$0.01 on Base, Solana, XRP Ledger or Algorand";
  const res = await fetch(`${LIVE}/v1/screen?address=${TRON_MARKAZI}`);
  if (res.status !== 402) throw new Error(`expected 402 from ${LIVE}/v1/screen, got ${res.status}`);
  const challenge = JSON.parse(Buffer.from(res.headers.get("payment-required"), "base64").toString("utf8"));
  const nets = challenge.accepts.map((a) => a.network);
  const has = (p) => nets.some((n) => n.startsWith(p));
  if (!(has("eip155:8453") && has("solana:") && has("xrpl:") && has("algorand:"))) throw new Error(`live screen route offers ${nets}, expected Base, Solana, XRPL and Algorand`);
  const base = challenge.accepts.find((a) => a.network === "eip155:8453");
  return `$${(Number(base.amount) / 1e6).toFixed(2)} on Base, Solana, XRP Ledger or Algorand`;
}

// Captions: a bar at the bottom of every page, re-created after navigation.
async function caption(page, text) {
  await page.evaluate(
    ({ text }) => {
      let el = document.getElementById('__cap');
      if (!el) {
        el = document.createElement('div');
        el.id = '__cap';
        el.style.cssText = 'position:fixed;left:50%;bottom:48px;transform:translateX(-50%);max-width:1500px;z-index:2147483647;' +
          'background:rgba(2,7,8,.88);border:1px solid rgba(97,245,195,.35);color:#f4f8f7;font:600 38px/1.35 "DM Sans",system-ui,sans-serif;' +
          'padding:14px 28px;border-radius:14px;text-align:center;';
        document.body.appendChild(el);
      }
      el.style.zoom = String(1 / (parseFloat(document.documentElement.style.zoom) || 1));
      el.style.display = text ? 'block' : 'none';
      el.textContent = text;
    },
    { text }
  );
}

const zoomPage = (page) => page.evaluate((z) => { document.documentElement.style.zoom = String(z); }, ZOOM);
const center = (page, selector) => page.evaluate((s) => document.querySelector(s).scrollIntoView({ behavior: "smooth", block: "center" }), selector);
const glow = (page, selector, color = "rgba(97,245,195,.55)") =>
  page.evaluate(({ selector, color }) => {
    const el = document.querySelector(selector);
    el.style.transition = "box-shadow .3s";
    el.style.boxShadow = `0 0 0 5px ${color}`;
  }, { selector, color });

// The price an agent sees, from the live 402 challenge.
async function livePrice() {
  if (process.env.MOCK_LIVE === "1") return "$0.01 on Base, Solana, XRP Ledger or Algorand";
  const res = await fetch(`${LIVE}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  if (res.status !== 402) throw new Error(`expected 402 from ${LIVE}/v1/check, got ${res.status}`);
  const challenge = JSON.parse(Buffer.from(res.headers.get("payment-required"), "base64").toString("utf8"));
  const a = challenge.accepts.find((x) => x.network === "eip155:8453");
  if (!a) throw new Error("live service offers no Base option");
  return `$${(Number(a.amount) / 1e6).toFixed(2)} on Base, Solana, XRP Ledger or Algorand`;
}

const EXPECT = { unlimited: "orange", permit: "red", payment: "green" };
const GLOW = { green: "rgba(110,231,183,.55)", orange: "rgba(253,186,116,.55)", red: "rgba(252,165,165,.6)" };

// Pick a preset on the page, check it with the engine, show the verdict the way the page does.
async function showPreset(page, preset, ms) {
  await page.click(`#presets button[data-preset="${preset}"]`);
  await center(page, "#body");
  await sleep(ms * 0.3);
  const body = await page.inputValue("#body");
  const res = await fetch(`${SITE}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body });
  const out = await res.json();
  if (!res.ok) throw new Error(`${preset}: HTTP ${res.status} ${JSON.stringify(out)}`);
  console.log(`${preset}: ${out.verdict} ${out.reasons.map((r) => r.code).join(", ")}`);
  if (out.verdict !== EXPECT[preset]) throw new Error(`${preset}: expected ${EXPECT[preset]}, got ${out.verdict}`);
  await page.evaluate((out) => {
    document.getElementById("status").textContent = "Verdict:";
    const v = document.getElementById("verdict");
    v.textContent = out.verdict;
    v.className = `badge ${out.verdict}`;
    document.getElementById("reasons").replaceChildren(...out.reasons.map((r) => {
      const li = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = r.code;
      li.append(`${r.severity}: `, code);
      return li;
    }));
    document.getElementById("explain").textContent = "";
    document.getElementById("result").style.display = "block";
  }, out);
  await center(page, "#verdict");
  await sleep(500);
  await glow(page, "#verdict", GLOW[out.verdict]);
}

async function main() {
  const tokenVideo = script.segments.some((seg) => seg.scene.startsWith("token"));
  const screenVideo = script.segments.some((seg) => seg.scene.startsWith("screen"));
  const price = tokenVideo ? await liveTokenPrice() : screenVideo ? await liveScreenPrice() : await livePrice();
  const tokens = tokenVideo ? await tokenData() : null;
  const screens = screenVideo ? await screenData() : null;
  const agentLines = [
    { cls: "", text: "$ POST presign-guard.fizzl.eu/v1/check   { what the agent is about to sign }" },
    { cls: "in", text: `\u2190 402 Payment Required: ${price}` },
    { cls: "dim", text: "\u2192 agent signs the payment and retries" },
    { cls: "ok", text: "\u2190 200 OK" },
    { cls: "ok", text: '{ "verdict": "orange",' },
    { cls: "dim", text: '  "reasons": [{ "code": "UNLIMITED_APPROVAL", "severity": "orange" }] }' },
  ];
  const safeLines = [
    { cls: "", text: "Bad request        \u2192 400, payment cancelled, verdict: null" },
    { cls: "", text: "Data source down   \u2192 503, payment cancelled, verdict: null" },
    { cls: "dim", text: "" },
    { cls: "ok", text: "Never charged for an error. Never a guessed green." },
  ];

  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
  const context = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir: OUT, size: { width: W, height: H } }, colorScheme: "dark" });
  const page = await context.newPage();
  const t0 = Date.now();
  const timeline = [];

  const lines = async (label, list, ms, share) => {
    await setPage(page, terminalHtml(label, list), { waitUntil: "load" });
    for (let i = 0; i < list.length; i++) {
      await page.evaluate((i) => document.getElementById(`l${i}`).classList.add("on"), i);
      await sleep(Math.max(250, (ms * share) / list.length));
    }
    await page.evaluate(() => { for (const el of document.querySelectorAll(".l.in, .l.ok")) el.classList.add("hl"); });
  };

  const tokenAgentLines = tokens && [
    { cls: "", text: `$ GET presign-guard.fizzl.eu/v1/token?chain=solana&address=${BONK.slice(0, 6)}…` },
    { cls: "in", text: `\u2190 402 Payment Required: ${price}` },
    { cls: "dim", text: "\u2192 agent pays and retries" },
    { cls: "ok", text: `\u2190 200 OK  { "verdict": "${tokens.safe.verdict}", "grade": "${tokens.safe.grade}",` },
    { cls: "ok", text: `           "one_liner": "${tokens.safe.one_liner}" }` },
    { cls: "dim", text: " " },
    { cls: "", text: "MCP  token_quick_verdict { chain: \"solana\", address: … }" },
    { cls: "ok", text: `\u2190 { "verdict": "${tokens.safe.verdict}", "grade": "${tokens.safe.grade}" }   free, 10 calls an hour` },
  ];
  const screenGoplusLines = screens && [
    { cls: "", text: `$ GET api.gopluslabs.io/api/v1/address_security/${short(TRON_MARKAZI)}?chain_id=tron` },
    { cls: "in", text: `\u2190 { "sanctioned": "${screens.goplus.sanctioned}", "stealing_attack": "${screens.goplus.stealing_attack}", "phishing_activities": "${screens.goplus.phishing_activities}", \u2026 }` },
    { cls: "dim", text: " " },
    { cls: "", text: `$ GET presign-guard.fizzl.eu/v1/screen?address=${short(TRON_MARKAZI)}` },
    { cls: "ok", text: `\u2190 { "verdict": "${screens.tron.verdict}", "reasons": [{ "code": "SANCTIONED_ADDRESS" }],` },
    { cls: "ok", text: `    "sanctions": { "matches": [{ "name": "${sdnNames(screens.tron)[0]}" }] } }` },
  ];
  const screenAgentLines = screens && [
    { cls: "", text: `$ GET presign-guard.fizzl.eu/v1/screen?address=${short(TRON_MARKAZI)}` },
    { cls: "in", text: `\u2190 402 Payment Required: ${price}` },
    { cls: "dim", text: "\u2192 agent pays and retries" },
    { cls: "ok", text: `\u2190 200 OK  { "verdict": "${screens.tron.verdict}", "grade": "${screens.tron.grade}",` },
    { cls: "ok", text: `           "reasons": [{ "code": "SANCTIONED_ADDRESS", "severity": "red" }],` },
    { cls: "ok", text: `           "receipt": { \u2026 EIP-191 signature } }` },
    { cls: "dim", text: " " },
    { cls: "dim", text: `A real payment for this call (12 Oct 2026): basescan.org/tx/${PAID_TX.slice(0, 10)}\u2026${PAID_TX.slice(-4)}` },
  ];
  const screenOpenLines = screens && [
    { cls: "", text: "$ GET presign-guard.fizzl.eu/v1/sanctions                    free, no key" },
    { cls: "ok", text: `\u2190 { "count": ${screens.open.count}, "published": "${screens.open.published}", "addresses": [ \u2026 ] }` },
    { cls: "dim", text: " " },
    { cls: "", text: "$ npm i presign-guard-payer-screen                            for x402 sellers" },
    { cls: "", text: "app.use(screenPayers());   // before your x402 payment middleware" },
    { cls: "ok", text: "\u2190 451 for a sanctioned payer: the payment never settles" },
  ];
  const screenDoctorLines = screens && [
    { cls: "", text: "$ GET x402-doctor.fizzl.eu/api/v1/preflight?url=<the seller's endpoint>" },
    { cls: "dim", text: "  screens the seller's payout address (x402 payTo, MPP recipient) against the same list" },
    { cls: "in", text: '\u2190 when it is listed:  { "verdict": "no_go", "reasons": ["payto_sanctioned"] }' },
    { cls: "dim", text: " " },
    { cls: "ok", text: `x402 Doctor's Trust Index: ${screens.open.endpoints.toLocaleString("en-US")} paid endpoints from ${screens.open.sellers.toLocaleString("en-US")} sellers, checked daily` },
  ];
  // The sanctions video's terminals hold more lines: keep them above the caption bar.
  const aboveCaption = () => page.evaluate(() => { document.body.style.boxSizing = "border-box"; document.body.style.paddingBottom = "230px"; });
  // Pages are loaded in a prepare step, before the caption is drawn; the scene only reveals.
  const reveal = async (selector, ms, share) => {
    const steps = await page.evaluate((sel) => document.querySelectorAll(sel).length, selector);
    for (let i = 0; i < steps; i++) {
      await page.evaluate(({ sel, i }) => document.querySelectorAll(sel)[i].classList.add("on"), { sel: selector, i });
      await sleep(Math.max(200, (ms * share) / steps));
    }
  };

  const scenes = {
    async "prepare:tokenHome"() {
      await page.goto(SITE, { waitUntil: "networkidle", timeout: 90000 });
      await zoomPage(page);
      await sleep(300);
    },
    async tokenHome(seg, ms) {
      await center(page, "#token-card");
      await sleep(ms * 0.35);
      await glow(page, "#token-card");
    },
    async "prepare:tokenSafe"() { await setPage(page, verdictHtml(tokens.safe), { waitUntil: "load" }); },
    async "prepare:tokenRisky"() { await setPage(page, verdictHtml(tokens.risky), { waitUntil: "load" }); },
    async "prepare:tokenTrusted"() { await setPage(page, verdictHtml(tokens.trusted), { waitUntil: "load" }); },
    async tokenSafe(seg, ms) { await reveal(".r", ms, 0.6); },
    async tokenRisky(seg, ms) { await reveal(".r", ms, 0.6); },
    async tokenTrusted(seg, ms) { await reveal(".r", ms, 0.6); },
    async "prepare:tokenAgents"() {
      await setPage(page, terminalHtml("An AI agent checking a token before it buys", tokenAgentLines), { waitUntil: "load" });
    },
    async tokenAgents(seg, ms) {
      await reveal(".l", ms, 0.8);
      await page.evaluate(() => { for (const el of document.querySelectorAll(".l.in, .l.ok")) el.classList.add("hl"); });
    },
    async "prepare:screenTron"() { await setPage(page, screenHtml([screenCard(screens.tron, { label: "Tron address" })]), { waitUntil: "load" }); },
    async screenTron(seg, ms) { await reveal(".r", ms, 0.6); },
    async "prepare:screenGoplus"() {
      await setPage(page, terminalHtml("The same Tron address, two sources", screenGoplusLines), { waitUntil: "load" });
      await aboveCaption();
    },
    async screenGoplus(seg, ms) {
      await reveal(".l", ms, 0.75);
      await page.evaluate(() => { for (const el of document.querySelectorAll(".l.in, .l.ok")) el.classList.add("hl"); });
    },
    async "prepare:screenEvm"() {
      await setPage(page, screenHtml([screenCard(screens.vitalik, { compact: true, label: "vitalik.eth" }), screenCard(screens.lazarus, { compact: true })]), { waitUntil: "load" });
    },
    async screenEvm(seg, ms) { await reveal(".r", ms, 0.7); },
    async "prepare:screenAgent"() {
      await setPage(page, terminalHtml("An AI agent screening a wallet before it pays", screenAgentLines), { waitUntil: "load" });
      await aboveCaption();
    },
    async screenAgent(seg, ms) {
      await reveal(".l", ms, 0.8);
      await page.evaluate(() => { for (const el of document.querySelectorAll(".l.in, .l.ok")) el.classList.add("hl"); });
    },
    async "prepare:screenOpen"() {
      await setPage(page, terminalHtml("Free open data, and a screen for sellers", screenOpenLines), { waitUntil: "load" });
      await aboveCaption();
    },
    async screenOpen(seg, ms) {
      await reveal(".l", ms, 0.75);
      await page.evaluate(() => { for (const el of document.querySelectorAll(".l.ok")) el.classList.add("hl"); });
    },
    async "prepare:screenDoctor"() {
      await setPage(page, terminalHtml("x402 Doctor's pre-payment check, for buyers", screenDoctorLines), { waitUntil: "load" });
      await aboveCaption();
    },
    async screenDoctor(seg, ms) {
      await reveal(".l", ms, 0.75);
      await page.evaluate(() => { for (const el of document.querySelectorAll(".l.in, .l.ok")) el.classList.add("hl"); });
    },
    async card(seg) {
      await setPage(page, cardHtml(seg.card), { waitUntil: "load" });
    },
    async "prepare:hero"() {
      await page.goto(SITE, { waitUntil: "networkidle", timeout: 90000 });
      await zoomPage(page);
      await sleep(300);
    },
    async hero() {},
    async form(seg, ms) {
      await center(page, "#presets");
      await sleep(ms * 0.4);
      await glow(page, "#body");
    },
    async unlimited(seg, ms) { await showPreset(page, "unlimited", ms); },
    async permit(seg, ms) { await showPreset(page, "permit", ms); },
    async payment(seg, ms) { await showPreset(page, "payment", ms); },
    async agents(seg, ms) { await lines("An AI agent checking before it signs", agentLines, ms, 0.8); },
    async safe(seg, ms) { await lines("Fail-closed", safeLines, ms, 0.6); },
  };

  for (const seg of script.segments) {
    const ms = Math.round((durations[seg.id] || 3) * 1000);
    const scene = scenes[seg.scene];
    if (!scene) throw new Error(`unknown scene ${seg.scene}`);
    let action = null;
    if (scenes[`prepare:${seg.scene}`]) await scenes[`prepare:${seg.scene}`](seg, ms);
    if (seg.scene === "card") await scene(seg, ms);
    else action = scene(seg, ms);
    await caption(page, seg.text);
    const start = (Date.now() - t0) / 1000;
    timeline.push({ id: seg.id, start, duration: ms / 1000 });
    const minEnd = Date.now() + ms + 450;
    if (action) await action;
    const rest = minEnd - Date.now();
    if (rest > 0) await sleep(rest);
    console.log(`${seg.id}: ${start.toFixed(2)} s`);
  }
  await caption(page, "").catch(() => {});
  await sleep(1200);
  const total = (Date.now() - t0) / 1000;

  const videoPath = await page.video().path();
  await context.close();
  await browser.close();
  fs.renameSync(videoPath, path.join(OUT, "screen.webm"));
  fs.writeFileSync(path.join(OUT, "timeline.json"), JSON.stringify({ total, segments: timeline }, null, 2));
  console.log(`recorded ${total.toFixed(1)} s`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
