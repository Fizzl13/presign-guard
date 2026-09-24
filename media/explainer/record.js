// Records the explainer video's picture: drives a real browser through the
// presign-guard homepage, timed to the narration (out/durations.json), with
// burned-in captions. Writes out/screen.webm and out/timeline.json.
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
const LIVE = "https://presign-guard.onrender.com";
const W = 1920;
const H = 1080;
const ZOOM = 2.0;

const script = JSON.parse(fs.readFileSync(path.join(HERE, "script.json"), "utf8"));
const durations = JSON.parse(fs.readFileSync(path.join(OUT, "durations.json"), "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");

const THEME = `
  :root { --bg:#0f1115; --panel:#171a21; --line:#2a2f3a; --text:#f3f4f6; --soft:#9ca3af; --bull:#6ee7b7; --red:#fca5a5; --accent:#a78bfa; --warn:#fcd34d; }
  html, body { margin:0; height:100%; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,'Segoe UI',sans-serif; }
`;

function cardHtml({ title, sub, note }) {
  return `<!doctype html><html><head><style>${THEME}
    body { display:flex; align-items:center; justify-content:center; }
    .c { text-align:center; animation: in .6s ease-out both; padding: 0 120px; }
    h1 { font-size: 120px; margin: 0 0 24px; letter-spacing: -0.02em; }
    p { font-size: 52px; color: var(--soft); margin: 0; }
    .note { font-family: ui-monospace, 'DejaVu Sans Mono', monospace; font-size: 30px; margin-top: 44px; color: var(--accent); }
    @keyframes in { from { opacity:0; transform: translateY(24px);} to { opacity:1; transform:none; } }
  </style></head><body><div class="c"><h1>${esc(title)}</h1><p>${esc(sub || '')}</p>${note ? `<p class="note">${esc(note)}</p>` : ''}</div></body></html>`;
}

function terminalHtml(label, lines) {
  return `<!doctype html><html><head><style>${THEME}
    body { display:flex; align-items:center; justify-content:center; }
    .t { width: 1560px; background: var(--panel); border:1px solid var(--line); border-radius: 18px; padding: 36px 44px; box-shadow: 0 30px 80px rgba(0,0,0,.5); }
    .bar { display:flex; gap:10px; margin-bottom: 26px; } .bar i { width:16px; height:16px; border-radius:50%; background:#30363d; display:block; }
    .label { color: var(--soft); font-size: 24px; margin: -8px 0 22px; }
    pre { margin:0; font: 29px/1.55 ui-monospace, 'DejaVu Sans Mono', monospace; white-space: pre-wrap; }
    .l { opacity: 0; transition: opacity .35s; } .l.on { opacity: 1; }
    .in { color: var(--warn); } .ok { color: var(--bull); } .dim { color: var(--soft); }
    .hl { background: rgba(110,231,183,.14); border-radius: 6px; outline: 2px solid var(--bull); }
  </style></head><body><div class="t"><div class="bar"><i></i><i></i><i></i></div><div class="label">${esc(label)}</div><pre>${lines
    .map((l, i) => `<div class="l ${l.cls || ''}" id="l${i}">${esc(l.text)}</div>`)
    .join('')}</pre></div></body></html>`;
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
          'background:rgba(0,0,0,.8);color:#fff;font:600 38px/1.35 system-ui,-apple-system,"Segoe UI",sans-serif;' +
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
const glow = (page, selector, color = "rgba(167,139,250,.55)") =>
  page.evaluate(({ selector, color }) => {
    const el = document.querySelector(selector);
    el.style.transition = "box-shadow .3s";
    el.style.boxShadow = `0 0 0 5px ${color}`;
  }, { selector, color });

// The price an agent sees, from the live 402 challenge.
async function livePrice() {
  if (process.env.MOCK_LIVE === "1") return "$0.01 USDC on Base";
  const res = await fetch(`${LIVE}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  if (res.status !== 402) throw new Error(`expected 402 from ${LIVE}/v1/check, got ${res.status}`);
  const challenge = JSON.parse(Buffer.from(res.headers.get("payment-required"), "base64").toString("utf8"));
  const a = challenge.accepts.find((x) => x.network === "eip155:8453");
  if (!a) throw new Error("live service offers no Base option");
  return `$${(Number(a.amount) / 1e6).toFixed(2)} USDC on Base`;
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
  const price = await livePrice();
  const agentLines = [
    { cls: "", text: "$ POST presign-guard.onrender.com/v1/check   { what the agent is about to sign }" },
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
    await page.setContent(terminalHtml(label, list), { waitUntil: "load" });
    for (let i = 0; i < list.length; i++) {
      await page.evaluate((i) => document.getElementById(`l${i}`).classList.add("on"), i);
      await sleep(Math.max(250, (ms * share) / list.length));
    }
    await page.evaluate(() => { for (const el of document.querySelectorAll(".l.in, .l.ok")) el.classList.add("hl"); });
  };

  const scenes = {
    async card(seg) {
      await page.setContent(cardHtml(seg.card), { waitUntil: "load" });
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
