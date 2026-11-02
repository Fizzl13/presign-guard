// Toll (t0ll.xyz): launch facts for tokens on Robinhood Chain, Solana and BSC, as an extra source in /v1/token.
//
// GET https://t0ll.xyz/api/check?addr=<token>&chain=rh|sol|bsc&wait=1 reads, from the chain: who launched the coin
// (the dev), the dev's earlier launches and how many graduated, who funded the dev, the first buyers (snipers in the
// first 3 s, wallets that moved together), and Toll's findings ("flags": good, a note, or against).
//
// Partnership with Toll (2 Nov 2026): Toll's data is shown as a source with a link ("source: Toll"), never as the
// verdict. presign-guard's grade comes from its own checks; Toll's findings are added as one info reason at most.
// Render env TOLL_PASS (Toll's partner key, header x-toll-pass) raises the free limit of 10 new coins a day per IP;
// TOLL=off turns the source off. A slow, missing or failed answer is reported and skipped, never a reason to fail.

const TOLL_BASE = "https://t0ll.xyz";
const TIMEOUT_MS = 6000;
const TTL_MS = 10 * 60 * 1000;
const MAX_CACHE = 500;
const MAX_FLAGS = 8;

// presign-guard chain name → Toll's chain parameter.
export const TOLL_CHAINS = { robinhood: "rh", solana: "sol", bsc: "bsc" };

const cache = new Map(); // `${chain}:${address}` → { at, value }

export function tollEnabled(env = process.env) {
  return String(env.TOLL ?? "").toLowerCase() !== "off";
}

// The page a person opens for this token (the link "source: Toll" points at).
export function tollLink(chain, address) {
  const c = TOLL_CHAINS[chain];
  return c === "rh" ? `${TOLL_BASE}/check/${address}` : `${TOLL_BASE}/${c}/check/${address}`;
}

const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v, max = 300) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);

// Toll's answer, cut down to what an agent needs: the dev's record, the first buyers and the findings.
// Only known fields are copied, as plain values: nothing from Toll's answer is passed through as is.
export function summarizeToll(body, chain, address) {
  const dev = body?.dev && typeof body.dev === "object" ? body.dev : null;
  const early = body?.early && typeof body.early === "object" ? body.early : null;
  const flags = Array.isArray(body?.flags) ? body.flags : [];
  const tally = body?.tally?.combined;
  const findings = flags
    .filter((f) => f && typeof f === "object" && str(f.text))
    .slice(0, MAX_FLAGS)
    .map((f) => ({
      kind: f.good === true ? "good" : f.note === true ? "note" : "against",
      text: str(f.text),
      ...(str(f.when, 20) ? { when: str(f.when, 20) } : {}),
    }));
  return {
    source: "Toll",
    link: tollLink(chain, address),
    headline: str(body?.headline),
    dev: dev ? {
      address: str(dev.addr, 64),
      launches: num(dev.launches),
      graduated: num(dev.graduated),
      funder: str(dev.kin?.funder, 64),
    } : null,
    early_buyers: early ? {
      snipers: num(early.snipers),
      snipe_pct: num(early.snipe_pct),
      bundle_pct: num(early.bundle_pct),
      first_block_pct: num(early.first_block_pct),
      flagged_wallets: num(early.flagged?.wallets),
      flagged_bought_pct: num(early.flagged?.bought_pct),
    } : null,
    findings,
    tally: tally && typeof tally === "object"
      ? { against: num(tally.against), careful: num(tally.careful), clear: num(tally.clear) }
      : null,
    note: "Launch facts read by Toll (t0ll.xyz). Information, not part of presign-guard's verdict.",
  };
}

// One read. Resolves to { data } with the summary, or { error } saying why there is none (never throws).
export async function tollCheck(chain, address, { env = process.env, fetchImpl = globalThis.fetch, now = Date.now() } = {}) {
  if (!tollEnabled(env)) return { error: "off" };
  const c = TOLL_CHAINS[chain];
  if (!c) return { error: "chain not covered by Toll" };
  const key = `${chain}:${chain === "solana" ? address : address.toLowerCase()}`;
  const hit = cache.get(key);
  if (hit && now - hit.at < TTL_MS) return hit.value;

  const url = `${TOLL_BASE}/api/check?addr=${encodeURIComponent(address)}&chain=${c}&wait=1`;
  const headers = { accept: "application/json", "user-agent": "presign-guard (presign-guard.fizzl.eu)" };
  const pass = String(env.TOLL_PASS ?? "").trim();
  if (pass) headers["x-toll-pass"] = pass;
  let value;
  try {
    const res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (res.status === 200) {
      const body = await res.json();
      value = { data: summarizeToll(body, chain, address) };
    } else if (res.status === 202) {
      value = { error: "still reading", link: tollLink(chain, address) };
    } else if (res.status === 404) {
      value = { error: "not a token Toll knows" };
    } else if (res.status === 429) {
      value = { error: "rate limited" };
    } else {
      value = { error: `HTTP ${res.status}` };
    }
  } catch (err) {
    value = { error: err?.name === "TimeoutError" ? "timeout" : "unavailable" };
  }
  // Only whole answers and "no such token" are kept; a timeout or 202 is asked again next time.
  if (value.data || value.error === "not a token Toll knows") {
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(key, { at: now, value });
  }
  return value;
}

export function clearTollCache() { cache.clear(); }
