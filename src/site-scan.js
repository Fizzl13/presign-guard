// MetaMask's site scanner (run by Blockaid): the verdict behind MetaMask's
// "This website might be harmful" screen. Not the same as the static
// eth-phishing-detect list: it blocks domains that are on no list, with false
// positives (browser x402 payment pages get flagged as drainers), so a block is
// orange, never red. One GET per host, cached for an hour; null when unavailable.
//
// Off by default: the endpoint is internal to MetaMask (no published API or
// licence; MetaMask's terms cover its APIs, and Blockaid sells this verdict as a
// paid API). METAMASK_SCAN=on turns it on, e.g. once Blockaid grants access.

const SCAN_URL = "https://dapp-scanning.api.cx.metamask.io/scan?url=";
const TTL_MS = 60 * 60 * 1000;
const TIMEOUT_MS = 3000;
const cache = new Map();

export function resetSiteScan() { cache.clear(); }

// { action: "BLOCK" | "WARN" | "NONE" | ..., risks: [{ type, severity }] } or null.
export async function metamaskSiteScan(host) {
  if (process.env.METAMASK_SCAN !== "on") return null;
  const hit = cache.get(host);
  if (hit && hit.expires > Date.now()) return hit.value;
  let value = null;
  try {
    const res = await fetch(`${SCAN_URL}${encodeURIComponent(`https://${host}`)}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body = res.ok ? await res.json().catch(() => null) : null;
    if (body && typeof body.recommendedAction === "string") {
      value = {
        action: body.recommendedAction.toUpperCase(),
        risks: (Array.isArray(body.riskFactors) ? body.riskFactors : []).map((r) => ({ type: r.type ?? null, severity: r.severity ?? null })),
      };
    } else console.warn(`MetaMask site scan ${host}: ${res.ok ? "unexpected answer" : `HTTP ${res.status}`}`);
  } catch (e) {
    console.warn(`MetaMask site scan ${host}: ${e?.name === "TimeoutError" ? "timeout" : "network error"}`);
  }
  if (value) {
    cache.set(host, { value, expires: Date.now() + TTL_MS });
    if (cache.size > 5000) cache.delete(cache.keys().next().value);
  }
  return value;
}
