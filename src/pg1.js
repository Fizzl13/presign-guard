// PG1 (pg1-ai-agent.vercel.app), a free MCP server built on public data:
// - check_wallet_sanctions: the address against the OFAC SDN list (US Treasury, synced daily).
// - check_domain_age: RDAP registration age of a domain.
// - check_hostname_reputation: MetaMask's eth-phishing-detect block/allowlist
//   plus PG1's lookalike detection (synced daily).
// Used as an extra source, credited as "pg1" in `sources`. When PG1 is slow or down,
// the check goes on without it and says so (info), never a 503: GoPlus also carries
// a sanctions flag, and a missing domain age is not a warning.

const PG1_URL = () => process.env.PG1_MCP_URL || "https://pg1-ai-agent.vercel.app/api/mcp";
const PG1_TIMEOUT_MS = 3000;
const SANCTIONS_TTL_MS = 60 * 60 * 1000;      // the list syncs daily
const DOMAIN_TTL_MS = 24 * 60 * 60 * 1000;   // PG1 caches RDAP answers for 24 h too
const REPUTATION_TTL_MS = 60 * 60 * 1000;    // the lists sync daily; new phishing sites appear fast
const RATE_LIMIT_PAUSE_MS = 5 * 60 * 1000;
export const NEW_DOMAIN_DAYS = 30;

const cache = new Map();
async function cached(key, ttl, fn) {
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return hit.value;
  const value = await fn();
  if (value !== null) {
    cache.set(key, { value, expires: Date.now() + ttl });
    if (cache.size > 5000) cache.delete(cache.keys().next().value);
  }
  return value;
}

let rpcId = 0;
// Anonymous callers get 60 calls an hour per IP (shared on Render); PG1_API_KEY
// (the PG1 membership key, set in Render only) is exempt. After a rate_limited
// answer PG1 is left alone for a few minutes instead of being asked again.
let pausedUntil = 0;
export const pg1Paused = () => Date.now() < pausedUntil;
export function resetPg1() { pausedUntil = 0; cache.clear(); keyStatus = null; lastKnown = null; }

// One tools/call; the tool's JSON result, or null when PG1 can't be used right now.
// A timeout, network error or 5xx (e.g. a Vercel cold start) is tried once more.
// Each failure is logged with its reason, never with the key or the arguments.
async function callTool(name, args) {
  if (process.env.PG1_DISABLED === "1" || pg1Paused()) return null;
  const first = await attempt(name, args);
  if (!first.fail) return first.out;
  if (!first.retry) { console.warn(`PG1 ${name}: ${first.fail}`); return null; }
  const second = await attempt(name, args);
  if (!second.fail) { console.warn(`PG1 ${name}: ${first.fail}, retry ok`); return second.out; }
  console.warn(`PG1 ${name}: ${first.fail}, retry ${second.fail}`);
  return null;
}

// { out } on success, else { fail: reason, retry: whether trying again can help }.
async function attempt(name, args) {
  const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };
  const key = process.env.PG1_API_KEY?.trim();
  if (key) headers["x-api-key"] = key;
  const started = Date.now();
  let res;
  try {
    res = await fetch(PG1_URL(), {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
      signal: AbortSignal.timeout(PG1_TIMEOUT_MS),
    });
  } catch (e) {
    const timedOut = e?.name === "TimeoutError" || e?.name === "AbortError";
    return { fail: timedOut ? `timeout after ${Date.now() - started} ms` : `network error (${e?.cause?.code ?? e?.name ?? "unknown"})`, retry: true };
  }
  if (res.status === 429) { pausedUntil = Date.now() + RATE_LIMIT_PAUSE_MS; return { fail: "HTTP 429, paused 5 min", retry: false }; }
  if (!res.ok) return { fail: `HTTP ${res.status}`, retry: res.status >= 500 };
  try {
    const text = await res.text();
    const sse = text.match(/^data: (.*)$/m);
    const body = JSON.parse(sse ? sse[1] : text);
    const result = body?.result;
    if (!result) return { fail: `no result${body?.error?.code != null ? ` (JSON-RPC error ${body.error.code})` : ""}`, retry: false };
    if (result.isError) {
      const limited = /rate_limited/.test(JSON.stringify(result));
      if (limited) pausedUntil = Date.now() + RATE_LIMIT_PAUSE_MS;
      return { fail: limited ? "rate_limited, paused 5 min" : "tool error", retry: false };
    }
    if (result.structuredContent && typeof result.structuredContent === "object") return { out: result.structuredContent };
    const out = JSON.parse(result.content?.[0]?.text ?? "null");
    return out && typeof out === "object" ? { out } : { fail: "empty result", retry: false };
  } catch (e) {
    return { fail: e?.name === "TimeoutError" ? `timeout after ${Date.now() - started} ms` : "unreadable response", retry: e?.name === "TimeoutError" };
  }
}

// Whether PG1 accepts PG1_API_KEY, for /health: "unset", PG1's license_status
// (e.g. "invalid_or_expired" for a wrong key), or "unknown" when PG1 can't be
// asked. Only the status leaves this function, never the key. Cached for an hour.
let keyStatus = null;
export async function pg1KeyStatus() {
  const key = process.env.PG1_API_KEY?.trim();
  if (!key) return "unset";
  if (keyStatus && keyStatus.expires > Date.now() && keyStatus.key === key) return keyStatus.value;
  const r = await callTool("get_usage_status", { license_key: key });
  const value = r && typeof r.license_status === "string" && r.license_status ? r.license_status.slice(0, 40) : "unknown";
  if (value !== "unknown") keyStatus = { key, value, expires: Date.now() + 60 * 60 * 1000 };
  return value;
}

// For /health, which Render also uses as its health check: never waits on PG1.
// Returns the last known status ("checking" before the first answer) and refreshes in the background.
let lastKnown = null;
let refreshing = false;
export function pg1KeyStatusNow() {
  if (!process.env.PG1_API_KEY?.trim()) return "unset";
  if (!refreshing && !(keyStatus && keyStatus.expires > Date.now())) {
    refreshing = true;
    pg1KeyStatus().then((v) => { lastKnown = v; }).catch(() => {}).finally(() => { refreshing = false; });
  }
  return keyStatus?.value ?? lastKnown ?? "checking";
}

// { listed, matches: [{ sdnName, programs }], listSynced } or null.
// Only call with an address that is already validated (PG1 answers "not listed" for anything).
export function screenSanctions(address) {
  return cached(`sanctions:${address.toLowerCase()}`, SANCTIONS_TTL_MS, async () => {
    const r = await callTool("check_wallet_sanctions", { address });
    if (!r || typeof r.listed !== "boolean") return null;
    return {
      listed: r.listed,
      matches: (Array.isArray(r.matches) ? r.matches : []).map((m) => ({ sdnName: m.sdn_name ?? null, programs: m.programs ?? [], sdnUid: m.sdn_uid ?? null })),
      listSynced: r.list_last_synced ?? null,
    };
  });
}

// { domain, found: true, ageDays, registered } | { domain, found: false, unregistered, reason } | null.
export function domainAge(host) {
  return cached(`domain:${host}`, DOMAIN_TTL_MS, async () => {
    const r = await callTool("check_domain_age", { domain: host });
    if (!r) return null;
    const found = r.found ?? r.available;
    if (found && Number.isFinite(Number(r.age_days))) {
      return { domain: r.domain ?? host, found: true, ageDays: Number(r.age_days), registered: r.registration_date ?? null };
    }
    const reason = String(r.reason ?? "");
    // RDAP 404 = the registry has no such domain; anything else = unknown (e.g. no RDAP for the TLD).
    return { domain: r.domain ?? host, found: false, unregistered: /\b404\b/.test(reason), reason: reason.slice(0, 200) };
  });
}

// { verdict: "listed" | "lookalike" | "allowlisted" | "not_listed", matchType, lookalikeOf, listSynced } or null.
// not_listed means "not on the lists", never "safe"; PG1 errors instead of a false not_listed.
export function hostnameReputation(host) {
  return cached(`reputation:${host}`, REPUTATION_TTL_MS, async () => {
    const r = await callTool("check_hostname_reputation", { hostname: host });
    if (!r || !["listed", "lookalike", "allowlisted", "not_listed"].includes(r.verdict)) return null;
    const source = Array.isArray(r.sources) ? r.sources[0] : null;
    return { verdict: r.verdict, matchType: source?.match_type ?? null, lookalikeOf: r.lookalike_of ?? null, listSynced: r.list_synced_at ?? null };
  });
}

// The host a signature request comes from: a URL or a bare hostname.
// Null for local and IP origins, where a domain age means nothing.
export function originHost(origin) {
  const raw = String(origin).trim();
  let host;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    return undefined;
  }
  if (host === "localhost" || host.endsWith(".localhost") || host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null;
  if (!host.includes(".") || host.length > 253) return undefined;
  return host;
}
