// PG1 (pg1-ai-agent.vercel.app), a free MCP server built on public data:
// - check_wallet_sanctions: the address against the OFAC SDN list (US Treasury, synced daily).
// - check_domain_age: RDAP registration age of a domain.
// Used as an extra source, credited as "pg1" in `sources`. When PG1 is slow or down,
// the check goes on without it and says so (info), never a 503: GoPlus also carries
// a sanctions flag, and a missing domain age is not a warning.

const PG1_URL = () => process.env.PG1_MCP_URL || "https://pg1-ai-agent.vercel.app/api/mcp";
const PG1_TIMEOUT_MS = 3000;
const SANCTIONS_TTL_MS = 60 * 60 * 1000;      // the list syncs daily
const DOMAIN_TTL_MS = 6 * 60 * 60 * 1000;
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
// One tools/call; the tool's JSON result, or null when PG1 can't be used right now.
async function callTool(name, args) {
  if (process.env.PG1_DISABLED === "1") return null;
  try {
    const res = await fetch(PG1_URL(), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
      signal: AbortSignal.timeout(PG1_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const text = await res.text();
    const sse = text.match(/^data: (.*)$/m);
    const body = JSON.parse(sse ? sse[1] : text);
    const result = body?.result;
    if (!result || result.isError) return null;
    if (result.structuredContent && typeof result.structuredContent === "object") return result.structuredContent;
    const out = JSON.parse(result.content?.[0]?.text ?? "null");
    return out && typeof out === "object" ? out : null;
  } catch {
    return null;
  }
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
