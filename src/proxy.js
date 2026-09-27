// How many proxies to trust for req.ip. Requests reach the app through three
// (the caller, then two hops, the last a private Render address: measured on
// x402-doctor, 26 Sep). With 1, req.ip was the Render hop, so the free MCP limit
// was shared by every caller and the usage log's visitor code was the same for
// nearly everyone. TRUST_PROXY_HOPS overrides it (a whole number from 0 to 10).
export function trustProxyHops(env = process.env) {
  const n = Number(env.TRUST_PROXY_HOPS);
  return Number.isInteger(n) && n >= 0 && n <= 10 && String(env.TRUST_PROXY_HOPS).trim() !== "" ? n : 3;
}
