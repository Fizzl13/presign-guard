// Fizzl Pass (phase 2, the same as x402-doctor's lib/fizzl-pass.js): a pass holder's agent sends its signed proof in the X-Fizzl-Pass header and gets higher free
// limits. The proof ("fzp1.<claims>.<signature>", Ed25519) is made by the Agent Wallet (wallet.fizzl.eu, src/pass.js)
// and checked here offline with the public key the wallet publishes at /.well-known/fizzl-pass.json (fetched once,
// kept 6 hours). The proof is a bearer token: whoever sends it gets the pass's limits, counted per pass (not per IP),
// until the pass ends. A missing, broken, expired or foreign proof is ignored: the normal limits apply.
import crypto from "node:crypto";

export const DEFAULT_JWKS = 'https://wallet.fizzl.eu/.well-known/fizzl-pass.json';
export const HEADER = 'x-fizzl-pass';
// How many times the normal free limits each tier gets.
export const LIMIT_FACTOR = { bronze: 5, silver: 10, gold: 25 };
const TTL_MS = 6 * 60 * 60 * 1000;
const RETRY_MS = 5 * 60 * 1000;

export function createPassVerifier({ jwksUrl = DEFAULT_JWKS, fetchImpl = globalThis.fetch, now = () => Date.now(), keys: fixed = null } = {}) {
  let keys = fixed ? toKeys(fixed) : null;
  let loadedAt = fixed ? Infinity : 0;
  let failedAt = 0;
  let pending = null;

  async function load() {
    if (pending) return pending;
    pending = (async () => {
      try {
        const res = await fetchImpl(jwksUrl, { signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        keys = toKeys(await res.json());
        loadedAt = now();
      } catch {
        failedAt = now();
      } finally {
        pending = null;
      }
    })();
    return pending;
  }

  // The claims of a valid, unexpired proof with a known tier; null otherwise.
  function verify(token) {
    const parts = String(token ?? '').trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'fzp1' || !keys) return null;
    let claims;
    try { claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch { return null; }
    const key = keys.get(claims?.kid);
    if (!key) return null;
    let ok = false;
    try { ok = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url')); } catch { return null; }
    if (!ok || !(claims.until > now()) || !LIMIT_FACTOR[claims.tier]) return null;
    return { ...claims, ref: crypto.createHash('sha256').update(token).digest('hex').slice(0, 16) };
  }

  // The pass in the request's X-Fizzl-Pass header, or null. Loads the public key the first time (and every 6 hours).
  async function fromRequest(req) {
    const token = req?.headers?.[HEADER];
    if (!token) return null;
    const stale = now() - loadedAt > TTL_MS;
    if ((!keys || stale) && now() - failedAt > RETRY_MS) await load();
    return verify(Array.isArray(token) ? token[0] : token);
  }

  return { fromRequest, verify, factor: (claims) => LIMIT_FACTOR[claims?.tier] || 1 };
}

function toKeys(jwks) {
  const out = new Map();
  for (const k of jwks?.keys || []) {
    if (k?.kty !== 'OKP' || k.crv !== 'Ed25519' || !k.x || !k.kid) continue;
    try { out.set(k.kid, crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' })); } catch { /* skip a bad key */ }
  }
  return out;
}

// The rate-limit key and factor for a request: the pass (per pass, the tier's factor) or the caller's IP (factor 1).
export async function limitKeyOf(pass, req, ip = req.ip) {
  const claims = pass ? await pass.fromRequest(req).catch(() => null) : null;
  return claims ? { key: `pass:${claims.ref}`, factor: pass.factor(claims), claims } : { key: ip, factor: 1, claims: null };
}

