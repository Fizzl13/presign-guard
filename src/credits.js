// Prepaid credit packs: an agent buys 100 or 1000 credits in one x402 payment
// (cheaper than paying per call) and gets a credit key. Sending that key in the
// x-credit-key header then pays for checks without a new payment: a credit is
// one cent, so a check costs 1, the explained check 3, a token verdict 1 and a
// wallet approval audit 2. A call that fails (any 4xx or 5xx) gives its credits
// back. With no key, a wrong key or too few credits the normal 402 applies.
//
// Balances live in Redis (CREDITS_REDIS_URL, a persistent instance such as
// Upstash; Render only). Without it, packs are not sold at all, so nobody can
// buy credits that would vanish on a restart. Only a SHA-256 of each key is
// stored, never the key itself.
import { createHash, randomBytes } from "node:crypto";

export const CREDIT_HEADER = "x-credit-key";
export const PACKS = {
  "100": { credits: 100, price: "0.80" },
  "1000": { credits: 1000, price: "7.00" },
};
export const CREDIT_TTL_DAYS = 365;
const KEY_RE = /^pgc_[A-Za-z0-9_-]{43}$/;

export const hashKey = (key) => createHash("sha256").update(key).digest("hex");
export const newKey = () => `pgc_${randomBytes(32).toString("base64url")}`;
export const isKey = (key) => typeof key === "string" && KEY_RE.test(key);

// What a call costs in credits: its x402 price in cents ("$0.03" -> 3).
export function creditCosts(routes) {
  const costs = {};
  for (const [route, config] of Object.entries(routes)) {
    const price = String(config.accepts?.[0]?.price ?? "").replace("$", "");
    const cents = Math.round(Number(price) * 100);
    if (Number.isInteger(cents) && cents > 0) costs[route] = cents;
  }
  return costs;
}

// In-memory store, for tests and local runs only.
export function memoryStore({ now = () => Date.now() } = {}) {
  const balances = new Map();
  const live = (h) => {
    const e = balances.get(h);
    if (e && e.expiresAt <= now()) { balances.delete(h); return null; }
    return e;
  };
  return {
    persistent: false,
    async issue(hash, credits, ttlDays) { balances.set(hash, { credits, expiresAt: now() + ttlDays * 86400_000 }); },
    async balance(hash) { const e = live(hash); return e ? { credits: e.credits, expiresAt: e.expiresAt } : null; },
    async take(hash, n) {
      const e = live(hash);
      if (!e) return { ok: false, reason: "unknown" };
      if (e.credits < n) return { ok: false, reason: "insufficient", credits: e.credits };
      e.credits -= n;
      return { ok: true, credits: e.credits };
    },
    async refund(hash, n) { const e = live(hash); if (e) e.credits += n; },
  };
}

// Atomic: only take the credits when there are enough.
const TAKE = `local b = redis.call('GET', KEYS[1])
if not b then return -1 end
b = tonumber(b)
local n = tonumber(ARGV[1])
if b < n then return -2 - b end
return redis.call('DECRBY', KEYS[1], n)`;

export async function redisStore(url) {
  const { createClient } = await import("redis");
  const client = createClient({ url, socket: { reconnectStrategy: (tries) => Math.min(tries * 200, 5000) } });
  client.on("error", (err) => console.warn(`[credits] redis: ${err.message}`));
  await client.connect();
  const k = (hash) => `credits:${hash}`;
  return {
    persistent: true,
    async issue(hash, credits, ttlDays) { await client.set(k(hash), String(credits), { EX: ttlDays * 86400 }); },
    async balance(hash) {
      const [credits, ttl] = await Promise.all([client.get(k(hash)), client.ttl(k(hash))]);
      return credits === null ? null : { credits: Number(credits), expiresAt: ttl > 0 ? Date.now() + ttl * 1000 : null };
    },
    async take(hash, n) {
      const r = Number(await client.eval(TAKE, { keys: [k(hash)], arguments: [String(n)] }));
      if (r === -1) return { ok: false, reason: "unknown" };
      if (r < -1) return { ok: false, reason: "insufficient", credits: -2 - r };
      return { ok: true, credits: r };
    },
    async refund(hash, n) { await client.eval("if redis.call('EXISTS', KEYS[1]) == 1 then return redis.call('INCRBY', KEYS[1], ARGV[1]) end return 0", { keys: [k(hash)], arguments: [String(n)] }); },
    close: () => client.quit(),
  };
}

// The x402 routes that sell the packs.
export function packRoutes(network, payTo, solana = null) {
  const routes = {};
  for (const [size, pack] of Object.entries(PACKS)) {
    routes[`GET /v1/credits/${size}`] = {
      accepts: [
        { scheme: "exact", price: `$${pack.price}`, network, payTo },
        ...(solana?.payTo ? [{ scheme: "exact", price: `$${pack.price}`, network: solana.network, payTo: solana.payTo }] : []),
      ],
      description: `${pack.credits} prepaid presign-guard credits (1 credit = $0.01 of checks), valid ${CREDIT_TTL_DAYS} days. Returns a credit key for the ${CREDIT_HEADER} header.`,
      mimeType: "application/json",
    };
  }
  return routes;
}

// Free: how many credits a key has left.
export function creditsRouter(express, { store, costs, publicUrl }) {
  const router = express.Router();
  const info = { costs, header: CREDIT_HEADER, packs: Object.fromEntries(Object.entries(PACKS).map(([s, p]) => [s, { credits: p.credits, price_usd: p.price, buy: `${publicUrl}/v1/credits/${s}` }])) };
  router.get("/v1/credits", async (req, res) => {
    const key = req.get(CREDIT_HEADER);
    if (!key) return res.json({ ...info, credits: null });
    if (!isKey(key)) return res.status(400).json({ error: "invalid_key", message: `${CREDIT_HEADER} is not a credit key` });
    const b = await store.balance(hashKey(key));
    if (!b) return res.status(404).json({ error: "unknown_key", message: "No credits for this key (never bought, used up and expired, or mistyped)." });
    res.json({ ...info, credits: b.credits, expires_at: b.expiresAt ? new Date(b.expiresAt).toISOString() : null });
  });
  // Runs after the paywall: the payment for the pack is verified by now.
  router.get("/v1/credits/:size", async (req, res, next) => {
    const pack = PACKS[req.params.size];
    if (!pack) return next();
    const key = newKey();
    await store.issue(hashKey(key), pack.credits, CREDIT_TTL_DAYS);
    res.json({
      credit_key: key,
      credits: pack.credits,
      expires_at: new Date(Date.now() + CREDIT_TTL_DAYS * 86400_000).toISOString(),
      how_to_use: `Send the header "${CREDIT_HEADER}: <credit_key>" with any paid call; it is paid from your credits instead of a new payment. Costs per call: ${Object.entries(costs).map(([r, c]) => `${r} ${c}`).join(", ")}. Check your balance with GET ${publicUrl}/v1/credits and the same header.`,
      keep_it_secret: "Anyone with this key can spend these credits. It is not stored on our side, so it cannot be recovered.",
    });
  });
  return router;
}

// Before the paywall: pay a call from credits when a valid key with enough
// credits is sent. Sets req.fizzlCredits; refunds when the call fails.
export function payWithCredits({ store, costs }) {
  return async (req, res, next) => {
    const key = req.get(CREDIT_HEADER);
    const cost = costs[`${req.method} ${req.path}`];
    if (!key || !cost) return next();
    if (!isKey(key)) { res.set("x-credit-status", "invalid"); return next(); }
    const hash = hashKey(key);
    let taken;
    try { taken = await store.take(hash, cost); } catch (err) {
      console.warn(`[credits] take failed: ${err.message}`);
      res.set("x-credit-status", "unavailable");
      return next();
    }
    if (!taken.ok) {
      res.set("x-credit-status", taken.reason);
      if (taken.reason === "insufficient") res.set("x-credits-remaining", String(taken.credits));
      return next(); // falls through to the normal 402
    }
    req.fizzlCredits = { cost };
    res.set("x-credit-status", "paid");
    res.set("x-credits-remaining", String(taken.credits));
    res.on("finish", () => {
      if (res.statusCode >= 400) store.refund(hash, cost).catch((err) => console.warn(`[credits] refund failed: ${err.message}`));
    });
    next();
  };
}
