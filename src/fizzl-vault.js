// Fizzl Pass (phase 3): credit back into a vault, spendable at all four Fizzl services.
//
// Credit back: after a paid x402 (or MPP) call that settled, the service looks at who paid. When that wallet is
// covered by a Fizzl Pass, part of what was paid goes into the vault: 10% for Bronze, 20% for Silver, 30% for Gold.
// The wallet's pass is known from the X-Fizzl-Pass proof on the call (when it lists the paying wallet) or from the
// Agent Wallet's free check (GET wallet.fizzl.eu/v1/pass/status?wallet=…, kept 10 minutes). No client change needed.
//
// Spend: a call to a paid route with a valid X-Fizzl-Pass proof and no payment is paid from the vault when it holds
// enough; a call that fails (4xx or 5xx) gets it back. Without enough credit the normal 402 applies.
//
// The vault is one balance per wallet in the shared credits Redis (CREDITS_REDIS_URL, the same instance at all four
// services), in millionths of a dollar. A pass spends from all its wallets (the owner's and its agents'). Credit
// can only be spent at Fizzl, earns nothing and can't be paid out. Bronze and Silver credit ends 12 months after
// the wallet's last credit; Gold credit does not end. The same file is in presign-guard, ichimoku-signal and
// x402-doctor (also used by Fizzl Buy).
export const VAULT_SHARE = { bronze: 0.10, silver: 0.20, gold: 0.30 };
export const KEEP_DAYS = 365;
export const STATUS_URL = 'https://wallet.fizzl.eu/v1/pass/status';
const MICRO = 1e6;
const MAX_WALLETS = 50;
const RLUSD_HEX = '524C555344000000000000000000000000000000';

// One spelling per wallet (as the Agent Wallet's pass index): EVM addresses in lower case, others as they are.
export const walletKey = (w) => (/^0x[0-9a-fA-F]{40}$/.test(String(w)) ? String(w).toLowerCase() : String(w ?? '').trim());
const isWallet = (w) => /^0x[0-9a-fA-F]{40}$/.test(w) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(w) || /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(w) || /^[A-Z2-7]{58}$/.test(w);
const usdText = (micro) => Number((micro / MICRO).toFixed(6));
const ttlFor = (tier) => (tier === 'gold' ? 0 : KEEP_DAYS * 86400);

function decodeBase64Json(value) {
  if (!value) return null;
  try { return JSON.parse(Buffer.from(String(value), 'base64').toString('utf8')); } catch { return null; }
}

// Dollars in an x402 payment requirement: RLUSD on the XRP Ledger as a decimal, Stellar in 7 decimals, others in 6.
export function usdOf(accepted) {
  const amount = accepted && (accepted.amount || accepted.maxAmountRequired);
  if (amount === undefined || amount === null) return null;
  if (/^xrpl:/.test(String(accepted.network || ''))) return accepted.asset === RLUSD_HEX && /^\d+(\.\d+)?$/.test(String(amount)) ? Number(amount) : null;
  return /^\d+$/.test(String(amount)) ? Number(amount) / (/^stellar:/.test(String(accepted.network || '')) ? 1e7 : 1e6) : null;
}

// What a finished call was paid: { payer, usd }, from the settlement header and the payment header (or MPP). Null
// when it wasn't paid, didn't settle or failed.
export function paidOf(req, res) {
  if (res.statusCode >= 400) return null;
  const mpp = res.locals && res.locals.mppPayment;
  if (mpp) return mpp.payer && mpp.usd > 0 ? { payer: mpp.payer, usd: mpp.usd } : null;
  const settlement = decodeBase64Json(res.getHeader('PAYMENT-RESPONSE') || res.getHeader('X-PAYMENT-RESPONSE'));
  if (!settlement || settlement.success === false || !settlement.payer) return null;
  const payload = decodeBase64Json(req.headers['payment-signature'] || req.headers['x-payment']);
  const usd = usdOf(payload && (payload.accepted || payload.requirements));
  return usd > 0 ? { payer: settlement.payer, usd } : null;
}

// In-memory vault, for tests and local runs only.
export function memoryVault({ now = () => Date.now() } = {}) {
  const m = new Map(); // wallet -> { micro, expiresAt|null }
  const live = (k) => { const e = m.get(k); if (e && e.expiresAt && e.expiresAt <= now()) { m.delete(k); return null; } return e || null; };
  const add = (k, micro, ttl) => {
    const e = live(k) || { micro: 0, expiresAt: null };
    e.micro += micro;
    e.expiresAt = ttl > 0 ? now() + ttl * 1000 : null;
    m.set(k, e);
    return e.micro;
  };
  return {
    ready: true,
    async credit(k, micro, ttl) { return add(k, micro, ttl); },
    async refund(k, micro, ttl) { const e = live(k); if (e) { e.micro += micro; return e.micro; } return add(k, micro, ttl); },
    async balance(keys) { return keys.reduce((s, k) => s + (live(k)?.micro || 0), 0); },
    async take(keys, micro) {
      const total = keys.reduce((s, k) => s + (live(k)?.micro || 0), 0);
      if (total < micro) return { ok: false, balance: total };
      let left = micro;
      for (const k of keys) { const e = live(k); if (!e || left <= 0) continue; const t = Math.min(e.micro, left); e.micro -= t; left -= t; }
      return { ok: true, balance: total - micro };
    },
  };
}

// Atomic over the pass's wallets: only take when they hold enough together, then from the first wallets on.
const TAKE = `local need = tonumber(ARGV[1])
local total = 0
for _, k in ipairs(KEYS) do total = total + (tonumber(redis.call('GET', k) or '0') or 0) end
if total < need then return -1 - total end
local left = need
for _, k in ipairs(KEYS) do
  if left <= 0 then break end
  local b = tonumber(redis.call('GET', k) or '0') or 0
  if b > 0 then
    local t = math.min(b, left)
    redis.call('DECRBY', k, t)
    left = left - t
  end
end
return total - need`;
// Credit: add and (re)start the 12 months, or keep it for good (ttl 0). Refund: add, and only set an end on a new key.
const CREDIT = `local v = redis.call('INCRBY', KEYS[1], ARGV[1])
local ttl = tonumber(ARGV[2])
if ARGV[3] == 'refund' then
  if ttl > 0 and redis.call('TTL', KEYS[1]) == -1 then redis.call('EXPIRE', KEYS[1], ttl) end
elseif ttl > 0 then redis.call('EXPIRE', KEYS[1], ttl)
else redis.call('PERSIST', KEYS[1]) end
return v`;

function normalizeRedisUrl(raw) {
  const m = /rediss?:\/\/[^\s"'`)]+/.exec(String(raw ?? '').trim());
  if (!m) return null;
  try {
    const u = new URL(m[0]);
    return u.protocol === 'redis:' && /\.upstash\.io$/i.test(u.hostname) ? `rediss:${m[0].slice('redis:'.length)}` : m[0];
  } catch { return null; }
}

// The vault in Redis; connects in the background. ready stays false until the connection works (and calls throw).
// client: an already connected node-redis client to share (presign-guard's credits store) instead of a URL.
export function redisVault(rawUrl, { log = console, connect = null, client: shared = null } = {}) {
  const url = shared ? null : normalizeRedisUrl(rawUrl);
  const store = { ready: false };
  if (shared) Object.defineProperty(store, 'ready', { get: () => shared.isReady !== false, enumerable: true });
  else if (!url) { log.warn('[vault] off: CREDITS_REDIS_URL is not a redis:// or rediss:// URL'); return store; }
  let client = shared;
  const k = (w) => `fizzl-vault:${w}`;
  const need = () => { if (!store.ready) throw new Error('vault not connected'); return client; };
  if (!shared) (async () => {
    const { createClient } = connect ? { createClient: connect } : await import('redis');
    client = createClient({ url, socket: { reconnectStrategy: (tries) => Math.min(tries * 200, 5000) } });
    client.on('error', (err) => log.warn(`[vault] redis: ${err.message}`));
    await client.connect();
    client.unref?.(); // the HTTP server keeps the process up; the vault alone doesn't
    await client.ping();
    store.ready = true;
    log.log('[vault] on');
  })().catch((err) => log.warn(`[vault] off: ${err.message}`));
  Object.assign(store, {
    async credit(w, micro, ttl) { return Number(await need().eval(CREDIT, { keys: [k(w)], arguments: [String(micro), String(ttl), 'credit'] })); },
    async refund(w, micro, ttl) { return Number(await need().eval(CREDIT, { keys: [k(w)], arguments: [String(micro), String(ttl), 'refund'] })); },
    async balance(ws) { const vals = ws.length ? await need().mGet(ws.map(k)) : []; return vals.reduce((s, v) => s + (Number(v) || 0), 0); },
    async take(ws, micro) {
      const r = Number(await need().eval(TAKE, { keys: ws.map(k), arguments: [String(micro)] }));
      return r < 0 ? { ok: false, balance: -1 - r } : { ok: true, balance: r };
    },
  });
  return store;
}

// The vault for a service. store: memoryVault() or redisVault(); pass: the createPassVerifier() of lib/fizzl-pass.js.
export function createVault({ store, pass, statusUrl = STATUS_URL, fetchImpl = globalThis.fetch, now = () => Date.now(), log = console } = {}) {
  const known = new Map(); // wallet -> { tier|null, at }
  const enabled = () => Boolean(store && store.ready);

  // The tier of the pass that covers this wallet: from the call's own proof when it lists the wallet, else the
  // Agent Wallet's free check (kept 10 minutes, also "no pass"). Null without a pass or when the check fails.
  async function tierOf(wallet, req) {
    const claims = pass && req ? await pass.fromRequest(req).catch(() => null) : null;
    if (claims && (claims.wallets || []).map(walletKey).includes(wallet)) return claims.tier;
    const hit = known.get(wallet);
    if (hit && hit.at > now() - 10 * 60_000) return hit.tier;
    let tier = null;
    try {
      const res = await fetchImpl(`${statusUrl}?wallet=${encodeURIComponent(wallet)}`, { signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } });
      if (!res.ok) return null; // don't keep a failed check
      const body = await res.json();
      tier = body?.pass && body.pass.until > now() && VAULT_SHARE[body.pass.tier] ? body.pass.tier : null;
    } catch { return null; }
    known.set(wallet, { tier, at: now() });
    if (known.size > 5000) known.delete(known.keys().next().value);
    return tier;
  }

  // Credit back for one paid call. Returns the credit in millionths of a dollar (0 when none).
  async function creditPaid(req, res) {
    if (!enabled() || req.fizzlCredits || req.fizzlInternal) return 0;
    const paid = paidOf(req, res);
    if (!paid) return 0;
    const wallet = walletKey(paid.payer);
    if (!isWallet(wallet)) return 0;
    const tier = await tierOf(wallet, req);
    const micro = tier ? Math.floor(paid.usd * MICRO * VAULT_SHARE[tier]) : 0;
    if (micro <= 0) return 0;
    await store.credit(wallet, micro, ttlFor(tier));
    return micro;
  }

  // Middleware for every request (before the paywall): after a paid call finishes, credit back.
  function creditBack() {
    return (req, res, next) => {
      if (enabled()) res.on('finish', () => { creditPaid(req, res).catch((err) => log.warn(`[vault] credit: ${err.message}`)); });
      next();
    };
  }

  // Before the paywall: pay a call from the vault. priceOf(req) gives the route's price in dollars (null when free).
  // Sets req.fizzlCredits = { vault: micro } (so the paywall is skipped as for credits); gives it back on a failure.
  function payFromVault(priceOf) {
    return async (req, res, next) => {
      if (!enabled() || req.fizzlCredits || req.fizzlInternal || !req.headers['x-fizzl-pass']) return next();
      if (req.headers['payment-signature'] || req.headers['x-payment'] || req.headers['x-credit-key'] || /^Payment\s/i.test(req.headers.authorization || '')) return next();
      const usd = priceOf(req);
      if (!(usd > 0)) return next();
      const claims = pass ? await pass.fromRequest(req).catch(() => null) : null;
      const wallets = [...new Set((claims?.wallets || []).map(walletKey).filter(isWallet))].slice(0, MAX_WALLETS);
      if (!claims || !wallets.length) return next();
      const micro = Math.round(usd * MICRO);
      let taken;
      try { taken = await store.take(wallets, micro); } catch { res.set('x-fizzl-vault', 'unavailable'); return next(); }
      res.set('x-fizzl-vault-balance', String(usdText(taken.balance)));
      if (!taken.ok) { res.set('x-fizzl-vault', 'insufficient'); return next(); }
      req.fizzlCredits = { vault: micro, cost: 0 };
      res.set('x-fizzl-vault', 'paid');
      res.set('Cache-Control', 'private, no-store');
      res.on('finish', () => { if (res.statusCode >= 400) store.refund(wallets[0], micro, ttlFor(claims.tier)).catch(() => {}); });
      next();
    };
  }

  // GET <path>: what the vault is; with X-Fizzl-Pass, the pass's balance.
  function balanceHandler() {
    return async (req, res) => {
      res.set('Cache-Control', 'private, no-store');
      const info = {
        what: 'Fizzl Pass vault: part of every paid call to a Fizzl service comes back as credit (Bronze 10%, Silver 20%, Gold 30%), spendable at x402 Doctor, presign-guard, Ichimoku Signal and Fizzl Buy. Send your X-Fizzl-Pass proof with a paid call and no payment: it is paid from the vault when it holds enough.',
        share: VAULT_SHARE,
        keeps: 'Bronze and Silver: 12 months after the last credit. Gold: does not end.',
        on: enabled(),
      };
      if (!req.headers['x-fizzl-pass']) return res.json({ ...info, balance_usd: null });
      const claims = pass ? await pass.fromRequest(req).catch(() => null) : null;
      if (!claims) return res.status(401).json({ ...info, error: 'invalid_pass', message: 'X-Fizzl-Pass is not a valid, current Fizzl Pass proof.' });
      if (!enabled()) return res.status(503).json({ ...info, error: 'vault_unavailable' });
      const wallets = [...new Set((claims.wallets || []).map(walletKey).filter(isWallet))].slice(0, MAX_WALLETS);
      let micro;
      try { micro = await store.balance(wallets); } catch { return res.status(503).json({ ...info, error: 'vault_unavailable' }); }
      res.json({ ...info, tier: claims.tier, until: new Date(claims.until).toISOString(), wallets: wallets.length, balance_usd: usdText(micro) });
    };
  }

  return { creditBack, creditPaid, payFromVault, balanceHandler, tierOf, enabled };
}

