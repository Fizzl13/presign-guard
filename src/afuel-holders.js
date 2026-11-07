// $AFUEL holder tiers: a bot whose wallet holds AFUEL gets a few paid calls a day for free.
//
// The same signed headers as api.agentfuel.eu, so one signing helper works on both:
//   X-Wallet: <base58 Solana address>
//   X-Wallet-Timestamp: <unix seconds, within 5 minutes>
//   X-Wallet-Signature: <base58 ed25519 signature of "agent-coin-api:<timestamp>">
// The signature proves the bot holds the wallet's key (otherwise anyone could name a large holder's address).
// The AFUEL balance is read on-chain (cached a minute per wallet). Nothing is locked or staked.
//
// Thresholds as on agentfuel.eu, fewer free calls (Frits, 7 Nov 2026): at launch prices 1M AFUEL is about $3, and
// 5,000 free checks a day would be $50. So per wallet per day: Bronze 20, Silver 100, Gold 500; and all
// holders together at most AFUEL_HOLDER_DAILY_CAP (default 2,000) free calls a day, against moving the same tokens
// through new wallets. Only calls priced up to AFUEL_HOLDER_MAX_USD (default $0.01) are free: dearer checks stay paid.
// Counts live in memory: a restart starts the day's counts again.
//
// On with AFUEL_PAYMENTS=on, unless AFUEL_HOLDERS=off. HTTP paywall only (like AFUEL payments); MCP tools are unchanged.

import crypto from 'node:crypto';
import { AFUEL_MINT, AFUEL_DECIMALS } from './afuel.js';

const TIERS = [
  { name: 'gold', minTokens: 1_000_000, freePerDay: 500 },
  { name: 'silver', minTokens: 250_000, freePerDay: 100 },
  { name: 'bronze', minTokens: 100_000, freePerDay: 20 },
];
const MAX_SKEW_S = 300;
const BALANCE_TTL_MS = 60_000;
const MAX_CACHED = 5_000;
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Base58 to bytes, or null for anything that is not base58. */
function b58decode(s) {
  if (typeof s !== 'string' || !s || s.length > 120) return null;
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of s) { if (c !== '1') break; bytes.unshift(0); }
  return Buffer.from(bytes);
}

const authMessage = (ts) => `agent-coin-api:${ts}`;

/** True when signature is the wallet's ed25519 signature of agent-coin-api:<timestamp>, made within 5 minutes. */
function verifyWalletSignature(wallet, timestamp, signature, nowS = Math.floor(Date.now() / 1000)) {
  const ts = Number(timestamp);
  if (!/^\d{1,12}$/.test(String(timestamp)) || Math.abs(nowS - ts) > MAX_SKEW_S) return false;
  const pub = b58decode(wallet);
  const sig = b58decode(signature);
  if (!pub || !sig || pub.length !== 32 || sig.length !== 64) return false;
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, pub]), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(authMessage(ts)), key, sig);
  } catch {
    return false;
  }
}

/** The tier for a raw balance (base units), or null below Bronze. */
function tierFor(raw, decimals = AFUEL_DECIMALS) {
  const whole = BigInt(raw) / 10n ** BigInt(decimals);
  return TIERS.find((t) => whole >= BigInt(t.minTokens)) || null;
}

const carriesPayment = (req) => Boolean(req.headers['payment-signature'] || req.headers['x-payment'] || req.headers['x-credit-key'] || /^Payment\s/i.test(req.headers.authorization || ''));

function createHolders({ env = process.env, fetchImpl = globalThis.fetch, now = () => Date.now(), log = console } = {}) {
  const enabled = env.AFUEL_PAYMENTS === 'on' && env.AFUEL_HOLDERS !== 'off';
  const mint = env.AFUEL_MINT?.trim() || AFUEL_MINT;
  const rpcUrl = env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
  const dailyCap = Math.max(0, Number(env.AFUEL_HOLDER_DAILY_CAP ?? 2000) || 0);
  const maxUsd = Number(env.AFUEL_HOLDER_MAX_USD ?? 0.01) || 0;
  const balances = new Map(); // wallet -> { at, raw }
  let day = '';
  let used = new Map(); // wallet -> free calls today
  let usedTotal = 0;

  function today() {
    const d = new Date(now()).toISOString().slice(0, 10);
    if (d !== day) { day = d; used = new Map(); usedTotal = 0; }
    return d;
  }

  async function balanceOf(wallet) {
    const hit = balances.get(wallet);
    if (hit && now() - hit.at < BALANCE_TTL_MS) return hit.raw;
    const res = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTokenAccountsByOwner', params: [wallet, { mint }, { encoding: 'jsonParsed' }] }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) throw new Error(`Solana RPC HTTP ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`Solana RPC ${body.error.message ?? 'error'}`);
    let raw = 0n;
    for (const a of body.result?.value ?? []) raw += BigInt(a?.account?.data?.parsed?.info?.tokenAmount?.amount ?? 0);
    if (balances.size >= MAX_CACHED) balances.delete(balances.keys().next().value);
    balances.set(wallet, { at: now(), raw });
    return raw;
  }

  /** { wallet, tier, freeLeft } for a request with valid wallet headers; null without them; throws on RPC failure. */
  async function fromRequest(req) {
    const wallet = req.headers['x-wallet'];
    const ts = req.headers['x-wallet-timestamp'];
    const sig = req.headers['x-wallet-signature'];
    if (!wallet && !ts && !sig) return null;
    if (!verifyWalletSignature(wallet, ts, sig, Math.floor(now() / 1000))) return { invalid: true };
    const tier = tierFor(await balanceOf(wallet));
    today();
    const freeLeft = tier ? Math.max(0, tier.freePerDay - (used.get(wallet) || 0)) : 0;
    return { wallet, tier, freeLeft };
  }

  // Before the paywall: a holder's call is free while its tier has calls left today (and the daily cap allows).
  // Sets req.fizzlCredits = { holder, wallet, cost: 0 }, so the paywall is skipped as for credits; a failed call
  // (status 400 or more) gives the free call back. priceOf(req) gives the route's price in dollars (null when free).
  function payWithHolding(priceOf) {
    return async (req, res, next) => {
      if (!enabled || req.fizzlCredits || req.fizzlInternal || !req.headers['x-wallet'] || carriesPayment(req)) return next();
      const usd = priceOf(req);
      if (!(usd > 0) || usd > maxUsd + 1e-9) return next();
      let h;
      try { h = await fromRequest(req); } catch (err) {
        log.warn?.(`[afuel-holders] balance: ${err.message}`);
        res.set('x-afuel-holder', 'unavailable');
        return next();
      }
      if (!h) return next();
      if (h.invalid) { res.set('x-afuel-holder', 'invalid_signature'); return next(); }
      if (!h.tier) { res.set('x-afuel-holder', 'below_bronze'); return next(); }
      res.set('x-afuel-tier', h.tier.name);
      if (h.freeLeft < 1) { res.set('x-afuel-holder', 'used_up'); res.set('x-afuel-free-remaining', '0'); return next(); }
      if (usedTotal >= dailyCap) { res.set('x-afuel-holder', 'daily_cap'); return next(); }
      used.set(h.wallet, (used.get(h.wallet) || 0) + 1);
      usedTotal += 1;
      const countedDay = day;
      req.fizzlCredits = { holder: h.tier.name, wallet: h.wallet, cost: 0 };
      res.set('x-afuel-holder', 'free');
      res.set('x-afuel-free-remaining', String(h.freeLeft - 1));
      res.set('Cache-Control', 'private, no-store');
      res.on('finish', () => {
        if (res.statusCode < 400 || day !== countedDay) return;
        used.set(h.wallet, Math.max(0, (used.get(h.wallet) || 1) - 1));
        usedTotal = Math.max(0, usedTotal - 1);
      });
      next();
    };
  }

  // GET <path>: the tiers and how to sign; with the wallet headers, that wallet's tier and free calls left today.
  function statusHandler() {
    return async (req, res) => {
      res.set('Cache-Control', 'private, no-store');
      const info = {
        what: 'Bots whose Solana wallet holds $AFUEL get some paid calls free each day. Sign "agent-coin-api:<unix seconds>" with the wallet key and send X-Wallet, X-Wallet-Timestamp and X-Wallet-Signature (base58), the same headers as api.agentfuel.eu and x402 Doctor. Nothing is locked or staked; the balance is read on-chain. HTTP API only.',
        mint,
        tiers: TIERS.map((t) => ({ tier: t.name, min_afuel: t.minTokens, free_calls_per_day: t.freePerDay })),
        free_on: `paid HTTP calls priced up to $${maxUsd}`,
        daily_cap_all_holders: dailyCap,
        on: enabled,
        facts: 'https://agentfuel.eu/token',
      };
      if (!req.headers['x-wallet']) return res.json(info);
      if (!enabled) return res.status(503).json({ ...info, error: 'holders_off' });
      let h;
      try { h = await fromRequest(req); } catch { return res.status(503).json({ ...info, error: 'balance_unavailable' }); }
      if (h.invalid) return res.status(401).json({ ...info, error: 'invalid_signature', message: 'X-Wallet-Signature must sign "agent-coin-api:<X-Wallet-Timestamp>" with the X-Wallet key, within 5 minutes.' });
      res.json({ ...info, wallet: h.wallet, tier: h.tier ? h.tier.name : null, free_calls_left_today: h.freeLeft });
    };
  }

  return { enabled, payWithHolding, statusHandler, fromRequest, status: () => ({ on: enabled, day, used_today: usedTotal, daily_cap: dailyCap }) };
}

export { TIERS, authMessage, b58decode, verifyWalletSignature, tierFor, createHolders };
