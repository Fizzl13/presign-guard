// xrp-rate.js
//
// XRP as a payment option next to RLUSD on the XRP Ledger. A route's price is in dollars, so a payment in XRP needs
// the dollar price of XRP; it is read from the ledger itself, the XRP/RLUSD AMM pool (amm_info: RLUSD in the pool
// divided by XRP in the pool), with no outside price API.
//
// The amount in drops has to be the same when the 402 is made and when the signed payment comes back (x402 matches
// the payment against the requirements it builds again), so the rate does not follow every tick:
// - it is read at most every refreshMs (10 minutes), in the background, never while a request waits;
// - a new reading replaces the rate only when it is more than `band` (2%) away from it;
// - the drops are rounded up to three significant digits (at most 1% above the price).
// Until a first reading, and after the last reading is older than staleMs (an hour), there is no rate and the XRP
// option is left out of the 402 (the price function returns null; facilitator-start.js then skips the option).
//
// The same file is copied into each Fizzl service.

'use strict';

const RLUSD_HEX = '524C555344000000000000000000000000000000';
const RLUSD_ISSUER = 'rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De';

// Dollars ("$0.01", "0.01" or 0.01) to drops of XRP at `usdPerXrp`, rounded up to three significant digits.
function dropsFor(usd, usdPerXrp) {
  const dollars = Number(String(usd).replace(/^\$/, ''));
  if (!(dollars > 0) || !(usdPerXrp > 0)) return null;
  const exact = Math.ceil((dollars / usdPerXrp) * 1e6);
  const step = 10 ** Math.max(0, Math.floor(Math.log10(exact)) - 2);
  return String(Math.ceil(exact / step) * step);
}

// The pool's price from an amm_info result: RLUSD per XRP, or null.
function rateOfPool(amm) {
  if (!amm || typeof amm.amount !== 'string' || !amm.amount2) return null;
  const { currency, issuer, value } = amm.amount2;
  if (currency !== RLUSD_HEX || issuer !== RLUSD_ISSUER) return null;
  const xrp = Number(amm.amount) / 1e6;
  const usd = Number(value);
  return xrp > 0 && usd > 0 ? usd / xrp : null;
}

const readPool = (rpcUrl) => async () => {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ method: 'amm_info', params: [{ asset: { currency: 'XRP' }, asset2: { currency: RLUSD_HEX, issuer: RLUSD_ISSUER }, ledger_index: 'validated' }] }),
    signal: AbortSignal.timeout(5000),
  });
  const body = await res.json();
  return rateOfPool(body && body.result && body.result.amm);
};

function createXrpRate({ rpcUrl = process.env.XRPL_RPC_URL || 'https://xrplcluster.com', read = readPool(rpcUrl), refreshMs = 10 * 60 * 1000, staleMs = 60 * 60 * 1000, band = 0.02, now = () => Date.now(), log = console } = {}) {
  let rate = null;
  let readAt = 0;
  let asking = null;
  let askedAt = -Infinity;

  function refresh() {
    askedAt = now();
    asking ??= (async () => {
      try {
        const fresh = await read();
        if (!(fresh > 0)) throw new Error('no XRP/RLUSD pool price');
        if (rate === null || Math.abs(fresh - rate) / rate > band) rate = fresh;
        readAt = now();
      } catch (err) {
        log.warn?.(`[xrp] rate: ${err.message}`);
      }
    })().finally(() => { asking = null; });
    return asking;
  }

  // Dollars per XRP, or null when there is no reading or it is too old. Starts a background reading when due.
  function usdPerXrp() {
    if (now() - askedAt >= refreshMs) refresh();
    return rate !== null && now() - readAt < staleMs ? rate : null;
  }

  // An x402 price function for a dollar price: { amount: drops, asset: "XRP" }, or null without a rate.
  const price = (usd) => () => {
    const r = usdPerXrp();
    const amount = r && dropsFor(usd, r);
    return amount ? { amount, asset: 'XRP' } : null;
  };

  // The dollar value of an amount of drops at the current rate (for the usage log), or null.
  const usdOfDrops = (drops) => {
    const r = rate !== null && now() - readAt < staleMs ? rate : null;
    return r && /^\d+$/.test(String(drops)) ? Math.round((Number(drops) / 1e6) * r * 1e6) / 1e6 : null;
  };

  return { refresh, usdPerXrp, price, usdOfDrops };
}

// One rate per process, shared by the routes and the usage log.
let shared = null;
const sharedXrpRate = () => (shared ??= createXrpRate());

module.exports = { createXrpRate, sharedXrpRate, dropsFor, rateOfPool, RLUSD_HEX, RLUSD_ISSUER };
