// $AFUEL (AgentFuel, https://www.agentfuel.eu) as an extra way to pay, next to USDC on Solana.
//
// Every paid route that takes USDC on Solana gets a second Solana option: the same price in AFUEL, converted at the
// live AFUEL price with a discount (AFUEL_DISCOUNT_PCT, default 25). Same flow as api.agentfuel.eu, where AFUEL
// payments through PayAI settle (tested 7 Nov 2026).
//
// Off unless AFUEL_PAYMENTS=on: the Solana payout wallet needs an AFUEL token account first, or settlement fails.
// Price: Jupiter's price API, else the pump.fun bonding curve on-chain (in SOL, times Jupiter's SOL price).
// Without a fresh price (older than 5 minutes) the AFUEL option is left out of the 402, and USDC stays as it was.
//
// Only the HTTP paywall offers AFUEL (withAfuel on its routes, attach on its resource server); the MCP tools keep
// their fixed accepts[].

export const AFUEL_MINT = "8Qj1i5Q8DJ1HJW2rEpdzED47jNi2f5XvaqwykqQQpump";
export const AFUEL_DECIMALS = 6;
const SOL_MINT = "So11111111111111111111111111111111111111112";
const PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const REFRESH_MS = 60_000;
const MAX_AGE_MS = 5 * 60_000;
/** Marks the AFUEL options, so attach() can leave them out while there is no price. */
const AFUEL_OPTION = Symbol.for("fizzl.afuel-option");

/** SOL per whole token from a pump.fun bonding curve account, or null once the curve is complete. */
export function curvePriceSol(data, tokenDecimals = AFUEL_DECIMALS) {
  if (data.length < 49) return null;
  const vTok = data.readBigUInt64LE(8);
  const vSol = data.readBigUInt64LE(16);
  if (data.readUInt8(48) === 1 || vTok === 0n) return null;
  return Number(vSol) / 1e9 / (Number(vTok) / 10 ** tokenDecimals);
}

/** "$0.01" -> 0.01; null for anything that is not a plain dollar price. */
export function usdOf(price) {
  const m = /^\$(\d+(?:\.\d+)?)$/.exec(String(price ?? "").trim());
  return m ? Number(m[1]) : null;
}

/** AFUEL base units for a dollar price at a given AFUEL price in USD, after the discount; at least 1. */
export function afuelAmount(usd, afuelUsd, discountPct) {
  const discounted = (usd * (100 - discountPct)) / 100;
  return BigInt(Math.max(1, Math.ceil((discounted / afuelUsd) * 10 ** AFUEL_DECIMALS))).toString();
}

export function createAfuel({ env = process.env, fetchImpl = globalThis.fetch, now = () => Date.now() } = {}) {
  const enabled = env.AFUEL_PAYMENTS === "on";
  const mint = env.AFUEL_MINT?.trim() || AFUEL_MINT;
  const discountPct = Math.min(90, Math.max(0, Number(env.AFUEL_DISCOUNT_PCT ?? 25) || 0));
  const rpcUrl = env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
  // A fixed price for tests or emergencies: AFUEL_USD_PRICE=0.00002 overrides the live price.
  const fixedUsd = Number(env.AFUEL_USD_PRICE) > 0 ? Number(env.AFUEL_USD_PRICE) : 0;
  let cache = null; // { at, usd, source }
  let inflight = null;

  async function rpc(method, params) {
    const res = await fetchImpl(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) throw new Error(`Solana RPC HTTP ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`Solana RPC ${body.error.message ?? "error"}`);
    return body.result;
  }

  async function jupiterPrices(ids) {
    const headers = env.JUPITER_API_KEY ? { "x-api-key": env.JUPITER_API_KEY } : {};
    const res = await fetchImpl(`https://api.jup.ag/price/v3?ids=${ids.join(",")}`, { headers, signal: AbortSignal.timeout(5_000) });
    if (!res.ok) throw new Error(`Jupiter price API HTTP ${res.status}`);
    const body = await res.json();
    const out = {};
    for (const id of ids) {
      const p = body?.[id]?.usdPrice;
      if (typeof p === "number" && p > 0) out[id] = p;
    }
    return out;
  }

  // The bonding curve is the pump.fun-owned owner of one of the mint's largest token accounts.
  async function curvePrice() {
    const largest = (await rpc("getTokenLargestAccounts", [mint]))?.value ?? [];
    const holders = (await rpc("getMultipleAccounts", [largest.slice(0, 3).map((a) => a.address), { encoding: "jsonParsed" }]))?.value ?? [];
    for (const h of holders) {
      const owner = h?.data?.parsed?.info?.owner;
      if (!owner) continue;
      const acct = (await rpc("getAccountInfo", [owner, { encoding: "base64" }]))?.value;
      if (acct?.owner !== PUMP_PROGRAM) continue;
      return curvePriceSol(Buffer.from(acct.data[0], "base64"));
    }
    return null;
  }

  async function refresh() {
    try {
      const prices = await jupiterPrices([mint, SOL_MINT]);
      if (prices[mint]) {
        cache = { at: now(), usd: prices[mint], source: "jupiter" };
        return;
      }
      const inSol = prices[SOL_MINT] ? await curvePrice() : null;
      if (inSol) cache = { at: now(), usd: inSol * prices[SOL_MINT], source: "bonding-curve" };
    } catch (err) {
      console.error("AFUEL price refresh failed:", err.message);
    }
  }

  /** Refreshes the cached price when it is older than a minute. Never throws. */
  async function ensurePrice() {
    if (!enabled || fixedUsd) return;
    if (cache && now() - cache.at < REFRESH_MS) return;
    inflight ??= refresh().finally(() => { inflight = null; });
    await inflight;
  }

  /** AFUEL in USD, or null without a fresh price. */
  function usdPrice() {
    if (fixedUsd) return fixedUsd;
    return cache && now() - cache.at <= MAX_AGE_MS ? cache.usd : null;
  }

  /** The x402 price of a dollar amount in AFUEL ({ asset, amount }), or null without a fresh price. */
  async function priceFor(usd) {
    await ensurePrice();
    const p = usdPrice();
    return p ? { asset: mint, amount: afuelAmount(usd, p, discountPct) } : null;
  }

  /** The AFUEL option next to a USDC-on-Solana option, or null when that option has no plain dollar price. */
  function optionFor(solanaOption) {
    const usd = usdOf(solanaOption.price);
    if (usd === null) return null;
    return {
      scheme: "exact",
      network: solanaOption.network,
      payTo: solanaOption.payTo,
      price: async () => {
        const price = await priceFor(usd);
        if (!price) throw new Error("no fresh AFUEL price");
        return price;
      },
      [AFUEL_OPTION]: () => priceFor(usd),
    };
  }

  /** Routes config with an AFUEL option after every USDC-on-Solana option. Unchanged when AFUEL payments are off. */
  function withAfuel(routes) {
    if (!enabled) return routes;
    return Object.fromEntries(Object.entries(routes).map(([key, route]) => {
      if (!Array.isArray(route?.accepts)) return [key, route];
      const accepts = route.accepts.flatMap((a) => {
        const extra = String(a?.network).startsWith("solana:") && a.scheme === "exact" ? optionFor(a) : null;
        return extra ? [a, extra] : [a];
      });
      return [key, { ...route, accepts }];
    }));
  }

  // x402 builds accepts[] from every option and fails the whole 402 when one price can't be resolved; this
  // leaves the AFUEL options out (USDC stays) while there is no fresh AFUEL price.
  function attach(resourceServer) {
    if (!enabled) return resourceServer;
    const build = resourceServer.buildPaymentRequirementsFromOptions.bind(resourceServer);
    resourceServer.buildPaymentRequirementsFromOptions = async (options, context) => {
      const kept = [];
      for (const option of options) {
        if (!option?.[AFUEL_OPTION]) { kept.push(option); continue; }
        const price = await option[AFUEL_OPTION]();
        if (price) kept.push({ scheme: option.scheme, network: option.network, payTo: option.payTo, price });
      }
      return build(kept, context);
    };
    return resourceServer;
  }

  return {
    enabled,
    mint,
    discountPct,
    withAfuel,
    attach,
    ensurePrice,
    usdPrice,
    priceFor,
    status: () => (enabled ? { on: true, mint, discountPct, ...(cache ? { usd: cache.usd, source: cache.source, ageMs: now() - cache.at } : fixedUsd ? { usd: fixedUsd, source: "fixed" } : { usd: null }) } : { on: false }),
    setPriceForTest: (usd) => { cache = usd === null ? null : { at: now(), usd, source: "test" }; },
  };
}
