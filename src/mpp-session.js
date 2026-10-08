// MPP sessions (intent "session", method "tempo"): an agent opens a payment channel on Tempo once, then pays
// each check with a signed cumulative voucher, verified here without an on-chain transaction per call. Built on
// mppx (wevm/mppx), the reference implementation, so any mppx client can pay this way.
//
// Money flow: the channel's payee is MPP_TEMPO_RECIPIENT (the owner's wallet). This server only holds an
// operator key (MPP_TEMPO_OPERATOR_KEY, a separate account with a little USDC.e for fees): an operator may
// settle and close channels, and settled funds go to the payee, never to the operator.
//
// Channel state lives in Redis (CREDITS_REDIS_URL), so vouchers survive restarts and can still be settled.
// Settlement: mppx settles after $0.50 of new spend or 10 minutes, and a sweep here settles any channel with
// unsettled spend every 10 minutes, so an agent that goes quiet and force-closes (a 15-minute grace period)
// can't walk away with what it already spent. Single instance: updates are serialized in this process.
// The challenge suggests a $1 deposit, so mppx clients open a channel that covers many calls (they cap it themselves).
import { Mppx, Store, tempo } from "mppx/server";
import { createClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { tempo as tempoMainnet, tempoModerato } from "viem/chains";
import { createHash } from "node:crypto";
import mppPay from "./mpp-pay.cjs";

const { TEMPO_CHAINS } = mppPay;
const SWEEP_MS = 10 * 60 * 1000;

// A Redis adapter with an atomic update for mppx's Store.redis. Updates to one key run one after another in this
// process (presign-guard runs as a single instance), which is what mppx needs for spent/voucher/close state.
export function redisAtomic(client) {
  const chains = new Map();
  const update = (key, fn) => {
    const run = (chains.get(key) ?? Promise.resolve()).then(async () => {
      const change = fn(await client.get(key));
      if (change.op === "set") await put(key, change.value);
      else if (change.op === "delete") await client.del(key);
      return change.result;
    });
    const tail = run.catch(() => {});
    chains.set(key, tail);
    tail.then(() => { if (chains.get(key) === tail) chains.delete(key); });
    return run;
  };
  // mppx's replay markers ({type: "mppx:replay", expires}) get a Redis expiry so they don't pile up forever.
  const put = (key, value) => {
    let expires = null;
    try { const v = JSON.parse(value); if (v?.type === "mppx:replay") expires = Number(v.expires); } catch {}
    return expires ? client.set(key, value, { PXAT: Math.max(expires, Date.now() + 1000) }) : client.set(key, value);
  };
  return { get: (k) => client.get(k), set: put, del: (k) => client.del(k), update };
}

// The credential in the Authorization header, decoded without verifying it (null when there is none).
function decodeCredential(auth) {
  const m = /(?:^|,)\s*Payment\s+([A-Za-z0-9_-]+)/i.exec(String(auth || ""));
  if (!m) return null;
  try { return JSON.parse(Buffer.from(m[1], "base64url").toString("utf8")); } catch { return null; }
}
// The credential's intent: "session", "charge" or null.
export const credentialIntent = (auth) => decodeCredential(auth)?.challenge?.intent ?? null;

// routes: { "POST /v1/check": "$0.01", ... }. Returns null when the operator key, recipient or store is missing.
export function createMppSession({ operatorKey, recipient, secret, realm, routes, chainId = 4217, store, publicUrl, rpcUrl, settlementSchedule = { amount: "0.5", intervalMs: SWEEP_MS }, suggestedDeposit = "1", log = console }) {
  if (!operatorKey || !recipient || !secret || !store) return null;
  const known = TEMPO_CHAINS[chainId];
  if (!known) throw new Error(`MPP sessions: unknown Tempo chain ${chainId}`);
  const account = privateKeyToAccount(operatorKey.trim().startsWith("0x") ? operatorKey.trim() : `0x${operatorKey.trim()}`);
  // mppx wants its own 32+ byte secret for challenge ids; derived from MPP_SECRET so there is nothing new to set.
  const secretKey = createHash("sha256").update(`mpp-session:${secret}`).digest("base64");
  const mppx = Mppx.create({
    secretKey,
    realm,
    methods: [tempo.session({ account, recipient, operator: account.address, chainId, currency: known.currency, store, settlementSchedule, suggestedDeposit })],
  });

  const prices = new Map(Object.entries(routes).map(([route, price]) => [route, String(price).replace(/^\$/, "")]));
  const patterns = [...prices.keys()].map((route) => {
    const [method, path] = route.split(" ");
    const re = new RegExp(`^${path.split("/").map((part) => (part.startsWith(":") ? "[^/]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))).join("/")}/?$`);
    return { route, method, re };
  });
  const routeOf = (req) => {
    const path = `${req.baseUrl || ""}${req.path}`;
    return patterns.find((p) => p.method === req.method && p.re.test(path))?.route ?? null;
  };
  const toRequest = (req) => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
    return new Request(new URL(req.originalUrl || req.url, publicUrl || `https://${req.headers.host || "localhost"}`), { method: req.method === "GET" || req.method === "HEAD" ? req.method : "POST", headers });
  };
  const handle = (req, route) => mppx.session({ amount: prices.get(route), unitType: "request" })(toRequest(req));

  // The session challenge for one route, as a WWW-Authenticate value (added next to x402 and the MPP charge ones).
  async function challengeHeader(req, route) {
    const unauth = { ...req, headers: { ...req.headers, authorization: undefined } };
    const result = await handle(unauth, route);
    return result.status === 402 ? result.challenge.headers.get("www-authenticate") : null;
  }

  // Channel ids for the settlement sweep, kept in the store so a restart still settles them.
  const CHANNELS = "fizzl:channels";
  const norm = (id) => String(id).toLowerCase();
  const track = (id) => store.update(CHANNELS, (ids) => (ids?.includes(id) ? { op: "noop", result: null } : { op: "set", value: [...(ids ?? []), id], result: null }));
  const untrack = (id) => store.update(CHANNELS, (ids) => (ids?.includes(id) ? { op: "set", value: ids.filter((x) => x !== id), result: null } : { op: "noop", result: null }));
  async function send(res, response) {
    res.status(response.status);
    response.headers.forEach((v, k) => res.setHeader(k, v));
    res.send(Buffer.from(await response.arrayBuffer()));
  }

  // Before the MPP charge middleware and the x402 paywall.
  function middleware(req, res, next) {
    const route = routeOf(req);
    if (!route) return next();
    const auth = req.headers.authorization;
    if (credentialIntent(auth) !== "session") {
      // Not a session credential: on a 402, add the session challenge to whatever the others put there.
      // Built before the route runs (a local HMAC, no network), so it is ready when a 402 goes out.
      return challengeHeader(req, route).then((extra) => {
        const writeHead = res.writeHead;
        res.writeHead = function (...args) {
          if (res.statusCode === 402 && extra) {
            const current = res.getHeader("WWW-Authenticate");
            res.setHeader("WWW-Authenticate", current ? [].concat(current, extra) : extra);
          }
          return writeHead.apply(this, args);
        };
      }, (err) => log.warn(`[mpp-session] challenge on ${route}: ${err.message}`)).then(() => next());
    }
    handle(req, route).then(async (result) => {
      if (result.status === 402) {
        res.locals.mppRefused = "session credential refused";
        return send(res, result.challenge);
      }
      const receipt = result.withReceipt(new Response(null)).headers.get("payment-receipt");
      const rawId = decodeCredential(auth)?.payload?.channelId;
      const channelId = /^0x[0-9a-fA-F]{64}$/.test(rawId ?? "") ? norm(rawId) : null;
      if (channelId) await track(channelId).catch((err) => log.warn(`[mpp-session] track ${channelId}: ${err.message}`));
      const payer = channelId ? (await store.get(channelId).catch(() => null))?.payer ?? null : null;
      req.mppPaid = { payer, amount: prices.get(route), session: true };
      res.locals.mppPayment = { usd: Number(prices.get(route)), network: known.name, payer, tx: null, channel: channelId, protocol: "mpp", intent: "session" };
      if (receipt) res.setHeader("Payment-Receipt", receipt);
      next();
    }, (err) => {
      log.warn(`MPP session on ${route}: ${err.message}`);
      res.status(402).type("application/problem+json").send(JSON.stringify({ type: "https://paymentauth.org/problems/verification-failed", title: "Payment failed", status: 402, detail: "The session voucher could not be checked right now. Send it again in a moment." }));
    });
  }

  // Settles channels whose highest voucher is above what is settled on-chain (see the header comment).
  const chainClient = createClient({ chain: chainId === 4217 ? tempoMainnet : tempoModerato, transport: http(rpcUrl || known.rpc), account });
  async function sweep() {
    const settled = [];
    for (const id of (await store.get(CHANNELS)) ?? []) {
      try {
        const ch = await store.get(id);
        if (!ch || ch.finalized) { await untrack(id); continue; }
        if (!ch.highestVoucher || BigInt(ch.highestVoucherAmount) <= BigInt(ch.settledOnChain)) continue;
        settled.push(await tempo.settle(store, chainClient, id, { account }));
      } catch (err) {
        log.warn(`[mpp-session] settle ${id}: ${err.message}`);
      }
    }
    return settled;
  }
  const timer = setInterval(() => { sweep().catch(() => {}); }, SWEEP_MS);
  timer.unref?.();

  return { middleware, challengeHeader, routeOf, sweep, operator: account.address, recipient, chainId, currency: known.currency };
}

// Store.redis over a node-redis client (or Store.memory() when there is none: tests only).
export const sessionStore = (client) => (client ? Store.redis(redisAtomic(client), { keyPrefix: "mpp-session:" }) : Store.memory());
