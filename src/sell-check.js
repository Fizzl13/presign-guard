// Sell check for POST /v1/token/verdict: can a holder sell this token back?
//
// Built from what the token verdict already reads (src/token-verdict.js), each item naming its source:
// - GoPlus (EVM): honeypot, cannot sell all at once, sell tax, transfers pausable, blacklist, trading cooldown,
//   tax changeable, owner can change balances. GoPlus (Solana): non-transferable, freeze authority, transfer hook,
//   transfer fee, balances changeable. The chain itself for a token paused right now and for permissioned (Token ACL)
//   mints; the XRP Ledger and the Algorand node for freeze, clawback and required authorisation.
// - DexScreener: is there enough liquidity to sell into.
// - On Base only, a simulation (eth_simulateV1, the standard simulation call, on the same RPCs as src/simulate.js):
//   a new wallet gets a little of the token from its deepest pool, then sends half of it back into that pool, a
//   block later. That is the token movement of a sell, and where honeypots block it; the router swap itself (price,
//   slippage) is not simulated. `simulated` is true only when that sell transfer actually ran.
//
// The same rule as the verdict: missing data never makes it "no". A check without data is "unknown"; a simulation
// that can't run says why and changes nothing.

import { encodeFunctionData, parseAbi } from "viem";
import { getTokenSecurity, flag } from "./presign-guard.js";
import { TOKEN_CHAINS, LOW_LIQUIDITY_USD, getMarket, getSolanaSecurity } from "./token-verdict.js";
import { createSimulator } from "./simulate.js";

export const SELL_SIMULATION_CHAINS = new Set([8453]);
// The simulated buyer: a fixed address without code or history on Base, so nothing on chain is touched or implied.
export const SIM_HOLDER = "0x5e11c4ec0000000000000000000000000000c4ec";
const SIM_BUDGET_MS = 6000;
const HIGH_SELL_TAX_PCT = 10;
const T_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC20 = parseAbi(["function transfer(address to, uint256 amount) returns (bool)", "function balanceOf(address owner) view returns (uint256)"]);

// Reason codes of the verdict that say something about selling: [check, source, blocks a sale outright].
const SELL_REASONS = {
  TOKEN_HONEYPOT: ["honeypot", "GoPlus", true],
  RUGGED: ["rugged", "RugCheck", true],
  NON_TRANSFERABLE: ["transferable", "GoPlus", true],
  TOKEN_PAUSED: ["paused_now", "chain", true],
  TOKEN_FROZEN: ["frozen_now", "XRP Ledger", true],
  NOT_A_TOKEN: ["is_token", "chain", true],
  TOKEN_NOT_FOUND: ["is_token", "Algorand node", true],
  TOKEN_CANNOT_SELL_ALL: ["sell_all", "GoPlus"],
  TOKEN_HIGH_TAX: ["sell_tax", "GoPlus"],
  TOKEN_TAX: ["sell_tax", "GoPlus"],
  HIGH_TRANSFER_FEE: ["transfer_fee", "GoPlus"],
  TRANSFER_FEE: ["transfer_fee", "GoPlus"],
  TRANSFER_FEE_UPGRADABLE: ["fee_changeable", "GoPlus"],
  TOKEN_TAX_MODIFIABLE: ["tax_changeable", "GoPlus"],
  TOKEN_TRADING_COOLDOWN: ["cooldown", "GoPlus"],
  TOKEN_PAUSABLE: ["pausable", "GoPlus"],
  TOKEN_BLACKLIST: ["blacklist", "GoPlus"],
  FREEZE_AUTHORITY_ACTIVE: ["freeze", "GoPlus"],
  PERMISSIONED_TOKEN: ["permissioned", "chain"],
  TRANSFER_HOOK: ["transfer_hook", "GoPlus"],
  CLAWBACK_ENABLED: ["clawback", "GoPlus"],
  BALANCE_MUTABLE: ["balances_changeable", "GoPlus"],
  TOKEN_OWNER_CAN_CHANGE_BALANCES: ["balances_changeable", "GoPlus"],
  LOW_LIQUIDITY: ["liquidity", "DexScreener"],
  NO_DEX_MARKET: ["liquidity", "DexScreener"],
};
const RESULT = { red: "fail", orange: "warn", info: "info" };
const pct1 = (x) => Math.round(x * 10) / 10;

function sourceOf(code, details, chain, fallback) {
  if (code === "LOW_LIQUIDITY" || code === "NO_DEX_MARKET") return "DexScreener";
  if (chain === "xrpl") return "XRP Ledger";
  if (chain === "algorand") return "Algorand node";
  if (details?.source === "onchain") return "chain";
  if (chain === "solana" && code === "PERMISSIONED_TOKEN") return "chain (Token ACL)";
  return fallback;
}

// The verdict's sell-related reasons as checks, then what the raw data shows was checked and found fine.
function checksFrom(verdict, chain, sec) {
  const rows = new Map();
  const put = (row) => { if (!rows.has(row.check)) rows.set(row.check, row); };
  for (const r of verdict.reasons) {
    const entry = SELL_REASONS[r.code];
    if (!entry) continue;
    const [check, fallback, blocks] = entry;
    const row = { check, result: blocks && r.severity !== "info" ? "fail" : RESULT[r.severity], code: r.code, source: sourceOf(r.code, r.details, chain, fallback) };
    if (check === "sell_tax") {
      const sellPct = pct1(Number(r.details?.sellTax ?? 0) * 100);
      Object.assign(row, { value: sellPct, result: sellPct >= HIGH_SELL_TAX_PCT ? "warn" : sellPct > 0 ? "info" : "pass" });
    }
    if (check === "transfer_fee" && r.details?.feePct !== undefined) row.value = r.details.feePct;
    if (check === "liquidity" && r.details?.liquidityUsd !== undefined) row.value = r.details.liquidityUsd;
    put(row);
  }
  const has = (check) => rows.has(check);
  if (chain === "solana") {
    if (sec) {
      if (!has("transferable")) put({ check: "transferable", result: "pass", source: "GoPlus" });
      if (!has("freeze") && !has("permissioned")) put({ check: "freeze", result: "pass", source: "GoPlus" });
    } else put({ check: "transferable", result: "unknown", source: "GoPlus" });
  } else if (TOKEN_CHAINS[chain]?.chainId && !has("is_token")) {
    if (sec) {
      if (!has("honeypot")) put({ check: "honeypot", result: sec.is_honeypot === undefined || sec.is_honeypot === "" ? "unknown" : "pass", source: "GoPlus" });
      if (!has("sell_all") && sec.cannot_sell_all !== undefined && sec.cannot_sell_all !== "" && !flag(sec.cannot_sell_all)) put({ check: "sell_all", result: "pass", source: "GoPlus" });
      if (!has("sell_tax") && sec.sell_tax !== undefined && sec.sell_tax !== "") {
        const v = pct1(Number(sec.sell_tax) * 100);
        if (Number.isFinite(v)) put({ check: "sell_tax", result: v >= HIGH_SELL_TAX_PCT ? "warn" : v > 0 ? "info" : "pass", value: v, source: "GoPlus" });
      }
    } else put({ check: "honeypot", result: "unknown", source: "GoPlus" });
  }
  const m = verdict.market;
  if (!has("liquidity") && m && m.liquidityUsd >= LOW_LIQUIDITY_USD) put({ check: "liquidity", result: "pass", value: m.liquidityUsd, source: "DexScreener" });
  return [...rows.values()];
}

// The deepest pool with a plain contract address (Uniswap v2/v3, Aerodrome, ...) that holds the token; a v4 pool is
// an id inside the PoolManager, not an address that holds tokens, so it is skipped.
export function poolOf(pairs, address) {
  const a = String(address).toLowerCase();
  const pools = (pairs ?? []).filter((p) => /^0x[0-9a-fA-F]{40}$/.test(p?.pairAddress ?? "")
    && [p?.baseToken?.address, p?.quoteToken?.address].some((t) => String(t).toLowerCase() === a));
  pools.sort((x, y) => (Number(y?.liquidity?.usd) || 0) - (Number(x?.liquidity?.usd) || 0));
  return pools[0] ? { address: pools[0].pairAddress.toLowerCase(), dex: pools[0].dexId ?? null, labels: pools[0].labels ?? [] } : null;
}

const hex = (n) => `0x${BigInt(n).toString(16)}`;
const returnedFalse = (data) => typeof data === "string" && /^0x0{64}$/.test(data); // an old ERC-20 that returns false
const passed = (call) => call?.status === "0x1" && !returnedFalse(call.returnData);
const topicAddress = (t) => (typeof t === "string" && t.length === 66 ? `0x${t.slice(26)}`.toLowerCase() : null);

// { ran: true, ok, ... } when the sell transfer ran (ok false: it reverted), { ran: false, why } when it couldn't.
export async function simulateSell({ chainId, token, pool, simulator }) {
  const call = (data) => ({ to: token, data });
  const balanceOf = (who) => encodeFunctionData({ abi: ERC20, functionName: "balanceOf", args: [who] });
  const transfer = (to, amount) => encodeFunctionData({ abi: ERC20, functionName: "transfer", args: [to, amount] });
  const first = await simulator.send(chainId, [
    { jsonrpc: "2.0", id: 1, method: "eth_call", params: [call(balanceOf(pool)), "latest"] },
    { jsonrpc: "2.0", id: 2, method: "eth_getBlockByNumber", params: ["latest", false] },
  ]);
  if (!first) return { ran: false, why: "no RPC answered" };
  const byId = new Map(first.answer.map((a) => [a.id, a.result]));
  let poolBalance;
  try { poolBalance = BigInt(byId.get(1)); } catch { return { ran: false, why: "the pool's balance could not be read" }; }
  const head = byId.get(2);
  if (!head?.number || !head?.timestamp) return { ran: false, why: "the latest block could not be read" };
  const amount = poolBalance / 10_000n; // 0.01% of the pool: small enough for max-transaction and max-wallet limits
  if (amount === 0n) return { ran: false, why: "the pool holds too little of the token" };
  const sent = amount / 2n;
  const n = BigInt(head.number);
  const t = BigInt(head.timestamp);
  const sim = await simulator.send(chainId, { jsonrpc: "2.0", id: 3, method: "eth_simulateV1", params: [{
    blockStateCalls: [
      { blockOverrides: { number: hex(n + 1n), time: hex(t + 2n) }, calls: [{ from: pool, ...call(transfer(SIM_HOLDER, amount)) }, { from: SIM_HOLDER, ...call(balanceOf(SIM_HOLDER)) }] },
      // A block and five minutes later, so a same-block or short cooldown rule doesn't read as a blocked sale.
      { blockOverrides: { number: hex(n + 2n), time: hex(t + 302n) }, calls: [{ from: SIM_HOLDER, ...call(transfer(pool, sent)) }] },
    ],
  }, head.number] }); // on the block just read, so the overrides follow it whichever node answers
  if (!sim) return { ran: false, why: "no RPC answered the simulation" };
  const [b1, b2] = Array.isArray(sim.answer.result) ? sim.answer.result : [];
  const [buy, held] = b1?.calls ?? [];
  const [sell] = b2?.calls ?? [];
  if (!buy || !sell) return { ran: false, why: "the simulation returned no result" };
  const base = { method: "eth_simulateV1", pool, holder: SIM_HOLDER, source: sim.source };
  if (!passed(buy)) return { ran: false, ...base, why: "the pool's transfer to a new wallet failed (trading may not be open, or the token blocks new wallets)", error: String(buy.error?.message ?? "reverted").slice(0, 200) };
  let received;
  try { received = BigInt(held?.returnData); } catch { return { ran: false, ...base, why: "the new wallet's balance could not be read" }; }
  const buyTaxPct = pct1(Number(((amount - received) * 10_000n) / amount) / 100);
  if (received < sent) return { ran: false, ...base, buy_tax_pct: buyTaxPct, why: "the new wallet received less than half of what the pool sent" };
  if (!passed(sell)) {
    return { ran: true, ok: false, ...base, amount_raw: String(amount), received_raw: String(received), sent_raw: String(sent), buy_tax_pct: buyTaxPct, error: String(sell.error?.message ?? "reverted").slice(0, 200) };
  }
  const arrived = (sell.logs ?? [])
    .filter((l) => String(l.address).toLowerCase() === token && l.topics?.[0] === T_TRANSFER && topicAddress(l.topics[1]) === SIM_HOLDER && topicAddress(l.topics[2]) === pool)
    .reduce((s, l) => { try { return s + BigInt(l.data); } catch { return s; } }, 0n);
  const sellTaxPct = pct1(Number(((sent - (arrived > sent ? sent : arrived)) * 10_000n) / sent) / 100);
  return { ran: true, ok: true, ...base, amount_raw: String(amount), received_raw: String(received), sent_raw: String(sent), arrived_raw: String(arrived), buy_tax_pct: buyTaxPct, sell_tax_pct: sellTaxPct };
}

const withBudget = (work, ms) => {
  let timer;
  const late = new Promise((resolve) => { timer = setTimeout(() => resolve({ ran: false, why: `the simulation took longer than ${ms / 1000} s` }), ms); });
  return Promise.race([work.catch((err) => ({ ran: false, why: `simulation error: ${String(err.message).slice(0, 120)}` })), late]).finally(() => clearTimeout(timer));
};

// verdict: the GET /v1/token answer for request ({ chain, address }).
export async function sellCheck(request, verdict, { simulator = createSimulator({ timeoutMs: 3000 }), budgetMs = SIM_BUDGET_MS } = {}) {
  const { chain, address } = request;
  const chainId = TOKEN_CHAINS[chain]?.chainId;
  // The raw data comes from the verdict's own cache (10 minutes), so this asks GoPlus nothing new.
  const sec = chain === "solana"
    ? (await getSolanaSecurity(address).catch(() => null))?.data ?? null
    : chainId ? (await getTokenSecurity(chainId, address).catch(() => null))?.data ?? null : null;
  const checks = checksFrom(verdict, chain, sec);

  let simulation = null;
  const blocked = checks.some((c) => c.result === "fail");
  if (SELL_SIMULATION_CHAINS.has(chainId) && simulator?.enabled !== false && !blocked) {
    const pairs = await getMarket(chain, address).catch(() => []);
    const pool = poolOf(pairs, address);
    simulation = pool ? await withBudget(simulateSell({ chainId, token: address, pool: pool.address, simulator }), budgetMs) : { ran: false, why: "no pool with a contract address to sell into" };
    if (pool) simulation = { ...simulation, dex: pool.dex };
    if (simulation.ran) {
      checks.push({
        check: "simulated_sell",
        result: !simulation.ok ? "fail" : simulation.sell_tax_pct >= HIGH_SELL_TAX_PCT ? "warn" : simulation.sell_tax_pct > 0 ? "info" : "pass",
        ...(simulation.ok && { value: simulation.sell_tax_pct }),
        source: `simulation (${simulation.source === "alchemy" ? "Alchemy" : "public RPC"})`,
      });
    }
  }
  const simulated = Boolean(simulation?.ran);

  const results = new Set(checks.map((c) => c.result));
  const evidence = checks.some((c) => c.result === "pass" && ["honeypot", "transferable", "simulated_sell", "sell_all", "sell_tax"].includes(c.check))
    || (["xrpl", "algorand"].includes(chain) && verdict.sources?.some((s) => s === "xrpl-ledger" || s === "algod") && !verdict.reasons.some((r) => r.code === "LEDGER_UNAVAILABLE"));
  const canSell = results.has("fail") ? "no" : results.has("warn") ? "limited" : evidence ? "yes" : "unknown";
  return {
    can_sell: canSell,
    simulated,
    checks,
    ...(simulation && { simulation }),
    sources: [...new Set(checks.map((c) => c.source))],
    note: simulated
      ? "Simulated with eth_simulateV1: a new wallet gets a little of the token from its deepest pool, then sends half back into that pool a block later (the token movement of a sell). The swap itself (router, price impact) is not simulated. The other checks come from the sources named."
      : "Not simulated: judged from the data sources named per check. Missing data is unknown, never a no.",
  };
}
