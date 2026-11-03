// Uniswap v4 hooks: what the hook of a pool may do to a swap or a position, read before signing.
//
// A v4 pool can name a hook: a contract the PoolManager calls around every swap and every liquidity change. The hook's
// address says what it may do: its lowest 14 bits are its permissions (v4-core Hooks.sol), checked by the PoolManager
// on every call. Three of those matter most to the one signing:
// - beforeSwap/afterSwap "returns delta" (bits 3 and 2): the hook changes the amounts of the swap itself, so it can
//   keep part of what you pay or receive. Only your own limit (amountOutMinimum, amountInMaximum) bounds that: with a
//   limit it is info (launchpad hooks take their fee this way), without one red.
// - a dynamic fee (the pool's fee is 0x800000): the hook sets the swap fee, up to 100%. Again only your limit bounds it.
// - beforeRemoveLiquidity (bit 9) and afterRemoveLiquidity "returns delta" (bit 0): the hook can refuse a withdrawal
//   or keep part of it. Liquidity you add can be stuck or taxed on the way out.
// And a hook behind a proxy can be changed by its owner after you sign.
//
// Read from the calldata of the Universal Router (execute: V4_SWAP, V4_POSITION_MANAGER_CALL, EXECUTE_SUB_PLAN) and of
// the v4 PositionManager (modifyLiquidities). Positions named only by token id are looked up on the PositionManager the
// transaction calls (getPoolAndPositionInfo). Command and action numbers: universal-router Commands.sol and
// v4-periphery Actions.sol.

import { decodeAbiParameters, decodeFunctionData, decodeFunctionResult, encodeFunctionData, parseAbi, parseAbiParameters } from "viem";
import { rpcBatch } from "./presign-guard.js";

export const HOOK_FLAGS = {
  beforeInitialize: 1 << 13,
  afterInitialize: 1 << 12,
  beforeAddLiquidity: 1 << 11,
  afterAddLiquidity: 1 << 10,
  beforeRemoveLiquidity: 1 << 9,
  afterRemoveLiquidity: 1 << 8,
  beforeSwap: 1 << 7,
  afterSwap: 1 << 6,
  beforeDonate: 1 << 5,
  afterDonate: 1 << 4,
  beforeSwapReturnsDelta: 1 << 3,
  afterSwapReturnsDelta: 1 << 2,
  afterAddLiquidityReturnsDelta: 1 << 1,
  afterRemoveLiquidityReturnsDelta: 1 << 0,
};
export const DYNAMIC_FEE = 0x800000;
const ZERO = "0x0000000000000000000000000000000000000000";
const UINT128_UNLIMITED = 2n ** 127n; // an amountInMaximum this high is no limit

// The permissions a hook address carries, by name.
export function hookPermissions(hook) {
  const bits = Number(BigInt(hook) & 0x3fffn);
  return Object.entries(HOOK_FLAGS).filter(([, bit]) => bits & bit).map(([name]) => name);
}

const ROUTER_ABI = parseAbi([
  "function execute(bytes commands, bytes[] inputs, uint256 deadline)",
  "function execute(bytes commands, bytes[] inputs)",
]);
const POSM_ABI = parseAbi([
  "function modifyLiquidities(bytes unlockData, uint256 deadline)",
  "function modifyLiquiditiesWithoutUnlock(bytes actions, bytes[] params)",
  "function multicall(bytes[] data)",
]);
const POSM_READ = parseAbi(["function getPoolAndPositionInfo(uint256 tokenId) view returns ((address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks) poolKey, uint256 info)"]);

const POOL_KEY = "(address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks)";
const PATH_KEY = "(address intermediateCurrency, uint24 fee, int24 tickSpacing, address hooks, bytes hookData)";
const P = {
  actions: parseAbiParameters("bytes actions, bytes[] params"),
  subPlan: parseAbiParameters("bytes commands, bytes[] inputs"),
  exactInSingle: parseAbiParameters(`(${POOL_KEY} poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)`),
  exactIn: parseAbiParameters(`(address currencyIn, ${PATH_KEY}[] path, uint128 amountIn, uint128 amountOutMinimum)`),
  exactOutSingle: parseAbiParameters(`(${POOL_KEY} poolKey, bool zeroForOne, uint128 amountOut, uint128 amountInMaximum, bytes hookData)`),
  exactOut: parseAbiParameters(`(address currencyOut, ${PATH_KEY}[] path, uint128 amountOut, uint128 amountInMaximum)`),
  mint: parseAbiParameters(`${POOL_KEY} poolKey, int24 tickLower, int24 tickUpper, uint256 liquidity, uint128 amount0Max, uint128 amount1Max, address owner, bytes hookData`),
  mintFromDeltas: parseAbiParameters(`${POOL_KEY} poolKey, int24 tickLower, int24 tickUpper, uint128 amount0Max, uint128 amount1Max, address owner, bytes hookData`),
  increase: parseAbiParameters("uint256 tokenId, uint256 liquidity, uint128 amount0Max, uint128 amount1Max, bytes hookData"),
  increaseFromDeltas: parseAbiParameters("uint256 tokenId, uint128 amount0Max, uint128 amount1Max, bytes hookData"),
  decrease: parseAbiParameters("uint256 tokenId, uint256 liquidity, uint128 amount0Min, uint128 amount1Min, bytes hookData"),
  burn: parseAbiParameters("uint256 tokenId, uint128 amount0Min, uint128 amount1Min, bytes hookData"),
};
// Universal Router commands (the low 6 bits; bit 7 allows a revert).
const CMD = { SWEEP: 0x04, BALANCE_CHECK_ERC20: 0x0e, V4_SWAP: 0x10, V4_POSITION_MANAGER_CALL: 0x14, EXECUTE_SUB_PLAN: 0x21 };
// v4-periphery actions.
const ACT = {
  INCREASE_LIQUIDITY: 0x00, DECREASE_LIQUIDITY: 0x01, MINT_POSITION: 0x02, BURN_POSITION: 0x03,
  INCREASE_LIQUIDITY_FROM_DELTAS: 0x04, MINT_POSITION_FROM_DELTAS: 0x05,
  SWAP_EXACT_IN_SINGLE: 0x06, SWAP_EXACT_IN: 0x07, SWAP_EXACT_OUT_SINGLE: 0x08, SWAP_EXACT_OUT: 0x09,
  SETTLE: 0x0b, SETTLE_ALL: 0x0c, TAKE: 0x0e, TAKE_ALL: 0x0f,
};
// The other places a swap's limit can sit: the amount taken or paid in the same action list (TAKE_ALL's minAmount,
// TAKE's exact amount, SETTLE_ALL's maxAmount, SETTLE's exact amount) and the router's own SWEEP (amountMin) and
// BALANCE_CHECK_ERC20 (minBalance), which revert the whole transaction when too little arrives.
const GUARD = {
  currencyAmount: parseAbiParameters("address currency, uint256 amount"),
  take: parseAbiParameters("address currency, address recipient, uint256 amount"),
  settle: parseAbiParameters("address currency, uint256 amount, bool payerIsUser"),
  sweep: parseAbiParameters("address token, address recipient, uint256 amountMin"),
  balanceCheck: parseAbiParameters("address owner, address token, uint256 minBalance"),
};

const lower = (a) => String(a).toLowerCase();
const bytesOf = (hex) => (typeof hex === "string" && hex.length >= 2 ? Array.from({ length: (hex.length - 2) / 2 }, (_, i) => parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16)) : []);
const tryDecode = (params, data) => { try { return decodeAbiParameters(params, data); } catch { return null; } };

// Everything a transaction does in v4 pools: swaps ({ kind: "swap", hooks: [{ hook, fee }], limited, limit }),
// liquidity added ({ kind: "add", hook, fee, maxima }) and taken out ({ kind: "remove", hook?, tokenId, minima }).
// tokenId-only positions carry `tokenId` and `positionManager` (when known) for the lookup.
export function v4Operations(data, to) {
  const ops = [];
  const guards = { out: false, in: false }; // a minimum received / a maximum paid, somewhere in the transaction
  const fromActions = (unlockData, positionManager) => {
    const decoded = tryDecode(P.actions, unlockData);
    if (decoded) fromActionList(decoded[0], decoded[1], positionManager);
  };
  const fromActionList = (actions, params, positionManager) => {
    bytesOf(actions).forEach((action, i) => {
      const p = params[i];
      if (!p) return;
      if (action === ACT.TAKE_ALL) { if ((tryDecode(GUARD.currencyAmount, p)?.[1] ?? 0n) > 0n) guards.out = true; return; }
      if (action === ACT.TAKE) { if ((tryDecode(GUARD.take, p)?.[2] ?? 0n) > 0n) guards.out = true; return; }
      if (action === ACT.SETTLE_ALL) { const max = tryDecode(GUARD.currencyAmount, p)?.[1]; if (max !== undefined && max < UINT128_UNLIMITED) guards.in = true; return; }
      if (action === ACT.SETTLE) { const amount = tryDecode(GUARD.settle, p)?.[1]; if (amount !== undefined && amount > 0n && amount < UINT128_UNLIMITED) guards.in = true; return; }
      if (action === ACT.SWAP_EXACT_IN_SINGLE || action === ACT.SWAP_EXACT_OUT_SINGLE) {
        const exactIn = action === ACT.SWAP_EXACT_IN_SINGLE;
        const s = tryDecode(exactIn ? P.exactInSingle : P.exactOutSingle, p)?.[0];
        if (!s) return;
        const limit = exactIn ? s.amountOutMinimum : s.amountInMaximum;
        ops.push({ kind: "swap", exactIn, hooks: [{ hook: lower(s.poolKey.hooks), fee: Number(s.poolKey.fee) }], limit: limit.toString(), limited: exactIn ? limit > 0n : limit < UINT128_UNLIMITED });
      } else if (action === ACT.SWAP_EXACT_IN || action === ACT.SWAP_EXACT_OUT) {
        const exactIn = action === ACT.SWAP_EXACT_IN;
        const s = tryDecode(exactIn ? P.exactIn : P.exactOut, p)?.[0];
        if (!s) return;
        const limit = exactIn ? s.amountOutMinimum : s.amountInMaximum;
        ops.push({ kind: "swap", exactIn, hooks: s.path.map((k) => ({ hook: lower(k.hooks), fee: Number(k.fee) })), limit: limit.toString(), limited: exactIn ? limit > 0n : limit < UINT128_UNLIMITED });
      } else if (action === ACT.MINT_POSITION || action === ACT.MINT_POSITION_FROM_DELTAS) {
        const m = tryDecode(action === ACT.MINT_POSITION ? P.mint : P.mintFromDeltas, p);
        if (!m) return;
        const [key] = m;
        const [amount0Max, amount1Max] = action === ACT.MINT_POSITION ? [m[4], m[5]] : [m[3], m[4]];
        ops.push({ kind: "add", hook: lower(key.hooks), fee: Number(key.fee), maxima: [amount0Max.toString(), amount1Max.toString()], unlimited: amount0Max >= UINT128_UNLIMITED || amount1Max >= UINT128_UNLIMITED });
      } else if (action === ACT.INCREASE_LIQUIDITY || action === ACT.INCREASE_LIQUIDITY_FROM_DELTAS) {
        const m = tryDecode(action === ACT.INCREASE_LIQUIDITY ? P.increase : P.increaseFromDeltas, p);
        if (!m) return;
        const [amount0Max, amount1Max] = action === ACT.INCREASE_LIQUIDITY ? [m[2], m[3]] : [m[1], m[2]];
        ops.push({ kind: "add", tokenId: m[0].toString(), ...(positionManager && { positionManager }), maxima: [amount0Max.toString(), amount1Max.toString()], unlimited: amount0Max >= UINT128_UNLIMITED || amount1Max >= UINT128_UNLIMITED });
      } else if (action === ACT.DECREASE_LIQUIDITY || action === ACT.BURN_POSITION) {
        const m = tryDecode(action === ACT.DECREASE_LIQUIDITY ? P.decrease : P.burn, p);
        if (!m) return;
        const [amount0Min, amount1Min] = action === ACT.DECREASE_LIQUIDITY ? [m[2], m[3]] : [m[1], m[2]];
        ops.push({ kind: "remove", tokenId: m[0].toString(), ...(positionManager && { positionManager }), minima: [amount0Min.toString(), amount1Min.toString()], unprotected: amount0Min === 0n && amount1Min === 0n });
      }
    });
  };
  const fromPositionManagerCall = (calldata, positionManager, depth) => {
    let call;
    try { call = decodeFunctionData({ abi: POSM_ABI, data: calldata }); } catch { return; }
    if (call.functionName === "modifyLiquidities") fromActions(call.args[0], positionManager);
    else if (call.functionName === "modifyLiquiditiesWithoutUnlock") fromActionList(call.args[0], call.args[1], positionManager);
    else if (call.functionName === "multicall" && depth < 2) for (const c of call.args[0]) fromPositionManagerCall(c, positionManager, depth + 1);
  };
  const fromCommands = (commands, inputs, depth) => {
    bytesOf(commands).forEach((byte, i) => {
      const command = byte & 0x3f;
      if (command === CMD.SWEEP) { if ((tryDecode(GUARD.sweep, inputs[i])?.[2] ?? 0n) > 0n) guards.out = true; }
      else if (command === CMD.BALANCE_CHECK_ERC20) { if ((tryDecode(GUARD.balanceCheck, inputs[i])?.[2] ?? 0n) > 0n) guards.out = true; }
      else if (command === CMD.V4_SWAP) fromActions(inputs[i], null);
      else if (command === CMD.V4_POSITION_MANAGER_CALL) fromPositionManagerCall(inputs[i], null, depth);
      else if (command === CMD.EXECUTE_SUB_PLAN && depth < 3) {
        const sub = tryDecode(P.subPlan, inputs[i]);
        if (sub) fromCommands(sub[0], sub[1], depth + 1);
      }
    });
  };

  if (typeof data !== "string" || data.length < 10) return ops;
  let router = null;
  try { router = decodeFunctionData({ abi: ROUTER_ABI, data }); } catch { /* not the Universal Router */ }
  if (router) fromCommands(router.args[0], router.args[1], 0);
  else fromPositionManagerCall(data, to ? lower(to) : null, 0);
  // A swap without its own limit is still limited when the transaction checks what arrives (exact in) or what is paid
  // (exact out) elsewhere.
  for (const o of ops) if (o.kind === "swap" && !o.limited && (o.exactIn ? guards.out : guards.in)) { o.limited = true; o.limitElsewhere = true; }
  return ops;
}

const PROXY_SLOTS = [
  ["eip1967", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"],
  ["eip1967-beacon", "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"],
  ["eip1822", "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"],
];
const MINIMAL_PROXY = /^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/i;
const addressIn = (word) => {
  const m = /^0x0*([0-9a-f]{1,40})$/i.exec(String(word || ""));
  return m && /[1-9a-f]/i.test(m[1]) ? `0x${m[1].padStart(40, "0").toLowerCase()}` : null;
};

// Reasons for one EVM transaction: [{ code, severity, subject, details }]. Never throws; without the chain (no RPC, or
// it fails) the hooks are still judged by their address, only the proxy check and token-id lookups are left out.
export async function uniswapV4Reasons({ chainId, to, data }, { rpc = rpcBatch } = {}) {
  const ops = v4Operations(data, to);
  if (!ops.length) return [];
  const reasons = [];
  const add = (code, severity, subject, details) => {
    const d = JSON.stringify(details || {});
    if (reasons.some((r) => r.code === code && r.subject === subject && JSON.stringify(r.details || {}) === d)) return;
    reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  };

  let unavailable = false;
  // Positions named by token id: their pool key from the PositionManager the transaction calls.
  const lookups = ops.filter((o) => o.tokenId && o.positionManager && !o.hook);
  if (lookups.length) {
    try {
      const answers = await rpc(chainId, lookups.map((o) => ["eth_call", [{ to: o.positionManager, data: encodeFunctionData({ abi: POSM_READ, functionName: "getPoolAndPositionInfo", args: [BigInt(o.tokenId)] }) }, "latest"]]));
      lookups.forEach((o, i) => {
        try {
          const [key] = decodeFunctionResult({ abi: POSM_READ, functionName: "getPoolAndPositionInfo", data: answers[i] });
          o.hook = lower(key.hooks);
          o.fee = Number(key.fee);
        } catch { /* not a position, or not a PositionManager */ }
      });
    } catch { unavailable = true; /* the chain couldn't be asked */ }
  }

  // Every hook involved, with its permissions, and whether it sits behind a proxy (one batch for all).
  const hooks = [...new Set(ops.flatMap((o) => (o.kind === "swap" ? o.hooks.map((h) => h.hook) : o.hook ? [o.hook] : [])).filter((h) => h !== ZERO))];
  const upgradable = {};
  if (hooks.length) {
    try {
      const requests = hooks.flatMap((h) => [["eth_getCode", [h, "latest"]], ...PROXY_SLOTS.map(([, slot]) => ["eth_getStorageAt", [h, slot, "latest"]])]);
      const answers = await rpc(chainId, requests);
      const per = PROXY_SLOTS.length + 1;
      hooks.forEach((h, i) => {
        const [code, ...slots] = answers.slice(i * per, i * per + per);
        const minimal = MINIMAL_PROXY.exec(String(code || ""));
        if (minimal) return; // a clone: its code can't change
        const k = slots.findIndex((s) => addressIn(s));
        if (k >= 0) upgradable[h] = { kind: PROXY_SLOTS[k][0], points_to: addressIn(slots[k]) };
      });
    } catch { unavailable = true; /* the chain couldn't be asked: judged by address only */ }
  }
  // Said out loud, so the answer's not_checked (src/coverage.js) names what was left out.
  if (unavailable) add("V4_CHAIN_UNAVAILABLE", "info", String(chainId));
  for (const h of hooks) {
    add("V4_HOOK", "info", h, { permissions: hookPermissions(h) });
    if (upgradable[h]) add("V4_HOOK_UPGRADEABLE", "orange", h, upgradable[h]);
  }

  for (const o of ops) {
    if (o.kind === "swap") {
      const limit = { exactIn: o.exactIn, [o.exactIn ? "amountOutMinimum" : "amountInMaximum"]: o.limit };
      let risky = false;
      for (const { hook, fee } of o.hooks) {
        if (hook === ZERO) continue;
        const perms = hookPermissions(hook);
        if (perms.includes("beforeSwapReturnsDelta") || perms.includes("afterSwapReturnsDelta")) {
          risky = true;
          add("V4_HOOK_CAN_TAKE_SWAP", o.limited ? "info" : "red", hook, { ...limit, permissions: perms.filter((p) => /SwapReturnsDelta$/.test(p)) });
        }
        if (fee === DYNAMIC_FEE) {
          risky = true;
          add("V4_HOOK_SETS_FEE", o.limited ? "info" : "red", hook, { ...limit, maxFee: "100%" });
        }
      }
      if (!o.limited && !risky) add("V4_SWAP_NO_LIMIT", "orange", o.hooks.map((h) => h.hook).find((h) => h !== ZERO) || ZERO, limit);
    } else if (o.kind === "add" && o.hook && o.hook !== ZERO) {
      const perms = hookPermissions(o.hook);
      const where = { ...(o.tokenId && { tokenId: o.tokenId }) };
      if (perms.includes("beforeRemoveLiquidity")) add("V4_HOOK_CAN_BLOCK_WITHDRAWAL", "orange", o.hook, where);
      if (perms.includes("afterRemoveLiquidityReturnsDelta")) add("V4_HOOK_CAN_TAKE_WITHDRAWAL", "orange", o.hook, where);
      if (perms.includes("afterAddLiquidityReturnsDelta")) add("V4_HOOK_CAN_TAKE_DEPOSIT", o.unlimited ? "orange" : "info", o.hook, { ...where, maxima: o.maxima });
    } else if (o.kind === "remove" && o.hook && o.hook !== ZERO) {
      const perms = hookPermissions(o.hook);
      if (perms.includes("afterRemoveLiquidityReturnsDelta")) add("V4_HOOK_CAN_TAKE_WITHDRAWAL", o.unprotected ? "red" : "orange", o.hook, { tokenId: o.tokenId, minima: o.minima });
    }
  }
  return reasons;
}
