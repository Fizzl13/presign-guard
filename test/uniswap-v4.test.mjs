// Uniswap v4 hooks (src/uniswap-v4.js): the Universal Router's V4_SWAP and the PositionManager's modifyLiquidities,
// built here with viem, judged by the hook's permission bits, the pool's fee and the swap's limit. The chain is a fake
// JSON-RPC (proxy slots, position lookups); no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeAbiParameters, encodeFunctionData, parseAbi, parseAbiParameters } from "viem";
import { uniswapV4Reasons, v4Operations, hookPermissions, HOOK_FLAGS, DYNAMIC_FEE } from "../src/uniswap-v4.js";

const UR = "0x6ff5693b99212da76ad316178a184ab56d299b43";
const POSM = "0x7c5f5a4bbd8fd63184577525326123b519429bdc";
const ETH = "0x0000000000000000000000000000000000000000";
const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const TOKEN = "0x4444444444444444444444444444444444444444";
const ME = "0x2222222222222222222222222222222222222222";
const NONE = "0x0000000000000000000000000000000000000000";
// Hook addresses carry their permissions in the low 14 bits.
const hookWith = (...names) => `0x${(0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5ac000n | BigInt(names.reduce((b, n) => b | HOOK_FLAGS[n], 0))).toString(16).padStart(40, "0")}`;
const TAKER = hookWith("beforeSwap", "afterSwap", "afterSwapReturnsDelta"); // keeps part of the swap (launchpad style)
const PLAIN = hookWith("afterInitialize"); // does nothing to the swap
const GATE = hookWith("beforeAddLiquidity", "beforeRemoveLiquidity"); // can refuse a withdrawal
const SKIM = hookWith("afterRemoveLiquidity", "afterRemoveLiquidityReturnsDelta"); // keeps part of a withdrawal

const POOL_KEY = "(address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks)";
const PATH_KEY = "(address intermediateCurrency, uint24 fee, int24 tickSpacing, address hooks, bytes hookData)";
const key = (hooks, fee = 3000) => ({ currency0: ETH, currency1: TOKEN, fee, tickSpacing: 60, hooks });
const enc = (params, values) => encodeAbiParameters(parseAbiParameters(params), values);
const actions = (list) => enc("bytes actions, bytes[] params", [`0x${list.map(([a]) => a.toString(16).padStart(2, "0")).join("")}`, list.map(([, p]) => p)]);
const exactInSingle = (hooks, { min = 1000n, fee } = {}) => [0x06, enc(`(${POOL_KEY} poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)`, [{ poolKey: key(hooks, fee), zeroForOne: true, amountIn: 10n ** 18n, amountOutMinimum: min, hookData: "0x" }])];
const exactOut = (hooks, max) => [0x09, enc(`(address currencyOut, ${PATH_KEY}[] path, uint128 amountOut, uint128 amountInMaximum)`, [{ currencyOut: USDC, path: hooks.map((h) => ({ intermediateCurrency: TOKEN, fee: 500, tickSpacing: 10, hooks: h, hookData: "0x" })), amountOut: 10n ** 6n, amountInMaximum: max }])];
const settleAll = (max) => [0x0c, enc("address currency, uint256 maxAmount", [ETH, max])];
const takeAll = (min) => [0x0f, enc("address currency, uint256 minAmount", [TOKEN, min])];
const ROUTER = parseAbi(["function execute(bytes commands, bytes[] inputs, uint256 deadline)", "function execute(bytes commands, bytes[] inputs)"]);
const router = (commands, inputs) => encodeFunctionData({ abi: ROUTER, functionName: "execute", args: [`0x${commands.map((c) => c.toString(16).padStart(2, "0")).join("")}`, inputs, 1893456000n] });
const v4Swap = (list) => router([0x10], [actions(list)]);
const POSM_ABI = parseAbi(["function modifyLiquidities(bytes unlockData, uint256 deadline)"]);
const modify = (list) => encodeFunctionData({ abi: POSM_ABI, functionName: "modifyLiquidities", args: [actions(list), 1893456000n] });
const mint = (hooks, max = 10n ** 18n) => [0x02, enc(`${POOL_KEY} poolKey, int24 tickLower, int24 tickUpper, uint256 liquidity, uint128 amount0Max, uint128 amount1Max, address owner, bytes hookData`, [key(hooks), -600, 600, 10n ** 12n, max, max, ME, "0x"])];
const decrease = (tokenId, min = 0n) => [0x01, enc("uint256 tokenId, uint256 liquidity, uint128 amount0Min, uint128 amount1Min, bytes hookData", [tokenId, 10n ** 12n, min, min, "0x"])];

// A fake chain: proxy slots per hook ({ [hook]: implementation }), positions per token id ({ [id]: hook }).
function chain({ proxies = {}, positions = {}, fail = false } = {}) {
  const asked = [];
  const rpc = async (chainId, requests) => {
    if (fail) throw new Error("Chain RPC unreachable");
    asked.push(...requests.map(([m]) => m));
    return requests.map(([method, params]) => {
      if (method === "eth_getCode") return "0x6080604052";
      if (method === "eth_getStorageAt") {
        const impl = proxies[params[0]];
        return impl && params[1] === "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" ? encodeAbiParameters([{ type: "address" }], [impl]) : `0x${"0".repeat(64)}`;
      }
      if (method === "eth_call") {
        const id = BigInt(`0x${params[0].data.slice(10)}`).toString();
        const hook = positions[id];
        if (!hook) return null;
        return encodeAbiParameters(parseAbiParameters(`${POOL_KEY} poolKey, uint256 info`), [key(hook), 0n]);
      }
      return undefined;
    });
  };
  return { rpc, asked };
}
const codes = (reasons) => reasons.map((r) => `${r.severity}:${r.code}`);
const check = (data, opts = {}, to = UR) => uniswapV4Reasons({ chainId: 8453, to, data }, { rpc: chain(opts).rpc });

test("hookPermissions: the low 14 bits of the hook address, by name", () => {
  assert.deepEqual(hookPermissions("0x00000000000000000000000000000000000000cc"), ["beforeSwap", "afterSwap", "beforeSwapReturnsDelta", "afterSwapReturnsDelta"]);
  assert.deepEqual(hookPermissions(GATE), ["beforeAddLiquidity", "beforeRemoveLiquidity"]);
  assert.deepEqual(hookPermissions(NONE), []);
  assert.equal(DYNAMIC_FEE, 0x800000);
});

test("a swap through a hook that changes its amounts: info with a limit (it keeps no more than your slippage), red without", async () => {
  const limited = await check(v4Swap([exactInSingle(TAKER), settleAll(10n ** 18n), takeAll(0n)]));
  assert.deepEqual(codes(limited), ["info:V4_HOOK", "info:V4_HOOK_CAN_TAKE_SWAP"]);
  assert.deepEqual(limited[0].details.permissions, ["beforeSwap", "afterSwap", "afterSwapReturnsDelta"]);
  assert.deepEqual(limited[1].details, { exactIn: true, amountOutMinimum: "1000", permissions: ["afterSwapReturnsDelta"] });

  const open = await check(v4Swap([exactInSingle(TAKER, { min: 0n }), settleAll(10n ** 18n), takeAll(0n)]));
  assert.deepEqual(codes(open), ["info:V4_HOOK", "red:V4_HOOK_CAN_TAKE_SWAP"]);

  // The limit can sit in TAKE_ALL instead of the swap (or in the router's SWEEP / BALANCE_CHECK_ERC20).
  assert.deepEqual(codes(await check(v4Swap([exactInSingle(TAKER, { min: 0n }), settleAll(10n ** 18n), takeAll(500n)]))), ["info:V4_HOOK", "info:V4_HOOK_CAN_TAKE_SWAP"]);
  const sweep = router([0x10, 0x04], [actions([exactInSingle(TAKER, { min: 0n }), settleAll(10n ** 18n), takeAll(0n)]), enc("address token, address recipient, uint256 amountMin", [TOKEN, ME, 500n])]);
  assert.deepEqual(codes(await check(sweep)), ["info:V4_HOOK", "info:V4_HOOK_CAN_TAKE_SWAP"]);
});

test("a dynamic-fee pool: the hook sets the fee, up to 100%; red without a limit", async () => {
  assert.deepEqual(codes(await check(v4Swap([exactInSingle(PLAIN, { fee: DYNAMIC_FEE })]))), ["info:V4_HOOK", "info:V4_HOOK_SETS_FEE"]);
  const open = await check(v4Swap([exactInSingle(PLAIN, { fee: DYNAMIC_FEE, min: 0n })]));
  assert.deepEqual(codes(open), ["info:V4_HOOK", "red:V4_HOOK_SETS_FEE"]);
  assert.equal(open[1].details.maxFee, "100%");
});

test("a swap without any limit and without a risky hook: orange (any price goes); with a limit and no hook: nothing to say", async () => {
  const open = await check(v4Swap([exactInSingle(NONE, { min: 0n }), settleAll(10n ** 18n), takeAll(0n)]));
  assert.deepEqual(codes(open), ["orange:V4_SWAP_NO_LIMIT"]);
  assert.deepEqual(await check(v4Swap([exactInSingle(NONE)])), []);
  assert.deepEqual(codes(await check(v4Swap([exactInSingle(PLAIN, { min: 0n })]))), ["info:V4_HOOK", "orange:V4_SWAP_NO_LIMIT"]);
});

test("exact out over a path: every hop's hook, and an unlimited amountInMaximum is no limit unless SETTLE_ALL caps it", async () => {
  const unlimited = (2n ** 128n) - 1n;
  const ops = v4Operations(v4Swap([exactOut([PLAIN, TAKER], unlimited)]));
  assert.deepEqual(ops[0].hooks.map((h) => h.hook), [PLAIN, TAKER]);
  assert.deepEqual(codes(await check(v4Swap([exactOut([PLAIN, TAKER], unlimited)]))), ["info:V4_HOOK", "info:V4_HOOK", "red:V4_HOOK_CAN_TAKE_SWAP"]);
  assert.deepEqual(codes(await check(v4Swap([exactOut([PLAIN, TAKER], unlimited), settleAll(10n ** 17n)]))), ["info:V4_HOOK", "info:V4_HOOK", "info:V4_HOOK_CAN_TAKE_SWAP"]);
});

test("a sub-plan and a command that may revert (bit 7) are read too", async () => {
  const sub = enc("bytes commands, bytes[] inputs", ["0x90", [actions([exactInSingle(TAKER, { min: 0n })])]]);
  assert.deepEqual(codes(await check(router([0x21], [sub]))), ["info:V4_HOOK", "red:V4_HOOK_CAN_TAKE_SWAP"]);
});

test("adding liquidity: a hook that can refuse or tax the withdrawal is orange", async () => {
  assert.deepEqual(codes(await check(modify([mint(GATE)]), {}, POSM)), ["info:V4_HOOK", "orange:V4_HOOK_CAN_BLOCK_WITHDRAWAL"]);
  assert.deepEqual(codes(await check(modify([mint(SKIM)]), {}, POSM)), ["info:V4_HOOK", "orange:V4_HOOK_CAN_TAKE_WITHDRAWAL"]);
  // The same through the Universal Router's V4_POSITION_MANAGER_CALL.
  assert.deepEqual(codes(await check(router([0x14], [modify([mint(GATE)])]))), ["info:V4_HOOK", "orange:V4_HOOK_CAN_BLOCK_WITHDRAWAL"]);
  assert.deepEqual(await check(modify([mint(NONE)]), {}, POSM), []);
});

test("taking liquidity out by token id: the pool is looked up on the PositionManager; zero minimums through a skimming hook are red", async () => {
  const positions = { 7: SKIM, 8: NONE };
  const red = await check(modify([decrease(7n)]), { positions }, POSM);
  assert.deepEqual(codes(red), ["info:V4_HOOK", "red:V4_HOOK_CAN_TAKE_WITHDRAWAL"]);
  assert.deepEqual(red[1].details, { tokenId: "7", minima: ["0", "0"] });
  assert.deepEqual(codes(await check(modify([decrease(7n, 10n)]), { positions }, POSM)), ["info:V4_HOOK", "orange:V4_HOOK_CAN_TAKE_WITHDRAWAL"]);
  assert.deepEqual(await check(modify([decrease(8n)]), { positions }, POSM), []);
  assert.deepEqual(await check(modify([decrease(9n)]), { positions }, POSM), [], "not a position: nothing claimed");
});

test("a hook behind a proxy: its owner can change it after you sign (orange)", async () => {
  const impl = "0x1166100c7d909fece5e82a021e0331c77d0d0fc0";
  const r = await check(v4Swap([exactInSingle(PLAIN)]), { proxies: { [PLAIN]: impl } });
  assert.deepEqual(codes(r), ["info:V4_HOOK", "orange:V4_HOOK_UPGRADEABLE"]);
  assert.deepEqual(r[1].details, { kind: "eip1967", points_to: impl });
});

test("without the chain: hooks are still judged by their address; other calldata is left alone", async () => {
  const r = await uniswapV4Reasons({ chainId: 8453, to: UR, data: v4Swap([exactInSingle(TAKER, { min: 0n })]) }, { rpc: chain({ fail: true }).rpc });
  assert.deepEqual(codes(r), ["info:V4_CHAIN_UNAVAILABLE", "info:V4_HOOK", "red:V4_HOOK_CAN_TAKE_SWAP"]);
  const transfer = encodeFunctionData({ abi: parseAbi(["function transfer(address to, uint256 amount)"]), functionName: "transfer", args: [ME, 1n] });
  const c = chain();
  assert.deepEqual(await uniswapV4Reasons({ chainId: 8453, to: USDC, data: transfer }, { rpc: c.rpc }), []);
  assert.deepEqual(c.asked, [], "no chain calls for calldata that isn't Uniswap v4");
  assert.deepEqual(await check("0x"), []);
});
