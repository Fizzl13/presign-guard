// USDC on Polygon, Arbitrum and Avalanche C-Chain as more ways to pay (the same as x402 Doctor and Fizzl Buy since
// 5 Nov 2026). Circle's USDC is @x402/evm's default asset on all three, so prices stay in dollars. Coinbase's
// facilitator settles a network where it lists it; PayAI settles the rest (it lists all three). When no facilitator
// lists one, it stays out of the 402 (src/facilitator-start.cjs).
// The payout is PAY_TO, the same plain wallet as on Base; <NAME>_PAY_TO (POLYGON_PAY_TO, ARBITRUM_PAY_TO,
// AVALANCHE_PAY_TO) overrides it, and <NAME>_PAY_TO=off turns that network off.

export const EXTRA_EVM = { POLYGON: "eip155:137", ARBITRUM: "eip155:42161", AVALANCHE: "eip155:43114" };
export const EXTRA_EVM_NAMES = { "eip155:137": "Polygon", "eip155:42161": "Arbitrum", "eip155:43114": "Avalanche" };
export const EXTRA_EVM_FACILITATOR = "https://facilitator.payai.network";

// [{ network, payTo }] for the networks that are on (mainnet only: server.js passes [] elsewhere).
export function extraEvmConfig(env = process.env, payTo = env.PAY_TO) {
  return Object.entries(EXTRA_EVM).flatMap(([name, network]) => {
    const own = (env[`${name}_PAY_TO`] || "").trim();
    if (own === "off") return [];
    const to = own || (payTo || "").trim();
    return /^0x[0-9a-fA-F]{40}$/.test(to) ? [{ network, payTo: to }] : [];
  });
}

// The accept entries for one price: the same dollar price, in USDC.
export const extraEvmAccept = (extraEvm, price) =>
  (extraEvm ?? []).map(({ network, payTo }) => ({ scheme: "exact", price, network, payTo }));
