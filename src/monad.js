// USDC on Monad (eip155:143) as one more way to pay. Circle's USDC there (0x7547…b603, EIP-3009, domain "USDC"
// version "2") is @x402/evm's default asset on Monad, so prices stay in dollars. Coinbase's facilitator settles it
// where it lists Monad (which also puts the routes in the x402 Bazaar for Monad buyers); otherwise the facilitator in
// Monad's own x402 guide (docs.monad.xyz/guides/x402) does. MONAD_FACILITATOR_URL replaces that one, "off" leaves
// Monad to Coinbase alone. When no facilitator lists Monad it stays out of the 402 (src/facilitator-start.cjs).
// The payout is PAY_TO, the same plain wallet as on Base; MONAD_PAY_TO overrides it and MONAD_PAY_TO=off turns
// Monad off.
import { HTTPFacilitatorClient } from "@x402/core/server";

export const MONAD_NETWORK = "eip155:143";
export const MONAD_USDC = "0x754704bc059f8c67012fed69bc8a327a5aafb603";
export const MONAD_FACILITATOR = "https://x402-facilitator.molandak.org";

// { network, payTo } on mainnet, or null when turned off.
export function monadConfig(env = process.env, payTo = env.PAY_TO) {
  const own = (env.MONAD_PAY_TO || "").trim();
  if (own === "off") return null;
  const to = own || (payTo || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) return null;
  return { network: MONAD_NETWORK, payTo: to };
}

// The fallback facilitator, or null when MONAD_FACILITATOR_URL=off.
export function monadFacilitator(env = process.env) {
  const url = (env.MONAD_FACILITATOR_URL || "").trim();
  if (url === "off") return null;
  return new HTTPFacilitatorClient({ url: url || MONAD_FACILITATOR });
}

// One Monad accept entry: the same dollar price, in USDC.
export const monadAccept = (monad, price) =>
  monad?.payTo ? [{ scheme: "exact", price, network: monad.network, payTo: monad.payTo }] : [];
