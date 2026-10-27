// USD₮0 on X Layer (OKX's chain, eip155:196) as one more way to pay, next to Base, Solana, the XRP Ledger, Algorand
// and Stellar. It is what x402 sellers on X Layer ask for (all 1,067 X Layer endpoints in the x402 Trust Index on
// 27 Oct 2026 named USD₮0, 0x779d…3736, EIP-3009 with the domain "USD₮0" version "1"). PayAI's facilitator verifies
// and settles it (exact scheme, x402 v2), as it already does our Solana payments. @x402/evm has no default asset for
// X Layer, so each price is given as the token amount (6 decimals).
// The payout is PAY_TO, the same plain wallet as on Base (no code on X Layer); XLAYER_PAY_TO overrides it and
// XLAYER_PAY_TO=off turns X Layer off.
import { HTTPFacilitatorClient } from "@x402/core/server";

export const XLAYER_NETWORK = "eip155:196";
export const XLAYER_USDT0 = "0x779ded0c9e1022225f8e0630b35a9b54be713736";
export const XLAYER_FACILITATOR = "https://facilitator.payai.network";
const USDT0_DOMAIN = { name: "USD₮0", version: "1" };

// { network, payTo } on mainnet, or null when turned off.
export function xlayerConfig(env = process.env, payTo = env.PAY_TO) {
  const own = (env.XLAYER_PAY_TO || "").trim();
  if (own === "off") return null;
  const to = own || (payTo || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) return null;
  return { network: XLAYER_NETWORK, payTo: to };
}

export const xlayerFacilitator = (env = process.env) =>
  new HTTPFacilitatorClient({ url: (env.XLAYER_FACILITATOR_URL || "").trim() || XLAYER_FACILITATOR });

// "$0.01" → "10000" (USD₮0 has 6 decimals).
export function usdt0Amount(price) {
  const m = /^\$?(\d+)(?:\.(\d{1,6}))?$/.exec(String(price).trim());
  if (!m) throw new Error(`unsupported price ${price}`);
  return (BigInt(m[1]) * 1_000_000n + BigInt((m[2] || "").padEnd(6, "0"))).toString();
}

// One X Layer accept entry: the same dollar price, in USD₮0.
export const xlayerAccept = (xlayer, price) =>
  xlayer?.payTo ? [{ scheme: "exact", price: { amount: usdt0Amount(price), asset: XLAYER_USDT0, extra: USDT0_DOMAIN }, network: xlayer.network, payTo: xlayer.payTo }] : [];
