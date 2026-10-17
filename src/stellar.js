// USDC on Stellar (the Stellar Asset Contract, 7 decimals) as one more way to pay, next to Base, Solana, the XRP
// Ledger and Algorand. OpenZeppelin's "Built on Stellar" facilitator verifies and settles it and pays the fee; it
// needs an API key (STELLAR_FACILITATOR_KEY, from channels.openzeppelin.com/gen). STELLAR_FACILITATOR_URL points at
// another facilitator, with or without the key. The payout account must have a USDC trustline.
import { HTTPFacilitatorClient } from "@x402/core/server";

export const STELLAR_NETWORK = "stellar:pubnet";
export const STELLAR_FACILITATOR = "https://channels.openzeppelin.com/x402";
// Frits's account; it has the USDC trustline.
const DEFAULT_PAY_TO = "GCH2J5UAY24YNKA65MPAATVKWRCZZRZNF3JZKYYS5MIBZPG6U7WJ6CDQ";

// { network, payTo } when a Stellar facilitator is configured: STELLAR_PAY_TO, else Frits's account. Null without a
// facilitator, or with STELLAR_PAY_TO=off.
export function stellarConfig(env = process.env) {
  if (env.STELLAR_PAY_TO === "off") return null;
  if (!(env.STELLAR_FACILITATOR_KEY || "").trim() && !(env.STELLAR_FACILITATOR_URL || "").trim()) return null;
  return { network: STELLAR_NETWORK, payTo: (env.STELLAR_PAY_TO || "").trim() || DEFAULT_PAY_TO };
}

// The facilitator client, with the key as a bearer token on verify, settle and supported.
export function stellarFacilitator(env = process.env) {
  const key = (env.STELLAR_FACILITATOR_KEY || "").trim();
  const headers = { Authorization: `Bearer ${key}` };
  return new HTTPFacilitatorClient({
    url: (env.STELLAR_FACILITATOR_URL || "").trim() || STELLAR_FACILITATOR,
    ...(key ? { createAuthHeaders: async () => ({ verify: headers, settle: headers, supported: headers }) } : {}),
  });
}

// One Stellar accept entry: the same dollar price, in USDC.
export const stellarAccept = (stellar, price) =>
  stellar?.payTo ? [{ scheme: "exact", price, network: stellar.network, payTo: stellar.payTo }] : [];
