// USDC on Algorand (ASA 31566704) as one more way to pay, next to Base, Solana and the XRP Ledger. GoPlausible's
// public facilitator verifies and settles it and pays the Algorand fee (no key needed). The payout account
// (ALGORAND_PAY_TO) must have opted in to USDC, or payments to it fail. The network is the CAIP-2 id (the first 32
// characters of the genesis hash): @x402/avm 2.29.0 accepts only that form (2.28.0 also took the whole hash).
export const ALGORAND_NETWORK = "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k";
export const ALGORAND_FACILITATOR = "https://facilitator.goplausible.xyz";

// { network, payTo } from ALGORAND_PAY_TO, or null when unset or "off".
export function algorandConfig(env = process.env) {
  const payTo = (env.ALGORAND_PAY_TO || "").trim();
  return payTo && payTo !== "off" ? { network: ALGORAND_NETWORK, payTo } : null;
}

// One Algorand accept entry: the same dollar price, in USDC.
export const algorandAccept = (algorand, price) =>
  algorand?.payTo ? [{ scheme: "exact", price, network: algorand.network, payTo: algorand.payTo }] : [];
