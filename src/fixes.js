// What to change to get green: a `fix` on each orange or red reason, so a red verdict gives the agent a direction and
// not only a stop ("red is not feedback, it is a verdict"). Each fix says what a safe version looks like (`expected`),
// what this request does instead (`saw`), what to change (`change`), and `retry`:
// - "change": build the request again with the change and check it again; it can come back green;
// - "elsewhere": nothing in this request fixes it (the contract, the pool, the site is the problem): use another
//   one, or ask the user;
// - "ask": only the user can decide (a smart account they chose, a token's own tax);
// - "never": don't sign; no version of this is safe.
// Where a field can be set directly, `set` names it. A fix never changes the verdict: the verdict is the check's,
// the fix is advice for the next attempt, which is checked again in full.

const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const NEVER = (saw) => ({ expected: "a counterparty with no record of theft, phishing or sanctions", saw, change: "Don't sign. No version of this request is safe; tell the user what was found.", retry: "never" });

function grantOf(req, spender) {
  return (req?.grants || []).find((g) => g.spender === spender) || req?.grants?.[0] || null;
}

const FIXES = {
  // Allowances and signatures
  UNLIMITED_APPROVAL: (r) => ({ expected: "an allowance for the amount this action needs", saw: "an unlimited allowance", change: `Approve ${r.subject} for exactly the amount this action spends, not the maximum; approve again next time.`, retry: "change", set: { amount: "the exact amount needed" } }),
  UNLIMITED_TRANSFER: (r) => ({ expected: "a transfer of a fixed amount", saw: "an unlimited amount", change: `Sign for exactly the amount ${r.subject} should receive.`, retry: "change", set: { amount: "the exact amount needed" } }),
  UNLIMITED_APPROVAL_TO_EOA: (r) => ({ expected: "allowances only for contracts (a router, a marketplace)", saw: `an unlimited allowance for a plain wallet (${r.subject})`, change: "Don't approve a plain wallet. If the user means to pay this address, send a transfer of the exact amount instead, after the user confirms the full address.", retry: "ask" }),
  APPROVAL_TO_EOA: (r) => ({ expected: "allowances only for contracts (a router, a marketplace)", saw: `an allowance for a plain wallet (${r.subject})`, change: "If the user means to pay this address, send a transfer of the exact amount instead, after the user confirms the full address.", retry: "ask" }),
  SIGNATURE_GRANT_TO_EOA: (r) => NEVER(`an off-chain signature that lets a plain wallet (${r.subject}) take tokens: the common drainer pattern`),
  APPROVAL_FOR_ALL: (r) => ({ expected: "access to one NFT", saw: `${r.subject} gets every NFT of the collection`, change: "Approve only the NFT this action needs (approve(to, tokenId)), or use the marketplace's own listing flow; revoke afterwards.", retry: "change" }),
  SIGNATURE_TRANSFER: (r) => ({ expected: "a payment you send yourself, for a known amount", saw: `a signature that lets ${r.subject} move the tokens`, change: "Sign only if this is the payment the user asked for, to this exact recipient and amount; otherwise send a normal transfer.", retry: "ask" }),
  LONG_LIVED_PERMISSION: (r) => ({ expected: "a permission that ends within the hour", saw: `valid until ${r.details?.expiresAt ? new Date(r.details.expiresAt * 1000).toISOString() : "far in the future"}`, change: "Set the expiry (deadline, expiration or validBefore) to at most one hour from now.", retry: "change", set: { expiresAt: "now + 3600 seconds or less" } }),
  NONCANONICAL_PERMIT2: (r) => ({ expected: `the Permit2 contract ${PERMIT2}`, saw: `a Permit2-style signature for ${r.subject}`, change: `Sign Permit2 messages only with verifyingContract ${PERMIT2}.`, retry: "change", set: { verifyingContract: PERMIT2 } }),
  NEW_WALLET_SPENDER: (r) => ({ expected: "a spender with history", saw: `a wallet with ${r.details?.ageDays == null ? "no history" : `${r.details.ageDays} days of history`}`, change: "Confirm the full address with the user before granting it anything; a fresh wallet is how drainers start.", retry: "ask" }),
  // Tokens
  TOKEN_IMPERSONATION: (r) => (r.details?.realToken
    ? { expected: `the real token ${r.details.realToken}`, saw: `a copy at ${r.subject}`, change: `Use the real token contract ${r.details.realToken} instead.`, retry: "change", set: { token: r.details.realToken } }
    : { expected: "the real token", saw: `a copy at ${r.subject}`, change: "Find the official contract on the issuer's own site and use that one.", retry: "change" }),
  TOKEN_HONEYPOT: (r) => NEVER(`a token you can buy but not sell (${r.subject})`),
  TOKEN_AIRDROP_SCAM: (r) => NEVER(`a scam airdrop token (${r.subject})`),
  TOKEN_HIGH_TAX: (r) => ({ expected: "a token without a large transfer tax", saw: "a high buy or sell tax", change: "Tell the user how much the tax takes before going on; or pick another token.", retry: "ask" }),
  TOKEN_PAUSED: (r) => ({ expected: "a token that moves", saw: "transfers are paused", change: "Wait until the issuer resumes transfers; the transaction would fail or get stuck now.", retry: "elsewhere" }),
  // Recipients and sites
  ADDRESS_POISONING: (r) => ({ expected: r.details?.lookalikeOf ? `the address ${r.details.lookalikeOf}${r.details.name ? ` (${r.details.name})` : ""}` : "the address the user means", saw: `a look-alike: ${r.subject}`, change: r.details?.lookalikeOf ? `If the user meant ${r.details.lookalikeOf}, use that full address; never copy an address from transaction history.` : "Confirm the full address with the user.", retry: "change", ...(r.details?.lookalikeOf && { set: { to: r.details.lookalikeOf } }) }),
  SANCTIONED_ADDRESS: (r) => NEVER(`an address on the OFAC SDN list (${r.subject})`),
  PHISHING_SITE: (r) => NEVER(`a request from a known phishing site (${r.subject})`),
  LOOKALIKE_SITE: (r) => ({ expected: r.details?.lookalikeOf ? `the real site ${r.details.lookalikeOf}` : "the real site", saw: `a look-alike site (${r.subject})`, change: "Go to the real site yourself and do it there; don't sign for this one.", retry: "elsewhere" }),
  NEW_DOMAIN: (r) => ({ expected: "a site with a history", saw: `a domain registered days ago (${r.subject})`, change: "Ask the user whether they know this site; phishing sites are usually days old.", retry: "ask" }),
  WALLET_BLOCKS_SITE: (r) => ({ expected: "a site no wallet blocks", saw: `a wallet's blocklist names this site (${r.subject})`, change: "Don't sign for this site; do it on the protocol's real site instead.", retry: "elsewhere" }),
  // Contracts
  UNVERIFIED_CONTRACT: (r) => ({ expected: "a contract with published source", saw: `no verified source for ${r.subject}`, change: "Nothing in this request fixes that: use the verified contract for the same action (the protocol's official address), or ask the user.", retry: "elsewhere" }),
  RECENTLY_DEPLOYED: (r) => ({ expected: "a contract with a track record", saw: `${r.subject} was deployed very recently`, change: "Ask the user whether they expect a new contract here; drainers deploy fresh ones.", retry: "ask" }),
  MALICIOUS_CONTRACT_BEHAVIOR: (r) => NEVER(`a contract flagged for malicious behaviour (${r.subject})`),
  ON_DOUBT_LIST: (r) => NEVER(`a contract on GoPlus's doubt list (${r.subject})`),
  PHISHING_ACTIVITIES: (r) => NEVER(`an address reported for phishing (${r.subject})`),
  STEALING_ATTACK: (r) => NEVER(`an address reported for theft (${r.subject})`),
  CREATOR_OF_MALICIOUS_CONTRACTS: (r) => NEVER(`an address that created malicious contracts (${r.subject})`),
  MALICIOUS_DELEGATE: (r) => NEVER(`a wallet that delegates to a flagged contract (${r.subject})`),
  // Messages and EIP-7702
  ETH_SIGN: () => ({ expected: "personal_sign or eth_signTypedData_v4", saw: "eth_sign, which signs a raw hash that can be a transaction", change: "Ask for the same content as personal_sign or typed data; never use eth_sign.", retry: "change" }),
  MESSAGE_IS_TRANSACTION: () => NEVER("a 'message' that is really a transaction"),
  EIP7702_AUTHORIZATION: (r) => ({ expected: "a smart account the user chose by name", saw: `the whole wallet delegated to ${r.subject}`, change: "Sign only if the user asked for this smart account by name and address.", retry: "ask" }),
  AUTHORIZATION_ALL_CHAINS: () => ({ expected: "a delegation for one chain", saw: "authorizationChainId 0: valid on every chain", change: "Set the authorization's chainId to the one chain it is for.", retry: "change", set: { authorizationChainId: "this chain's id" } }),
  AUTHORIZATION_TO_NO_CONTRACT: (r) => NEVER(`a delegation to an address with no code (${r.subject}): whoever deploys there later controls the wallet`),
  AUTHORIZATION_TO_FLAGGED_CONTRACT: (r) => NEVER(`a delegation to a flagged contract (${r.subject})`),
  AUTHORIZATION_TO_UNVERIFIED_CONTRACT: (r) => ({ expected: "a delegate with published source", saw: `no verified source for ${r.subject}`, change: "Delegate only to a verified smart-account implementation the user chose.", retry: "elsewhere" }),
  AUTHORIZATION_TO_DELEGATED_WALLET: (r) => NEVER(`a delegation to another wallet (${r.subject}), not a contract`),
  // x402 payments against the seller's 402
  X402_RECIPIENT_MISMATCH: (r, req) => ({ expected: `payment to the seller's payTo${req?.x402?.payTo ? ` ${req.x402.payTo}` : ""}`, saw: `payment to ${r.subject}`, change: "Sign the payment to the payTo in the seller's 402, nothing else.", retry: "change", ...(req?.x402?.payTo && { set: { to: req.x402.payTo } }) }),
  X402_AMOUNT_ABOVE_REQUIRED: (r) => ({ expected: `${r.details?.required ?? "the amount asked"} (base units)`, saw: `${r.details?.signing ?? "more"} (base units)`, change: "Sign for exactly the amount in the seller's 402.", retry: "change", ...(r.details?.required && { set: { value: r.details.required } }) }),
  X402_ASSET_MISMATCH: (r, req) => ({ expected: `the token the seller asked for${req?.x402?.asset ? ` (${req.x402.asset})` : ""}`, saw: "another token", change: "Pay with the asset in the seller's 402.", retry: "change", ...(req?.x402?.asset && { set: { token: req.x402.asset } }) }),
  X402_NETWORK_MISMATCH: () => ({ expected: "the network the seller asked for", saw: "another network", change: "Sign on the network in the seller's 402 (its chainId).", retry: "change" }),
  X402_DOMAIN_MISMATCH: () => ({ expected: "the token's EIP-712 domain from the 402 (extra.name, extra.version)", saw: "another domain", change: "Use the name and version in the 402's extra; a signature with another domain is refused or signs for another contract.", retry: "change" }),
  X402_VALIDITY_TOO_LONG: (r, req) => ({ expected: `valid for at most the seller's timeout${req?.x402?.maxTimeoutSeconds ? ` (${req.x402.maxTimeoutSeconds} s)` : ""}`, saw: "a longer validity", change: "Set validBefore to now + maxTimeoutSeconds from the 402.", retry: "change", set: { validBefore: "now + maxTimeoutSeconds" } }),
  X402_SCHEME_UNEXPECTED: () => ({ expected: "the scheme the seller offered", saw: "another scheme", change: "Pay with the scheme in the seller's 402 (usually exact).", retry: "change" }),
  // Uniswap v4
  V4_SWAP_NO_LIMIT: (r) => swapLimit(r),
  V4_HOOK_CAN_TAKE_SWAP: (r) => (r.severity === "red" ? swapLimit(r) : null),
  V4_HOOK_SETS_FEE: (r) => (r.severity === "red" ? swapLimit(r) : null),
  V4_HOOK_CAN_TAKE_WITHDRAWAL: (r) => (r.details?.minima
    ? { expected: "minimum amounts back when taking liquidity out", saw: "amount0Min and amount1Min are 0", change: "Set amount0Min and amount1Min to what you expect back minus your slippage, so the hook can't keep more.", retry: "change", set: { amount0Min: "expected − slippage", amount1Min: "expected − slippage" } }
    : hookElsewhere(r, "a hook that can keep part of what you take out")),
  V4_HOOK_CAN_BLOCK_WITHDRAWAL: (r) => hookElsewhere(r, "a hook that can refuse your withdrawal (beforeRemoveLiquidity)"),
  V4_HOOK_UPGRADEABLE: (r) => hookElsewhere(r, "a hook its owner can change after you sign"),
};

function swapLimit(r) {
  const exactIn = r.details?.exactIn !== false;
  const field = exactIn ? "amountOutMinimum" : "amountInMaximum";
  return {
    expected: exactIn ? "a minimum you receive" : "a maximum you pay",
    saw: exactIn ? "amountOutMinimum 0 and no other check on what arrives" : "no maximum on what you pay",
    change: exactIn ? "Set amountOutMinimum to your quote minus your slippage (for example 0.5%); a TAKE_ALL minAmount or the router's SWEEP amountMin works too." : "Set amountInMaximum to your quote plus your slippage (or cap SETTLE_ALL's maxAmount).",
    retry: "change",
    set: { [field]: exactIn ? "quote × (1 − slippage)" : "quote × (1 + slippage)" },
  };
}
function hookElsewhere(r, what) {
  return { expected: "a pool whose hook can't do this", saw: what, change: "Nothing in this transaction changes the pool's hook: use a pool for the same tokens without this hook (or with no hook), or ask the user.", retry: "elsewhere" };
}

// The fix for one reason, or null when there is none to give (info reasons, or codes without a safe recipe).
export function fixFor(reason, req) {
  if (!reason || reason.severity === "info") return null;
  const f = FIXES[reason.code];
  return f ? f(reason, req) || null : null;
}

// Adds `fix` to every orange or red reason that has one, and `fixable` to the result: true when every orange and red
// reason can be fixed by changing the request (retry "change"), so building it again can come back green.
export function withFixes(result, req) {
  if (!result || !Array.isArray(result.reasons)) return result;
  let blocking = 0, changeable = 0;
  for (const r of result.reasons) {
    if (r.severity === "info") continue;
    blocking++;
    const fix = fixFor(r, req);
    if (fix) { r.fix = fix; if (fix.retry === "change") changeable++; }
  }
  if (blocking) result.fixable = changeable === blocking;
  return result;
}

export const FIX_CODES = Object.keys(FIXES);
