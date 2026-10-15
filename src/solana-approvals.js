// Solana side of the wallet approval audit (approvals.js): GET /v1/approvals?chain=solana&address=<wallet>.
//
// SPL Token's Approve gives a delegate the right to move up to an amount of one token account's tokens without the
// owner's signature: the Solana form of an ERC-20 allowance, and what drainers ask a wallet to sign. The wallet's
// token accounts (SPL Token and Token-2022) are read from the RPC (getTokenAccountsByOwner, jsonParsed); the
// delegates are looked up once (getMultipleAccounts) to tell a plain wallet from a program account, and screened
// against the OFAC SDN list in memory.
//
// Rules per delegation, in the spirit of the EVM audit:
// - red: the delegate is on the OFAC SDN list.
// - orange: the delegate is a plain wallet (owned by the System Program, or no account at all: a key that can sign),
//   or the delegation is unlimited (2^63 and up; wallets write u64 max).
// - info: a limited delegation to a program account.
// A Token-2022 token the wallet holds whose mint has a permanent delegate is listed apart: that delegate can move
// every holder's balance, and no holder can revoke it.

import { isAddress } from "@solana/kit";
import { solanaRpc } from "./solana-rpc.js";
import { screenOfacLoaded } from "./ofac.js";

const SYSTEM = "11111111111111111111111111111111";
const TOKEN_PROGRAMS = [
  ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "token"],
  ["TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "token-2022"],
];
const UNLIMITED = 1n << 63n;
const RPC_TIMEOUT_MS = 15000; // a wallet with many token accounts takes the public RPC a while
const BATCH = 100; // getMultipleAccounts takes at most 100 keys

export const isSolanaWallet = (value) => typeof value === "string" && isAddress(value);

const bigint = (v) => {
  try {
    return BigInt(String(v ?? "0"));
  } catch {
    return 0n;
  }
};

async function multipleAccounts(keys, config) {
  const out = [];
  for (let i = 0; i < keys.length; i += BATCH) {
    const value = await solanaRpc("getMultipleAccounts", [keys.slice(i, i + BATCH), config], { timeoutMs: RPC_TIMEOUT_MS });
    out.push(...(Array.isArray(value) ? value : keys.slice(i, i + BATCH).map(() => null)));
  }
  return out;
}

// Everything the audit needs from the chain, in three reads at most:
// { accounts, delegations: [{ account, delegate }], delegates: Map(address → { owner, executable } | null),
//   permanentDelegates: [{ mint, delegate, tokenAccount }] }.
export async function readSolanaDelegations(owner) {
  const lists = await Promise.all(TOKEN_PROGRAMS.map(([programId]) =>
    solanaRpc("getTokenAccountsByOwner", [owner, { programId }, { encoding: "jsonParsed", commitment: "confirmed" }], { timeoutMs: RPC_TIMEOUT_MS })));
  const accounts = lists.flatMap((list, i) => (Array.isArray(list) ? list : []).map((a) => ({
    pubkey: a.pubkey,
    program: TOKEN_PROGRAMS[i][1],
    info: a.account?.data?.parsed?.info ?? {},
  })));

  const delegated = accounts.filter((a) => a.info.delegate && bigint(a.info.delegatedAmount?.amount) > 0n);
  const delegateKeys = [...new Set(delegated.map((a) => a.info.delegate))];
  const delegateInfo = delegateKeys.length
    ? await multipleAccounts(delegateKeys, { encoding: "base64", dataSlice: { offset: 0, length: 0 } })
    : [];
  const delegates = new Map(delegateKeys.map((k, i) => [k, delegateInfo[i] ? { owner: delegateInfo[i].owner, executable: Boolean(delegateInfo[i].executable) } : null]));

  // Token-2022 mints of tokens the wallet holds: a permanent delegate there can move this balance too.
  const held = accounts.filter((a) => a.program === "token-2022" && bigint(a.info.tokenAmount?.amount) > 0n);
  const mints = [...new Set(held.map((a) => a.info.mint))];
  const mintInfo = mints.length ? await multipleAccounts(mints, { encoding: "jsonParsed" }) : [];
  const permanentDelegates = [];
  mints.forEach((mint, i) => {
    const ext = (mintInfo[i]?.data?.parsed?.info?.extensions ?? []).find((e) => e?.extension === "permanentDelegate");
    const delegate = ext?.state?.delegate;
    if (delegate) permanentDelegates.push({ mint, delegate, tokenAccount: held.find((a) => a.info.mint === mint).pubkey });
  });

  return { accounts, delegations: delegated.map((account) => ({ account, delegate: account.info.delegate })), delegates, permanentDelegates };
}

// One delegation, in the shape of an EVM approval (approvals.js) plus the token account to revoke it on.
export function assessDelegation({ account, delegate }, delegateAccount, now = () => Date.now()) {
  const codes = [];
  const add = (code, severity, details) => codes.push({ code, severity, ...(details ? { details } : {}) });
  const raw = bigint(account.info.delegatedAmount?.amount);
  const unlimited = raw >= UNLIMITED;
  const wallet = !delegateAccount || (delegateAccount.owner === SYSTEM && !delegateAccount.executable);

  const sanctions = screenOfacLoaded(delegate, { now });
  if (sanctions?.listed) add("SANCTIONED_ADDRESS", "red", { list: "OFAC SDN", matches: sanctions.matches.map(({ name, programs }) => ({ name, programs })) });
  if (wallet) add("APPROVAL_TO_WALLET", "orange");
  if (unlimited) add("UNLIMITED_APPROVAL", "orange");

  const severity = codes.some((c) => c.severity === "red") ? "red" : codes.length ? "orange" : "info";
  return {
    token: { address: account.info.mint ?? null, symbol: null, name: null },
    tokenAccount: account.pubkey,
    program: account.program,
    spender: { address: delegate, name: null, trusted: false, contract: !wallet },
    amount: unlimited ? "unlimited" : String(account.info.delegatedAmount?.uiAmountString ?? raw),
    unlimited,
    balance: account.info.tokenAmount?.uiAmountString ?? null,
    approvedAt: null,
    severity,
    codes,
    revoke: severity !== "info",
  };
}
