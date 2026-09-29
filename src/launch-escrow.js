// Token launch escrows on Solana: accounts of the Metaplex Genesis program that hold
// a launch's supply until it is distributed (sale, launch pool and unlocked buckets).
// A bucket holding 97% of a token mid-launch is not a whale, so the holder check
// leaves it out and says so. One getMultipleAccounts on the top holders' owners.

import { cached } from "./presign-guard.js";
import { solanaRpc } from "./solana-rpc.js";

export const GENESIS_PROGRAM = "GNS1S5J5AspKXgpjz6SvKL66kPaKWAhaGRhCqPRxii2B";

// owners: holder (owner) addresses. Returns the ones owned by the Genesis program;
// an empty set when the chain can't be asked.
export async function launchEscrows(owners) {
  const list = [...new Set(owners)].filter(Boolean).slice(0, 20);
  if (!list.length) return new Set();
  try {
    return await cached(`escrow:${list.join(",")}`, async () => {
      const accounts = await solanaRpc("getMultipleAccounts", [list, { encoding: "base64", dataSlice: { offset: 0, length: 0 } }]);
      return new Set(list.filter((_, i) => accounts?.[i]?.owner === GENESIS_PROGRAM));
    });
  } catch {
    return new Set();
  }
}
