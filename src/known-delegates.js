// EIP-7702 delegate contracts we can name although their source isn't verified, so a red or orange verdict says
// whose code it is. A name never changes the verdict: unverified code that gets the whole wallet stays unverified.
// The name comes from the block explorer's tag; label_source says so.
const KNOWN_DELEGATES = {
  8453: {
    // Bitget Wallet's "7702 Logic" (Basescan name tag), 158 and 107 delegated wallets of paying agents on 30 Oct 2026
    // (Agentic Finance Graph). Source asked for in github.com/bitgetwallet/download/issues/90.
    "0x490aac77c960b0569c8e446ac7e12490bd44ca1d": { known_as: "Bitget Wallet 7702 Logic v0.0.3", label_source: "Basescan name tag; source not published" },
    "0xa845c74344fc9405b1fcf712f04668979573c1bf": { known_as: "Bitget Wallet 7702 Logic v0.0.2", label_source: "Basescan name tag; source not published" },
  },
};

export function knownDelegate(chainId, address) {
  if (typeof address !== "string") return null;
  return KNOWN_DELEGATES[Number(chainId)]?.[address.toLowerCase()] ?? null;
}
