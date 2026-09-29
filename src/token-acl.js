// Permissioned Solana tokens (Token ACL, sRFC 37; MPL-3643 builds on it).
//
// A Token ACL token is a Token-2022 mint whose new token accounts start frozen
// (DefaultAccountState = frozen) and whose freeze authority is a MintConfig PDA of
// the Token ACL program. An issuer-chosen gate program decides which wallets may be
// thawed (allow or block list). To GoPlus that looks like "holders can be frozen";
// for a buyer the real point is different: without approval you may not be able to
// sell or send the token after buying it.
//
// One jsonParsed getAccountInfo on the mint, and one on the MintConfig when the
// freeze authority matches. Program source: github.com/solana-foundation/token-acl
// (the seed is "MINT_CONFIG" in program/src/state.rs; the sRFC text says "MINT_CFG").

import { address, getAddressDecoder, getAddressEncoder, getProgramDerivedAddress } from "@solana/kit";
import { cached } from "./presign-guard.js";
import { solanaRpc as rpc } from "./solana-rpc.js";

export const TOKEN_ACL_PROGRAM = "TACLkU6CiCdkQN2MjoyDkVg2yAH9zkxiHDsiztQ52TP";
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM_PROGRAM = "11111111111111111111111111111111";

export async function mintConfigAddress(mint) {
  const [pda] = await getProgramDerivedAddress({
    programAddress: address(TOKEN_ACL_PROGRAM),
    seeds: ["MINT_CONFIG", getAddressEncoder().encode(address(mint))],
  });
  return pda;
}

// MintConfig (program/src/state.rs, repr(C)): discriminator u8 = 1, bump u8,
// enable_permissionless_thaw bool, enable_permissionless_freeze bool, mint,
// freeze_authority (the issuer's authority), gating_program: 100 bytes.
export function decodeMintConfig(bytes) {
  if (!bytes || bytes.length < 100 || bytes[0] !== 1) return null;
  const decode = (at) => getAddressDecoder().decode(bytes.subarray(at, at + 32));
  const gate = decode(68);
  return {
    permissionlessThaw: bytes[2] === 1,
    permissionlessFreeze: bytes[3] === 1,
    mint: decode(4),
    authority: decode(36),
    gateProgram: gate === SYSTEM_PROGRAM ? null : gate,
  };
}


const extension = (info, name) => (info?.extensions ?? []).find((e) => e?.extension === name)?.state ?? null;

// null: not a Token ACL token. { error }: the chain couldn't be asked (not cached).
export async function permissionedToken(mint) {
  try {
    return await cached(`token-acl:${mint}`, () => readPermissioned(mint));
  } catch (err) {
    return { error: err.message };
  }
}

async function readPermissioned(mint) {
  const account = await rpc("getAccountInfo", [mint, { encoding: "jsonParsed", commitment: "confirmed" }]);
  if (account?.owner !== TOKEN_2022_PROGRAM) return null;
  const info = account.data?.parsed?.info;
  const pda = await mintConfigAddress(mint);
  if (!info || info.freezeAuthority !== pda) return null;
  const config = await rpc("getAccountInfo", [pda, { encoding: "base64", commitment: "confirmed" }]);
  const decoded = config?.owner === TOKEN_ACL_PROGRAM ? decodeMintConfig(Buffer.from(config.data?.[0] ?? "", "base64")) : null;
  return {
    standard: "token-acl",
    defaultFrozen: extension(info, "defaultAccountState")?.accountState === "frozen",
    mintConfig: pda,
    configAuthority: decoded?.authority ?? null,
    gateProgram: decoded?.gateProgram ?? null,
    permissionlessThaw: decoded?.permissionlessThaw ?? null,
    permanentDelegate: extension(info, "permanentDelegate")?.delegate ?? null,
    pausable: Boolean(extension(info, "pausableConfig")),
  };
}
