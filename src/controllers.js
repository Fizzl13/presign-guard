// Who holds an EVM token's powers: one key, a multisig, a timelock, or nobody.
//
// GoPlus says a token is upgradeable and names its owner, but not who can upgrade it or what kind of account
// that is. For a holder that is the difference between "one leaked key can swap the code" and "three of six
// signers must agree, and everyone gets two days' notice". Read on-chain, in a few JSON-RPC batches:
// - the upgrader: the proxy admin (EIP-1967 admin slot, or the older ZeppelinOS slot that Circle's FiatToken
//   proxy uses) or the beacon (EIP-1967 beacon slot). A UUPS proxy (implementation slot only) has no admin:
//   its owner usually upgrades it, which is reported but not taken as certain.
// - the role holders the common issuer contracts expose: owner(), masterMinter() (FiatToken), minter(),
//   pauser(), blacklister().
// Each holder is then classified. No code is one key (an EIP-7702 wallet is still one key). getThreshold() and
// getOwners() (Safe), or required() and getOwners() (the older MultiSigWallet, Tether's), is a multisig.
// getMinDelay() (OpenZeppelin TimelockController) or delay() with admin() (Compound's Timelock) is a timelock.
// Another contract with an owner() (a ProxyAdmin, a minter contract) is followed to that owner, two hops at
// most. The zero and dead addresses mean renounced.

import { decodeFunctionResult, encodeFunctionData, parseAbi } from "viem";
import { rpcBatch } from "./presign-guard.js";

const SLOTS = {
  admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
  zosAdmin: "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b",
  beacon: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
  implementation: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  proxiable: "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",
};
const ABI = parseAbi([
  "function owner() view returns (address)",
  "function masterMinter() view returns (address)",
  "function minter() view returns (address)",
  "function pauser() view returns (address)",
  "function blacklister() view returns (address)",
  "function getThreshold() view returns (uint256)",
  "function required() view returns (uint256)",
  "function getOwners() view returns (address[])",
  "function getMinDelay() view returns (uint256)",
  "function delay() view returns (uint256)",
  "function admin() view returns (address)",
]);
const call = (to, functionName) => ["eth_call", [{ to, data: encodeFunctionData({ abi: ABI, functionName }) }, "latest"]];
const ROLE_GETTERS = [["owner", "owner"], ["masterMinter", "mint"], ["minter", "mint"], ["pauser", "pause"], ["blacklister", "blacklist"]];
const CLASSIFIERS = ["getThreshold", "required", "getOwners", "getMinDelay", "delay", "admin", "owner"];
export const ROLES = ["upgrade", "owner", "mint", "pause", "blacklist"];
const MAX_HOPS = 2;
const RENOUNCED = new Set(["0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead"]);

// A 32-byte word holding an address (a storage slot, or an address getter's answer); null otherwise.
const wordAddress = (raw) => (typeof raw === "string" && /^0x0{24}[0-9a-f]{40}$/i.test(raw) ? `0x${raw.slice(26).toLowerCase()}` : null);
// A role or slot holder: a real address, not zero, dead or a small number such as a bool (precompiles have no code
// and would pass for one key).
const setAddress = (raw) => { const a = wordAddress(raw); return a && !RENOUNCED.has(a) && BigInt(a) > 0xffffffffn ? a : null; };
const uint = (raw) => (typeof raw === "string" && /^0x[0-9a-f]{64}$/i.test(raw) && BigInt(raw) <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(BigInt(raw)) : null);
function owners(raw) {
  if (typeof raw !== "string" || raw.length < 130) return null;
  try { return decodeFunctionResult({ abi: ABI, functionName: "getOwners", data: raw }); } catch { return null; }
}

// { type: "key" | "multisig" | "timelock" | "contract" | "renounced" | "unknown", … } for one address.
async function classify(chainId, address, hops = 0) {
  if (RENOUNCED.has(address)) return { type: "renounced" };
  let code, answers;
  try {
    [code, ...answers] = await rpcBatch(chainId, [["eth_getCode", [address, "latest"]], ...CLASSIFIERS.map((fn) => call(address, fn))]);
  } catch {
    return { type: "unknown" };
  }
  if (typeof code !== "string") return { type: "unknown" };
  if (code === "0x") return { type: "key" };
  if (/^0xef0100[0-9a-f]{40}$/i.test(code)) return { type: "key", delegated: true };
  const r = Object.fromEntries(CLASSIFIERS.map((fn, i) => [fn, answers[i]]));
  const signers = owners(r.getOwners);
  const threshold = uint(r.getThreshold) ?? uint(r.required);
  if (signers?.length && threshold >= 1 && threshold <= signers.length) return { type: "multisig", threshold, owners: signers.length };
  const minDelay = uint(r.getMinDelay);
  if (minDelay !== null) return { type: "timelock", delaySeconds: minDelay };
  const next = async (a) => ({ address: a, ...(await classify(chainId, a, hops + 1)) });
  const delay = uint(r.delay);
  const admin = setAddress(r.admin);
  if (delay !== null && admin) return { type: "timelock", delaySeconds: delay, ...(hops < MAX_HOPS && { admin: await next(admin) }) };
  const owner = setAddress(r.owner);
  if (owner && owner !== address && hops < MAX_HOPS) return { type: "contract", owner: await next(owner) };
  return { type: "contract" };
}

// { upgradeVia: "proxy admin" | "beacon" | "owner (UUPS)" | null, holders: [{ address, roles, type, … }] },
// or null when the chain RPC can't be asked. ownerHint: GoPlus's owner_address, used when owner() isn't there.
export async function tokenControllers(chainId, token, { ownerHint = null } = {}) {
  const slotNames = Object.keys(SLOTS);
  let answers;
  try {
    answers = await rpcBatch(chainId, [
      ...slotNames.map((name) => ["eth_getStorageAt", [token, SLOTS[name], "latest"]]),
      ...ROLE_GETTERS.map(([fn]) => call(token, fn)),
    ]);
  } catch {
    return null;
  }
  const slot = Object.fromEntries(slotNames.map((name, i) => [name, setAddress(answers[i])]));
  const roles = new Map();
  const give = (address, role) => { if (!roles.has(address)) roles.set(address, new Set()); roles.get(address).add(role); };
  ROLE_GETTERS.forEach(([, role], i) => {
    const raw = answers[slotNames.length + i];
    // A renounced owner is worth saying; a minter or pauser set to zero just means nobody has that role.
    const a = role === "owner" && RENOUNCED.has(wordAddress(raw)) ? wordAddress(raw) : setAddress(raw);
    if (a) give(a, role);
  });
  let owner = [...roles].find(([, set]) => set.has("owner"))?.[0];
  if (!owner && ownerHint) give((owner = ownerHint), "owner");
  let upgradeVia = null;
  const admin = slot.admin ?? slot.zosAdmin;
  if (admin) { give(admin, "upgrade"); upgradeVia = "proxy admin"; }
  else if (slot.beacon) { give(slot.beacon, "upgrade"); upgradeVia = "beacon"; }
  else if ((slot.implementation || slot.proxiable) && owner) { give(owner, "upgrade"); upgradeVia = "owner (UUPS)"; }
  const holders = await Promise.all([...roles].map(async ([address, set]) => ({
    address, roles: ROLES.filter((r) => set.has(r)), ...(await classify(chainId, address)),
  })));
  return { upgradeVia, holders };
}

// Follow contracts to their owners: the account that decides in the end, with the contracts in between.
export function finalHolder(holder) {
  const via = [];
  let h = holder;
  while (h.type === "contract" && h.owner) { via.push(h.address); h = h.owner; }
  return { ...h, via };
}

const duration = (s) => (s === 0 ? "no delay" : s < 3600 ? `${Math.round(s / 60)} min delay` : s < 2 * 86400 ? `${Math.round(s / 3600)} h delay` : `${Math.round(s / 86400)} days delay`);

export function describeHolder(holder) {
  const h = finalHolder(holder);
  const what = h.type === "multisig" ? `${h.threshold}-of-${h.owners} multisig`
    : h.type === "timelock" ? `timelock (${duration(h.delaySeconds)}${h.admin ? `, run by ${describeHolder(h.admin)}` : ""})`
    : { key: "one key", renounced: "renounced", contract: "a contract", unknown: "unknown" }[h.type];
  return h.via.length && h.type !== "contract" && h.type !== "unknown" ? `${what} via a contract` : what;
}

// "upgrade: one key; owner: 2-of-3 multisig; mint: one key via a contract"
export function controllerSummary({ upgradeVia, holders }) {
  return ROLES.map((role) => {
    const with_ = holders.filter((h) => h.roles.includes(role));
    if (!with_.length) return null;
    const label = role === "upgrade" && upgradeVia === "owner (UUPS)" ? "upgrade (UUPS, likely the owner)" : role;
    return `${label}: ${[...new Set(with_.map(describeHolder))].join(" and ")}`;
  }).filter(Boolean).join("; ");
}

// add(code, severity, details). An upgrade that one key can make on its own changes everything a holder relies
// on, so it is orange, except on a trust-list token (USDC, cbBTC: the issuer keeps it on purpose). An upgrade
// by the owner of a UUPS proxy is likely but not certain: context only.
export function controllerReasons(controllers, add, { trusted = false } = {}) {
  if (!controllers?.holders.length) return;
  const upgrader = controllers.upgradeVia !== "owner (UUPS)" && controllers.holders.find((h) => h.roles.includes("upgrade"));
  const final = upgrader && finalHolder(upgrader);
  if (final?.type === "key") {
    add("TOKEN_UPGRADE_ONE_KEY", trusted ? "info" : "orange", {
      upgrader: upgrader.address, key: final.address, ...(final.via.length && { via: final.via }),
    });
  }
  add("TOKEN_CONTROLLERS", "info", { summary: controllerSummary(controllers) });
}
