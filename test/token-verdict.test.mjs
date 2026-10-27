// Token verdict rules and the GET /v1/token route, without network: GoPlus,
// RugCheck and DexScreener are mocked through globalThis.fetch. The fixtures
// follow real responses (BONK, a fresh pump token, DEGEN on Base).
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import {
  tokenVerdict, parseTokenRequest, summarizeMarket, gradeOf, oneLiner,
  validateTokenQuery, createTokenRouter,
} from "../src/token-verdict.js";
import { mintConfigAddress, decodeMintConfig, TOKEN_2022_PROGRAM, TOKEN_ACL_PROGRAM } from "../src/token-acl.js";
import { GENESIS_PROGRAM } from "../src/launch-escrow.js";
import { getAddressDecoder, getAddressEncoder } from "@solana/kit";
import { encodeAbiParameters, toFunctionSelector } from "viem";
import { controllerSummary, describeHolder, finalHolder } from "../src/controllers.js";

const NOW = Date.UTC(2026, 8, 25, 12);
const DAY = 86400e3;
const BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
const FRESH = "qikeUfbJaWPHy7sTTYfQuBuafzmUBZAH7SjCbjZCyFA";
const RUGGED = "Rug1111111111111111111111111111111111111111";
const USDC_SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const UNKNOWN_SOL = "Unkn111111111111111111111111111111111111111";
const DOWN_SOL = "Down111111111111111111111111111111111111111";
// Token ACL (sRFC 37) mints: Token-2022, frozen by default, a MintConfig PDA as freeze authority.
const solAddress = (n) => getAddressDecoder().decode(new Uint8Array(32).fill(n));
const ACL = solAddress(11);
const ACL_DELEGATE = solAddress(12);
const FROZEN_WALLET = solAddress(13); // freeze authority is a plain wallet
const FROZEN_WALLET_2 = solAddress(14);
const GATE = solAddress(15);
const ISSUER = solAddress(16);
// Mid-launch Genesis token (as H6H8…PLEX on 29 Sep 2026): 96.9% sits in a Genesis bucket.
const LAUNCH = solAddress(17);
const BUCKET = solAddress(18);
const WHALE_LAUNCH = solAddress(19); // the same shape, but the big holder is a plain wallet
const BIG_WALLET = solAddress(20);
const DEGEN = "0x4ed4e862860bed51a9570b96d89af5e1b0efefed";
const HONEY = "0x1111111111111111111111111111111111111111";
const NOMARKET = "0x2222222222222222222222222222222222222222";
const WETH = "0x4200000000000000000000000000000000000006";
const CBBTC = "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf";
const PAUSED = "0x6666666666666666666666666666666666666666";

// A 32-byte word: a number, or an address padded on the left.
const word = (v) => "0x" + (typeof v === "string" ? v.slice(2).toLowerCase() : BigInt(v).toString(16)).padStart(64, "0");
const sel = (signature) => toFunctionSelector(signature);
const SLOT = {
  admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
  zosAdmin: "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b",
  implementation: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
};
const ownersOf = (n) => encodeAbiParameters([{ type: "address[]" }], [Array.from({ length: n }, (_, i) => `0x${String(i + 1).padStart(40, "0")}`)]);

const off = { status: "0" };
const on = { status: "1" };
const solSec = (over = {}) => ({
  mintable: off, freezable: off, closable: off, balance_mutable_authority: { status: "0", authority: [] },
  non_transferable: "0", transfer_fee: {}, transfer_fee_upgradable: off, transfer_hook: [], transfer_hook_upgradable: off,
  default_account_state_upgradable: off, metadata_mutable: { status: "0", metadata_upgrade_authority: [] }, creators: [],
  trusted_token: 0, holders: [], ...over,
});

const pair = (address, { liq, createdDaysAgo, symbol = "TKN", socials = true, h24 = 1000 }) => ({
  dexId: "raydium", url: `https://dexscreener.com/x/${address}`, pairCreatedAt: NOW - createdDaysAgo * DAY,
  baseToken: { address, name: symbol, symbol }, quoteToken: { address: "So11111111111111111111111111111111111111112", symbol: "SOL" },
  priceUsd: "0.5", liquidity: { usd: liq }, marketCap: 1e6, fdv: 2e6, volume: { h24 },
  ...(socials ? { info: { socials: [{ type: "twitter", url: "https://x.com/t" }] } } : {}),
});

const FIXTURES = {
  goplusSol: {
    [BONK]: solSec({ metadata_mutable: { status: "1", metadata_upgrade_authority: [{ address: "9AhK", malicious_address: 0 }] },
      holders: [{ account: "a", percent: "0.088" }, { account: "b", percent: "0.05", tag: "Raydium" }] }),
    [FRESH]: solSec({ transfer_fee: { current_fee_rate: { fee_rate: "0.01", maximum_fee: "1000" } }, transfer_fee_upgradable: on,
      holders: [{ account: "whale", percent: "0.194" }, { account: "w2", percent: "0.12" }, { account: "w3", percent: "0.11" }, { account: "w4", percent: "0.1" }] }),
    [RUGGED]: solSec({ mintable: on, freezable: on }),
    [USDC_SOL]: solSec({ mintable: on, freezable: on, trusted_token: 1 }),
    [DOWN_SOL]: solSec(),
    [ACL]: solSec({ freezable: on, default_account_state_upgradable: on }),
    [ACL_DELEGATE]: solSec({ freezable: on }),
    [FROZEN_WALLET]: solSec({ freezable: on }),
    [FROZEN_WALLET_2]: solSec({ freezable: on }),
  },
  rugcheck: {
    [BONK]: { rugged: false, risks: [], markets: [{ lp: { lpLockedPct: 0 } }] },
    [FRESH]: { rugged: false, risks: [{ name: "Top 10 holders high ownership", level: "danger" }], markets: [{ lp: { lpLockedPct: 100 } }] },
    [RUGGED]: { rugged: true, risks: [], markets: [{ lp: { lpLockedPct: 0 } }] },
    [LAUNCH]: { rugged: false, risks: [{ name: "Single holder ownership", level: "danger" }], markets: [],
      topHolders: [{ address: "ta1", owner: BUCKET, pct: 96.86 }, { address: "ta2", owner: ISSUER, pct: 3.14 }] },
    [WHALE_LAUNCH]: { rugged: false, risks: [], markets: [],
      topHolders: [{ address: "ta3", owner: BIG_WALLET, pct: 96.86 }, { address: "ta4", owner: ISSUER, pct: 3.14 }] },
  },
  dex: {
    [BONK]: [pair(BONK, { liq: 422000, createdDaysAgo: 1000, symbol: "Bonk" })],
    [FRESH]: [pair(FRESH, { liq: 21000, createdDaysAgo: 0.01, symbol: "LITECAT", socials: false })],
    [RUGGED]: [pair(RUGGED, { liq: 300, createdDaysAgo: 3 })],
    [USDC_SOL]: [pair(USDC_SOL, { liq: 5e7, createdDaysAgo: 900, symbol: "USDC" })],
    [UNKNOWN_SOL]: [],
    [DOWN_SOL]: [pair(DOWN_SOL, { liq: 1e6, createdDaysAgo: 100 })],
    [ACL]: [pair(ACL, { liq: 2e6, createdDaysAgo: 200, symbol: "RWA" })],
    [ACL_DELEGATE]: [pair(ACL_DELEGATE, { liq: 2e6, createdDaysAgo: 200, symbol: "RWA2" })],
    [FROZEN_WALLET]: [pair(FROZEN_WALLET, { liq: 2e6, createdDaysAgo: 200, symbol: "FRZ" })],
    [FROZEN_WALLET_2]: [pair(FROZEN_WALLET_2, { liq: 2e6, createdDaysAgo: 200, symbol: "FRZ2" })],
    [LAUNCH]: [pair(LAUNCH, { liq: 2e6, createdDaysAgo: 200, symbol: "PLEX" })],
    [WHALE_LAUNCH]: [pair(WHALE_LAUNCH, { liq: 2e6, createdDaysAgo: 200, symbol: "WHL" })],
    [DEGEN]: [pair(DEGEN, { liq: 3e6, createdDaysAgo: 900, symbol: "DEGEN" })],
    [HONEY]: [pair(HONEY, { liq: 80000, createdDaysAgo: 0.5 })],
    [NOMARKET]: [],
    [WETH]: [pair(WETH, { liq: 20000, createdDaysAgo: 5, symbol: "WETH" })],
    [CBBTC]: [pair(CBBTC, { liq: 5e7, createdDaysAgo: 700, symbol: "cbBTC" })],
    [PAUSED]: [pair(PAUSED, { liq: 2e6, createdDaysAgo: 400, symbol: "PSD" })],
  },
  goplusEvm: {
    [DEGEN]: { is_open_source: "1", is_honeypot: "0", buy_tax: "0", sell_tax: "0", holder_count: "900000",
      holders: [{ address: "0xpool", percent: "0.3", is_locked: 0 }, { address: "0xstaking", percent: "0.4", is_contract: 1 }, { address: "0xa", percent: "0.05", is_locked: 0 }],
      dex: [{ pair: "0xpool", liquidity: "3000000" }] },
    [HONEY]: { is_open_source: "1", is_honeypot: "1", buy_tax: "0", sell_tax: "1" },
    [NOMARKET]: { is_open_source: "0" },
    [WETH]: { is_open_source: "1", trust_list: "1", owner_change_balance: "1", holders: [{ address: "0xw", percent: "0.25", is_contract: 0 }],
      lp_holders: [{ address: "0xlp", percent: "1", is_locked: 0 }] },
    // A proxy token: GoPlus reports is_proxy and the owner, and no control fields (as for cbBTC and EURC on Base).
    [CBBTC]: { is_proxy: "1", is_open_source: "1", trust_list: "1", owner_address: "0x5e8114643966b7fd7d5cfdd8695ffc5c51ff32c0" },
    [PAUSED]: { is_proxy: "1", is_open_source: "1" },
  },
  // eth_call answers by token and 4-byte selector; anything else reverts (no such function).
  rpc: {
    [CBBTC]: {
      "0x5c975abb": "0x" + "0".repeat(64), // paused() → false
      "0x9fd0506d": "0x" + "0".repeat(24) + "1ac78dfcae082e9fe286d1ccb12c17a3e906b906", // pauser()
      "0xbd102430": "0x" + "0".repeat(24) + "158cfa498b1f72f458acf8df993c709efca11e31", // blacklister()
      "0xfe575a87": "0x" + "0".repeat(64), // isBlacklisted(0x0) → false
    },
    [PAUSED]: { "0x5c975abb": "0x" + "0".repeat(63) + "1" },
  },
  // eth_getStorageAt answers by contract and slot (unset slots are zero), and eth_getCode by address (no code: a wallet).
  slots: {},
  code: {},
};

// Solana RPC getAccountInfo answers, filled in before() (the PDAs need async derivation).
const solanaAccounts = {};
const enc = getAddressEncoder();
function mintConfigBytes({ mint, thaw = true, gate = GATE }) {
  const b = new Uint8Array(100);
  b.set([1, 255, thaw ? 1 : 0, 0]);
  b.set(enc.encode(mint), 4);
  b.set(enc.encode(ISSUER), 36);
  b.set(enc.encode(gate), 68);
  return b;
}
const token2022Mint = (freezeAuthority, extensions) => ({
  owner: TOKEN_2022_PROGRAM,
  data: { parsed: { type: "mint", info: { freezeAuthority, mintAuthority: null, extensions } }, program: "spl-token-2022" },
});

const realFetch = globalThis.fetch;
const calls = [];
const rpcCalls = [];
let down = new Set();

before(async () => {
  for (const mint of [ACL, ACL_DELEGATE]) {
    const pda = await mintConfigAddress(mint);
    solanaAccounts[mint] = token2022Mint(pda, [
      { extension: "defaultAccountState", state: { accountState: "frozen" } },
      ...(mint === ACL_DELEGATE ? [{ extension: "permanentDelegate", state: { delegate: ISSUER } }] : []),
    ]);
    solanaAccounts[pda] = { owner: TOKEN_ACL_PROGRAM, data: [Buffer.from(mintConfigBytes({ mint })).toString("base64"), "base64"] };
  }
  solanaAccounts[BUCKET] = { owner: GENESIS_PROGRAM, data: ["", "base64"] };
  solanaAccounts[BIG_WALLET] = { owner: "11111111111111111111111111111111", data: ["", "base64"] };
  solanaAccounts[FROZEN_WALLET] = token2022Mint(ISSUER, [{ extension: "defaultAccountState", state: { accountState: "initialized" } }]);
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    calls.push(u.hostname);
    if (down.has(u.hostname)) return new Response("busy", { status: 503 });
    if (u.hostname === "api.typesafe.ai") {
      const q = JSON.parse(init.body).questions;
      return Response.json({ model: "jev-test", answers: Object.fromEntries(Object.keys(q).map((id) => [id, { type: "noul", noul: jevP }])), usage: {} });
    }
    if (u.hostname === "api.gopluslabs.io") {
      const a = u.searchParams.get("contract_addresses");
      const table = u.pathname.includes("/solana/") ? FIXTURES.goplusSol : FIXTURES.goplusEvm;
      return Response.json({ code: 1, message: "OK", result: table[a] ? { [a]: table[a] } : {} });
    }
    if (u.hostname === "api.rugcheck.xyz") {
      const mint = u.pathname.split("/")[3];
      if (mint === DOWN_SOL) return new Response("rate limited", { status: 429 });
      return FIXTURES.rugcheck[mint] ? Response.json(FIXTURES.rugcheck[mint]) : new Response("not found", { status: 404 });
    }
    if (u.hostname === "base-rpc.publicnode.com" || u.hostname === "rpc.xlayer.tech") {
      if (down.has("rpc")) throw new TypeError("fetch failed");
      // One JSON-RPC batch per token (or per role holder): storage slots, code and eth_call.
      return Response.json(JSON.parse(init.body).map(({ id, method, params }) => {
        if (method === "eth_getStorageAt") {
          rpcCalls.push("slot");
          return { jsonrpc: "2.0", id, result: FIXTURES.slots[params[0]]?.[params[1]] ?? word(0) };
        }
        if (method === "eth_getCode") {
          rpcCalls.push("code");
          return { jsonrpc: "2.0", id, result: FIXTURES.code[params[0]] ?? "0x" };
        }
        const [{ to, data }] = params;
        rpcCalls.push(data.slice(0, 10));
        const result = FIXTURES.rpc[to]?.[data.slice(0, 10)];
        return result ? { jsonrpc: "2.0", id, result } : { jsonrpc: "2.0", id, error: { code: 3, message: "execution reverted" } };
      }));
    }
    if (u.hostname === "api.mainnet-beta.solana.com") {
      if (down.has("solana-rpc")) throw new TypeError("fetch failed");
      const { id, method, params: [account] } = JSON.parse(init.body);
      const value = method === "getMultipleAccounts" ? account.map((a) => solanaAccounts[a] ?? null) : solanaAccounts[account] ?? null;
      return Response.json({ jsonrpc: "2.0", id, result: { context: { slot: 1 }, value } });
    }
    if (u.hostname === "api.dexscreener.com") {
      return Response.json(FIXTURES.dex[u.pathname.split("/").pop()] ?? []);
    }
    throw new Error(`unexpected fetch ${u}`);
  };
});
after(() => { globalThis.fetch = realFetch; });
beforeEach(() => { calls.length = 0; rpcCalls.length = 0; down = new Set(); });

let jevP = 0.02;
const codes = (r, severity) => r.reasons.filter((x) => !severity || x.severity === severity).map((x) => x.code).sort();

test("input: chain and address are checked, EVM addresses lowercased", () => {
  assert.deepEqual(parseTokenRequest({ chain: "Base", address: "0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed" }), { chain: "base", address: DEGEN });
  assert.deepEqual(parseTokenRequest({ chain: "solana", address: BONK }), { chain: "solana", address: BONK });
  assert.throws(() => parseTokenRequest({ chain: "tron", address: BONK }), /chain must be one of/);
  assert.throws(() => parseTokenRequest({ chain: "solana", address: DEGEN }), /Solana mint/);
  assert.throws(() => parseTokenRequest({ chain: "base", address: BONK }), /0x-prefixed/);
  assert.throws(() => parseTokenRequest({}), /chain/);
});

test("Solana, established token (BONK): green, SAFE, market facts in the one-liner", async () => {
  const r = await tokenVerdict({ chain: "solana", address: BONK }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  // LP 0% locked on a 2.7-year-old token is context (concentrated-liquidity pools have no LP token).
  assert.deepEqual(codes(r, "info"), ["LP_NOT_LOCKED", "MUTABLE_METADATA"]);
  assert.equal(r.one_liner, "SAFE: no red flags, $422k liquidity, 2.7 years old");
  assert.deepEqual([r.market.symbol, r.market.liquidityUsd, r.market.priceUsd], ["Bonk", 422000, 0.5]);
  assert.deepEqual(r.sources, ["goplus", "dexscreener", "rugcheck"]);
});

test("Solana, fresh pump token: orange, RISKY, reasons in order of weight", async () => {
  const r = await tokenVerdict({ chain: "solana", address: FRESH }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "RISKY"]);
  assert.deepEqual(codes(r, "orange"), ["LOW_LIQUIDITY", "NEW_TOKEN", "TOP_HOLDERS_CONCENTRATED", "TRANSFER_FEE", "TRANSFER_FEE_UPGRADABLE"]);
  assert.deepEqual(r.reasons.find((x) => x.code === "TOP_HOLDERS_CONCENTRATED").details, { top1Pct: 19.4, top10Pct: 52.4 });
  assert.deepEqual(r.reasons.find((x) => x.code === "TRANSFER_FEE").details, { feePct: 1 });
  assert.ok(codes(r, "info").includes("NO_SOCIALS"));
  assert.ok(codes(r, "info").includes("RUGCHECK_DANGER"));
  assert.ok(!codes(r).includes("LP_NOT_LOCKED"), "100% LP locked");
  assert.ok(r.one_liner.startsWith("RISKY: "));
  assert.ok(r.one_liner.length <= 140);
});

test("Solana, rugged: red, AVOID", async () => {
  const r = await tokenVerdict({ chain: "solana", address: RUGGED }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["red", "AVOID"]);
  assert.equal(r.reasons[0].code, "RUGGED");
  assert.ok(codes(r, "orange").includes("MINT_AUTHORITY_ACTIVE"));
  assert.ok(codes(r, "orange").includes("LP_NOT_LOCKED"), "a 3-day-old token with unlocked LP");
  assert.match(r.one_liner, /^AVOID: marked rugged by RugCheck; /);
});

test("Solana, trusted issuer (USDC): mint and freeze authority are context, not a warning", async () => {
  const r = await tokenVerdict({ chain: "solana", address: USDC_SOL }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.deepEqual(codes(r, "info"), ["FREEZE_AUTHORITY_ACTIVE", "MINT_AUTHORITY_ACTIVE", "TOKEN_ON_TRUST_LIST"]);
  assert.equal(r.one_liner, "SAFE: no red flags, on the GoPlus trust list");
});

test("Solana, permissioned token (Token ACL): one reason that says what it means for a buyer, not \"holders can be frozen\"", async () => {
  const r = await tokenVerdict({ chain: "solana", address: ACL }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "CAUTION"]);
  assert.deepEqual(codes(r, "orange"), ["PERMISSIONED_TOKEN"]);
  assert.ok(!codes(r).includes("FREEZE_AUTHORITY_ACTIVE"));
  const reason = r.reasons.find((x) => x.code === "PERMISSIONED_TOKEN");
  assert.deepEqual(reason.details, { standard: "token-acl", defaultFrozen: true, gateProgram: GATE, configAuthority: ISSUER, permissionlessThaw: true, pausable: false });
  assert.equal(r.permissioned.mintConfig, await mintConfigAddress(ACL));
  assert.equal(r.permissioned.permanentDelegate, null);
  assert.ok(r.sources.includes("chain"));
  assert.equal(r.one_liner, "CAUTION: permissioned: only approved wallets can hold or send it");
});

test("Solana, permissioned token with a permanent delegate: the issuer can also move balances", async () => {
  const r = await tokenVerdict({ chain: "solana", address: ACL_DELEGATE }, NOW);
  assert.deepEqual(codes(r, "orange"), ["BALANCE_MUTABLE", "PERMISSIONED_TOKEN"]);
  assert.deepEqual(r.reasons.find((x) => x.code === "BALANCE_MUTABLE").details, { permanentDelegate: ISSUER });
});

test("Solana, a Token-2022 freeze authority that is a plain wallet is not Token ACL; RPC down keeps the old reason", async () => {
  const r = await tokenVerdict({ chain: "solana", address: FROZEN_WALLET }, NOW);
  assert.deepEqual(codes(r, "orange"), ["FREEZE_AUTHORITY_ACTIVE"]);
  assert.equal(r.permissioned, undefined);
  assert.ok(!r.sources.includes("chain"));

  down.add("solana-rpc");
  const r2 = await tokenVerdict({ chain: "solana", address: FROZEN_WALLET_2 }, NOW);
  assert.ok(codes(r2, "info").includes("PERMISSION_CHECK_UNAVAILABLE"));
});

test("Solana, the chain is only asked when GoPlus reports a freeze authority, and never for a trust-list token", async () => {
  await tokenVerdict({ chain: "solana", address: BONK }, NOW);
  await tokenVerdict({ chain: "solana", address: USDC_SOL }, NOW);
  assert.ok(!calls.includes("api.mainnet-beta.solana.com"));
});

test("Solana, mid-launch Genesis token: the launch bucket is not a whale, and the verdict says so", async () => {
  const r = await tokenVerdict({ chain: "solana", address: LAUNCH }, NOW);
  assert.ok(!codes(r).includes("TOP_HOLDERS_CONCENTRATED"));
  assert.deepEqual(r.reasons.find((x) => x.code === "GENESIS_LAUNCH_ESCROW").details, { pct: 96.9 });
  assert.ok(r.sources.includes("chain"));

  const w = await tokenVerdict({ chain: "solana", address: WHALE_LAUNCH }, NOW);
  assert.ok(codes(w, "orange").includes("TOP_HOLDERS_CONCENTRATED"), "a wallet holding 97% still counts");
  assert.ok(!codes(w).includes("GENESIS_LAUNCH_ESCROW"));
});

test("Solana, launch-bucket check: only asked when holders look concentrated; RPC down keeps the warning", async () => {
  await tokenVerdict({ chain: "solana", address: BONK }, NOW);
  assert.ok(!calls.includes("api.mainnet-beta.solana.com"), "BONK is not concentrated");
  down.add("solana-rpc");
  const r = await tokenVerdict({ chain: "solana", address: WHALE_LAUNCH }, NOW);
  assert.ok(codes(r, "orange").includes("TOP_HOLDERS_CONCENTRATED"));
});

test("MintConfig PDA: seeds [\"MINT_CONFIG\", mint], as on Solana mainnet (the sRFC text says MINT_CFG)", async () => {
  // Real mainnet pairs (Token ACL program accounts, 29 Sep 2026): mint → its freeze authority.
  assert.equal(await mintConfigAddress("Gy3Z9BuZAXHgtcXTyViwPu1dSvps82G3PSBaCRbFSRgz"), "CC7XEhUUko1saNtEAXxo4jTSeDrDQ7ovT3NqVNihaUf");
  assert.equal(await mintConfigAddress("u6ckpYSMLF57AZupbc7jq1cz4ZqvaFDj2TGxGadQ2QY"), "yu3xt9cktk9nYor6eY2zrYzHtoRdR7AFrY7o5WvkU5U");
});

test("MintConfig layout (program/src/state.rs): flags, mint, authority, gate; no gate is null", () => {
  const cfg = decodeMintConfig(mintConfigBytes({ mint: ACL, thaw: false }));
  assert.deepEqual(cfg, { permissionlessThaw: false, permissionlessFreeze: false, mint: ACL, authority: ISSUER, gateProgram: GATE });
  assert.equal(decodeMintConfig(mintConfigBytes({ mint: ACL, gate: "11111111111111111111111111111111" })).gateProgram, null);
  assert.equal(decodeMintConfig(new Uint8Array(100)), null, "wrong discriminator");
  assert.equal(decodeMintConfig(new Uint8Array(20)), null, "too short");
});

test("unknown token: no data is orange, never red", async () => {
  const r = await tokenVerdict({ chain: "solana", address: UNKNOWN_SOL }, NOW);
  assert.equal(r.verdict, "orange");
  assert.deepEqual(codes(r, "orange"), ["NO_DEX_MARKET"]);
  assert.ok(codes(r, "info").includes("NO_SECURITY_DATA"));
  assert.equal(r.market, null);
  assert.deepEqual(r.sources, ["goplus", "dexscreener"], "RugCheck 404: not a source");
});

test("RugCheck down: still a verdict, with the gap reported", async () => {
  const r = await tokenVerdict({ chain: "solana", address: DOWN_SOL }, NOW);
  assert.equal(r.verdict, "green");
  assert.deepEqual(codes(r, "info"), ["RUGCHECK_UNAVAILABLE"]);
  assert.ok(!r.sources.includes("rugcheck"));
});

test("Base, established token (DEGEN): pools and contracts are not counted as whales", async () => {
  const r = await tokenVerdict({ chain: "base", address: DEGEN }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.ok(!codes(r).includes("TOP_HOLDERS_CONCENTRATED"));
});

test("Base, LP lock and an unknown pair age: 10,000+ holders isn't a young token (EURC, cbETH); a few hundred still is", async () => {
  const noAge = (address, symbol) => { const p = pair(address, { liq: 1e6, createdDaysAgo: 0, symbol }); delete p.pairCreatedAt; return [p]; };
  const unlocked = { is_open_source: "1", lp_holders: [{ address: "0xlp", percent: "1", is_locked: 0 }] };
  const old = "0x7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d";
  const fresh = "0x7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";
  FIXTURES.goplusEvm[old] = { ...unlocked, holder_count: "114326" };
  FIXTURES.goplusEvm[fresh] = { ...unlocked, holder_count: "312" };
  FIXTURES.dex[old] = noAge(old, "OLD");
  FIXTURES.dex[fresh] = noAge(fresh, "NEW");
  const established = await tokenVerdict({ chain: "base", address: old }, NOW);
  assert.equal(established.market.ageSeconds, null);
  assert.deepEqual([established.verdict, established.grade], ["green", "SAFE"]);
  assert.equal(established.reasons.find((x) => x.code === "LP_NOT_LOCKED").severity, "info");
  const young = await tokenVerdict({ chain: "base", address: fresh }, NOW);
  assert.deepEqual(codes(young, "orange"), ["LP_NOT_LOCKED"]);
});

test("Base, trusted token: issuer powers, thin DexScreener liquidity and LP lock are context; a big wallet still counts", async () => {
  const r = await tokenVerdict({ chain: "base", address: WETH }, NOW);
  assert.deepEqual(codes(r, "orange"), ["TOP_HOLDERS_CONCENTRATED"]);
  for (const code of ["LOW_LIQUIDITY", "LP_NOT_LOCKED", "TOKEN_OWNER_CAN_CHANGE_BALANCES"]) assert.ok(codes(r, "info").includes(code), code);
});

test("Base, proxy token (cbBTC): GoPlus is silent on controls, so the chain is asked; pause and blacklist powers are context", async () => {
  const r = await tokenVerdict({ chain: "base", address: CBBTC }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  const byCode = Object.fromEntries(r.reasons.map((x) => [x.code, x]));
  assert.deepEqual(byCode.TOKEN_PAUSABLE, { code: "TOKEN_PAUSABLE", severity: "info", details: { source: "onchain", pauser: "0x1ac78dfcae082e9fe286d1ccb12c17a3e906b906" } });
  assert.deepEqual(byCode.TOKEN_BLACKLIST, { code: "TOKEN_BLACKLIST", severity: "info", details: { source: "onchain", blacklister: "0x158cfa498b1f72f458acf8df993c709efca11e31" } });
  assert.ok(!byCode.TOKEN_PAUSED);
  assert.ok(r.sources.includes("chain"));
  assert.equal(r.one_liner, "SAFE: no red flags, on the GoPlus trust list; issuer can pause transfers and blacklist holders");
});

test("Base, a token paused right now: orange, whatever else it looks like", async () => {
  const r = await tokenVerdict({ chain: "base", address: PAUSED }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "CAUTION"]);
  assert.deepEqual(codes(r, "orange"), ["TOKEN_PAUSED"]);
  assert.ok(codes(r, "info").includes("TOKEN_PAUSABLE"));
  assert.match(r.one_liner, /^CAUTION: transfers are paused/);
});

test("Base, controls: no RPC calls when GoPlus answers; RPC down means no control reasons, still a verdict", async () => {
  const answered = "0x5555555555555555555555555555555555555555";
  FIXTURES.goplusEvm[answered] = { is_open_source: "1", transfer_pausable: "0", is_blacklisted: "0" };
  FIXTURES.dex[answered] = [pair(answered, { liq: 2e6, createdDaysAgo: 400 })];
  await tokenVerdict({ chain: "base", address: answered }, NOW);
  assert.equal(rpcCalls.length, 0);

  down = new Set(["rpc"]);
  const silent = "0x4444444444444444444444444444444444444444";
  FIXTURES.goplusEvm[silent] = { is_proxy: "1", is_open_source: "1" };
  FIXTURES.dex[silent] = [pair(silent, { liq: 2e6, createdDaysAgo: 400 })];
  const r = await tokenVerdict({ chain: "base", address: silent }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.ok(!r.reasons.some((x) => ["TOKEN_PAUSABLE", "TOKEN_BLACKLIST", "TOKEN_PAUSED", "TOKEN_CONTROLLERS", "TOKEN_UPGRADE_ONE_KEY"].includes(x.code)));
  assert.ok(!r.sources.includes("chain"));
});

// Who holds a token's powers (src/controllers.js). Addresses: 0xa… wallets, 0xb… contracts.
const KEY = "0xaaaa000000000000000000000000000000000001";
const SAFE = "0xbbbb000000000000000000000000000000000001";
const PROXY_ADMIN = "0xbbbb000000000000000000000000000000000002";
const TIMELOCK = "0xbbbb000000000000000000000000000000000003";
const OLD_MULTISIG = "0xbbbb000000000000000000000000000000000004";
const EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42";
function controlFixture(token, goplus, { slots = {}, calls = {} } = {}) {
  FIXTURES.goplusEvm[token] = { is_open_source: "1", ...goplus };
  FIXTURES.dex[token] = [pair(token, { liq: 2e6, createdDaysAgo: 400 })];
  FIXTURES.slots[token] = slots;
  FIXTURES.rpc[token] = { ...FIXTURES.rpc[token], ...calls };
}
FIXTURES.code[SAFE] = "0x6080";
FIXTURES.rpc[SAFE] = { [sel("getThreshold()")]: word(2), [sel("getOwners()")]: ownersOf(3) };
FIXTURES.code[PROXY_ADMIN] = "0x6080";
FIXTURES.rpc[PROXY_ADMIN] = { [sel("owner()")]: word(TIMELOCK) };
FIXTURES.code[TIMELOCK] = "0x6080";
FIXTURES.rpc[TIMELOCK] = { [sel("getMinDelay()")]: word(172800) };
FIXTURES.code[OLD_MULTISIG] = "0x6080";
FIXTURES.rpc[OLD_MULTISIG] = { [sel("required()")]: word(3), [sel("getOwners()")]: ownersOf(5) };
const MINTER = "0xbbbb000000000000000000000000000000000005"; // like Aerodrome's Minter: no owner(), run by team()
FIXTURES.code[MINTER] = "0x6080";
FIXTURES.rpc[MINTER] = { [sel("team()")]: word(SAFE) };
const ADMINED = "0xbbbb000000000000000000000000000000000006"; // admin() without a delay: not a timelock
FIXTURES.code[ADMINED] = "0x6080";
FIXTURES.rpc[ADMINED] = { [sel("owner()")]: word(ADMINED), [sel("admin()")]: word(KEY) };

test("Base, who can upgrade: one key on a token nobody vouches for is orange, and every role holder is named", async () => {
  const token = "0x7777777777777777777777777777777777777777";
  controlFixture(token, { is_proxy: "1" }, { slots: { [SLOT.admin]: word(KEY) }, calls: { [sel("owner()")]: word(SAFE) } });
  const r = await tokenVerdict({ chain: "base", address: token }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "CAUTION"]);
  assert.deepEqual(codes(r, "orange"), ["TOKEN_UPGRADE_ONE_KEY"]);
  const byCode = Object.fromEntries(r.reasons.map((x) => [x.code, x]));
  assert.deepEqual(byCode.TOKEN_UPGRADE_ONE_KEY.details, { upgrader: KEY, key: KEY });
  assert.equal(byCode.TOKEN_CONTROLLERS.details.summary, "upgrade: one key; owner: 2-of-3 multisig");
  assert.match(r.one_liner, /^CAUTION: one key can upgrade the contract/);
  assert.equal(r.controllers.upgradeVia, "proxy admin");
  assert.deepEqual(r.controllers.holders.find((h) => h.address === SAFE), { address: SAFE, roles: ["owner"], type: "multisig", threshold: 2, owners: 3 });
  assert.ok(r.sources.includes("chain"));
});

test("Base, an upgrade through a ProxyAdmin owned by a two-day timelock: context, not a warning", async () => {
  const token = "0x7878787878787878787878787878787878787878";
  controlFixture(token, { is_proxy: "1" }, { slots: { [SLOT.admin]: word(PROXY_ADMIN) } });
  const r = await tokenVerdict({ chain: "base", address: token }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.equal(r.reasons.find((x) => x.code === "TOKEN_CONTROLLERS").details.summary, "upgrade: timelock (2 days delay) via a contract");
  assert.deepEqual(finalHolder(r.controllers.holders[0]), { address: TIMELOCK, type: "timelock", delaySeconds: 172800, via: [PROXY_ADMIN] });
});

test("Base, one key that can upgrade a trust-list or official token (cbBTC, EURC) is context: the issuer keeps it on purpose", async () => {
  // Set up like cbBTC on Base (verdicts are cached, so a fresh address): FiatToken roles, the ZeppelinOS admin slot.
  const trusted = "0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
  controlFixture(trusted, { is_proxy: "1", trust_list: "1", owner_address: "0x5e8114643966b7fd7d5cfdd8695ffc5c51ff32c0" }, {
    slots: { [SLOT.zosAdmin]: word(KEY) }, calls: FIXTURES.rpc[CBBTC],
  });
  const cb = await tokenVerdict({ chain: "base", address: trusted }, NOW);
  assert.deepEqual([cb.verdict, cb.grade], ["green", "SAFE"]);
  assert.equal(cb.reasons.find((x) => x.code === "TOKEN_UPGRADE_ONE_KEY").severity, "info");
  assert.equal(cb.one_liner, "SAFE: no red flags, on the GoPlus trust list; issuer can pause transfers and blacklist holders");
  assert.equal(cb.reasons.find((x) => x.code === "TOKEN_CONTROLLERS").details.summary, "upgrade: one key; owner: one key; pause: one key; blacklist: one key");

  controlFixture(EURC, { is_proxy: "1" }, { slots: { [SLOT.zosAdmin]: word(KEY) } }); // not on the GoPlus trust list
  const eurc = await tokenVerdict({ chain: "base", address: EURC }, NOW);
  assert.deepEqual([eurc.verdict, eurc.grade], ["green", "SAFE"]);
  assert.equal(eurc.reasons.find((x) => x.code === "TOKEN_UPGRADE_ONE_KEY").severity, "info");
});

test("Base, UUPS proxy: its owner likely upgrades it; said, but never orange on a guess", async () => {
  const token = "0x7979797979797979797979797979797979797979";
  controlFixture(token, { is_proxy: "1" }, { slots: { [SLOT.implementation]: word("0x9999999999999999999999999999999999999999") }, calls: { [sel("owner()")]: word(KEY) } });
  const r = await tokenVerdict({ chain: "base", address: token }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.ok(!codes(r).includes("TOKEN_UPGRADE_ONE_KEY"));
  assert.equal(r.reasons.find((x) => x.code === "TOKEN_CONTROLLERS").details.summary, "upgrade (UUPS, likely the owner): one key; owner: one key");
  assert.equal(r.controllers.upgradeVia, "owner (UUPS)");
});

test("Base, a mintable token: GoPlus's owner is classified (an older MultiSigWallet); a renounced owner costs no RPC calls", async () => {
  const minted = "0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
  controlFixture(minted, { is_mintable: "1", owner_address: OLD_MULTISIG });
  const r = await tokenVerdict({ chain: "base", address: minted }, NOW);
  assert.equal(r.reasons.find((x) => x.code === "TOKEN_CONTROLLERS").details.summary, "owner: 3-of-5 multisig");
  assert.ok(!r.controllers.upgradeVia);

  const renounced = "0x7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b";
  controlFixture(renounced, { is_mintable: "1", owner_address: "0x0000000000000000000000000000000000000000" });
  rpcCalls.length = 0;
  const plain = await tokenVerdict({ chain: "base", address: renounced }, NOW);
  assert.ok(!rpcCalls.includes("slot") && !rpcCalls.includes(sel("owner()")), rpcCalls.join()); // only the pause/blacklist getters
  assert.ok(!codes(plain).includes("TOKEN_CONTROLLERS"));
  assert.ok(!plain.controllers);
});

test("Base, a mintable token GoPlus names no owner for (like AERO): its Minter is followed through team() to a Safe", async () => {
  const token = "0x7f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
  controlFixture(token, { is_mintable: "1" }, { calls: { [sel("minter()")]: word(MINTER) } });
  const r = await tokenVerdict({ chain: "base", address: token }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["green", "SAFE"]);
  assert.equal(r.reasons.find((x) => x.code === "TOKEN_CONTROLLERS").details.summary, "mint: 2-of-3 multisig via a contract");
  assert.deepEqual(r.controllers.holders, [{
    address: MINTER, roles: ["mint"], type: "contract", ownerVia: "team()",
    owner: { address: SAFE, type: "multisig", threshold: 2, owners: 3 },
  }]);
});

test("Base, an upgrade through a contract run by admin() (no delay, owner() is itself): one key behind it is orange", async () => {
  const token = "0x7f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f";
  controlFixture(token, { is_proxy: "1" }, { slots: { [SLOT.admin]: word(ADMINED) } });
  const r = await tokenVerdict({ chain: "base", address: token }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "CAUTION"]);
  assert.deepEqual(r.reasons.find((x) => x.code === "TOKEN_UPGRADE_ONE_KEY").details, { upgrader: ADMINED, key: KEY, via: [ADMINED] });
  assert.equal(r.reasons.find((x) => x.code === "TOKEN_CONTROLLERS").details.summary, "upgrade: one key via a contract");
  assert.equal(r.controllers.holders[0].ownerVia, "admin()");
});

test("controller descriptions: timelock run by a multisig, a delegated wallet, a renounced owner, the same holder named once", () => {
  const timelock = { address: TIMELOCK, type: "timelock", delaySeconds: 3 * 3600, admin: { address: SAFE, type: "multisig", threshold: 4, owners: 7 } };
  assert.equal(describeHolder(timelock), "timelock (3 h delay, run by 4-of-7 multisig)");
  assert.equal(describeHolder({ address: KEY, type: "key", delegated: true }), "one key");
  assert.equal(describeHolder({ address: PROXY_ADMIN, type: "contract", owner: { address: KEY, type: "key" } }), "one key via a contract");
  assert.equal(describeHolder({ address: PROXY_ADMIN, type: "contract" }), "a contract");
  assert.equal(controllerSummary({ upgradeVia: null, holders: [
    { address: "0x0000000000000000000000000000000000000000", roles: ["owner"], type: "renounced" },
    { address: KEY, roles: ["mint", "pause"], type: "key" },
    { address: "0xaaaa000000000000000000000000000000000002", roles: ["mint"], type: "key" },
  ] }), "owner: renounced; mint: one key; pause: one key");
});

test("Base, honeypot: red, AVOID, and the GoPlus token rules from /v1/check apply", async () => {
  const r = await tokenVerdict({ chain: "base", address: HONEY }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["red", "AVOID"]);
  assert.deepEqual(codes(r, "red"), ["TOKEN_HONEYPOT"]);
  assert.ok(codes(r, "orange").includes("TOKEN_HIGH_TAX"));
  assert.ok(codes(r, "orange").includes("NEW_TOKEN"));
  assert.match(r.one_liner, /^AVOID: honeypot: can't be sold; /);
});

test("Base, unverified token with no market: orange", async () => {
  const r = await tokenVerdict({ chain: "base", address: NOMARKET }, NOW);
  assert.deepEqual([r.verdict, r.grade], ["orange", "RISKY"]);
  assert.deepEqual(codes(r, "orange"), ["NO_DEX_MARKET", "TOKEN_UNVERIFIED"]);
});

test("market summary: liquidity summed, price from the pair where the token is the base", () => {
  const quoteSide = { ...pair("other", { liq: 900, createdDaysAgo: 10 }), quoteToken: { address: BONK, symbol: "Bonk", name: "Bonk" }, priceUsd: "99" };
  const m = summarizeMarket([quoteSide, pair(BONK, { liq: 100, createdDaysAgo: 20, symbol: "Bonk" })], "solana", BONK, NOW);
  assert.deepEqual([m.liquidityUsd, m.priceUsd, m.pairs, m.symbol], [1000, 0.5, 2, "Bonk"]);
  assert.equal(m.ageSeconds, 20 * 86400, "age from the oldest pair");
  assert.equal(summarizeMarket([], "solana", BONK, NOW), null);
});

test("grades and the one-liner", () => {
  const o = (code) => ({ code, severity: "orange" });
  assert.deepEqual(gradeOf([]), { verdict: "green", grade: "SAFE" });
  assert.deepEqual(gradeOf([o("NEW_TOKEN")]), { verdict: "orange", grade: "CAUTION" });
  assert.deepEqual(gradeOf([o("NEW_TOKEN"), o("LOW_LIQUIDITY")]), { verdict: "orange", grade: "RISKY" });
  assert.deepEqual(gradeOf([{ code: "RUGGED", severity: "red" }, o("NEW_TOKEN")]), { verdict: "red", grade: "AVOID" });
  const many = ["MINT_AUTHORITY_ACTIVE", "FREEZE_AUTHORITY_ACTIVE", "BALANCE_MUTABLE", "CLOSABLE"].map(o);
  assert.equal(oneLiner({ grade: "RISKY", reasons: many, market: null }),
    "RISKY: supply can still be minted; holders can be frozen; balances can be changed (+1 more)");
});

// ---------- HTTP route ----------

async function withApp(fn) {
  const app = express();
  app.use(validateTokenQuery);
  app.get("/v1/token", (req, res, next) => (req.query.paid === "no" ? res.status(402).json({ price: true }) : next())); // stands in for the paywall
  app.use(createTokenRouter());
  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

test("route: invalid input is a 400 before the paywall; a verdict otherwise", async () => {
  await withApp(async (base) => {
    const bad = await realFetch(`${base}/v1/token?chain=solana&address=nope&paid=no`);
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, "invalid_request");
    const probe = await realFetch(`${base}/v1/token?paid=no`);
    assert.equal(probe.status, 402, "a bare probe gets the price, not a 400");
    const paidBare = await realFetch(`${base}/v1/token`);
    assert.equal(paidBare.status, 400, "paying without a query still gets a 400 (never settled)");
    const unpaid = await realFetch(`${base}/v1/token?chain=solana&address=${BONK}&paid=no`);
    assert.equal(unpaid.status, 402);
    const ok = await realFetch(`${base}/v1/token?chain=solana&address=${BONK}`);
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).grade, "SAFE");
  });
});

test("route: DexScreener or GoPlus down is a 503 with no verdict (nothing is charged)", async () => {
  await withApp(async (base) => {
    down = new Set(["api.dexscreener.com"]);
    const r = await realFetch(`${base}/v1/token?chain=base&address=0x3333333333333333333333333333333333333333`);
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: "upstream_unavailable", message: "DexScreener HTTP 503", verdict: null });
    down = new Set(["api.gopluslabs.io"]);
    const g = await realFetch(`${base}/v1/token?chain=solana&address=So44444444444444444444444444444444444444444`);
    assert.equal(g.status, 503);
  });
});

test("Jev second opinion on the token name: orange CAUTION when Jev is sure; the real USDC is never asked; off without a key", async () => {
  try {
    jevP = 0.95;
    const off = await tokenVerdict({ chain: "solana", address: BONK }, NOW);
    assert.equal(off.verdict, "green"); // no key: unchanged
    process.env.TYPESAFE_API_KEY = "ts-test";
    const r = await tokenVerdict({ chain: "solana", address: BONK }, NOW);
    assert.deepEqual([r.verdict, r.grade], ["orange", "CAUTION"]);
    assert.equal(r.reasons.find((x) => x.code === "AI_TOKEN_IMPERSONATION").details.decidedBy, "jev");
    assert.match(r.one_liner, /AI check/);
    assert.ok(r.sources.includes("typesafe-jev"));
    calls.length = 0;
    const usdc = await tokenVerdict({ chain: "solana", address: USDC_SOL }, NOW);
    assert.ok(!usdc.reasons.some((x) => x.code === "AI_TOKEN_IMPERSONATION"));
    assert.ok(!calls.includes("api.typesafe.ai"));
    jevP = 0.1;
    assert.equal((await tokenVerdict({ chain: "solana", address: BONK }, NOW)).verdict, "green");
  } finally { delete process.env.TYPESAFE_API_KEY; jevP = 0.02; }
});

test("Robinhood Chain (4663): a token chain for /v1/token, not for /v1/approvals (GoPlus has no wallet approvals there)", async () => {
  const { APPROVAL_CHAINS, parseApprovalsRequest } = await import("../src/approvals.js");
  const { TOKEN_CHAINS } = await import("../src/token-verdict.js");
  assert.equal(TOKEN_CHAINS.robinhood.chainId, 4663);
  assert.equal(parseTokenRequest({ chain: "robinhood", address: "0x45C83b37C5BAF4dad26f3845C28295e2DE010962" }).chain, "robinhood");
  assert.equal(APPROVAL_CHAINS.robinhood, undefined);
  assert.throws(() => parseApprovalsRequest({ chain: "robinhood", address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" }), /chain must be one of/);
});

test("Avalanche C-Chain (43114): a token chain for /v1/token, not for /v1/approvals; Circle's USDC and WAVAX are official", async () => {
  const { APPROVAL_CHAINS, parseApprovalsRequest } = await import("../src/approvals.js");
  const { TOKEN_CHAINS } = await import("../src/token-verdict.js");
  const { isOfficialToken } = await import("../src/jev.js");
  assert.deepEqual(TOKEN_CHAINS.avalanche, { chainId: 43114, dexscreener: "avalanche", approvals: false });
  assert.equal(parseTokenRequest({ chain: "avalanche", address: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E" }).chain, "avalanche");
  assert.equal(APPROVAL_CHAINS.avalanche, undefined);
  assert.throws(() => parseApprovalsRequest({ chain: "avalanche", address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" }), /chain must be one of/);
  assert.ok(isOfficialToken(43114, "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"));
  assert.ok(isOfficialToken(43114, "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7"));
});

test("X Layer (196): a token chain for /v1/token without DexScreener (no market data, info), not for /v1/approvals; OKX's official tokens", async () => {
  const { APPROVAL_CHAINS } = await import("../src/approvals.js");
  const { TOKEN_CHAINS } = await import("../src/token-verdict.js");
  const { isOfficialToken } = await import("../src/jev.js");
  assert.deepEqual(TOKEN_CHAINS.xlayer, { chainId: 196, dexscreener: null, approvals: false });
  assert.equal(APPROVAL_CHAINS.xlayer, undefined);
  for (const t of ["0x74b7f16337b8972027f6196a17a631ac6de26d22", "0x1e4a5963abfd975d8c9021ce480b42188849d41d", "0x779ded0c9e1022225f8e0630b35a9b54be713736", "0xe538905cf8410324e03a5a23c1c177a474d59b2b"]) assert.ok(isOfficialToken(196, t), t);
  calls.length = 0;
  const r = await tokenVerdict({ chain: "xlayer", address: DEGEN }, NOW);
  assert.ok(!calls.includes("api.dexscreener.com"), "DexScreener has no X Layer pairs: not asked");
  assert.ok(r.reasons.some((x) => x.code === "NO_MARKET_DATA" && x.severity === "info"));
  assert.ok(!r.reasons.some((x) => x.code === "NO_DEX_MARKET"));
  assert.ok(!r.sources.includes("dexscreener"));
});

test("Robinhood Chain: Paxos' USDG is the official dollar there; the token that calls itself USDC is not", async () => {
  const { isOfficialToken } = await import("../src/jev.js");
  assert.ok(isOfficialToken(4663, "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"));
  assert.ok(!isOfficialToken(4663, "0x11D04a2491AB485a54dA3817C10C2A9178c7991e"));
});
