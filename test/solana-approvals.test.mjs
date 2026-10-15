// Wallet approval audit on Solana (GET /v1/approvals?chain=solana): SPL token delegations read from the RPC,
// without network. The RPC is mocked through globalThis.fetch with jsonParsed answers in the shape the public
// mainnet RPC gives (getTokenAccountsByOwner, getMultipleAccounts).
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { walletApprovals, parseApprovalsRequest, validateApprovalsQuery, createApprovalsRouter } from "../src/approvals.js";
import { loadSdn, resetOfac } from "../src/ofac.js";
import { SDN_XML, SOL as SANCTIONED } from "./fixtures/sdn.mjs";

const NOW = Date.UTC(2026, 9, 15, 12);
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM = "11111111111111111111111111111111";

const MIXED = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const EMPTY = "Vote111111111111111111111111111111111111111";
const DOWN = "Stake11111111111111111111111111111111111111";
const LATE = "SysvarRent111111111111111111111111111111111";

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
const PYUSD = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
const PLAIN = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1"; // no account: a fresh key
const JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"; // a program
const ESCROW = "8szGkuLTAux9XMgZ2vtY39jVSowEcpBfFfD8hXSEqdGC"; // a program's account (PDA)
const PAXOS = "2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk";

const account = (pubkey, mint, { amount = "1000000", decimals = 6, delegate, delegated } = {}) => ({
  pubkey,
  account: {
    owner: TOKEN,
    data: {
      program: "spl-token",
      parsed: {
        type: "account",
        info: {
          mint, owner: MIXED, state: "initialized", isNative: false,
          tokenAmount: { amount, decimals, uiAmount: Number(amount) / 10 ** decimals, uiAmountString: String(Number(amount) / 10 ** decimals) },
          ...(delegate && { delegate, delegatedAmount: { amount: delegated, decimals, uiAmount: Number(delegated) / 10 ** decimals, uiAmountString: delegated === "18446744073709551615" ? "18446744073709.551615" : String(Number(delegated) / 10 ** decimals) } }),
        },
      },
    },
  },
});

const WALLETS = {
  [MIXED]: {
    [TOKEN]: [
      account("TA1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", USDC, { delegate: PLAIN, delegated: "50000000" }),
      account("TA2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BONK, { amount: "500000", decimals: 5, delegate: JUP, delegated: "18446744073709551615" }),
      account("TA3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", USDC, { delegate: ESCROW, delegated: "2000000" }),
      account("TA4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", USDC, { delegate: SANCTIONED, delegated: "1000000" }),
      account("TA5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BONK, { delegate: PLAIN, delegated: "0" }), // spent: no delegation left
    ],
    [TOKEN_2022]: [account("TA6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PYUSD, { amount: "10000000" })],
  },
  [LATE]: { [TOKEN]: [account("TA7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", USDC, { delegate: PLAIN, delegated: "1000000" })], [TOKEN_2022]: [] },
};
const ACCOUNTS = {
  [JUP]: { owner: "BPFLoaderUpgradeab1e11111111111111111111111", executable: true, lamports: 1141440, data: ["", "base64"] },
  [ESCROW]: { owner: JUP, executable: false, lamports: 2039280, data: ["", "base64"] },
  [SANCTIONED]: { owner: SYSTEM, executable: false, lamports: 5000000, data: ["", "base64"] },
};
const MINTS = {
  [PYUSD]: { owner: TOKEN_2022, executable: false, data: { program: "spl-token-2022", parsed: { type: "mint", info: { decimals: 6, extensions: [{ extension: "permanentDelegate", state: { delegate: PAXOS } }] } } } },
};

const realFetch = globalThis.fetch;
const calls = [];
let rpcDown = false;

before(async () => {
  await loadSdn({ fetchImpl: async () => new Response(SDN_XML) });
  globalThis.fetch = async (url, init) => {
    if (new URL(String(url)).hostname !== "api.mainnet-beta.solana.com") throw new Error(`unexpected fetch ${url}`);
    const { method, params } = JSON.parse(init.body);
    calls.push({ method, params });
    if (rpcDown) return new Response("busy", { status: 503 });
    const value = method === "getTokenAccountsByOwner"
      ? WALLETS[params[0]]?.[params[1].programId] ?? []
      : method === "getMultipleAccounts"
        ? params[0].map((k) => (params[1].encoding === "jsonParsed" ? MINTS[k] : ACCOUNTS[k]) ?? null)
        : null;
    return Response.json({ jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value } });
  };
});
after(() => { resetOfac(); globalThis.fetch = realFetch; });
beforeEach(() => { calls.length = 0; rpcDown = false; });

test("input: chain=solana takes a base58 wallet as is; an EVM address is refused", () => {
  assert.deepEqual(parseApprovalsRequest({ chain: "Solana", address: ` ${MIXED} ` }), { chain: "solana", address: MIXED });
  assert.throws(() => parseApprovalsRequest({ chain: "solana", address: "0x1000000000000000000000000000000000000001" }), /Solana wallet address/);
  assert.throws(() => parseApprovalsRequest({ chain: "tron", address: MIXED }), /chain must be one of: .*bsc, solana/);
});

test("mixed wallet: a sanctioned delegate is red; plain-wallet and unlimited delegations are listed to revoke", async () => {
  const r = await walletApprovals({ chain: "solana", address: MIXED }, NOW);
  assert.equal(r.verdict, "red");
  assert.equal(r.grade, "AVOID");
  assert.equal(r.one_liner, "AVOID: 4 approvals, 1 to a sanctioned address, 2 to a plain wallet, 1 unlimited; revoke 3");
  assert.deepEqual(r.summary, { approvals: 4, tokens: 2, unlimited: 1, toRevoke: 3, tokenAccounts: 6 });
  assert.equal(r.revokeUrl, null);
  assert.match(r.revokeHint, /Revoke instruction/);

  const by = (delegate) => r.approvals.find((a) => a.spender.address === delegate);
  assert.equal(r.approvals[0].spender.address, SANCTIONED, "red first");
  assert.deepEqual(by(SANCTIONED).codes.map((c) => c.code), ["SANCTIONED_ADDRESS", "APPROVAL_TO_WALLET"]);
  assert.equal(by(SANCTIONED).codes[0].details.list, "OFAC SDN");
  assert.deepEqual(by(PLAIN), {
    token: { address: USDC, symbol: null, name: null },
    tokenAccount: "TA1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    program: "token",
    spender: { address: PLAIN, name: null, trusted: false, contract: false },
    amount: "50",
    unlimited: false,
    balance: "1",
    approvedAt: null,
    severity: "orange",
    codes: [{ code: "APPROVAL_TO_WALLET", severity: "orange" }],
    revoke: true,
  });
  assert.deepEqual([by(JUP).amount, by(JUP).spender.contract, by(JUP).codes.map((c) => c.code)], ["unlimited", true, ["UNLIMITED_APPROVAL"]]);
  // A limited delegation to a program's account: context, not a reason to revoke.
  assert.deepEqual([by(ESCROW).severity, by(ESCROW).codes, by(ESCROW).revoke], ["info", [], false]);
  assert.equal(r.approvals.filter((a) => a.tokenAccount === "TA5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").length, 0, "a spent delegation is not listed");

  assert.deepEqual(r.permanentDelegates, [{ mint: PYUSD, delegate: PAXOS, tokenAccount: "TA6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]);
  assert.deepEqual(r.reasons.find((x) => x.code === "PERMANENT_DELEGATE"), { code: "PERMANENT_DELEGATE", severity: "info", details: { count: 1, tokens: [PYUSD] } });
  assert.deepEqual(r.reasons.map((x) => x.severity), [...r.reasons.map((x) => x.severity)].sort((a, b) => ["red", "orange", "info"].indexOf(a) - ["red", "orange", "info"].indexOf(b)));

  // Both token programs, one lookup for the delegates (no data), one for the Token-2022 mints.
  assert.deepEqual(calls.filter((c) => c.method === "getTokenAccountsByOwner").map((c) => c.params[1].programId).sort(), [TOKEN, TOKEN_2022].sort());
  const lookups = calls.filter((c) => c.method === "getMultipleAccounts");
  assert.equal(lookups.length, 2);
  assert.deepEqual(lookups.find((c) => c.params[1].encoding === "base64").params[0].sort(), [PLAIN, JUP, ESCROW, SANCTIONED].sort());
  assert.deepEqual(lookups.find((c) => c.params[1].encoding === "jsonParsed").params[0], [PYUSD]);
});

test("a wallet without delegations is green, without looking anything else up", async () => {
  const r = await walletApprovals({ chain: "solana", address: EMPTY }, NOW);
  assert.equal(r.grade, "SAFE");
  assert.equal(r.one_liner, "SAFE: no open token approvals on solana");
  assert.deepEqual(r.reasons, [{ code: "NO_APPROVALS", severity: "info" }]);
  assert.deepEqual(r.summary, { approvals: 0, tokens: 0, unlimited: 0, toRevoke: 0, tokenAccounts: 0 });
  assert.deepEqual(calls.map((c) => c.method), ["getTokenAccountsByOwner", "getTokenAccountsByOwner"]);
});

test("over HTTP: an invalid Solana address is a 400 before the paywall; the RPC down is a 503", async () => {
  const app = express();
  app.use(validateApprovalsQuery);
  app.use(createApprovalsRouter());
  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const bad = await realFetch(`${base}/v1/approvals?chain=solana&address=0x1234`);
    assert.equal(bad.status, 400);
    assert.match((await bad.json()).message, /Solana wallet address/);
    rpcDown = true;
    const down = await realFetch(`${base}/v1/approvals?chain=solana&address=${DOWN}`);
    assert.equal(down.status, 503);
    assert.equal((await down.json()).error, "upstream_unavailable");
  } finally {
    server.close();
  }
});

test("no sanctions list in memory: said so, never a silent pass", async () => {
  resetOfac();
  const r = await walletApprovals({ chain: "solana", address: LATE }, NOW);
  assert.equal(r.grade, "CAUTION");
  assert.ok(r.reasons.some((x) => x.code === "SANCTIONS_SCREEN_UNAVAILABLE" && x.severity === "info"));
});
