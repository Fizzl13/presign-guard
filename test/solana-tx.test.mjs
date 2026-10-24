// Solana transaction checks (src/solana-tx.js) against a stand-in RPC: no network, no money.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as k from "@solana/kit";
import { parseSolanaRequest, instructionReasons, simulateSolana, solanaSimulationReasons } from "../src/solana-tx.js";
import { analyze, parseRequest } from "../src/presign-guard.js";

const W = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
const OTHER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const TA = "2ocS3orPq3jyszjsJ4NozKWyhdotr3csDjAizmkj65aH";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MARGINFI = "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA"; // the lending program under Project 0
const SYSTEM = "11111111111111111111111111111111";
const R = k.AccountRole;
const A = (a, role) => ({ address: k.address(a), role });

function build(ixs, payer = W) {
  let m = k.createTransactionMessage({ version: 0 });
  m = k.setTransactionMessageFeePayer(k.address(payer), m);
  m = k.setTransactionMessageLifetimeUsingBlockhash({ blockhash: SYSTEM, lastValidBlockHeight: 0n }, m);
  for (const ix of ixs) m = k.appendTransactionMessageInstruction(ix, m);
  return k.getBase64EncodedWireTransaction(k.compileTransaction(m));
}
const sysIx = (op, accounts, extra = []) => {
  const d = new Uint8Array(4 + extra.length);
  new DataView(d.buffer).setUint32(0, op, true);
  d.set(extra, 4);
  return { programAddress: k.address(SYSTEM), accounts, data: d };
};
const transfer = () => { const d = new Uint8Array(8); new DataView(d.buffer).setBigUint64(0, 1000000n, true); return sysIx(2, [A(W, R.WRITABLE_SIGNER), A(OTHER, R.WRITABLE)], [...d]); };
const assign = () => sysIx(1, [A(W, R.WRITABLE_SIGNER)], [...k.getAddressEncoder().encode(k.address(OTHER))]);
const nonce = () => sysIx(4, [A(OTHER, R.WRITABLE), A("SysvarRecentB1ockHashes11111111111111111111", R.READONLY), A(W, R.READONLY_SIGNER)]);
const setAuthority = (type = 2) => { const d = new Uint8Array(35); d[0] = 6; d[1] = type; d[2] = 1; d.set(k.getAddressEncoder().encode(k.address(OTHER)), 3); return { programAddress: k.address(TOKEN), accounts: [A(TA, R.WRITABLE), A(W, R.READONLY_SIGNER)], data: d }; };
const approve = (amount) => { const d = new Uint8Array(9); d[0] = 4; new DataView(d.buffer).setBigUint64(1, amount, true); return { programAddress: k.address(TOKEN), accounts: [A(TA, R.WRITABLE), A(OTHER, R.READONLY), A(W, R.READONLY_SIGNER)], data: d }; };
const closeTo = () => ({ programAddress: k.address(TOKEN), accounts: [A(TA, R.WRITABLE), A(OTHER, R.WRITABLE), A(W, R.READONLY_SIGNER)], data: new Uint8Array([9]) });

const codes = (reasons) => reasons.map((r) => r.code);

test("parse: decodes the wallet (fee payer, or from), signers, writable accounts and instructions; bad input is refused", () => {
  const req = parseSolanaRequest({ transaction: build([transfer()]) });
  assert.equal(req.wallet, W);
  assert.deepEqual(req.signers, [W]);
  assert.ok(req.writable.includes(OTHER));
  assert.equal(req.instructions[0].program, SYSTEM);
  assert.equal(parseSolanaRequest({ transaction: build([transfer()]), from: OTHER }).wallet, OTHER);
  for (const bad of [{}, { transaction: "not base64!" }, { transaction: "AAAA" }, { transaction: build([transfer()]), from: "0x12" }]) {
    assert.throws(() => parseSolanaRequest(bad), (e) => e.status === 400);
  }
  // Through presign-guard's own parser: a 400 before payment, and x402 is not for Solana transactions.
  assert.equal(parseRequest({ type: "solana", transaction: build([transfer()]) }).kind, "solana");
  assert.throws(() => parseRequest({ type: "solana", transaction: build([transfer()]), x402: { amount: "1" } }), /x402/);
});

test("instructions: SetAuthority on the wallet's token account and System Assign are red; unlimited Approve, durable nonce and closing to another are orange", () => {
  const r = (ixs) => instructionReasons(parseSolanaRequest({ transaction: build(ixs) }));
  assert.deepEqual(codes(r([transfer()])), []);
  const takeover = r([setAuthority(2)]);
  assert.equal(takeover[0].code, "SOLANA_TOKEN_ACCOUNT_TAKEOVER");
  assert.equal(takeover[0].severity, "red");
  assert.equal(takeover[0].subject, OTHER);
  assert.equal(r([setAuthority(3)])[0].code, "SOLANA_TOKEN_ACCOUNT_TAKEOVER", "the close authority too");
  assert.equal(r([assign()])[0].code, "SOLANA_ACCOUNT_ASSIGN");
  assert.equal(r([approve((1n << 64n) - 1n)])[0].code, "SOLANA_UNLIMITED_DELEGATE");
  assert.equal(r([approve(1000n)])[0].severity, "info");
  assert.equal(r([nonce(), transfer()])[0].code, "SOLANA_DURABLE_NONCE");
  assert.equal(r([closeTo()])[0].code, "SOLANA_CLOSE_TO_OTHER");
});

function rpcStub({ before, after, err = null }) {
  return async (_url, init) => {
    const { method } = JSON.parse(init.body);
    if (method === "getMultipleAccounts") return Response.json({ jsonrpc: "2.0", id: 1, result: { value: before } });
    if (method === "simulateTransaction") return Response.json({ jsonrpc: "2.0", id: 1, result: { value: { err, accounts: after, fee: 5000, loadedAddresses: { writable: [], readonly: [] } } } });
    return Response.json({ jsonrpc: "2.0", id: 1, error: { message: "unknown" } });
  };
}
const wallet = (lamports, owner = SYSTEM) => ({ lamports, owner, data: ["", "base64"] });
const tokenAccount = (amount, { owner = W, delegate } = {}) => ({ lamports: 2039280, owner: TOKEN, data: { parsed: { type: "account", info: { owner, mint: USDC, tokenAmount: { uiAmountString: String(amount), amount: String(BigInt(Math.round(amount * 1e6))), decimals: 6 }, ...(delegate && { delegate, delegatedAmount: { uiAmountString: "18446744073709.551615" } }) } } } });

test("simulation: SOL and token changes of the wallet; an owner or delegate change the instructions don't show is red / orange; a failing transaction is orange", async () => {
  const req = parseSolanaRequest({ transaction: build([transfer()]) });
  const addresses = [...new Set([req.wallet, ...req.writable])];
  const at = (byAddress) => addresses.map((a) => byAddress[a] ?? null);

  const moved = await simulateSolana(req, { fetchImpl: rpcStub({ before: at({ [W]: wallet(2_000_000_000) }), after: at({ [W]: wallet(1_998_995_000) }) }) });
  assert.equal(moved.ok, true);
  assert.deepEqual(moved.changes, [{ type: "sol", account: W, change: -0.001005, lamports: "-1005000" }]);
  assert.equal(moved.partial, undefined);
  assert.equal(solanaSimulationReasons(moved, req, new Set()).at(-1).code, "SIMULATED");

  // A token account of the wallet that changes owner or gets a delegate, though no instruction said so (a wrapper program).
  const req2 = { ...req, writable: [...req.writable, TA] };
  const addrs2 = [...new Set([req2.wallet, ...req2.writable])];
  const at2 = (m) => addrs2.map((a) => m[a] ?? null);
  const hidden = await simulateSolana(req2, { fetchImpl: rpcStub({ before: at2({ [W]: wallet(1e9), [TA]: tokenAccount(50) }), after: at2({ [W]: wallet(1e9 - 5000), [TA]: tokenAccount(50, { owner: OTHER }) }) }) });
  const hr = solanaSimulationReasons(hidden, req2, new Set());
  assert.equal(hr.find((x) => x.code === "SOLANA_TOKEN_ACCOUNT_TAKEOVER").subject, OTHER);
  const delegated = await simulateSolana(req2, { fetchImpl: rpcStub({ before: at2({ [W]: wallet(1e9), [TA]: tokenAccount(50) }), after: at2({ [W]: wallet(1e9), [TA]: tokenAccount(50, { delegate: OTHER }) }) }) });
  assert.equal(solanaSimulationReasons(delegated, req2, new Set()).find((x) => x.code === "HIDDEN_APPROVAL").subject, OTHER);
  const drained = await simulateSolana(req2, { fetchImpl: rpcStub({ before: at2({ [W]: wallet(1e9), [TA]: tokenAccount(50) }), after: at2({ [W]: wallet(1e9), [TA]: tokenAccount(0) }) }) });
  assert.deepEqual(drained.changes.find((c) => c.type === "token"), { type: "token", account: TA, mint: USDC, change: -50, raw: "-50000000", decimals: 6 });

  const fails = await simulateSolana(req, { fetchImpl: rpcStub({ before: at({}), after: at({}), err: { InstructionError: [0, { Custom: 1 }] } }) });
  assert.equal(fails.ok, false);
  assert.equal(solanaSimulationReasons(fails, req, new Set())[0].code, "SIMULATION_FAILS");
  // A SOL transfer may go to an address that doesn't exist yet: that is not an account an earlier transaction creates.
  assert.equal(fails.missingAccounts, undefined);
  assert.equal(solanaSimulationReasons(fails, req, new Set())[0].details.note, undefined);
  // A failing simulation returns no accounts after (null for each): the wallet's token account is not "closed".
  const failsWithToken = await simulateSolana(req2, { fetchImpl: rpcStub({ before: at2({ [W]: wallet(1e9), [TA]: tokenAccount(50) }), after: addrs2.map(() => null), err: { InstructionError: [0, { Custom: 1 }] } }) });
  assert.deepEqual(failsWithToken.changes, []);

  // More writable accounts than are read: marked partial, so a wallet doesn't take the changes as complete.
  const many = { ...req, writable: Array.from({ length: 25 }, (_, i) => k.getAddressDecoder().decode(new Uint8Array(32).fill(i + 1))) };
  const wide = await simulateSolana(many, { fetchImpl: rpcStub({ before: Array(20).fill(null), after: Array(20).fill(null) }) });
  assert.equal(wide.partial, true);

  // The RPC down: no simulation (null), never a guessed green.
  assert.equal(await simulateSolana(req, { fetchImpl: async () => new Response("down", { status: 503 }) }), null);
  assert.deepEqual(solanaSimulationReasons(null, req, new Set()), []);
});

test("Project 0: a first deposit is two transactions sent in order; the deposit checked before the account exists is orange with that reason", async () => {
  // The unsigned transactions P0's MCP returned (test/fixtures/p0-first-deposit.json): v0, accounts from lookup tables.
  const p0 = JSON.parse(readFileSync(new URL("./fixtures/p0-first-deposit.json", import.meta.url), "utf8"));
  const [create, deposit] = p0.transactions.map((t) => parseSolanaRequest({ transaction: t.base64 }));
  for (const req of [create, deposit]) {
    assert.equal(req.wallet, p0.authority);
    assert.deepEqual(req.signers, [p0.authority]);
    assert.equal(req.version, 0);
    assert.equal(req.usesLookupTables, true);
    assert.ok(req.instructions.some((ix) => ix.program === MARGINFI));
    assert.deepEqual(instructionReasons(req), [], "nothing in the instructions hands over the wallet or a token account");
  }
  assert.equal(p0.authority, W);
  assert.ok(deposit.writable.includes(p0.account));
  const addresses = [...new Set([deposit.wallet, ...deposit.writable])];
  const usdcAccount = addresses.find((a) => a !== W && a !== p0.account);
  const at = (m) => addresses.map((a) => m[a] ?? null);
  const marginfiAccount = { lamports: 16_000_000, owner: MARGINFI, data: ["", "base64"] };

  // Before step 1 has landed the P0 account doesn't exist: the deposit fails, and the RPC returns no accounts after.
  const early = { before: at({ [W]: wallet(1e9), [usdcAccount]: tokenAccount(100) }), after: addresses.map(() => null), err: { InstructionError: [2, { Custom: 3007 }] } };
  const sim = await simulateSolana(deposit, { fetchImpl: rpcStub(early) });
  assert.deepEqual(sim.changes, [], "the USDC account is not reported closed");
  assert.deepEqual(sim.missingAccounts, [p0.account]);
  const [fails] = solanaSimulationReasons(sim, deposit, new Set());
  assert.equal(fails.code, "SIMULATION_FAILS");
  assert.equal(fails.severity, "orange");
  assert.deepEqual(fails.details.missingAccounts, [p0.account]);
  assert.match(fails.details.note, /check this one again after that one has landed/);

  // After step 1 has landed: 1 USDC and the fee leave the wallet, nothing else. Green.
  const later = { before: at({ [W]: wallet(1e9), [p0.account]: marginfiAccount, [usdcAccount]: tokenAccount(100) }), after: at({ [W]: wallet(1e9 - 5099), [p0.account]: marginfiAccount, [usdcAccount]: tokenAccount(99) }) };
  const realFetch = globalThis.fetch;
  globalThis.fetch = rpcStub(later);
  let answer;
  try { answer = await analyze(parseRequest({ type: "solana", transaction: p0.transactions[1].base64 })); } finally { globalThis.fetch = realFetch; }
  assert.equal(answer.verdict, "green");
  assert.deepEqual(answer.subject.programs, ["ComputeBudget111111111111111111111111111111", MARGINFI]);
  assert.deepEqual(answer.simulation.changes, [
    { type: "sol", account: W, change: -0.000005099, lamports: "-5099" },
    { type: "token", account: usdcAccount, mint: USDC, change: -1, raw: "-1000000", decimals: 6 },
  ]);
  assert.ok(answer.reasons.some((r) => r.code === "SOLANA_LOOKUP_TABLES"));
});

// Metaplex agents: an MPL Core asset whose signer PDA is the agent's own wallet. x402 pays from it through Core's
// Execute (the owner, or an execution delegate, authorises; the facilitator pays the fee), as Metaplex's
// MetaplexSvmExactScheme builds it: [Execute(TransferChecked agent ATA -> seller ATA, authority = the PDA)].
const MPL_CORE = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d";
const AGENT_TOOLS = "TLREGni9ZEyGC3vnPZtqUh95xQ8oPqJSvNjvB7FGK8S";
const ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const fake = (n) => k.getAddressDecoder().decode(new Uint8Array(32).fill(n));
const ASSET = fake(11), FACILITATOR = fake(12), PROFILE = fake(13), RECORD = fake(14), IDENTITY = fake(15);
const enc = k.getAddressEncoder();
const pda = async (program, seeds) => (await k.getProgramDerivedAddress({ programAddress: k.address(program), seeds }))[0];
const AGENT = await pda(MPL_CORE, [new TextEncoder().encode("mpl-core-execute"), enc.encode(k.address(ASSET))]);
const ata = (owner) => pda(ATA_PROGRAM, [enc.encode(k.address(owner)), enc.encode(k.address(TOKEN)), enc.encode(k.address(USDC))]);
const AGENT_ATA = await ata(AGENT), SELLER_ATA = await ata(OTHER);

const coreExecute = (inner, { delegateRecord } = {}) => {
  const d = new Uint8Array(5 + inner.data.length);
  d[0] = 31;
  new DataView(d.buffer).setUint32(1, inner.data.length, true);
  d.set(inner.data, 5);
  return { programAddress: k.address(MPL_CORE), data: d, accounts: [
    A(ASSET, R.WRITABLE), A(MPL_CORE, R.READONLY), A(AGENT, R.READONLY), A(FACILITATOR, R.WRITABLE_SIGNER), A(W, R.READONLY_SIGNER),
    A(SYSTEM, R.READONLY), A(inner.programAddress, R.READONLY), ...(delegateRecord ? [A(delegateRecord, R.READONLY)] : []), ...inner.accounts,
  ] };
};
const transferChecked = (amount, to = SELLER_ATA) => {
  const d = new Uint8Array(10); d[0] = 12; new DataView(d.buffer).setBigUint64(1, amount, true); d[9] = 6;
  return { programAddress: k.address(TOKEN), data: d, accounts: [A(AGENT_ATA, R.WRITABLE), A(USDC, R.READONLY), A(to, R.WRITABLE), A(AGENT, R.READONLY)] };
};
const agentTx = (ixs) => parseSolanaRequest({ transaction: build(ixs, FACILITATOR), from: W });

test("Metaplex agent: an x402 payment through Core Execute is unwrapped and reported as paid from the agent's wallet", () => {
  const req = agentTx([coreExecute(transferChecked(20000n))]);
  assert.equal(req.wallet, W);
  assert.deepEqual(req.agentWallets, [AGENT]);
  const [e] = req.agentExecutes;
  assert.equal(e.asset, ASSET);
  assert.equal(e.assetSigner, AGENT);
  assert.equal(e.authority, W);
  assert.equal(e.collection, null, "no collection: Core's own program id stands in");
  assert.equal(e.inner.program, TOKEN);
  assert.deepEqual(e.inner.accounts, [AGENT_ATA, USDC, SELLER_ATA, AGENT]);

  const [pay, ...rest] = instructionReasons(req);
  assert.deepEqual(rest, []);
  assert.equal(pay.code, "METAPLEX_AGENT_PAYMENT");
  assert.equal(pay.severity, "info");
  assert.equal(pay.subject, SELLER_ATA);
  assert.equal(pay.details.amount, "20000");
  assert.equal(pay.details.mint, USDC);
  assert.equal(pay.details.decimals, 6);
  assert.equal(pay.details.agentAsset, ASSET);
  assert.equal(pay.details.agentWallet, AGENT);
  assert.equal(pay.details.tokenAccount, AGENT_ATA);

  // Delegated mode (Metaplex's Mech): the remaining accounts start with the execution-delegate record.
  const delegated = agentTx([coreExecute(transferChecked(20000n), { delegateRecord: RECORD })]);
  assert.deepEqual(delegated.agentExecutes[0].inner.accounts, [AGENT_ATA, USDC, SELLER_ATA, AGENT]);
  assert.equal(instructionReasons(delegated)[0].subject, SELLER_ATA);
});

test("Metaplex agent: handing over the agent's token account, an unlimited approval or another program inside Execute are red / orange", () => {
  const tokenIx = (data, accounts) => ({ programAddress: k.address(TOKEN), data, accounts });
  const r = (inner) => instructionReasons(agentTx([coreExecute(inner)]));

  const setAuth = new Uint8Array(35); setAuth[0] = 6; setAuth[1] = 2; setAuth[2] = 1; setAuth.set(enc.encode(k.address(OTHER)), 3);
  const [takeover] = r(tokenIx(setAuth, [A(AGENT_ATA, R.WRITABLE), A(AGENT, R.READONLY)]));
  assert.equal(takeover.code, "SOLANA_TOKEN_ACCOUNT_TAKEOVER");
  assert.equal(takeover.severity, "red");
  assert.equal(takeover.subject, OTHER);
  assert.equal(takeover.details.agentWallet, AGENT);
  assert.equal(takeover.details.via, "metaplex-core-execute");

  const approveAll = new Uint8Array(9); approveAll[0] = 4; new DataView(approveAll.buffer).setBigUint64(1, (1n << 64n) - 1n, true);
  const [unlimited] = r(tokenIx(approveAll, [A(AGENT_ATA, R.WRITABLE), A(OTHER, R.READONLY), A(AGENT, R.READONLY)]));
  assert.equal(unlimited.code, "SOLANA_UNLIMITED_DELEGATE");
  assert.equal(unlimited.details.agentAsset, ASSET);

  const [other] = r({ programAddress: k.address(MARGINFI), data: new Uint8Array([1, 2, 3]), accounts: [A(AGENT, R.READONLY), A(AGENT_ATA, R.WRITABLE)] });
  assert.equal(other.code, "METAPLEX_AGENT_EXECUTE");
  assert.equal(other.severity, "orange");
  assert.equal(other.subject, MARGINFI);

  // The owner's signature carries into the wrapped instruction: handing over the owner's own token account is red too.
  const [ownerAuth] = r(tokenIx(setAuth, [A(TA, R.WRITABLE), A(W, R.READONLY)]));
  assert.equal(ownerAuth.code, "SOLANA_TOKEN_ACCOUNT_TAKEOVER");
  assert.equal(ownerAuth.details.tokenAccount, TA);
  assert.equal(ownerAuth.details.agentWallet, undefined);
});

test("Metaplex agent: DelegateExecution (a standing right to pay for the agent) is orange, RevokeExecution an info line", () => {
  const tools = (op, accounts) => ({ programAddress: k.address(AGENT_TOOLS), data: new Uint8Array([op, 0, 0, 0, 0, 0, 0, 0]), accounts });
  const delegate = tools(1, [A(PROFILE, R.READONLY), A(ASSET, R.READONLY), A(IDENTITY, R.READONLY), A(RECORD, R.WRITABLE), A(W, R.WRITABLE_SIGNER), A(W, R.READONLY_SIGNER), A(SYSTEM, R.READONLY)]);
  const [d] = instructionReasons(parseSolanaRequest({ transaction: build([delegate]) }));
  assert.equal(d.code, "METAPLEX_EXECUTION_DELEGATE");
  assert.equal(d.severity, "orange");
  assert.equal(d.subject, PROFILE);
  assert.equal(d.details.agentAsset, ASSET);
  assert.equal(d.details.delegateRecord, RECORD);
  assert.match(d.details.note, /until it is revoked/);

  const revoke = tools(2, [A(RECORD, R.WRITABLE), A(ASSET, R.READONLY), A(W, R.WRITABLE), A(W, R.WRITABLE_SIGNER), A(W, R.READONLY_SIGNER), A(SYSTEM, R.READONLY)]);
  const [rv] = instructionReasons(parseSolanaRequest({ transaction: build([revoke]) }));
  assert.equal(rv.code, "METAPLEX_EXECUTION_REVOKED");
  assert.equal(rv.severity, "info");
});

test("Metaplex agent: the simulation follows the agent's wallet; the full check names the seller and stays green", async () => {
  const tx = build([coreExecute(transferChecked(20000n))], FACILITATOR);
  const req = parseSolanaRequest({ transaction: tx, from: W });
  const addresses = [...new Set([req.wallet, AGENT, ...req.writable])];
  const at = (m) => addresses.map((a) => m[a] ?? null);
  const stub = rpcStub({
    before: at({ [W]: wallet(1e9), [AGENT_ATA]: tokenAccount(5, { owner: AGENT }), [SELLER_ATA]: tokenAccount(0, { owner: OTHER }) }),
    after: at({ [W]: wallet(1e9), [AGENT_ATA]: tokenAccount(4.98, { owner: AGENT }), [SELLER_ATA]: tokenAccount(0.02, { owner: OTHER }) }),
  });
  const sim = await simulateSolana(req, { fetchImpl: stub });
  assert.equal(sim.changes.length, 1);
  const [c] = sim.changes;
  assert.deepEqual({ ...c, change: Math.round(c.change * 1e6) / 1e6 }, { type: "token", account: AGENT_ATA, mint: USDC, change: -0.02, raw: "-20000", decimals: 6, agent: true, agentWallet: AGENT });
  assert.deepEqual(sim.tokenOwners, [OTHER], "the agent's wallet is not counted as a recipient");

  const realFetch = globalThis.fetch;
  globalThis.fetch = stub;
  let answer;
  try { answer = await analyze(parseRequest({ type: "solana", transaction: tx, from: W })); } finally { globalThis.fetch = realFetch; }
  assert.equal(answer.verdict, "green");
  const pay = answer.reasons.find((r) => r.code === "METAPLEX_AGENT_PAYMENT");
  assert.equal(pay.details.recipient, OTHER);
  assert.deepEqual(answer.subject.agents, [{ asset: ASSET, wallet: AGENT, program: TOKEN }]);
  assert.match(answer.scope, /Metaplex agents/);
});
