// Solana transactions before signing: { type: "solana", transaction: <base64 wire transaction>, from?, origin?, intent? }.
// Solana has no token approvals like EVM, so drainers go after the account itself: SetAuthority hands a token
// account to another owner, System Assign hands the wallet to a program, Approve gives a delegate the right to
// move tokens, and a durable nonce keeps a signed transaction valid until someone sends it. The instructions are
// decoded, and the transaction is simulated on the RPC (simulateTransaction, signatures not checked) to see what
// really leaves the wallet, also inside other programs: SOL and token balances, owners and delegates after.
//
// Metaplex agents (MPL Core assets with an agent identity) pay from their own wallet, the asset signer PDA, through
// Core's Execute instruction: the owner (or an execution delegate) signs an Execute that wraps an instruction the PDA
// "signs" by CPI, such as a USDC transfer for an x402 payment. The wrapped instruction is unwrapped and judged as if
// the agent's wallet signed it, and the simulation follows the agent wallet's token accounts too. Mint-and-register
// is just a Core asset; DelegateExecution (Metaplex's agent tools program) gives an executive a standing right to run
// Execute for the agent, as Metaplex's Mech does for instant x402 payments: that grant is called out.
import { address, getAddressEncoder, getBase64Encoder, getCompiledTransactionMessageDecoder, getProgramDerivedAddress, getTransactionDecoder } from "@solana/kit";

const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const SYSTEM = "11111111111111111111111111111111";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const TOKEN_PROGRAMS = new Set([TOKEN, TOKEN_2022]);
const ASSOCIATED_TOKEN = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const MPL_CORE = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d";
const MPL_AGENT_TOOLS = "TLREGni9ZEyGC3vnPZtqUh95xQ8oPqJSvNjvB7FGK8S";
const CORE_EXECUTE_V1 = 31; // ExecuteV1: [31, u32 length, inner instruction data]
// Accounts of a token instruction the agent wallet might run, so the Execute's remaining accounts (which may start
// with an execution-delegate record) can be cut to the inner instruction's own.
const TOKEN_ACCOUNTS = { 3: 3, 4: 3, 6: 2, 9: 3, 12: 4, 13: 4 };
const U64_MAX = (1n << 64n) - 1n;
const UNLIMITED = 1n << 63n; // a delegation this large is "unlimited" in practice
const MAX_TX_CHARS = 2400; // a wire transaction is at most 1,232 bytes
const AUTHORITY_TYPES = ["MintTokens", "FreezeAccount", "AccountOwner", "CloseAccount"];
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export class SolanaValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

export const isSolanaRequest = (body) => Boolean(body && typeof body === "object" && body.type === "solana");

const u32 = (d, o) => (d.length >= o + 4 ? new DataView(d.buffer, d.byteOffset).getUint32(o, true) : null);
const u64 = (d, o) => (d.length >= o + 8 ? new DataView(d.buffer, d.byteOffset).getBigUint64(o, true) : null);

// The wire transaction decoded: its accounts (static ones; address-table ones are known after simulation) and
// instructions with program and account addresses.
export function parseSolanaRequest(body) {
  const raw = typeof body.transaction === "string" ? body.transaction.trim() : "";
  if (!raw || raw.length > MAX_TX_CHARS || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) throw new SolanaValidationError("transaction must be the base64 wire transaction about to be signed (as returned by the dapp or getBase64EncodedWireTransaction)");
  let message;
  try {
    const tx = getTransactionDecoder().decode(getBase64Encoder().encode(raw));
    message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
  } catch {
    throw new SolanaValidationError("transaction could not be decoded as a Solana transaction (legacy or v0)");
  }
  const keys = message.staticAccounts.map(String);
  const { numSignerAccounts, numReadonlySignerAccounts, numReadonlyNonSignerAccounts } = message.header;
  const writable = keys.filter((_, i) => (i < numSignerAccounts ? i < numSignerAccounts - numReadonlySignerAccounts : i < keys.length - numReadonlyNonSignerAccounts));
  const instructions = message.instructions.map((ix) => ({
    program: keys[ix.programAddressIndex] ?? null,
    accounts: (ix.accountIndices ?? []).map((i) => keys[i] ?? null), // null: from an address lookup table
    data: ix.data ?? new Uint8Array(),
  }));
  const from = body.from !== undefined && body.from !== null && body.from !== "" ? String(body.from) : keys[0];
  if (!BASE58.test(from)) throw new SolanaValidationError("from must be a Solana address (base58)");
  const agentExecutes = instructions.map((ix, index) => coreExecuteOf(ix, index)).filter(Boolean);
  return { transaction: raw, feePayer: keys[0], wallet: from, signers: keys.slice(0, numSignerAccounts), writable, instructions, agentExecutes, agentWallets: [...new Set(agentExecutes.map((e) => e.assetSigner).filter(Boolean))], version: message.version, usesLookupTables: (message.addressTableLookups ?? []).length > 0 };
}

// A Metaplex Core Execute, unwrapped: the asset (the agent), its signer PDA (the agent's wallet), who authorises it,
// and the instruction the agent's wallet runs. null for anything else.
function coreExecuteOf(ix, index) {
  if (ix.program !== MPL_CORE || ix.data[0] !== CORE_EXECUTE_V1 || ix.accounts.length < 7) return null;
  const len = u32(ix.data, 1);
  if (len === null || ix.data.length < 5 + len) return null;
  const data = ix.data.subarray(5, 5 + len);
  const [asset, collection, assetSigner, payer, authority, , program] = ix.accounts;
  let accounts = ix.accounts.slice(7);
  const n = TOKEN_PROGRAMS.has(program) ? TOKEN_ACCOUNTS[data[0]] : null;
  if (n && accounts.length > n) accounts = accounts.slice(accounts.length - n);
  return { index, asset, collection: collection === MPL_CORE ? null : collection, assetSigner, payer, authority, inner: { program, accounts, data } };
}

// What each instruction does to the wallet, from its bytes alone; and what each Metaplex agent Execute makes the
// agent's wallet do.
export function instructionReasons(req) {
  const out = [];
  req.instructions.forEach((ix, n) => judge(ix, n, req.wallet, out));
  for (const e of req.agentExecutes ?? []) {
    const via = { instruction: e.index, via: "metaplex-core-execute", agentAsset: e.asset, agentWallet: e.assetSigner };
    const before = out.length;
    judge(e.inner, e.index, e.assetSigner, out, via);
    // The owner's signature carries into the wrapped instruction too, so it is judged for the owner's wallet as well.
    judge(e.inner, e.index, req.wallet, out, { instruction: e.index, via: "metaplex-core-execute", agentAsset: e.asset });
    const d = e.inner.data;
    if (TOKEN_PROGRAMS.has(e.inner.program) && (d[0] === 3 || d[0] === 12)) {
      // A token transfer from the agent's wallet: what an x402 payment by a Metaplex agent looks like.
      const [source, mintOrDest, destOrAuth] = e.inner.accounts;
      const checked = d[0] === 12;
      const amount = u64(d, 1);
      out.push({ code: "METAPLEX_AGENT_PAYMENT", severity: "info", subject: checked ? destOrAuth : mintOrDest, details: { ...via, tokenAccount: source, tokenProgram: e.inner.program, ...(checked && { mint: mintOrDest, decimals: d[9] ?? null }), amount: amount === null ? null : String(amount), note: "pays from the Metaplex agent's own wallet (its Core asset signer), authorised by the asset's owner or an execution delegate" } });
    } else if (e.inner.program === SYSTEM && u32(d, 0) === 2) {
      const lamports = u64(d, 4);
      out.push({ code: "METAPLEX_AGENT_PAYMENT", severity: "info", subject: e.inner.accounts[1], details: { ...via, lamports: lamports === null ? null : String(lamports), note: "sends SOL from the Metaplex agent's own wallet" } });
    } else if (out.length === before && ![MEMO, ASSOCIATED_TOKEN, ...TOKEN_PROGRAMS].includes(e.inner.program)) {
      out.push({ code: "METAPLEX_AGENT_EXECUTE", severity: "orange", subject: e.inner.program, details: { ...via, note: "runs another program's instruction as the agent's wallet: that program can move whatever the agent holds" } });
    }
  }
  req.instructions.forEach((ix, n) => {
    if (ix.program !== MPL_AGENT_TOOLS) return;
    if (ix.data[0] === 1) { // DelegateExecutionV1: [executiveProfile, agentAsset, agentIdentity, executionDelegateRecord, payer, authority, system]
      out.push({ code: "METAPLEX_EXECUTION_DELEGATE", severity: "orange", subject: ix.accounts[0], details: { instruction: n, agentAsset: ix.accounts[1], delegateRecord: ix.accounts[3], note: "gives the executive behind this profile a standing right to run Execute for the agent, so it can pay from the agent's wallet without asking each time (Metaplex's Mech uses this for instant x402 payments), until it is revoked" } });
    }
    if (ix.data[0] === 2) out.push({ code: "METAPLEX_EXECUTION_REVOKED", severity: "info", subject: ix.accounts[1], details: { instruction: n, delegateRecord: ix.accounts[0] } });
  });
  return out;
}

function judge(ix, n, me, out, via = null) {
  const at = (details) => ({ ...details, ...(via ?? {}), instruction: n });
  const d = ix.data;
  if (ix.program === SYSTEM) {
    const op = u32(d, 0);
    if ((op === 1 || op === 10) && ix.accounts[0] === me) out.push({ code: "SOLANA_ACCOUNT_ASSIGN", severity: "red", subject: me, details: at({ note: "hands the wallet itself to a program: it can then move everything in it" }) });
    if (op === 4 && n === 0 && !via) out.push({ code: "SOLANA_DURABLE_NONCE", severity: "orange", subject: ix.accounts[0], details: { note: "uses a durable nonce: once signed it stays valid until someone sends it, it does not expire" } });
  }
  if (TOKEN_PROGRAMS.has(ix.program)) {
    const op = d[0];
    if (op === 4 || op === 13) { // Approve / ApproveChecked
      const amount = u64(d, 1);
      const [source, delegate, owner] = op === 4 ? ix.accounts : [ix.accounts[0], ix.accounts[2], ix.accounts[3]];
      if (owner === me) out.push(amount !== null && amount >= UNLIMITED
        ? { code: "SOLANA_UNLIMITED_DELEGATE", severity: "orange", subject: delegate, details: at({ tokenAccount: source, amount: amount === U64_MAX ? "unlimited" : String(amount) }) }
        : { code: "SOLANA_TOKEN_DELEGATE", severity: "info", subject: delegate, details: at({ tokenAccount: source, amount: amount === null ? null : String(amount) }) });
    }
    if (op === 6) { // SetAuthority
      const type = AUTHORITY_TYPES[d[1]] ?? `type ${d[1]}`;
      const hasNew = d[2] === 1 && d.length >= 35;
      const newAuthority = hasNew ? bs58(d.subarray(3, 35)) : null;
      if (ix.accounts[1] === me && (type === "AccountOwner" || type === "CloseAccount") && newAuthority !== me) {
        out.push({ code: "SOLANA_TOKEN_ACCOUNT_TAKEOVER", severity: "red", subject: newAuthority, details: at({ tokenAccount: ix.accounts[0], authority: type, note: "hands this token account (and everything in it) to someone else" }) });
      } else if (ix.accounts[1] === me) {
        out.push({ code: "SOLANA_SET_AUTHORITY", severity: "orange", subject: newAuthority, details: at({ account: ix.accounts[0], authority: type }) });
      }
    }
    if (op === 9 && ix.accounts[2] === me && ix.accounts[1] && ix.accounts[1] !== me) { // CloseAccount
      out.push({ code: "SOLANA_CLOSE_TO_OTHER", severity: "orange", subject: ix.accounts[1], details: at({ tokenAccount: ix.accounts[0], note: "closes a token account and sends its SOL to another address" }) });
    }
  }
}

// Who a Metaplex agent pays: the owner whose associated token account the payment goes to, among the token owners the
// simulation saw (x402 pays the seller's associated account). Added to the payment line as recipient.
export async function addAgentPaymentRecipients(reasons, tokenOwners = []) {
  const enc = getAddressEncoder();
  for (const r of reasons) {
    const d = r.details;
    if (r.code !== "METAPLEX_AGENT_PAYMENT" || !d?.mint || !d.tokenProgram) continue;
    for (const owner of tokenOwners) {
      try {
        const [ata] = await getProgramDerivedAddress({ programAddress: address(ASSOCIATED_TOKEN), seeds: [enc.encode(address(owner)), enc.encode(address(d.tokenProgram)), enc.encode(address(d.mint))] });
        if (ata === r.subject) { d.recipient = owner; break; }
      } catch { /* not an address: skip */ }
    }
  }
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = "";
  while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = "1" + s; }
  return s;
}

async function rpc(method, params, { fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  const res = await fetchImpl(SOLANA_RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`Solana RPC HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`Solana RPC ${body.error.message ?? "error"}`);
  return body.result;
}

// The wallet's SOL and token accounts before and after the transaction, or null when the RPC can't tell. A Metaplex
// agent's wallet (the asset signer an Execute pays from) counts as the wallet's own: its changes are marked agent.
export async function simulateSolana(req, opts = {}) {
  const agents = new Set(req.agentWallets ?? []);
  const mine = (a) => a === req.wallet || agents.has(a);
  const all = [...new Set([req.wallet, ...agents, ...req.writable])];
  const addresses = all.slice(0, 20);
  try {
    const [before, sim] = await Promise.all([
      rpc("getMultipleAccounts", [addresses, { encoding: "jsonParsed" }], opts),
      rpc("simulateTransaction", [req.transaction, { encoding: "base64", sigVerify: false, replaceRecentBlockhash: true, accounts: { encoding: "jsonParsed", addresses } }], opts),
    ]);
    const v = sim?.value;
    if (!v) return null;
    const pre = before?.value ?? [];
    // A failed simulation returns no accounts after (null for each), which is not "closed": no changes then.
    const post = v.err ? [] : v.accounts ?? [];
    const changes = [];
    const tokenOwners = new Set(); // who owns the token accounts the transaction writes to: the real recipients
    // Accounts the transaction writes to that don't exist yet and that it doesn't create itself (no new keypair signing
    // for them, not a System transfer or token-account create): when it fails, an earlier transaction of the same flow
    // may be the one that creates them.
    const createdHere = new Set([...(req.signers ?? []), ...req.instructions.filter((ix) => ix.program === SYSTEM || ix.program === ASSOCIATED_TOKEN).flatMap((ix) => ix.accounts)]);
    const missing = addresses.filter((address, i) => address !== req.wallet && !createdHere.has(address) && pre[i] === null);
    addresses.forEach((address, i) => {
      const a = pre[i], b = post[i];
      for (const owner of [a?.data?.parsed?.info?.owner, b?.data?.parsed?.info?.owner]) {
        if (owner && !mine(owner) && [a, b].some((x) => x?.data?.parsed?.type === "account")) tokenOwners.add(owner);
      }
      if (v.err) return;
      if (mine(address)) {
        const agent = address !== req.wallet && { agent: true };
        if (a && b && b.lamports !== a.lamports) changes.push({ type: "sol", account: address, change: (b.lamports - a.lamports) / 1e9, lamports: String(BigInt(b.lamports) - BigInt(a.lamports)), ...agent });
        if (a && b && b.owner !== a.owner) changes.push({ type: "owner", account: address, from: a.owner, to: b.owner, ...agent });
      }
      const ai = a?.data?.parsed?.info, bi = b?.data?.parsed?.info;
      if (a?.data?.parsed?.type === "account" && mine(ai?.owner)) {
        const agent = ai.owner !== req.wallet && { agent: true, agentWallet: ai.owner };
        const delta = Number(bi?.tokenAmount?.uiAmountString ?? 0) - Number(ai.tokenAmount?.uiAmountString ?? 0);
        // raw: the exact change in base units, with the mint's decimals (change is the rounded display amount).
        const raw = /^\d+$/.test(String(bi?.tokenAmount?.amount ?? 0)) && /^\d+$/.test(String(ai.tokenAmount?.amount ?? 0)) ? BigInt(bi?.tokenAmount?.amount ?? 0) - BigInt(ai.tokenAmount?.amount ?? 0) : null;
        if (bi && delta !== 0) changes.push({ type: "token", account: address, mint: ai.mint, change: delta, ...(raw !== null && { raw: String(raw), decimals: ai.tokenAmount?.decimals }), ...agent });
        if (!b) changes.push({ type: "closed", account: address, mint: ai.mint, ...agent });
        if (bi && bi.owner !== ai.owner) changes.push({ type: "owner", account: address, mint: ai.mint, from: ai.owner, to: bi.owner, ...agent });
        if (bi?.delegate && bi.delegate !== ai.delegate) changes.push({ type: "delegate", account: address, mint: ai.mint, delegate: bi.delegate, amount: bi.delegatedAmount?.uiAmountString ?? null, ...agent });
      }
    });
    const error = v.err ? JSON.stringify(v.err).slice(0, 200) : null;
    // partial: more writable accounts than were read, so a change in one of the others isn't in changes.
    return { ok: !v.err, changes, ...(tokenOwners.size && { tokenOwners: [...tokenOwners] }), ...(all.length > addresses.length && { partial: true }), ...(v.fee !== undefined && { fee: v.fee / 1e9 }), ...(error && { error }), ...(error && missing.length && { missingAccounts: missing }), ...(v.loadedAddresses && { lookupTableAccounts: (v.loadedAddresses.writable?.length ?? 0) + (v.loadedAddresses.readonly?.length ?? 0) }) };
  } catch (err) {
    console.warn(`[solana-tx] simulation: ${err.message}`);
    return null;
  }
}

// Reasons from the simulation: an owner or delegate change the instructions don't show, or a failing transaction.
export function solanaSimulationReasons(sim, req, shown) {
  if (!sim) return [];
  if (!sim.ok) {
    // Protocols often send setup (creating an account) and the action as separate transactions, signed and sent in
    // order: checked on its own, the action fails until the setup has landed. Still orange, but with that reason.
    const missing = sim.missingAccounts ?? [];
    return [{ code: "SIMULATION_FAILS", severity: "orange", subject: req.wallet, details: { error: sim.error, ...(missing.length && {
      missingAccounts: missing,
      note: "this transaction writes to accounts that don't exist yet: if an earlier transaction of the same flow creates them, check this one again after that one has landed",
    }) } }];
  }
  const out = [];
  for (const c of sim.changes) {
    if (c.type === "owner" && !c.mint && !shown.has("SOLANA_ACCOUNT_ASSIGN")) out.push({ code: "SOLANA_ACCOUNT_ASSIGN", severity: "red", subject: c.to, details: { hidden: true, ...(c.agent && { agentWallet: c.account }) } });
    if (c.type === "owner" && c.account !== req.wallet && c.mint && !shown.has("SOLANA_TOKEN_ACCOUNT_TAKEOVER")) out.push({ code: "SOLANA_TOKEN_ACCOUNT_TAKEOVER", severity: "red", subject: c.to, details: { tokenAccount: c.account, mint: c.mint, hidden: true } });
    if (c.type === "delegate" && !shown.has("SOLANA_UNLIMITED_DELEGATE") && !shown.has("SOLANA_TOKEN_DELEGATE")) out.push({ code: "HIDDEN_APPROVAL", severity: "orange", subject: c.delegate, details: { tokenAccount: c.account, mint: c.mint, amount: c.amount } });
  }
  out.push({ code: "SIMULATED", severity: "info", subject: req.wallet, details: { changes: sim.changes.filter((c) => c.type === "sol" || c.type === "token" || c.type === "closed") } });
  return out;
}
