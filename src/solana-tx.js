// Solana transactions before signing: { type: "solana", transaction: <base64 wire transaction>, from?, origin?, intent? }.
// Solana has no token approvals like EVM, so drainers go after the account itself: SetAuthority hands a token
// account to another owner, System Assign hands the wallet to a program, Approve gives a delegate the right to
// move tokens, and a durable nonce keeps a signed transaction valid until someone sends it. The instructions are
// decoded, and the transaction is simulated on the RPC (simulateTransaction, signatures not checked) to see what
// really leaves the wallet, also inside other programs: SOL and token balances, owners and delegates after.
import { getBase64Encoder, getCompiledTransactionMessageDecoder, getTransactionDecoder } from "@solana/kit";

const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const SYSTEM = "11111111111111111111111111111111";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const TOKEN_PROGRAMS = new Set([TOKEN, TOKEN_2022]);
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
  return { transaction: raw, feePayer: keys[0], wallet: from, signers: keys.slice(0, numSignerAccounts), writable, instructions, version: message.version, usesLookupTables: (message.addressTableLookups ?? []).length > 0 };
}

// What each instruction does to the wallet, from its bytes alone.
export function instructionReasons(req) {
  const out = [];
  const me = req.wallet;
  req.instructions.forEach((ix, n) => {
    const d = ix.data;
    if (ix.program === SYSTEM) {
      const op = u32(d, 0);
      if ((op === 1 || op === 10) && ix.accounts[0] === me) out.push({ code: "SOLANA_ACCOUNT_ASSIGN", severity: "red", subject: me, details: { instruction: n, note: "hands the wallet itself to a program: it can then move everything in it" } });
      if (op === 4 && n === 0) out.push({ code: "SOLANA_DURABLE_NONCE", severity: "orange", subject: ix.accounts[0], details: { note: "uses a durable nonce: once signed it stays valid until someone sends it, it does not expire" } });
    }
    if (TOKEN_PROGRAMS.has(ix.program)) {
      const op = d[0];
      if (op === 4 || op === 13) { // Approve / ApproveChecked
        const amount = u64(d, 1);
        const [source, delegate, owner] = op === 4 ? ix.accounts : [ix.accounts[0], ix.accounts[2], ix.accounts[3]];
        if (owner === me) out.push(amount !== null && amount >= UNLIMITED
          ? { code: "SOLANA_UNLIMITED_DELEGATE", severity: "orange", subject: delegate, details: { tokenAccount: source, amount: amount === U64_MAX ? "unlimited" : String(amount) } }
          : { code: "SOLANA_TOKEN_DELEGATE", severity: "info", subject: delegate, details: { tokenAccount: source, amount: amount === null ? null : String(amount) } });
      }
      if (op === 6) { // SetAuthority
        const type = AUTHORITY_TYPES[d[1]] ?? `type ${d[1]}`;
        const hasNew = d[2] === 1 && d.length >= 35;
        const newAuthority = hasNew ? bs58(d.subarray(3, 35)) : null;
        if (ix.accounts[1] === me && (type === "AccountOwner" || type === "CloseAccount") && newAuthority !== me) {
          out.push({ code: "SOLANA_TOKEN_ACCOUNT_TAKEOVER", severity: "red", subject: newAuthority, details: { tokenAccount: ix.accounts[0], authority: type, note: "hands this token account (and everything in it) to someone else" } });
        } else if (ix.accounts[1] === me) {
          out.push({ code: "SOLANA_SET_AUTHORITY", severity: "orange", subject: newAuthority, details: { account: ix.accounts[0], authority: type } });
        }
      }
      if (op === 9 && ix.accounts[2] === me && ix.accounts[1] && ix.accounts[1] !== me) { // CloseAccount
        out.push({ code: "SOLANA_CLOSE_TO_OTHER", severity: "orange", subject: ix.accounts[1], details: { tokenAccount: ix.accounts[0], note: "closes a token account and sends its SOL to another address" } });
      }
    }
  });
  return out;
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

// The wallet's SOL and token accounts before and after the transaction, or null when the RPC can't tell.
export async function simulateSolana(req, opts = {}) {
  const addresses = [...new Set([req.wallet, ...req.writable])].slice(0, 20);
  try {
    const [before, sim] = await Promise.all([
      rpc("getMultipleAccounts", [addresses, { encoding: "jsonParsed" }], opts),
      rpc("simulateTransaction", [req.transaction, { encoding: "base64", sigVerify: false, replaceRecentBlockhash: true, accounts: { encoding: "jsonParsed", addresses } }], opts),
    ]);
    const v = sim?.value;
    if (!v) return null;
    const pre = before?.value ?? [];
    const post = v.accounts ?? [];
    const changes = [];
    addresses.forEach((address, i) => {
      const a = pre[i], b = post[i];
      if (address === req.wallet) {
        if (a && b && b.lamports !== a.lamports) changes.push({ type: "sol", account: address, change: (b.lamports - a.lamports) / 1e9 });
        if (a && b && b.owner !== a.owner) changes.push({ type: "owner", account: address, from: a.owner, to: b.owner });
      }
      const ai = a?.data?.parsed?.info, bi = b?.data?.parsed?.info;
      if (a?.data?.parsed?.type === "account" && ai?.owner === req.wallet) {
        const delta = Number(bi?.tokenAmount?.uiAmountString ?? 0) - Number(ai.tokenAmount?.uiAmountString ?? 0);
        if (bi && delta !== 0) changes.push({ type: "token", account: address, mint: ai.mint, change: delta });
        if (!b) changes.push({ type: "closed", account: address, mint: ai.mint });
        if (bi && bi.owner !== ai.owner) changes.push({ type: "owner", account: address, mint: ai.mint, from: ai.owner, to: bi.owner });
        if (bi?.delegate && bi.delegate !== ai.delegate) changes.push({ type: "delegate", account: address, mint: ai.mint, delegate: bi.delegate, amount: bi.delegatedAmount?.uiAmountString ?? null });
      }
    });
    const error = v.err ? JSON.stringify(v.err).slice(0, 200) : null;
    return { ok: !v.err, changes, ...(v.fee !== undefined && { fee: v.fee / 1e9 }), ...(error && { error }), ...(v.loadedAddresses && { lookupTableAccounts: (v.loadedAddresses.writable?.length ?? 0) + (v.loadedAddresses.readonly?.length ?? 0) }) };
  } catch (err) {
    console.warn(`[solana-tx] simulation: ${err.message}`);
    return null;
  }
}

// Reasons from the simulation: an owner or delegate change the instructions don't show, or a failing transaction.
export function solanaSimulationReasons(sim, req, shown) {
  if (!sim) return [];
  if (!sim.ok) return [{ code: "SIMULATION_FAILS", severity: "orange", subject: req.wallet, details: { error: sim.error } }];
  const out = [];
  for (const c of sim.changes) {
    if (c.type === "owner" && c.account === req.wallet && !shown.has("SOLANA_ACCOUNT_ASSIGN")) out.push({ code: "SOLANA_ACCOUNT_ASSIGN", severity: "red", subject: c.to, details: { hidden: true } });
    if (c.type === "owner" && c.account !== req.wallet && !shown.has("SOLANA_TOKEN_ACCOUNT_TAKEOVER")) out.push({ code: "SOLANA_TOKEN_ACCOUNT_TAKEOVER", severity: "red", subject: c.to, details: { tokenAccount: c.account, mint: c.mint, hidden: true } });
    if (c.type === "delegate" && !shown.has("SOLANA_UNLIMITED_DELEGATE") && !shown.has("SOLANA_TOKEN_DELEGATE")) out.push({ code: "HIDDEN_APPROVAL", severity: "orange", subject: c.delegate, details: { tokenAccount: c.account, mint: c.mint, amount: c.amount } });
  }
  out.push({ code: "SIMULATED", severity: "info", subject: req.wallet, details: { changes: sim.changes.filter((c) => c.type === "sol" || c.type === "token" || c.type === "closed") } });
  return out;
}
