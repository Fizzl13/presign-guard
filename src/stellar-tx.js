// stellar-tx.js — the pre-sign check for Stellar transactions (POST /v1/check with type "stellar").
//
//   { type: "stellar", transaction: "<base64 XDR envelope>", network?: "pubnet" | "testnet", from?, origin?, intent? }
//
// The envelope may be unsigned, signed or a fee bump; the wallet is `from`, else the transaction's source. Classic
// operations are judged by their fields: merging the account into another (all its XLM goes there and it is gone),
// adding a signer or switching off the master key (someone else can then move everything), changed thresholds, and
// payments, trustlines and DEX offers in a fake USDC or EURC (the real ones are Circle's). A payment without a memo
// to an account that requires one (SEP-29, mostly exchanges) is orange: the money arrives but nobody can tell whose
// it is. Soroban calls (invokeHostFunction) are read from the call and from every authorization the wallet signs,
// sub-calls included, which is how an x402 payment on Stellar is made: an approve to someone else is orange (hidden
// in a sub-call too). The call is then simulated on a public Soroban RPC with the authorizations left out, so the
// token transfers it would make show, also of a fake USDC. Address poisoning: right after an account's first
// transactions, a look-alike address (same first and last four characters as a counterparty) sends it dust, hoping
// the next payment goes there; a recipient that looks like an account the wallet dealt with before, but isn't it,
// is red. Fail-closed as in presign-guard.js: errors are non-2xx,
// never "green"; when Horizon or the RPC can't be reached the check says so (info) and the field rules still apply.
import { TransactionBuilder, FeeBumpTransaction, Networks, StrKey, Address, Account, Operation, xdr, scValToNative, extractBaseAddress } from "@stellar/stellar-sdk";

// Circle issues USDC and EURC on Stellar; a token with that code from any other issuer is a copy.
export const STELLAR_NETWORKS = {
  pubnet: {
    caip2: "stellar:pubnet", name: "Stellar", passphrase: Networks.PUBLIC,
    horizon: process.env.STELLAR_HORIZON_URL || "https://horizon.stellar.org",
    rpc: process.env.STELLAR_RPC_URL || "https://mainnet.sorobanrpc.com",
    stablecoins: { USDC: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", EURC: "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2" },
  },
  testnet: {
    caip2: "stellar:testnet", name: "Stellar testnet", passphrase: Networks.TESTNET,
    horizon: process.env.STELLAR_TESTNET_HORIZON_URL || "https://horizon-testnet.stellar.org",
    rpc: process.env.STELLAR_TESTNET_RPC_URL || "https://soroban-testnet.stellar.org",
    stablecoins: { USDC: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5" },
  },
};
const MAX_TX_CHARS = 12000; // as for the other chains: an x402 payment (a Soroban call in a fee bump) is ~1,600 characters
const HIGH_FEE = 50_000_000n; // stroops (5 XLM): a classic operation costs 0.00001 XLM, a Soroban call well under 1 XLM
const UNLIMITED = 2n ** 100n; // an allowance this large is meant as "everything"
const NODE_TIMEOUT_MS = 5000;
const STROOPS = 10_000_000; // XLM and Stellar assets have 7 decimals
const DUST = 0.01; // poisoning payments are 0.0001 XLM; less than a cent of anything isn't a counterparty

export class StellarValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

const plain = (v) => (typeof v === "bigint" ? v.toString() : Array.isArray(v) ? v.map(plain) : v && typeof v === "object" && !(v instanceof Uint8Array) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)])) : v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v);
const native = (scv) => { try { return plain(scValToNative(scv)); } catch { return null; } };
const base = (a) => { if (!a) return undefined; try { return a.startsWith("M") ? extractBaseAddress(a) : a; } catch { return a; } };
const assetName = (a) => (!a ? undefined : a.isNative?.() ? "XLM" : `${a.code}:${a.issuer}`);

function pickNetwork(n) {
  if (n === undefined || n === null || n === "") return "pubnet";
  const s = String(n).toLowerCase();
  if (s === "pubnet" || s === "mainnet" || s === "public" || s === "stellar:pubnet") return "pubnet";
  if (s === "testnet" || s === "stellar:testnet") return "testnet";
  throw new StellarValidationError(`unsupported Stellar network ${n}: pubnet and testnet are checked`);
}

// The request decoded: the network, the wallet whose funds are at stake (from, or the transaction's source), the
// transaction (the inner one of a fee bump) and the fee bump's fee source.
export function parseStellarRequest(body) {
  const raw = body.transaction;
  if (typeof raw !== "string" || !raw.trim() || raw.length > MAX_TX_CHARS || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw.trim())) {
    throw new StellarValidationError("transaction must be a base64 XDR Stellar transaction envelope (unsigned, signed or a fee bump)");
  }
  const network = pickNetwork(body.network);
  const net = STELLAR_NETWORKS[network];
  let env;
  try { env = TransactionBuilder.fromXDR(raw.trim(), net.passphrase); } catch {
    throw new StellarValidationError("transaction could not be decoded as a Stellar transaction envelope");
  }
  const feeBump = env instanceof FeeBumpTransaction;
  const tx = feeBump ? env.innerTransaction : env;
  if (!tx.operations.length) throw new StellarValidationError("the transaction has no operations");
  // An x402 payment on Stellar is sent by the facilitator: the buyer only signs an authorization inside the call. So
  // without `from`, the wallet is the one account that signs such an authorization, else the transaction's source.
  const signers = new Set(tx.operations.filter((o) => o.type === "invokeHostFunction").flatMap((o) => (o.auth ?? [])
    .filter((a) => a.credentials().switch().name === "sorobanCredentialsAddress")
    .map((a) => Address.fromScAddress(a.credentials().address().address()).toString())));
  let wallet = signers.size === 1 ? [...signers][0] : base(tx.source);
  if (body.from !== undefined && body.from !== null && body.from !== "") {
    if (typeof body.from !== "string" || !StrKey.isValidEd25519PublicKey(base(body.from))) throw new StellarValidationError("from must be a Stellar account (G…)");
    wallet = base(body.from);
  }
  return { network, wallet, tx, feeSource: feeBump ? base(env.feeSource) : null, fee: BigInt(feeBump ? env.fee : tx.fee), envelope: raw.trim() };
}

// A contract call as plain values: the contract, the function and its arguments.
function contractCall(fn) {
  return { contract: Address.fromScAddress(fn.contractAddress()).toString(), fn: fn.functionName().toString(), args: fn.args().map(native) };
}

// Every call an authorization covers, root first, with how deep it sits.
function authorizedCalls(invocation, depth = 0, out = []) {
  const f = invocation.function();
  if (f.switch().name === "sorobanAuthorizedFunctionTypeContractFn") out.push({ ...contractCall(f.contractFn()), depth });
  else out.push({ deploy: true, depth });
  for (const sub of invocation.subInvocations()) authorizedCalls(sub, depth + 1, out);
  return out;
}

// The authorizations on a Soroban operation: whose they are and every call they cover.
function authorizations(op, txSource) {
  return (op.auth ?? []).map((entry) => {
    const c = entry.credentials();
    const who = c.switch().name === "sorobanCredentialsAddress" ? Address.fromScAddress(c.address().address()).toString() : txSource;
    return { signer: who, sourceAccount: c.switch().name !== "sorobanCredentialsAddress", calls: authorizedCalls(entry.rootInvocation()) };
  });
}

// What an operation does, as plain values: for the answer's subject, the intent check and the usage log.
export function describeStellarOp(op, txSource) {
  const d = { type: op.type, source: base(op.source) || base(txSource) };
  switch (op.type) {
    case "payment": Object.assign(d, { destination: base(op.destination), asset: assetName(op.asset), amount: op.amount }); break;
    case "pathPaymentStrictSend": Object.assign(d, { destination: base(op.destination), sendAsset: assetName(op.sendAsset), sendAmount: op.sendAmount, destAsset: assetName(op.destAsset), destMin: op.destMin }); break;
    case "pathPaymentStrictReceive": Object.assign(d, { destination: base(op.destination), sendAsset: assetName(op.sendAsset), sendMax: op.sendMax, destAsset: assetName(op.destAsset), destAmount: op.destAmount }); break;
    case "createAccount": Object.assign(d, { destination: base(op.destination), startingBalance: op.startingBalance }); break;
    case "accountMerge": Object.assign(d, { destination: base(op.destination) }); break;
    case "changeTrust": Object.assign(d, { asset: op.line?.code ? assetName(op.line) : "liquidity pool", limit: op.limit }); break;
    case "manageSellOffer": case "manageBuyOffer": case "createPassiveSellOffer": Object.assign(d, { selling: assetName(op.selling), buying: assetName(op.buying), amount: op.amount ?? op.buyAmount, price: op.price }); break;
    case "setOptions": Object.assign(d, {
      ...(op.signer && { signer: op.signer.ed25519PublicKey || (op.signer.preAuthTx ? "preAuthTx" : op.signer.sha256Hash ? "sha256Hash" : "signedPayload"), signerWeight: op.signer.weight }),
      ...(op.masterWeight !== undefined && { masterWeight: op.masterWeight }),
      ...(op.lowThreshold !== undefined && { lowThreshold: op.lowThreshold }),
      ...(op.medThreshold !== undefined && { medThreshold: op.medThreshold }),
      ...(op.highThreshold !== undefined && { highThreshold: op.highThreshold }),
    }); break;
    case "invokeHostFunction": {
      const f = op.func;
      if (f.switch().name === "hostFunctionTypeInvokeContract") Object.assign(d, contractCall(f.invokeContract()));
      else d.function = f.switch().name;
      const auth = authorizations(op, txSource);
      if (auth.length) d.authorizations = auth.map((a) => ({ signer: a.signer, calls: a.calls.length }));
      break;
    }
    default: break;
  }
  return d;
}

// Horizon: an account's data (signers, thresholds, SEP-29 memo flag), or null when it doesn't exist.
function horizon(net, fetchImpl) {
  return {
    account: async (id) => {
      const res = await fetchImpl(`${net.horizon}/accounts/${id}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`horizon HTTP ${res.status}`);
      return res.json();
    },
    // The accounts this one has dealt with (its latest 200 payments, account creations and merges, Soroban token
    // transfers included): who it paid, who funded it, and who sent it more than dust. Dust is left out, because
    // dust from a look-alike address is the poisoning itself. An account that doesn't exist yet has dealt with nobody.
    counterparties: async (id) => {
      const res = await fetchImpl(`${net.horizon}/accounts/${id}/payments?order=desc&limit=200`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
      if (res.status === 404) return new Set();
      if (!res.ok) throw new Error(`horizon HTTP ${res.status}`);
      const known = new Set();
      const add = (a) => { if (typeof a === "string" && a !== id) known.add(a); };
      for (const r of (await res.json())?._embedded?.records ?? []) {
        if (r.type === "create_account") { add(r.funder === id ? r.account : r.funder); continue; }
        if (r.type === "account_merge") { add(r.account === id ? r.into : r.account); continue; }
        if (r.type === "invoke_host_function") {
          for (const c of r.asset_balance_changes ?? []) if (c.type === "transfer") add(c.from === id ? c.to : c.to === id && Number(c.amount) >= DUST ? c.from : null);
          continue;
        }
        if (r.from === id) add(r.to);
        else if (r.to === id && Number(r.amount) >= DUST) add(r.from);
      }
      return known;
    },
  };
}

// Same first four and last four characters (the "G" included), another account: how look-alike addresses are made.
export function stellarLookalike(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a === b || a.length !== 56 || b.length !== 56 || a[0] !== b[0]) return false;
  return a.slice(0, 4) === b.slice(0, 4) && a.slice(-4) === b.slice(-4);
}

// A token named like Circle's that isn't Circle's: { code, issuer } or null.
function fakeStable(net, assetStr) {
  if (!assetStr || assetStr === "XLM" || assetStr === "native") return null;
  const [code, issuer] = assetStr.split(":");
  const real = net.stablecoins[String(code).toUpperCase()];
  return real && issuer !== real ? { code, issuer, real: `${code.toUpperCase()}:${real}` } : null;
}

const amountOf = (v) => { try { return BigInt(v); } catch { return null; } };

// The rules: every operation the wallet is the source of, and every call it authorizes.
export async function stellarReasons(req, { fetchImpl = globalThis.fetch } = {}) {
  const net = STELLAR_NETWORKS[req.network];
  const reasons = [];
  const add = (code, severity, subject, details) => {
    if (reasons.some((r) => r.code === code && r.subject === subject)) return;
    reasons.push({ code, severity, ...(subject && { subject }), ...(details && { details }) });
  };
  const ask = horizon(net, fetchImpl);
  let nodeDown = false;
  let nodeUsed = false;
  const lookup = async (fn) => {
    try { const r = await fn(); nodeUsed = true; return r; } catch (err) {
      if (!nodeDown) add("STELLAR_NODE_UNAVAILABLE", "info", net.name, { error: String(err.message).slice(0, 120) });
      nodeDown = true;
      return undefined;
    }
  };
  const accounts = new Map();
  const account = (id) => { if (!accounts.has(id)) accounts.set(id, lookup(() => ask.account(id))); return accounts.get(id); };
  const fake = (assetStr, i) => {
    const f = fakeStable(net, assetStr);
    if (f) add("STELLAR_FAKE_STABLECOIN", "red", assetStr, { op: i, code: f.code, issuer: f.issuer, real: f.real, effect: `not Circle's ${f.code.toUpperCase()}: a copy with the same name` });
  };

  const tx = req.tx;
  const txSource = base(tx.source);
  const memo = tx.memo?.type && tx.memo.type !== "none";
  if (req.fee > HIGH_FEE) add("STELLAR_HIGH_FEE", "orange", req.feeSource || txSource, { feeXlm: Number(req.fee) / STROOPS, effect: "the fee is far above what a Stellar transaction costs" });
  if (req.feeSource && req.feeSource !== req.wallet) add("STELLAR_FEE_BUMP", "info", req.feeSource, { note: "another account pays the fee (a fee bump, as x402 facilitators do)" });

  const own = await account(req.wallet);
  if (own && Array.isArray(own.signers) && own.signers.filter((s) => s.weight > 0).length > 1) add("STELLAR_MULTISIG", "info", req.wallet, { signers: own.signers.length });

  const recipients = new Set(); // whom the wallet sends money to, for the address-poisoning check
  for (const [i, op] of tx.operations.entries()) {
    const source = base(op.source) || txSource;
    const mine = source === req.wallet;
    if (op.type === "invokeHostFunction") {
      const f = op.func;
      const kind = f.switch().name;
      if (kind !== "hostFunctionTypeInvokeContract") add("STELLAR_CONTRACT_DEPLOY", "info", source, { op: i, function: kind });
      else {
        const call = contractCall(f.invokeContract());
        add("STELLAR_CONTRACT_CALL", "info", call.contract, { op: i, function: call.fn });
      }
      // What the wallet authorizes: its address credentials, or the transaction source's own (source-account) credentials.
      for (const a of authorizations(op, txSource)) {
        if (a.signer !== req.wallet) continue;
        for (const c of a.calls) {
          if (c.deploy) { add("STELLAR_CONTRACT_DEPLOY", "info", req.wallet, { op: i }); continue; }
          if (c.fn === "approve" && c.args[0] === req.wallet && c.args[1] && c.args[1] !== req.wallet) {
            const amt = amountOf(c.args[2]);
            add(c.depth ? "STELLAR_HIDDEN_APPROVE" : "STELLAR_TOKEN_APPROVE", "orange", c.args[1], { op: i, token: c.contract, amount: amt !== null && amt >= UNLIMITED ? "unlimited" : String(c.args[2]), expirationLedger: c.args[3], effect: c.depth ? "an allowance to this spender inside another call, which the outer call doesn't show" : "lets this spender take the token from the wallet up to the amount, until the expiration ledger" });
          }
          if (c.fn === "transfer" && c.args[0] === req.wallet) {
            add("STELLAR_TOKEN_TRANSFER", "info", c.args[1], { op: i, token: c.contract, amount: String(c.args[2]) });
            if (typeof c.args[1] === "string" && c.args[1] !== req.wallet) recipients.add(c.args[1]);
          }
        }
      }
      continue;
    }
    if (!mine) { add("STELLAR_OTHER_SOURCE", "info", source, { op: i, note: "an operation of another account in this transaction; that account signs for it" }); continue; }

    switch (op.type) {
      case "accountMerge": {
        const to = base(op.destination);
        if (to !== req.wallet) {
          add("STELLAR_ACCOUNT_MERGE", "red", to, { op: i, effect: "closes the account: all its XLM goes to this address and the account is gone" });
          recipients.add(to);
        }
        break;
      }
      case "setOptions": {
        const s = op.signer;
        if (s) {
          const key = s.ed25519PublicKey || (s.preAuthTx ? "preAuthTx" : s.sha256Hash ? "sha256Hash" : "signedPayload");
          if (Number(s.weight) === 0) add("STELLAR_SIGNER_REMOVED", "info", key, { op: i });
          else if (key !== req.wallet) add("STELLAR_SIGNER_ADDED", "red", key, { op: i, weight: Number(s.weight), effect: "adds a signer: this key can then sign for the account, up to moving everything in it" });
        }
        if (op.masterWeight !== undefined && Number(op.masterWeight) === 0) add("STELLAR_MASTER_KEY_DISABLED", "red", req.wallet, { op: i, effect: "switches off the account's own key: only the other signers can use the account from then on" });
        if ([op.lowThreshold, op.medThreshold, op.highThreshold].some((t) => t !== undefined)) add("STELLAR_THRESHOLDS_CHANGED", "orange", req.wallet, { op: i, low: op.lowThreshold, med: op.medThreshold, high: op.highThreshold, effect: "changes how much signing weight each kind of operation needs" });
        if (op.setFlags || op.clearFlags || op.homeDomain !== undefined || op.inflationDest) add("STELLAR_ACCOUNT_SETTINGS", "info", req.wallet, { op: i });
        break;
      }
      case "payment": case "pathPaymentStrictSend": case "pathPaymentStrictReceive": {
        const to = base(op.destination);
        fake(assetName(op.asset || op.destAsset), i);
        if (op.sendAsset) fake(assetName(op.sendAsset), i);
        if (to && to !== req.wallet) recipients.add(to);
        const dest = to && to !== req.wallet ? await account(to) : undefined;
        if (dest === null) add("STELLAR_DESTINATION_MISSING", "orange", to, { op: i, effect: "this account doesn't exist, so the payment fails (send XLM with createAccount to open it)" });
        if (dest && !memo && dest.data?.["config.memo_required"] === "MQ==") add("STELLAR_MEMO_REQUIRED", "orange", to, { op: i, effect: "this account asks for a memo (SEP-29, usually an exchange): without one the money arrives but can't be credited to anyone" });
        if (op.type === "pathPaymentStrictSend" && op.destMin !== undefined && Number(op.destMin) <= 0.0000001) add("STELLAR_PATH_NO_MINIMUM", "orange", to, { op: i, effect: "the path payment accepts any amount at the other end, so a bad rate can take almost all of it" });
        break;
      }
      case "createAccount": recipients.add(base(op.destination)); break;
      case "changeTrust": {
        if (op.line?.code) fake(assetName(op.line), i);
        if (op.limit !== undefined && Number(op.limit) === 0) add("STELLAR_TRUSTLINE_REMOVED", "info", op.line?.code ? assetName(op.line) : "liquidity pool", { op: i });
        break;
      }
      case "manageSellOffer": case "manageBuyOffer": case "createPassiveSellOffer":
        fake(assetName(op.selling), i);
        fake(assetName(op.buying), i);
        add("STELLAR_DEX_OFFER", "info", req.wallet, { op: i, selling: assetName(op.selling), buying: assetName(op.buying), price: op.price });
        break;
      case "createClaimableBalance": add("STELLAR_CLAIMABLE_BALANCE", "info", req.wallet, { op: i, asset: assetName(op.asset), amount: op.amount }); break;
      case "claimClaimableBalance": case "liquidityPoolDeposit": case "liquidityPoolWithdraw": case "manageData": case "bumpSequence":
      case "beginSponsoringFutureReserves": case "endSponsoringFutureReserves": case "revokeSponsorship":
      case "extendFootprintTtl": case "restoreFootprint": case "inflation":
        add(`STELLAR_${op.type.replace(/[A-Z]/g, (m) => `_${m}`).toUpperCase()}`, "info", req.wallet, { op: i });
        break;
      case "clawback": case "clawbackClaimableBalance": case "setTrustLineFlags": case "allowTrust":
        add("STELLAR_ISSUER_ACTION", "info", req.wallet, { op: i, type: op.type });
        break;
      default: add("STELLAR_OP_NOT_ANALYZED", "orange", req.wallet, { op: i, type: op.type });
    }
  }
  // Address poisoning: each recipient against the accounts the wallet dealt with before.
  if (recipients.size) {
    const known = await lookup(() => ask.counterparties(req.wallet));
    for (const to of recipients) {
      if (!known) break;
      if (known.has(to)) { add("KNOWN_RECIPIENT", "info", to); continue; }
      const real = [...known].find((k) => stellarLookalike(k, to));
      if (real) add("ADDRESS_POISONING", "red", to, { lookalikeOf: real, note: "starts and ends like an account this wallet dealt with before, but it is another account: the address was probably copied from a look-alike payment in the history" });
      else add("NEW_RECIPIENT", "info", to, { pastCounterparties: known.size });
    }
  }
  return { reasons, nodeUsed };
}

// The token transfers and approvals in a simulation's contract events: SAC events carry the asset as "CODE:ISSUER".
function eventChanges(events = []) {
  const out = [];
  for (const raw of events) {
    let ev;
    try { ev = xdr.DiagnosticEvent.fromXDR(raw, "base64"); } catch { continue; }
    const e = ev.event();
    if (e.type().name !== "contract" || !ev.inSuccessfulContractCall()) continue;
    const body = e.body().v0();
    const topics = body.topics().map(native);
    const data = native(body.data());
    const token = e.contractId() ? StrKey.encodeContract(e.contractId()) : undefined;
    const name = topics[0];
    if (name === "transfer") out.push({ type: "transfer", token, from: topics[1], to: topics[2], asset: typeof topics[3] === "string" ? topics[3] : undefined, amount: String(data?.amount ?? data) });
    if (name === "approve") out.push({ type: "approve", token, from: topics[1], spender: topics[2], asset: typeof topics[3] === "string" ? topics[3] : undefined, amount: String(Array.isArray(data) ? data[0] : data), expirationLedger: Array.isArray(data) ? data[1] : undefined });
  }
  return out;
}

// Simulate the transaction's Soroban call on the RPC with its authorizations left out (record mode), so what it would
// transfer or approve shows whatever state the signatures are in. Classic-only transactions are not simulated.
export async function simulateStellar(req, { fetchImpl = globalThis.fetch } = {}) {
  const op = req.tx.operations.find((o) => o.type === "invokeHostFunction");
  if (!op) return undefined;
  const net = STELLAR_NETWORKS[req.network];
  try {
    const source = base(req.tx.source);
    const tx = new TransactionBuilder(new Account(source, (BigInt(req.tx.sequence) - 1n).toString()), { fee: String(req.tx.fee), networkPassphrase: net.passphrase })
      .addOperation(Operation.invokeHostFunction({ func: op.func, auth: [] }))
      .setTimeout(0)
      .build();
    const res = await fetchImpl(net.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "simulateTransaction", params: { transaction: tx.toXDR() } }), signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`soroban rpc HTTP ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`soroban rpc: ${body.error.message ?? "error"}`);
    const r = body.result ?? {};
    if (r.error) return { ok: false, error: String(r.error).split("\n")[0].slice(0, 300), changes: [] };
    return { ok: true, changes: eventChanges(r.events) };
  } catch (err) {
    console.warn(`[stellar-tx] simulation: ${err.message}`);
    return null;
  }
}

// Reasons from the simulation: a fake stablecoin moved, an approval the call didn't show, a call that would fail.
export function stellarSimulationReasons(sim, req, reasons) {
  if (sim === undefined) return [];
  if (!sim) return [{ code: "SIMULATION_UNAVAILABLE", severity: "info", subject: req.wallet }];
  if (!sim.ok) return [{ code: "SIMULATION_FAILS", severity: "orange", subject: req.wallet, details: { error: sim.error } }];
  const net = STELLAR_NETWORKS[req.network];
  const outgoing = sim.changes.filter((c) => c.type === "transfer" && c.from === req.wallet).map((c) => ({ to: c.to, token: c.token, asset: c.asset, amount: c.amount }));
  const out = [{ code: "SIMULATED", severity: "info", subject: req.wallet, details: { changes: sim.changes.length, outgoing } }];
  for (const c of sim.changes) {
    const f = fakeStable(net, c.asset);
    if (f && (c.from === req.wallet || c.to === req.wallet)) out.push({ code: "STELLAR_FAKE_STABLECOIN", severity: "red", subject: c.asset, details: { token: c.token, code: f.code, issuer: f.issuer, real: f.real, effect: `not Circle's ${f.code.toUpperCase()}: a copy with the same name` } });
    if (c.type === "approve" && c.from === req.wallet && c.spender !== req.wallet && !reasons.some((r) => (r.code === "STELLAR_TOKEN_APPROVE" || r.code === "STELLAR_HIDDEN_APPROVE") && r.subject === c.spender)) {
      out.push({ code: "STELLAR_HIDDEN_APPROVE", severity: "orange", subject: c.spender, details: { token: c.token, asset: c.asset, amount: c.amount, effect: "the simulation shows an allowance to this spender that the call doesn't show" } });
    }
  }
  return out;
}
