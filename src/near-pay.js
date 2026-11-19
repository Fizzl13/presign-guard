// USDC on NEAR (NEP-141 17208628…a1, 6 decimals) as one more way to pay, with the official @x402/near "exact"
// scheme: the buyer signs a NEP-366 SignedDelegate for exactly one ft_transfer to payTo, and a relayer of ours
// submits it and pays the NEAR gas, so the buyer needs no NEAR. No public facilitator lists near:mainnet yet
// (PayAI, x402.org and Doctor's board, 19 Nov 2026), so it settles in-process here, like the XRPL payments.
//
// On only when NEAR_RELAYER_ACCOUNT and NEAR_RELAYER_KEY are set (a dedicated account with a little NEAR for gas,
// set by Frits in Render; never a wallet that holds anything else). NEAR_PAY_TO overrides the payout account
// (default x402fizzl.near), NEAR_PAY_TO=off turns it off, NEAR_RPC_URL overrides FastNEAR's public RPC.
// The payout account must be registered on the USDC contract (NEP-145 storage_deposit), or every payment fails
// the library's preflight; nearStatus() reports it for /health.
import { x402Facilitator } from "@x402/core/facilitator";
import { createFacilitatorNearSigner, NEAR_MAINNET_CAIP2, NEAR_RPC_URLS } from "@x402/near";
import { ExactNearScheme } from "@x402/near/exact/facilitator";

export const NEAR_NETWORK = NEAR_MAINNET_CAIP2;
export const NEAR_USDC = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const DEFAULT_PAY_TO = "x402fizzl.near";
const ACCOUNT = /^(?=.{2,64}$)(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

// { network, payTo, relayer } when a relayer is configured; null otherwise, or with NEAR_PAY_TO=off.
export function nearConfig(env = process.env) {
  if ((env.NEAR_PAY_TO || "").trim() === "off") return null;
  const relayer = (env.NEAR_RELAYER_ACCOUNT || "").trim();
  const key = (env.NEAR_RELAYER_KEY || "").trim();
  if (!relayer || !key) return null;
  const payTo = (env.NEAR_PAY_TO || "").trim() || DEFAULT_PAY_TO;
  if (!ACCOUNT.test(payTo)) throw new Error(`NEAR_PAY_TO is not a NEAR account id: ${payTo}`);
  if (!ACCOUNT.test(relayer)) throw new Error("NEAR_RELAYER_ACCOUNT is not a NEAR account id");
  if (!/^(ed25519|secp256k1):[1-9A-HJ-NP-Za-km-z]+$/.test(key)) throw new Error("NEAR_RELAYER_KEY must be a secret key like ed25519:…");
  if (relayer === payTo) throw new Error("NEAR_RELAYER_ACCOUNT must not be the payout account: keep the gas account separate");
  return { network: NEAR_NETWORK, payTo, relayer };
}

const rpcUrl = (env = process.env) => (env.NEAR_RPC_URL || "").trim() || NEAR_RPC_URLS[NEAR_NETWORK];

// The in-process facilitator client (getSupported/verify/settle). The relayer key stays inside the signer.
export function nearFacilitator(env = process.env, { scheme } = {}) {
  const facilitator = new x402Facilitator().register(NEAR_NETWORK, scheme || new ExactNearScheme(createFacilitatorNearSigner({
    relayers: [{ accountId: env.NEAR_RELAYER_ACCOUNT.trim(), secretKey: env.NEAR_RELAYER_KEY.trim() }],
    rpcUrls: { [NEAR_NETWORK]: rpcUrl(env) },
  })));
  // The library's settle is idempotent: the same signed delegate again returns its cached success (spec §10), so a
  // replayed payment header would buy a second answer. Each signed delegate settles once here; a failed settle frees
  // it for a retry. A day is far past its max_block_height window (maxTimeoutSeconds blocks of ~1 s).
  // The relayer's transaction nonce is read from the chain per settle, so two settles at the same moment would take
  // the same nonce and one would fail: the chain part of each settle waits for the one before it.
  const settled = new Map();
  let queue = Promise.resolve();
  const oneAtATime = (fn) => { const run = queue.then(fn); queue = run.catch(() => {}); return run; };
  const keyOf = (payload) => String(payload?.payload?.signedDelegateAction || "");
  const prune = (t) => { for (const [k, until] of settled) if (until <= t) settled.delete(k); };
  return {
    getSupported: async () => facilitator.getSupported(),
    verify: (payload, requirements) => facilitator.verify(payload, requirements),
    async settle(payload, requirements) {
      const key = keyOf(payload);
      const t = now();
      prune(t);
      if (!key || settled.has(key)) return { success: false, transaction: "", network: requirements?.network || NEAR_NETWORK, payer: "", errorReason: "duplicate_settlement" };
      settled.set(key, t + DAY_MS);
      try {
        const result = await oneAtATime(() => facilitator.settle(payload, requirements));
        if (!result?.success) settled.delete(key);
        return result;
      } catch (err) {
        settled.delete(key);
        throw err;
      }
    },
  };
}
const DAY_MS = 24 * 3600 * 1000;
const now = () => Date.now();

// One NEAR accept entry: the same dollar price, in USDC on NEAR (the library's default asset for near:mainnet).
export const nearAccept = (near, price) => (near?.payTo ? [{ scheme: "exact", price, network: near.network, payTo: near.payTo }] : []);

// For /health: whether the payout account can receive USDC and how much NEAR the relayer has left for gas.
// Read-only view calls; errors give null fields, never a throw.
export async function nearStatus(near, { fetchImpl = fetch, env = process.env } = {}) {
  if (!near) return null;
  const call = async (body) => {
    const res = await fetchImpl(rpcUrl(env), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, ...body }), signal: AbortSignal.timeout(5000) });
    const json = await res.json();
    if (json.error || json.result?.error) throw new Error(json.error?.message || json.result.error);
    return json.result;
  };
  const view = async (method, args) => {
    const r = await call({ method: "query", params: { request_type: "call_function", finality: "final", account_id: NEAR_USDC, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString("base64") } });
    return JSON.parse(Buffer.from(r.result).toString("utf8"));
  };
  const out = { network: near.network, pay_to: near.payTo, relayer: near.relayer, pay_to_registered: null, relayer_near: null };
  try { out.pay_to_registered = (await view("storage_balance_of", { account_id: near.payTo })) !== null; } catch { /* unknown */ }
  try {
    const acct = await call({ method: "query", params: { request_type: "view_account", finality: "final", account_id: near.relayer } });
    out.relayer_near = Number(BigInt(acct.amount) / 10n ** 20n) / 10_000; // yoctoNEAR → NEAR, 4 decimals
  } catch { /* unknown */ }
  return out;
}
