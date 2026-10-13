// In-process facilitator for x402 payments on the XRP Ledger (xrpl:0, RLUSD), as in ichimoku-signal.
// On XRPL the payer signs a complete Payment and pays the XRPL fee itself; the facilitator verifies it
// (signature, destination, amount, sequence, InvoiceID, simulation) and submits it. No key or balance is
// needed here. Payments in t54's format (from its SDK) go to t54's hosted facilitator, see below.
// getSupported() needs no network, so the service starts even when the XRPL node is down;
// only XRPL payments fail then (nothing is charged).
import { x402Facilitator } from "@x402/core/facilitator";
import { ExactXrplScheme } from "@x402/xrpl/exact/facilitator";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { createHash } from "node:crypto";

export const XRPL_NETWORK = "xrpl:0";
// The XRPL SourceTag for x402 payments: t54-built payers sign with it, @x402/xrpl payers may.
export const X402_SOURCE_TAG = 804681468;
// Two kinds of XRPL payers exist. Clients built on @x402/xrpl send { signedTxBlob } and are verified and
// submitted here. Clients built on t54's SDK (x402-xrpl, Xrpl.X402: most agents in the XRPL AI Hub) send
// { signedTxBlob, invoiceId } and bind the invoice in Memos, which @x402/xrpl refuses; those payments go to
// t54's hosted facilitator, which accepts them (both paths settled on testnet, Oct 2026). t54Url "off" = local only.
export const isT54Payload = (payload) => Boolean(payload && payload.payload && typeof payload.payload.invoiceId === 'string');


// t54's hosted /settle is idempotent: the same settle request again returns its cached result. A replayed t54
// payment (the same signed blob sent again) would then come back "settled" and buy a second answer. So each blob is
// claimed once here, for a week (long past its LastLedgerSequence); a failed settle frees it for a retry. The local
// @x402/xrpl path has the same guard in the library (duplicate_settlement).
const T54_CLAIM_MS = 7 * 24 * 3600 * 1000;
function createClaims({ ttlMs = T54_CLAIM_MS, now = () => Date.now() } = {}) {
  const until = new Map();
  return {
    claim(key) {
      const t = now();
      for (const [k, u] of until) if (u <= t) until.delete(k);
      if (until.has(key)) return false;
      until.set(key, t + ttlMs);
      return true;
    },
    release: (key) => until.delete(key),
  };
}
const blobKey = (payload) => createHash("sha256").update(String(payload.payload.signedTxBlob || "")).digest("hex");

export function createXrplFacilitator({ network = XRPL_NETWORK, wsUrl = "wss://xrplcluster.com", scheme, t54Url = process.env.XRPL_T54_URL || "https://xrpl-facilitator-mainnet.t54.ai", t54, now } = {}) {
  const facilitator = new x402Facilitator().register(network, scheme || new ExactXrplScheme({ wsUrlByNetwork: { [network]: wsUrl } }));
  const remote = t54 || (t54Url && t54Url !== "off" ? new HTTPFacilitatorClient({ url: t54Url }) : null);
  const claims = createClaims({ now });
  return {
    getSupported: async () => facilitator.getSupported(),
    verify: (payload, requirements) => (remote && isT54Payload(payload) ? remote.verify(payload, requirements) : facilitator.verify(payload, requirements)),
    async settle(payload, requirements) {
      if (!(remote && isT54Payload(payload))) return facilitator.settle(payload, requirements);
      const key = blobKey(payload);
      if (!claims.claim(key)) return { success: false, transaction: "", network: payload.accepted?.network || network, payer: "", errorReason: "duplicate_settlement" };
      try {
        const result = await remote.settle(payload, requirements);
        if (!result || !result.success) claims.release(key);
        return result;
      } catch (err) {
        claims.release(key);
        throw err;
      }
    },
  };
}

// One XRPL accept entry: the dollar price in RLUSD, bound to this service and route by its InvoiceID.
export const xrplAccept = (xrpl, price, route) =>
  xrpl?.payTo ? [{ scheme: "exact", price, network: xrpl.network, payTo: xrpl.payTo, extra: { invoiceId: `presign-guard.fizzl.eu ${route}`, sourceTag: X402_SOURCE_TAG } }] : [];
