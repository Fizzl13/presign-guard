// In-process facilitator for x402 payments on the XRP Ledger (xrpl:0, RLUSD), as in ichimoku-signal.
// On XRPL the payer signs a complete Payment and pays the XRPL fee itself; the facilitator verifies it
// (signature, destination, amount, sequence, InvoiceID, simulation) and submits it. No key or balance is
// needed here. Payments in t54's format (from its SDK) go to t54's hosted facilitator, see below.
// getSupported() needs no network, so the service starts even when the XRPL node is down;
// only XRPL payments fail then (nothing is charged).
import { x402Facilitator } from "@x402/core/facilitator";
import { ExactXrplScheme } from "@x402/xrpl/exact/facilitator";
import { HTTPFacilitatorClient } from "@x402/core/server";

export const XRPL_NETWORK = "xrpl:0";
// The XRPL SourceTag for x402 payments: t54-built payers sign with it, @x402/xrpl payers may.
export const X402_SOURCE_TAG = 804681468;
// Two kinds of XRPL payers exist. Clients built on @x402/xrpl send { signedTxBlob } and are verified and
// submitted here. Clients built on t54's SDK (x402-xrpl, Xrpl.X402: most agents in the XRPL AI Hub) send
// { signedTxBlob, invoiceId } and bind the invoice in Memos, which @x402/xrpl refuses; those payments go to
// t54's hosted facilitator, which accepts them (both paths settled on testnet, Oct 2026). t54Url "off" = local only.
export const isT54Payload = (payload) => Boolean(payload && payload.payload && typeof payload.payload.invoiceId === 'string');


export function createXrplFacilitator({ network = XRPL_NETWORK, wsUrl = "wss://xrplcluster.com", scheme, t54Url = process.env.XRPL_T54_URL || "https://xrpl-facilitator-mainnet.t54.ai", t54 } = {}) {
  const facilitator = new x402Facilitator().register(network, scheme || new ExactXrplScheme({ wsUrlByNetwork: { [network]: wsUrl } }));
  const remote = t54 || (t54Url && t54Url !== "off" ? new HTTPFacilitatorClient({ url: t54Url }) : null);
  return {
    getSupported: async () => facilitator.getSupported(),
    verify: (payload, requirements) => (remote && isT54Payload(payload) ? remote.verify(payload, requirements) : facilitator.verify(payload, requirements)),
    settle: (payload, requirements) => (remote && isT54Payload(payload) ? remote.settle(payload, requirements) : facilitator.settle(payload, requirements)),
  };
}

// One XRPL accept entry: the dollar price in RLUSD, bound to this service and route by its InvoiceID.
export const xrplAccept = (xrpl, price, route) =>
  xrpl?.payTo ? [{ scheme: "exact", price, network: xrpl.network, payTo: xrpl.payTo, extra: { invoiceId: `presign-guard.fizzl.eu ${route}`, sourceTag: X402_SOURCE_TAG } }] : [];
