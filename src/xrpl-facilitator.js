// In-process facilitator for x402 payments on the XRP Ledger (xrpl:0, RLUSD), as in ichimoku-signal.
// On XRPL the payer signs a complete Payment and pays the XRPL fee itself; the facilitator verifies it
// (signature, destination, amount, sequence, InvoiceID, simulation) and submits it. No key or balance is
// needed here. t54's hosted facilitator rejected a payment that @x402/xrpl accepts (testnet, Oct 2026), so
// it is not used. getSupported() needs no network, so the service starts even when the XRPL node is down;
// only XRPL payments fail then (nothing is charged).
import { x402Facilitator } from "@x402/core/facilitator";
import { ExactXrplScheme } from "@x402/xrpl/exact/facilitator";

export const XRPL_NETWORK = "xrpl:0";

export function createXrplFacilitator({ network = XRPL_NETWORK, wsUrl = "wss://xrplcluster.com", scheme } = {}) {
  const facilitator = new x402Facilitator().register(network, scheme || new ExactXrplScheme({ wsUrlByNetwork: { [network]: wsUrl } }));
  return {
    getSupported: async () => facilitator.getSupported(),
    verify: (payload, requirements) => facilitator.verify(payload, requirements),
    settle: (payload, requirements) => facilitator.settle(payload, requirements),
  };
}

// One XRPL accept entry: the dollar price in RLUSD, bound to this service and route by its InvoiceID.
export const xrplAccept = (xrpl, price, route) =>
  xrpl?.payTo ? [{ scheme: "exact", price, network: xrpl.network, payTo: xrpl.payTo, extra: { invoiceId: `presign-guard.fizzl.eu ${route}` } }] : [];
