// An x402 v1 payment (the old x402-fetch / x402-axios clients: header X-PAYMENT, x402Version 1, network "base") can't
// be paid here: the service speaks x402 v2 (CAIP-2 networks, PAYMENT-SIGNATURE), and the @x402 server SDK has no v1.
// It got "No matching payment requirements", which tells a developer nothing. The 402 for such a request now says why
// and what to use instead, in the body's error (what v1 clients show) and in an upgrade field.
export const V1_UPGRADE = [
  'npm: @x402/fetch or @x402/axios (x402 v2)',
  'npm: x402-safe-fetch (checks the endpoint first, then pays over x402 v2)',
  'PyPI: x402 2.x',
];
export function v1PaymentOf(req) {
  for (const name of ['x-payment', 'payment-signature']) {
    const value = req.headers?.[name];
    if (!value) continue;
    try {
      const payment = JSON.parse(Buffer.from(String(value), 'base64').toString('utf8'));
      if (payment && (payment.x402Version === 1 || (typeof payment.network === 'string' && !payment.network.includes(':')))) return payment;
    } catch {
      // not a readable payment: not ours to explain
    }
  }
  return null;
}
export function v1Hint(payment) {
  const network = typeof payment?.network === 'string' ? ` (network "${payment.network.slice(0, 40)}")` : '';
  return {
    error: `x402 v1 payment not accepted${network}: this service speaks x402 v2, with CAIP-2 networks such as "eip155:8453" and the PAYMENT-SIGNATURE header. Pay with an x402 v2 client; the terms are in accepts and the PAYMENT-REQUIRED header.`,
    upgrade: V1_UPGRADE,
  };
}
