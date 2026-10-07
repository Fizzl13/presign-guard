// head-guard.js
//
// Express answers HEAD with the GET route, and the x402 middleware only guards
// the methods in its route keys ("GET /signal/:pair"): a HEAD request slipped
// past the paywall and ran the paid handler for free (no body went back, but
// the work was done, e.g. a token check). Every HEAD is now handled as the GET
// it stands for: paid paths get the normal 402 (Node sends no body for HEAD),
// free paths answer as before. Not only exact paths: Express also matches /SCAN
// and /scan/. A HEAD that carries a payment is refused: it would pay and get
// nothing back.

export const PAYMENT_HEADERS = ["payment-signature", "x-payment"];

export function headGuard() {
  return (req, res, next) => {
    if (req.method !== "HEAD") return next();
    const paying = PAYMENT_HEADERS.some((h) => req.headers[h]) || /(?:^|,)\s*Payment\s/i.test(String(req.headers.authorization || ""));
    if (paying) return res.status(405).set("Allow", "GET").end();
    req.method = "GET";
    next();
  };
}

