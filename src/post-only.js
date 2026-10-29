// post-only.js
//
// GET (and HEAD, which head-guard.js turns into GET) on a paid route that takes POST: /v1/check, /v1/check/explain
// and /v1/injection answered 404, so directories that probe every route with an unpaid GET listed them as gone
// (the Agent Exchange x402 census, 29 Oct 2026). They now get the same 402 as an unpaid POST, with Allow: POST.
// A GET that carries a payment or a credit key is refused with 405: the paid answer needs the POST body, and a
// payment on a GET would buy nothing.

import { PAYMENT_HEADERS } from "./head-guard.js";

export function postOnlyTerms({ paths, paywall, creditHeader = "x-credit-key" }) {
  const routes = new Set(paths);
  return (req, res, next) => {
    const path = req.path.replace(/\/+$/, "").toLowerCase();
    if (req.method !== "GET" || !routes.has(path)) return next();
    res.set("Allow", "POST");
    const refuse = () => res.status(405).json({ error: "method_not_allowed", message: `${req.path} takes POST with a JSON body (see /openapi.json); an unpaid POST gets the payment terms.` });
    const paying = PAYMENT_HEADERS.some((h) => req.headers[h]) || req.headers[creditHeader] || /(?:^|,)\s*Payment\s/i.test(String(req.headers.authorization || ""));
    if (paying) return refuse();
    // The paywall sees the POST this GET stands for (at the route's own path) and answers its 402; a path it doesn't
    // guard falls through to 405.
    const query = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
    paywall(Object.create(req, { method: { value: "POST", enumerable: true }, url: { value: `${path}${query}`, enumerable: true } }), res, refuse);
  };
}
