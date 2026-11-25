// Search-word paths for the CDP Bazaar.
//
// The Bazaar's search ranks a route mostly by the words in its URL (host and path); the description barely counts.
// A buyer searching "sanctions screening" or "transaction check" does not find /v1/screen or /v1/check. So each of
// these routes also answers under a path with those words: this middleware rewrites the path to the existing route
// before the paywall, so price, handler and usage log are the same. @x402/express matches the route by req.path
// (the rewritten one) but names the resource by req.originalUrl (the alias), so the 402 carries the alias URL and one
// indexing payment to it lists it in the Bazaar on its own.
//
// The same file is in x402-doctor (lib/bazaar-aliases.js).

export function bazaarAliases(aliases) {
  const map = new Map(Object.entries(aliases));
  return (req, _res, next) => {
    const q = req.url.indexOf("?");
    const path = q < 0 ? req.url : req.url.slice(0, q);
    const target = map.get(path) ?? map.get(path.replace(/\/+$/, ""));
    if (target) req.url = target + (q < 0 ? "" : req.url.slice(q));
    next();
  };
}

// presign-guard's: the words buyers search for, to the route that does it.
export const PRESIGN_ALIASES = {
  "/v1/transaction-check": "/v1/check",
  "/v1/sanctions-screening": "/v1/screen",
  "/v1/token-approval-check": "/v1/approvals",
};
