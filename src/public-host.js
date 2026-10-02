// x402 puts the address the buyer used into the payment challenge, and the x402 Bazaar lists
// the service under that address. A request that reaches this service on its Render address
// (…onrender.com) is answered as if it came to the public domain, so the challenge, and so the
// listing, always say presign-guard.fizzl.eu. Only the paywall sees this; nothing else changes.
export function onPublicHost(publicUrl, paywall) {
  const host = new URL(publicUrl).host;
  return (req, res, next) => {
    const asked = req.headers.host;
    if (!asked || asked === host || !/\.onrender\.com$/i.test(asked.split(":")[0])) return paywall(req, res, next);
    req.headers.host = host;
    Object.defineProperty(req, "protocol", { value: "https", configurable: true });
    return paywall(req, res, (err) => { req.headers.host = asked; delete req.protocol; next(err); });
  };
}
