// The Render address (presign-guard.onrender.com) serves the same app, and directories pick it up: MPPScan lists it
// next to presign-guard.fizzl.eu. Its payment challenges name the public domain (src/public-host.js: the MPP realm and
// the x402 resource), which a strict client refuses on another host. So every request there goes to the public domain
// instead: 308, so a POST keeps its method and body, and a paying client follows it to the same route. The health check
// stays on the Render address for Render's own probe; local runs and tests (any other host) are left alone.
export function canonicalHost(publicUrl, { keep = ["/health"] } = {}) {
  const target = new URL(publicUrl);
  return (req, res, next) => {
    const host = String(req.headers.host || "").split(":")[0].toLowerCase();
    if (!/\.onrender\.com$/.test(host) || host === target.hostname || keep.includes(req.path)) return next();
    res.redirect(308, `${target.origin}${req.originalUrl}`);
  };
}
