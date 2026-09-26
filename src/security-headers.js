// Security headers for every response: no MIME sniffing, no framing (clickjacking
// on the pay pages), HTTPS only, and no full URLs leaking in the Referer header.
// The CSP only restricts framing, <base> and plugins, so the inline page scripts
// and the x402 paywall keep working. Kept identical in presign-guard,
// x402-doctor and ichimoku-signal.
export function securityHeaders(_req, res, next) {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    "Strict-Transport-Security": "max-age=31536000",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  });
  next();
}
