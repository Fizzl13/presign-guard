// Internal access for our own services (PlainText): a request with the header
// x-fizzl-internal equal to FIZZL_INTERNAL_KEY skips the x402 paywall, so
// PlainText can build its plain-language answers on presign-guard's verdict
// without paying itself. Off unless the key is set (at least 32 characters,
// in Render only, the same value on both services). Everything else is the
// same as a paid call: validation, the verdict, the signed receipt, the usage
// log (marked via "internal").
import { createHash, timingSafeEqual } from "node:crypto";

export const INTERNAL_HEADER = "x-fizzl-internal";
const MIN_KEY_LENGTH = 32;

export function internalAccess(key = process.env.FIZZL_INTERNAL_KEY) {
  const k = String(key ?? "").trim();
  if (k.length < MIN_KEY_LENGTH) return () => false;
  const digest = (s) => createHash("sha256").update(s).digest();
  const want = digest(k);
  return (req) => {
    const got = req.get ? req.get(INTERNAL_HEADER) : req.headers?.[INTERNAL_HEADER];
    if (typeof got !== "string" || !got) return false;
    return timingSafeEqual(digest(got.trim()), want);
  };
}

// Run `middleware` (the paywall) unless the request is internal.
export function unlessInternal(isInternal, middleware) {
  return (req, res, next) => {
    if (isInternal(req)) {
      req.fizzlInternal = true;
      return next();
    }
    return middleware(req, res, next);
  };
}
