// x402's payment-identifier extension: the 402 declares it, the buyer's client sends an id with the payment and keeps
// it when it retries after a lost answer (a timeout, a dropped connection). A retry with an id this service already
// answered, for the same route and input and the same payer, gets that answer again and is not settled a second time.
// Only answers whose payment settled (a PAYMENT-RESPONSE header and a status below 400) are kept, so a failed
// settlement never leaves a free answer behind. In memory: a restart forgets them, and the retry is then a new payment.
import { createHash } from "node:crypto";
import { PAYMENT_IDENTIFIER, declarePaymentIdentifierExtension, extractPaymentIdentifier } from "@x402/extensions/payment-identifier";

export const paymentIdentifierExtension = { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension() };
const KEPT_HEADERS = ["content-type", "payment-response", "cache-control"];

function decodePayment(header) {
  try { return JSON.parse(Buffer.from(String(header), "base64").toString("utf8")); } catch { return null; }
}
// The payer of an EVM "exact" payment; other networks carry it inside a signed transaction, so null there.
const payerOf = (payment) => String(payment?.payload?.authorization?.from ?? "").toLowerCase() || null;

export function createPaymentRetry({ ttlMs = 86_400_000, max = 2000, maxBytes = 256 * 1024, now = () => Date.now() } = {}) {
  const answers = new Map(); // key → { status, headers, body, payer, until }, oldest first

  function prune() {
    const t = now();
    for (const [key, a] of answers) {
      if (answers.size > max || a.until <= t) answers.delete(key);
      else break;
    }
  }

  function middleware(req, res, next) {
    const header = req.get("payment-signature");
    const payment = header ? decodePayment(header) : null;
    const id = payment ? extractPaymentIdentifier(payment) : null;
    if (!id) return next();
    const input = req.body === undefined ? "" : createHash("sha256").update(JSON.stringify(req.body)).digest("hex");
    const key = `${req.method} ${req.originalUrl} ${input} ${id}`;
    const payer = payerOf(payment);
    prune();
    const stored = answers.get(key);
    if (stored && stored.until > now() && (!stored.payer || stored.payer === payer)) {
      res.status(stored.status);
      for (const [name, value] of Object.entries(stored.headers)) res.setHeader(name, value);
      return res.end(stored.body);
    }
    let sent = null;
    const send = res.send.bind(res);
    res.send = (body) => { sent = body; return send(body); };
    res.on("finish", () => {
      if (sent === null || res.statusCode >= 400 || !res.getHeader("payment-response")) return;
      const body = Buffer.isBuffer(sent) ? sent : Buffer.from(typeof sent === "string" ? sent : JSON.stringify(sent));
      if (body.length > maxBytes) return;
      const headers = {};
      for (const name of KEPT_HEADERS) if (res.getHeader(name) != null) headers[name] = String(res.getHeader(name));
      answers.delete(key);
      answers.set(key, { status: res.statusCode, headers, body, payer, until: now() + ttlMs });
      prune();
    });
    next();
  }

  return { middleware, size: () => answers.size };
}
