// An x402 v1 payment gets a 402 that says why (src/x402-v1.js through mirrorChallengeIntoBody).
import test from "node:test";
import assert from "node:assert/strict";
import { mirrorChallengeIntoBody } from "../src/discovery.js";
import { v1PaymentOf } from "../src/x402-v1.js";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
function run(headers) {
  const challenge = { x402Version: 2, accepts: [{ scheme: "exact", network: "eip155:8453", amount: "10000" }] };
  let sent;
  const res = { statusCode: 402, getHeader: (h) => (h === "PAYMENT-REQUIRED" ? b64(challenge) : undefined), json: (b) => { sent = b; return res; } };
  mirrorChallengeIntoBody({ headers }, res, () => {});
  res.json({});
  return sent;
}

test("a v1 payment: the 402 says this service speaks x402 v2, keeps the terms and names v2 clients", () => {
  const body = run({ "x-payment": b64({ x402Version: 1, scheme: "exact", network: "base", payload: {} }) });
  assert.match(body.error, /x402 v1 payment not accepted \(network "base"\): this service speaks x402 v2/);
  assert.ok(body.upgrade.some((u) => u.includes("x402-safe-fetch")));
  assert.equal(body.accepts[0].network, "eip155:8453");
});

test("a v2 payment, or none, gets the plain 402", () => {
  assert.equal(run({}).upgrade, undefined);
  assert.equal(run({ "payment-signature": b64({ x402Version: 2, accepted: { network: "eip155:8453" } }) }).upgrade, undefined);
  assert.equal(v1PaymentOf({ headers: { "x-payment": "not base64 json" } }), null);
});
