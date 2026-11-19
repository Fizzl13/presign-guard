// NEAR Builders Activity reports (src/activity.js): what is sent, when nothing is sent, and that a failing report
// never throws. The payment path (a real settle reporting check.paid) is in near-payments.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createActivityReporter, ACTIVITY_URL } from "../src/activity.js";

const quiet = { log() {}, error() {} };
const TX = "9rTxHashOnNear111";
const pay = { payer: "buyer.near", payTo: "x402fizzl.near", transaction: TX, amount: "10000", asset: "usdc", network: "near:mainnet" };

function stand(answers = []) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, headers: init.headers, body: JSON.parse(init.body) });
    const a = answers.length ? answers.shift() : 200;
    if (a instanceof Error) throw a;
    return { ok: a < 300, status: a, json: async () => ({ eventId: `ev${calls.length}` }), text: async () => "nope" };
  };
  return { calls, fetchImpl };
}

test("a NEAR payment reports check.paid for the buyer, keyed on the transaction", async () => {
  const s = stand();
  const a = createActivityReporter({ env: { ACTIVITY_API_KEY: "act_test" }, fetchImpl: s.fetchImpl, log: quiet });
  assert.equal(await a.checkPaid(pay), "ev1");
  assert.equal(s.calls[0].url, ACTIVITY_URL);
  assert.equal(s.calls[0].headers.authorization, "Bearer act_test");
  assert.deepEqual([s.calls[0].body.eventType, s.calls[0].body.actor, s.calls[0].body.idempotencyKey], ["check.paid", "buyer.near", `near:mainnet:${TX}:paid`]);
  assert.deepEqual(s.calls[0].body.payload, { network: "near:mainnet", transaction: TX, asset: "usdc", amount: "10000" });
  assert.deepEqual(a.stats(), { enabled: true, sent: 1, failed: 0 });
});

test("no key, no transaction, no NEAR account, or our own account paying itself: nothing is sent", async () => {
  const s = stand();
  assert.equal(await createActivityReporter({ env: {}, fetchImpl: s.fetchImpl, log: quiet }).checkPaid(pay), null);
  const a = createActivityReporter({ env: { ACTIVITY_API_KEY: "k" }, fetchImpl: s.fetchImpl, log: quiet });
  await a.checkPaid({ ...pay, transaction: "" });
  await a.checkPaid({ ...pay, payer: "Not Valid" });
  await a.checkPaid({ ...pay, payer: "x402fizzl.near" });
  assert.equal(s.calls.length, 0);
});

test("a 503 or a network error is retried with the same body; a 401 is logged once, never thrown, without the key", async () => {
  const errors = [];
  const log = { log() {}, error: (m) => errors.push(m) };
  const s = stand([503, new Error("reset"), 200]);
  const a = createActivityReporter({ env: { ACTIVITY_API_KEY: "act_secret" }, fetchImpl: s.fetchImpl, log, retryMs: [0, 0], sleep: async () => {} });
  assert.equal(await a.checkPaid(pay), "ev3");
  assert.deepEqual(s.calls[0].body, s.calls[2].body);
  const s2 = stand([401]);
  const b = createActivityReporter({ env: { ACTIVITY_API_KEY: "act_secret" }, fetchImpl: s2.fetchImpl, log, retryMs: [0, 0], sleep: async () => {} });
  assert.equal(await b.checkPaid(pay), null);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /check\.paid for buyer\.near not reported: 401/);
  assert.ok(!errors[0].includes("act_secret"));
});
