// A fix on each orange or red reason (src/fixes.js): what a safe version looks like, what this request does, what to
// change, and whether a changed request can come back green. Pure: no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fixFor, withFixes, FIX_CODES } from "../src/fixes.js";

const SPENDER = "0x1111111111111111111111111111111111111111";
const SELLER = "0x2222222222222222222222222222222222222222";
const RETRY = new Set(["change", "elsewhere", "ask", "never"]);

test("every fix has expected, saw, change and a known retry", () => {
  const sample = { subject: SPENDER, details: { exactIn: true, minima: ["0", "0"], realToken: SELLER, lookalikeOf: SELLER, required: "10000", signing: "20000", expiresAt: 1893456000, ageDays: 2 } };
  for (const code of FIX_CODES) {
    for (const severity of ["orange", "red"]) {
      const f = fixFor({ code, severity, ...sample }, { x402: { payTo: SELLER, asset: SELLER, maxTimeoutSeconds: 60 } });
      if (!f) continue; // V4 hook info-level fixes only exist when red
      assert.ok(f.expected && f.saw && f.change, code);
      assert.ok(RETRY.has(f.retry), `${code}: ${f.retry}`);
    }
  }
  assert.equal(fixFor({ code: "UNLIMITED_APPROVAL", severity: "info", subject: SPENDER }), null, "info reasons get no fix");
  assert.equal(fixFor({ code: "SOMETHING_NEW", severity: "red", subject: SPENDER }), null, "unknown codes get none");
});

test("an unlimited approval: approve the exact amount, then check again", () => {
  const f = fixFor({ code: "UNLIMITED_APPROVAL", severity: "orange", subject: SPENDER });
  assert.equal(f.retry, "change");
  assert.match(f.change, /exactly the amount/);
  assert.deepEqual(f.set, { amount: "the exact amount needed" });
});

test("x402: the fix names the seller's own payTo, amount and timeout from the 402", () => {
  const req = { x402: { payTo: SELLER, asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", maxTimeoutSeconds: 60 } };
  assert.deepEqual(fixFor({ code: "X402_RECIPIENT_MISMATCH", severity: "red", subject: SPENDER }, req).set, { to: SELLER });
  assert.deepEqual(fixFor({ code: "X402_AMOUNT_ABOVE_REQUIRED", severity: "red", subject: SELLER, details: { required: "10000", signing: "20000" } }, req).set, { value: "10000" });
  assert.match(fixFor({ code: "X402_VALIDITY_TOO_LONG", severity: "orange", subject: SELLER }, req).expected, /60 s/);
});

test("Uniswap v4: a swap without a limit gets the field to set; a hook problem is fixed elsewhere", () => {
  const exactIn = fixFor({ code: "V4_SWAP_NO_LIMIT", severity: "orange", subject: SPENDER, details: { exactIn: true, amountOutMinimum: "0" } });
  assert.deepEqual(Object.keys(exactIn.set), ["amountOutMinimum"]);
  const exactOut = fixFor({ code: "V4_HOOK_CAN_TAKE_SWAP", severity: "red", subject: SPENDER, details: { exactIn: false, amountInMaximum: "340282366920938463463374607431768211455" } });
  assert.deepEqual(Object.keys(exactOut.set), ["amountInMaximum"]);
  assert.equal(fixFor({ code: "V4_HOOK_CAN_TAKE_SWAP", severity: "info", subject: SPENDER }), null, "with a limit it is info: nothing to fix");
  assert.equal(fixFor({ code: "V4_HOOK_CAN_BLOCK_WITHDRAWAL", severity: "orange", subject: SPENDER }).retry, "elsewhere");
  assert.deepEqual(Object.keys(fixFor({ code: "V4_HOOK_CAN_TAKE_WITHDRAWAL", severity: "red", subject: SPENDER, details: { tokenId: "7", minima: ["0", "0"] } }).set), ["amount0Min", "amount1Min"]);
});

test("sanctions, phishing and drainer patterns: never, with no set", () => {
  for (const code of ["SANCTIONED_ADDRESS", "PHISHING_SITE", "SIGNATURE_GRANT_TO_EOA", "MALICIOUS_CONTRACT_BEHAVIOR", "TOKEN_HONEYPOT", "AUTHORIZATION_TO_NO_CONTRACT"]) {
    const f = fixFor({ code, severity: "red", subject: SPENDER });
    assert.equal(f.retry, "never", code);
    assert.equal(f.set, undefined, code);
    assert.match(f.change, /^Don't sign/);
  }
});

test("withFixes: fixes on orange and red reasons; fixable only when every one can be changed into green", () => {
  const changeable = withFixes({ verdict: "orange", reasons: [
    { code: "PAYMENT_AUTHORIZATION", severity: "info", subject: SELLER },
    { code: "UNLIMITED_APPROVAL", severity: "orange", subject: SPENDER },
    { code: "LONG_LIVED_PERMISSION", severity: "orange", subject: SPENDER, details: { expiresAt: 1893456000 } },
  ] });
  assert.equal(changeable.fixable, true);
  assert.equal(changeable.reasons[0].fix, undefined);
  assert.ok(changeable.reasons[1].fix && changeable.reasons[2].fix);
  const notChangeable = withFixes({ verdict: "red", reasons: [{ code: "UNLIMITED_APPROVAL", severity: "orange", subject: SPENDER }, { code: "SANCTIONED_ADDRESS", severity: "red", subject: SPENDER }] });
  assert.equal(notChangeable.fixable, false);
  const unknown = withFixes({ verdict: "orange", reasons: [{ code: "SOMETHING_NEW", severity: "orange", subject: SPENDER }] });
  assert.equal(unknown.fixable, false, "a reason without a recipe is not called fixable");
  const green = withFixes({ verdict: "green", reasons: [{ code: "SANCTIONS_SCREENED", severity: "info" }] });
  assert.equal(green.fixable, undefined, "nothing to fix on green");
  assert.equal(withFixes(null), null);
});
