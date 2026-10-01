// Internal access for PlainText: only with the right key, never without one.
import { test } from "node:test";
import assert from "node:assert";
import { internalAccess, unlessInternal } from "../src/internal.js";

const KEY = "k".repeat(40);
const req = (h) => ({ get: (name) => (name === "x-fizzl-internal" ? h : undefined) });

test("internal access is off without a key or with a short key", () => {
  assert.equal(internalAccess(undefined)(req(KEY)), false);
  assert.equal(internalAccess("")(req("")), false);
  assert.equal(internalAccess("short")(req("short")), false);
});

test("internal access needs the exact key", () => {
  const isInternal = internalAccess(KEY);
  assert.equal(isInternal(req(KEY)), true);
  assert.equal(isInternal(req(KEY + "x")), false);
  assert.equal(isInternal(req("k".repeat(39))), false);
  assert.equal(isInternal(req(undefined)), false);
});

test("the paywall is skipped only for internal requests", () => {
  let paywall = 0;
  const mw = unlessInternal(internalAccess(KEY), (_q, _s, next) => { paywall++; next(); });
  const a = req(KEY); let nextA = 0; mw(a, {}, () => nextA++);
  assert.equal(paywall, 0); assert.equal(nextA, 1); assert.equal(a.fizzlInternal, true);
  const b = req("nope"); mw(b, {}, () => {});
  assert.equal(paywall, 1); assert.equal(b.fizzlInternal, undefined);
});
