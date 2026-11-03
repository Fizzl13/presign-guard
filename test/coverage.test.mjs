// What a verdict covered and what it didn't (src/coverage.js). Pure: no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { evmCoverage, genericCoverage, withCoverage } from "../src/coverage.js";

const TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SPENDER = "0x1111111111111111111111111111111111111111";
const ME = "0x3333333333333333333333333333333333333333";
const approval = { chainId: 8453, kind: "token_approve", target: TOKEN, offchain: false, grants: [{ token: TOKEN, spender: SPENDER, mode: "approve" }] };
const checks = (list) => list.map((x) => x.check);
const not = (cov, check) => cov.not_checked.find((x) => x.check === check);

test("an approval without from, origin or intent: green covers the grant, reputation and tokens; it names what to send for more", () => {
  const cov = evmCoverage(approval, [{ code: "SANCTIONS_SCREENED", severity: "info", subject: SPENDER }], { simulationReason: "not_sent" });
  for (const c of ["permissions", "reputation", "tokens", "sanctions", "lookalikes"]) assert.ok(checks(cov.checked).includes(c), c);
  assert.deepEqual([not(cov, "simulation").because, not(cov, "simulation").send], ["not_sent", "from"]);
  assert.equal(not(cov, "site").send, "origin");
  assert.equal(not(cov, "intent").send, "intent");
  assert.equal(not(cov, "address_history").send, "from");
  assert.equal(cov.checks_complete, true, "nothing that applied failed to run");
});

test("a source that didn't answer makes checks_complete false and names the address", () => {
  const cov = evmCoverage({ ...approval, from: ME }, [
    { code: "SANCTIONS_SCREEN_UNAVAILABLE", severity: "info", subject: SPENDER },
    { code: "PARTIAL_SOURCE_DATA", severity: "info", subject: TOKEN },
    { code: "UPGRADEABLE_PROXY", severity: "info", subject: SPENDER, details: { confirmed: false } },
  ], { simulationReason: "unavailable", history: false });
  assert.equal(cov.checks_complete, false);
  assert.equal(not(cov, "sanctions").subject, SPENDER);
  assert.equal(not(cov, "reputation").subject, TOKEN);
  assert.equal(not(cov, "proxy").because, "unavailable");
  assert.equal(not(cov, "simulation").because, "unavailable");
  assert.equal(not(cov, "address_history").because, "unavailable");
  assert.ok(!checks(cov.checked).includes("sanctions"));
});

test("simulated, with history, origin and intent: those move to checked", () => {
  const cov = evmCoverage({ ...approval, from: ME, origin: "app.uniswap.org", intent: "swap" }, [], { simulation: { ok: true, changes: [] }, history: true, intentSources: ["typesafe-jev"] });
  for (const c of ["simulation", "site", "intent"]) assert.ok(checks(cov.checked).includes(c), c);
  assert.match(cov.checked.find((x) => x.check === "lookalikes").what, /paid before/);
  assert.deepEqual(cov.not_checked, []);
});

test("a signature is never simulated; a chain without eth_simulateV1 is out of scope, not a failure", () => {
  assert.equal(not(evmCoverage({ ...approval, offchain: true }, [], { simulationReason: "not_sent" }), "simulation"), undefined);
  const avax = evmCoverage({ ...approval, chainId: 43114, from: ME }, [], { simulationReason: "out_of_scope", history: true });
  assert.equal(not(avax, "simulation").because, "out_of_scope");
  assert.equal(avax.checks_complete, true);
});

test("x402: compared with the 402 when sent; the seller's delivery is always left to x402 Doctor", () => {
  const pay = { ...approval, kind: "eip3009", offchain: true, grants: [{ token: TOKEN, spender: SPENDER, mode: "payment" }] };
  const without = evmCoverage(pay, [], {});
  assert.equal(not(without, "x402").send, "x402");
  assert.match(not(without, "seller").why, /x402 Doctor/);
  const withReq = evmCoverage({ ...pay, x402: { payTo: SPENDER } }, [], {});
  assert.ok(checks(withReq.checked).includes("x402"));
  assert.equal(not(withReq, "seller").because, "out_of_scope");
});

test("Uniswap v4: the hook's code is out of scope; a chain that didn't answer is unavailable", () => {
  const cov = evmCoverage(approval, [{ code: "V4_HOOK", severity: "info", subject: SPENDER }, { code: "V4_CHAIN_UNAVAILABLE", severity: "info", subject: "8453" }], {});
  assert.ok(checks(cov.checked).includes("uniswap_v4"));
  assert.equal(not(cov, "hook_code").because, "out_of_scope");
  assert.equal(not(cov, "uniswap_v4").because, "unavailable");
  assert.equal(cov.checks_complete, false);
});

test("other request types: the sources that answered, and the checks that said they couldn't run", () => {
  const cov = genericCoverage({ reasons: [{ code: "XRPL_LEDGER_UNAVAILABLE", severity: "info", subject: "mainnet" }], sources: ["ofac-sdn"] });
  assert.deepEqual(checks(cov.checked), ["ofac-sdn"]);
  assert.equal(not(cov, "chain").because, "unavailable");
  assert.equal(cov.checks_complete, false);
  const done = { reasons: [], sources: [], checked: [{ check: "x", what: "y" }] };
  assert.equal(withCoverage(done).checked.length, 1, "an answer that already says what it covered is left alone");
  assert.equal(withCoverage(null), null);
});
