// Mandate check (src/mandate.js) against the conformance vectors of the x402 `authority`
// extension draft (specs/extensions/authority-vectors.json, x402-foundation/x402#3220), plus
// EVM payments checked against a mandate signed here.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { jcs, mandateDigest, mandateProblem, eip3009Binding, permit2Binding, checkMandatePayment } from "../src/mandate.js";

const V = JSON.parse(readFileSync(new URL("./fixtures/authority-vectors.json", import.meta.url), "utf8"));
const A = V.modelA;

test("vectors: JCS bytes, digest and the issuer signature", () => {
  assert.equal(jcs(A.mandate), A.jcs);
  assert.equal(mandateDigest(A.mandate), A.digest);
  // Signature checked through the payment check: everything else fails on non-EVM ids, the signature must not.
  const r = checkMandatePayment({ mandate: A.mandate, alg: A.alg, sig: A.sig }, "pay-001", { chainId: 8453, from: "0x" + "1".repeat(40), to: "0x" + "2".repeat(40), token: "0x" + "3".repeat(40), value: 1n, nonce: "0x" }, { now: Date.parse("2026-08-19T00:00:00Z") });
  assert.ok(!r.failures.some((f) => f.code === "MANDATE_BAD_SIGNATURE"));
  const bad = checkMandatePayment({ mandate: { ...A.mandate, cap: "2000000" }, alg: A.alg, sig: A.sig }, "pay-001", { chainId: 8453, from: "0x" + "1".repeat(40), to: "0x" + "2".repeat(40), token: "0x" + "3".repeat(40), value: 1n, nonce: "0x" });
  assert.ok(bad.failures.some((f) => f.code === "MANDATE_BAD_SIGNATURE"), "a widened cap breaks the signature");
});

test("vectors: binding values for EIP-3009 and Permit2", () => {
  assert.equal(eip3009Binding(A.digest, A.binding.paymentId), A.binding.eip3009);
  assert.equal(permit2Binding(A.digest, A.binding.paymentId), A.binding.permit2);
});

test("vectors: malformed mandates are refused (shape refusals, unknown member, surrogate)", () => {
  const base = A.mandate;
  assert.match(mandateProblem({ ...base, notAfter: "2027-02-30T00:00:00Z" }), /notAfter/);
  assert.match(mandateProblem({ ...base, recipients: [] }), /non-empty/);
  assert.match(mandateProblem({ ...base, recipients: ["*", "merchant.example"] }), /sole/);
  assert.match(mandateProblem({ ...base, cap: "1.5" }), /integer/);
  assert.match(mandateProblem({ ...base, perPayment: "2000000" }), /exceeds cap/);
  assert.match(mandateProblem({ ...base, extra: "x" }), /unknown member/);
  assert.match(mandateProblem({ ...base, purpose: "bad \uD800 surrogate" }), /well-formed/);
  assert.equal(mandateProblem(base), null);
  // Total: garbage gives a refusal, never an exception.
  assert.equal(checkMandatePayment(null, "x", {}).ok, false);
  assert.equal(checkMandatePayment({ mandate: base, alg: "ES256", sig: A.sig }, "pay-001", {}).ok, false);
});

// An EVM mandate signed here: an agent may pay up to 1 USDC per payment, 5 USDC in all, to one seller.
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const AGENT = "0x1111111111111111111111111111111111111111";
const SELLER = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const issuer = publicKey.export({ format: "jwk" }).x;
const mandate = { v: "x402-mandate/1", issuer, subject: `eip155:8453:${AGENT}`, asset: `eip155:8453/erc20:${USDC}`, cap: "5000000", perPayment: "1000000", recipients: [SELLER], accountant: issuer, purpose: "API calls for the research agent", notAfter: "2030-01-01T00:00:00Z", nonce: "test-1" };
const signed = (m) => ({ mandate: m, alg: "Ed25519", sig: sign(null, Buffer.from("x402-mandate/1\n" + jcs(m)), privateKey).toString("base64url") });
const pay = (over = {}) => ({ chainId: 8453, from: AGENT, to: SELLER, token: USDC, value: 20000n, nonce: eip3009Binding(mandateDigest(mandate), "call-1"), ...over });

test("an EVM payment inside the mandate passes", () => {
  const r = checkMandatePayment(signed(mandate), "call-1", pay());
  assert.equal(r.ok, true, JSON.stringify(r.failures));
  assert.equal(r.digest, mandateDigest(mandate));
});

test("each bound is enforced from the payment about to be signed", () => {
  const codes = (p, id = "call-1", env = signed(mandate), now) => checkMandatePayment(env, id, pay(p), now ? { now } : {}).failures.map((f) => f.code);
  assert.deepEqual(codes({ value: 1000001n }), ["MANDATE_OVER_LIMIT"]);
  assert.deepEqual(codes({ to: "0x" + "9".repeat(40) }), ["MANDATE_RECIPIENT_OUT_OF_SCOPE"]);
  assert.deepEqual(codes({ from: "0x" + "8".repeat(40) }), ["MANDATE_WRONG_PAYER"]);
  assert.deepEqual(codes({ token: "0x" + "7".repeat(40) }), ["MANDATE_WRONG_ASSET"]);
  assert.deepEqual(codes({ chainId: 1 }).sort(), ["MANDATE_WRONG_ASSET", "MANDATE_WRONG_PAYER"]);
  assert.deepEqual(codes({}, "call-2"), ["MANDATE_BINDING_MISMATCH"]);
  assert.deepEqual(codes({}, "call-1", signed(mandate), Date.parse("2030-01-01T00:00:00Z")), ["MANDATE_EXPIRED"]);
});

test("'*' recipients pass with a warning", () => {
  const open = { ...mandate, recipients: ["*"] };
  const r = checkMandatePayment(signed(open), "call-1", pay({ to: "0x" + "9".repeat(40), nonce: eip3009Binding(mandateDigest(open), "call-1") }));
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings.map((w) => w.code), ["MANDATE_ANY_RECIPIENT"]);
});
