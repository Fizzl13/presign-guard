// Signed verdicts (src/receipt.js): canonical JSON (same bytes as Python), signing,
// verification, tampering, the signer list and the Express middleware.
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { canonicalJson, createSigner, verifyReceipt, signPaidResponses, inputHash } from "../src/receipt.js";

const SECRET = "test-secret-that-is-long-enough-0123456789";

test("canonical JSON matches Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True)", () => {
  const v = { verdict: "red", reasons: [{ code: "SANCTIONED", detail: "Tornado Cash — OFAC ✓" }], b: 1.5, a: [1, null, true, { z: 0, y: "é" }], n: -0.001, skipped: undefined };
  assert.equal(canonicalJson(v), '{"a":[1,null,true,{"y":"\\u00e9","z":0}],"b":1.5,"n":-0.001,"reasons":[{"code":"SANCTIONED","detail":"Tornado Cash \\u2014 OFAC \\u2713"}],"verdict":"red"}');
});

test("no secret (or a short one): no signer, answers stay unsigned", () => {
  assert.equal(createSigner({}), null);
  assert.equal(createSigner({ RECEIPT_SIGNER_SECRET: "short" }), null);
});

test("the same secret gives the same signer; retired signers are published", () => {
  const a = createSigner({ RECEIPT_SIGNER_SECRET: SECRET });
  const b = createSigner({ RECEIPT_SIGNER_SECRET: SECRET, RECEIPT_RETIRED_SIGNERS: "0x000000000000000000000000000000000000dEaD:2026-01-01/2026-09-27, not-an-address" });
  assert.equal(a.address, b.address);
  assert.match(a.address, /^0x[0-9a-fA-F]{40}$/);
  assert.deepEqual(b.signers.map((s) => s.status), ["current", "retired"]);
  assert.deepEqual(b.signers[1], { address: "0x000000000000000000000000000000000000dEaD", valid_from: "2026-01-01", valid_until: "2026-09-27", status: "retired" });
});

test("a signed verdict verifies; flipping the verdict or moving it to another request breaks it", async () => {
  const signer = createSigner({ RECEIPT_SIGNER_SECRET: SECRET });
  const input = { chain: "base", address: "0xabc" };
  const signed = await signer.sign({ verdict: "green", reasons: [] }, { route: "GET /v1/token", input });
  assert.equal(signed.verdict, "green", "verdict fields untouched");
  assert.equal(signed.receipt.signer, signer.address);
  assert.equal(signed.receipt.input_sha256, inputHash("GET /v1/token", input));
  assert.match(signed.receipt.request_id, /^[0-9a-f-]{36}$/);

  const ok = await verifyReceipt(signed, { signers: signer.signers, route: "GET /v1/token", input });
  assert.deepEqual(ok, { valid: true, signer: signer.address, known_signer: true, signer_status: "current", input_matches: true });

  const flipped = await verifyReceipt({ ...signed, verdict: "red" }, { signers: signer.signers });
  assert.equal(flipped.valid, false);
  assert.match(flipped.reason, /changed/);

  const moved = await verifyReceipt({ ...signed, receipt: { ...signed.receipt, request_id: "00000000-0000-0000-0000-000000000000" } });
  assert.equal(moved.valid, false, "request id is inside the signed bytes");

  const otherInput = await verifyReceipt(signed, { signers: signer.signers, route: "GET /v1/token", input: { chain: "base", address: "0xdef" } });
  assert.equal(otherInput.valid, false);
  assert.equal(otherInput.input_matches, false);

  const stranger = createSigner({ RECEIPT_SIGNER_SECRET: `${SECRET}-other` });
  const foreign = await verifyReceipt(await stranger.sign({ verdict: "green" }, { route: "GET /v1/token", input }), { signers: signer.signers });
  assert.equal(foreign.valid, false);
  assert.match(foreign.reason, /not by a presign-guard signer/);

  assert.equal((await verifyReceipt({ verdict: "green" })).valid, false, "no receipt");
});

test("middleware: signs 200 JSON on paid routes only; errors and free routes stay unsigned", async () => {
  const signer = createSigner({ RECEIPT_SIGNER_SECRET: SECRET });
  const app = express();
  app.use(express.json());
  app.use(signPaidResponses(signer, ["POST /v1/check", "GET /v1/token"]));
  app.post("/v1/check", (req, res) => (req.body.bad ? res.status(400).json({ error: "invalid_request" }) : res.json({ verdict: "orange", reasons: ["UNLIMITED_APPROVAL"] })));
  app.get("/v1/token", (_req, res) => res.json({ verdict: "green" }));
  app.get("/health", (_req, res) => res.json({ ok: true }));
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const body = { type: "approval", chain: "base", spender: "0x1" };
    const paid = await (await fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
    assert.equal(paid.verdict, "orange");
    assert.equal((await verifyReceipt(paid, { signers: signer.signers, route: "POST /v1/check", input: body })).valid, true);

    const token = await (await fetch(`${base}/v1/token?chain=base&address=0xabc`)).json();
    assert.equal((await verifyReceipt(token, { signers: signer.signers, route: "GET /v1/token", input: { chain: "base", address: "0xabc" } })).input_matches, true, "GET input = the query strings");

    const bad = await (await fetch(`${base}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ bad: true }) })).json();
    assert.equal(bad.receipt, undefined);
    assert.equal((await (await fetch(`${base}/health`)).json()).receipt, undefined);
  } finally {
    server.close();
  }
});

test("without a signer the middleware does nothing", async () => {
  const app = express();
  app.use(signPaidResponses(null, ["GET /v1/token"]));
  app.get("/v1/token", (_req, res) => res.json({ verdict: "green" }));
  const server = app.listen(0);
  try {
    const body = await (await fetch(`http://127.0.0.1:${server.address().port}/v1/token`)).json();
    assert.deepEqual(body, { verdict: "green" });
  } finally {
    server.close();
  }
});

import { paymentOf, paymentFromHeaders, svmPayer, base58 } from "../src/receipt.js";
import { getBase58Decoder } from "@solana/kit";

test("payment: EVM EIP-3009 gives payer, nonce and amount; the receipt signs it", async () => {
  const payload = {
    x402Version: 2,
    accepted: { scheme: "exact", network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", amount: "10000", payTo: "0x6B0F4651eD42893ab58139938175E4a69f175F25" },
    payload: { signature: "0x11", authorization: { from: "0x0fD3D46E688855B24536df33BBa3dFa35b67445C", to: "0x6B0F4651eD42893ab58139938175E4a69f175F25", value: "10000", validAfter: "0", validBefore: "9", nonce: "0xabc" } },
  };
  assert.deepEqual(paymentOf(payload), { network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", amount: "10000", pay_to: "0x6B0F4651eD42893ab58139938175E4a69f175F25", payer: "0x0fD3D46E688855B24536df33BBa3dFa35b67445C", nonce: "0xabc", proof: "eip3009" });
  const header = Buffer.from(JSON.stringify(payload)).toString("base64");
  assert.equal(paymentFromHeaders({ "payment-signature": header }).nonce, "0xabc");
  assert.equal(paymentFromHeaders({ "x-payment": header }).payer, "0x0fD3D46E688855B24536df33BBa3dFa35b67445C", "v1 header name too");
  assert.equal(paymentFromHeaders({}), null);
  assert.equal(paymentFromHeaders({ "payment-signature": "not json" }), null);

  const signer = createSigner({ RECEIPT_SIGNER_SECRET: SECRET });
  const signed = await signer.sign({ verdict: "green" }, { route: "GET /v1/token", input: {}, payment: paymentOf(payload) });
  assert.equal(signed.receipt.payment.nonce, "0xabc");
  assert.equal((await verifyReceipt(signed, { signers: signer.signers })).valid, true);
  const swapped = { ...signed, receipt: { ...signed.receipt, payment: { ...signed.receipt.payment, payer: "0x0000000000000000000000000000000000000001" } } };
  assert.equal((await verifyReceipt(swapped, { signers: signer.signers })).valid, false, "the payment is inside the signed bytes");
});

test("payment: Solana gives the transfer authority (signer #2 after the fee payer) and a hash of the transaction", () => {
  const feePayer = Buffer.alloc(32, 7);
  const authority = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const other = Buffer.alloc(32, 9);
  // wire format: 2 signatures, v0 prefix, header [2 required, 0, 1], 3 account keys
  const tx = Buffer.concat([Buffer.from([2]), Buffer.alloc(128), Buffer.from([0x80, 2, 0, 1, 3]), feePayer, authority, other, Buffer.alloc(40)]);
  const expected = getBase58Decoder().decode(authority);
  assert.equal(base58(authority), expected, "base58 matches @solana/kit");
  assert.equal(svmPayer(tx.toString("base64")), expected);
  const p = paymentOf({ x402Version: 2, accepted: { scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", amount: "10000", asset: "EPjF", payTo: "ATWJ" }, payload: { transaction: tx.toString("base64") } });
  assert.equal(p.payer, expected);
  assert.equal(p.proof, "svm-transaction");
  assert.match(p.transaction_sha256, /^[0-9a-f]{64}$/);
  assert.equal(svmPayer("!!"), null, "garbage does not throw");
});
