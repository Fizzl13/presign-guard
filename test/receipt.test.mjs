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
