// Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { x402TrustTxt, x402TrustTxtRoute } from "../src/x402-trust-txt.js";

const LINE = `x402-trust-verification=v1:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${"a".repeat(86)}`;

test("only a well-formed verification line is served", () => {
  assert.equal(x402TrustTxt(` ${LINE}\n`), `${LINE}\n`);
  assert.equal(x402TrustTxt(undefined), null);
  assert.equal(x402TrustTxt("x402-trust-remove"), null, "never a removal line from a setting");
  assert.equal(x402TrustTxt(`${LINE}\nx402-trust-remove`), null);
  assert.equal(x402TrustTxt("x402-trust-verification=v1:<script>"), null);
});

test("GET /.well-known/x402-trust.txt: the line when set, 404 otherwise", async (t) => {
  const listen = (env) => new Promise((resolve) => {
    const app = express().get("/.well-known/x402-trust.txt", x402TrustTxtRoute(env));
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
  const set = await listen({ X402_TRUST_TXT: LINE });
  const unset = await listen({});
  t.after(() => { set.close(); unset.close(); });
  const a = await fetch(`http://127.0.0.1:${set.address().port}/.well-known/x402-trust.txt`);
  assert.equal(a.status, 200);
  assert.equal(await a.text(), `${LINE}\n`);
  assert.equal((await fetch(`http://127.0.0.1:${unset.address().port}/.well-known/x402-trust.txt`)).status, 404);
});
