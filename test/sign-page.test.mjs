import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { readFileSync } from "node:fs";
import { signPageRouter } from "../src/sign-page.js";

const AUTH = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const DOCTOR = "https://doctor.example/.well-known/x402-doctor-signer.json";
const page = readFileSync(new URL("../public/sign-receipt-key.html", import.meta.url), "utf8");

async function withApp(fetchImpl, fn) {
  const app = express();
  app.use(signPageRouter({
    page,
    authority: AUTH,
    self: "presign-guard",
    localSigner: async () => ({ signing: true, signers: [{ address: "0xf084", status: "current", valid_from: null }], certificate: { signer: "0xf084", valid_from: "2026-09-27", signature: "0xsig" } }),
    remotes: { "x402-doctor": DOCTOR },
    fetchImpl,
  }));
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  try { await fn(`http://127.0.0.1:${server.address().port}`); } finally { server.close(); }
}

const doctorFetch = async (url) => {
  assert.equal(url, DOCTOR);
  return new Response(JSON.stringify({ signing: true, signers: [{ address: "0xAaE6", status: "current", extra: "x" }], certificate: null, authority: AUTH }), { status: 200 });
};

test("the page defaults to presign-guard and links the other services", async () => {
  await withApp(doctorFetch, async (base) => {
    const html = await (await fetch(`${base}/sign-receipt-key`)).text();
    assert.match(html, /const SERVICE = "presign-guard"/);
    assert.match(html, /fetch\("\/sign-receipt-key\/presign-guard-signer\.json"\)/);
    assert.match(html, /href="\/\.well-known\/presign-guard-signer\.json"/);
    assert.match(html, /href="\/sign-receipt-key\?service=x402-doctor"/);
    assert.doesNotMatch(html, /\{\{/);
  });
});

test("?service=x402-doctor builds Doctor's certificate on this site", async () => {
  await withApp(doctorFetch, async (base) => {
    const html = await (await fetch(`${base}/sign-receipt-key?service=x402-doctor`)).text();
    assert.match(html, /const SERVICE = "x402-doctor"/);
    assert.match(html, /const AUTHORITY = "0x6B0F4651eD42893ab58139938175E4a69f175F25"/);
    assert.match(html, /fetch\("\/sign-receipt-key\/x402-doctor-signer\.json"\)/);
    assert.match(html, new RegExp(`href="${DOCTOR.replaceAll(".", "\\.")}"`));
    assert.match(html, /href="\/sign-receipt-key"/);
    assert.doesNotMatch(html, /\{\{/);
  });
});

test("unknown services are refused", async () => {
  await withApp(doctorFetch, async (base) => {
    assert.equal((await fetch(`${base}/sign-receipt-key?service=evil`)).status, 404);
    assert.equal((await fetch(`${base}/sign-receipt-key/evil-signer.json`)).status, 404);
  });
});

test("signer files: local and Doctor's, reduced to what the page uses", async () => {
  await withApp(doctorFetch, async (base) => {
    const own = await (await fetch(`${base}/sign-receipt-key/presign-guard-signer.json`)).json();
    assert.deepEqual(own, { service: "presign-guard", signing: true, signers: [{ address: "0xf084", status: "current" }], certificate: { signer: "0xf084", valid_from: "2026-09-27" } });
    const doc = await (await fetch(`${base}/sign-receipt-key/x402-doctor-signer.json`)).json();
    assert.deepEqual(doc, { service: "x402-doctor", signing: true, signers: [{ address: "0xAaE6", status: "current" }], certificate: null });
  });
});

test("Doctor unreachable: 502 with an error, no signer", async () => {
  await withApp(async () => new Response("down", { status: 503 }), async (base) => {
    const res = await fetch(`${base}/sign-receipt-key/x402-doctor-signer.json`);
    assert.equal(res.status, 502);
    assert.match((await res.json()).error, /HTTP 503/);
  });
});
