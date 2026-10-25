import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalHost } from "../src/canonical-host.js";

// What the middleware does with one request: { next: true } or the redirect it sends.
const run = (host, originalUrl, path = originalUrl.split("?")[0]) => {
  let out = null;
  const res = { redirect: (status, url) => { out = { status, url }; } };
  canonicalHost("https://presign-guard.fizzl.eu")({ headers: { host }, originalUrl, path }, res, () => { out = { next: true }; });
  return out;
};

test("canonical host: the Render address goes to presign-guard.fizzl.eu with 308, the health check and other hosts stay", () => {
  assert.deepEqual(run("presign-guard.onrender.com", "/v1/check"), { status: 308, url: "https://presign-guard.fizzl.eu/v1/check" });
  assert.deepEqual(run("Presign-Guard.onrender.com:443", "/v1/token?chain=base&address=0x83"), { status: 308, url: "https://presign-guard.fizzl.eu/v1/token?chain=base&address=0x83" });
  assert.deepEqual(run("presign-guard.onrender.com", "/health"), { next: true }, "Render's own probe");
  assert.deepEqual(run("presign-guard.fizzl.eu", "/v1/check"), { next: true });
  assert.deepEqual(run("localhost:3000", "/v1/check"), { next: true });
  assert.deepEqual(run("127.0.0.1:4021", "/"), { next: true });
});
