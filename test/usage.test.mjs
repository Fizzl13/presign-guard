// What the usage log keeps of each check (usage-log.cjs itself is tested in x402-doctor).
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createUsageLog, describePresignCall } from "../src/usage.js";

test("usage log: a check is logged with what was sent and the verdict", async () => {
  const written = [];
  const fetchFn = async (url, opts = {}) => {
    if ((opts.method || "GET") === "GET") return new Response("{}", { status: 404 });
    written.push(Buffer.from(JSON.parse(opts.body).content, "base64").toString("utf8"));
    return Response.json({}, { status: 201 });
  };
  const usageLog = createUsageLog({ service: "presign", env: { USAGE_LOG_TOKEN: "t" }, fetchFn, log: { warn() {}, error() {} } });
  const app = express();
  app.use(usageLog.middleware(describePresignCall));
  app.post("/v1/check", express.json(), (_req, res) => res.json({ verdict: "red", reasons: [{ code: "OFFCHAIN_SIGNATURE", severity: "info" }, { code: "SIGNATURE_GRANT_TO_EOA", severity: "red" }] }));
  const server = app.listen(0);
  const typedData = { primaryType: "Permit", domain: { verifyingContract: "0xToken" }, message: { spender: "0xSpender" } };
  await fetch(`http://127.0.0.1:${server.address().port}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "signature", chainId: 8453, typedData }) });
  await new Promise((r) => setTimeout(r, 30));
  await usageLog.flush();
  server.close();
  const event = JSON.parse(written[0].trim());
  assert.equal(event.service, "presign");
  assert.equal(event.route, "check");
  assert.deepEqual(event.input, { type: "signature", chainId: 8453, primaryType: "Permit", target: "0xToken", spender: "0xSpender" });
  assert.deepEqual(event.result, { verdict: "red", reasons: "SIGNATURE_GRANT_TO_EOA" });
  assert.equal(event.paid, false);
});

test("usage log: other routes are not logged", () => {
  assert.equal(describePresignCall({ method: "GET", path: "/health" }, {}, {}), null);
});

test("usage log: a token verdict is logged with the chain, token, verdict and grade", () => {
  const req = { method: "GET", path: "/v1/token", query: { chain: "solana", address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" }, get: () => undefined };
  const body = { verdict: "orange", grade: "CAUTION", reasons: [{ code: "NEW_TOKEN", severity: "orange" }, { code: "NO_SOCIALS", severity: "info" }] };
  assert.deepEqual(describePresignCall(req, {}, body), {
    route: "token",
    via: "api",
    input: { chain: "solana", target: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" },
    result: { verdict: "orange", grade: "CAUTION", reasons: "NEW_TOKEN", error: undefined },
  });
});
