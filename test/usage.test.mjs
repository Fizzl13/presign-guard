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
  assert.match(event.visitor, /^[0-9a-f]{12}$/, "a short visitor code");
  assert.ok(!JSON.stringify(event).includes("127.0.0.1"), "never the IP itself");
});

test("usage log: a refused x402 payment is logged with the reason the 402 gives", async () => {
  const written = [];
  const fetchFn = async (url, opts = {}) => {
    if ((opts.method || "GET") === "GET") return new Response("{}", { status: 404 });
    written.push(Buffer.from(JSON.parse(opts.body).content, "base64").toString("utf8"));
    return Response.json({}, { status: 201 });
  };
  const usageLog = createUsageLog({ service: "presign", env: { USAGE_LOG_TOKEN: "t" }, fetchFn, log: { warn() {}, error() {} } });
  const app = express();
  app.use(usageLog.middleware(describePresignCall));
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
  app.post("/v1/check", (_req, res) => res.set("PAYMENT-REQUIRED", b64({ x402Version: 2, error: "invalid_exact_evm_payload_signature", accepts: [] })).status(402).json({}));
  const server = app.listen(0);
  await fetch(`http://127.0.0.1:${server.address().port}/v1/check`, { method: "POST", headers: { "content-type": "application/json", "payment-signature": b64({ x402Version: 2 }) }, body: "{}" });
  await new Promise((r) => setTimeout(r, 30));
  await usageLog.flush();
  server.close();
  const event = JSON.parse(written[0].trim());
  assert.deepEqual([event.status, event.payment_failed, event.reason], [402, true, "invalid_exact_evm_payload_signature"]);
});

test("visitor code: stable per IP and secret, different per secret, none without one", async () => {
  const { default: usageLog } = await import("../src/usage-log.cjs");
  const { visitorOf } = usageLog;
  assert.equal(visitorOf("203.0.113.7", "s1"), visitorOf("203.0.113.7", "s1"));
  assert.equal(visitorOf("::ffff:203.0.113.7", "s1"), visitorOf("203.0.113.7", "s1"), "IPv4-mapped IPv6 is the same visitor");
  assert.notEqual(visitorOf("203.0.113.7", "s1"), visitorOf("203.0.113.8", "s1"));
  assert.notEqual(visitorOf("203.0.113.7", "s1"), visitorOf("203.0.113.7", "s2"));
  assert.equal(visitorOf("203.0.113.7", undefined), undefined);
});

test("usage log: other routes are not logged", () => {
  assert.equal(describePresignCall({ method: "GET", path: "/health" }, {}, {}), null);
});

test("usage log: reading the MCP server card is logged as discovery", () => {
  assert.deepEqual(describePresignCall({ method: "GET", path: "/.well-known/mcp/server-card.json" }, { statusCode: 200 }, {}), { route: "mcp server card", via: "discovery", input: {}, result: { status: 200 } });
});

test("usage log: an XRP Ledger check is logged with the ledger and the kind of transaction", () => {
  const req = { method: "POST", path: "/v1/check", body: { type: "xrpl", network: "xrpl:1", tx: { TransactionType: "SetRegularKey", Account: "rAccount", RegularKey: "rOther" } }, get: () => undefined };
  const event = describePresignCall(req, {}, { verdict: "red", reasons: [{ code: "XRPL_REGULAR_KEY_CHANGE", severity: "red" }] });
  assert.equal(event.input.type, "xrpl");
  assert.equal(event.input.network, "xrpl:1");
  assert.equal(event.input.txType, "SetRegularKey");
  const json = describePresignCall({ ...req, body: { type: "xrpl", tx_json: { TransactionType: "Payment" } } }, {}, { verdict: "green", reasons: [] });
  assert.equal(json.input.txType, "Payment");
  assert.equal(json.input.network, undefined);
  const evm = describePresignCall({ ...req, body: { type: "approval", chainId: 8453, token: "0xT", spender: "0xS", network: "xrpl:0" } }, {}, { verdict: "green", reasons: [] });
  assert.equal(evm.input.network, undefined, "only an xrpl check logs a network");
});

test("usage log: an Algorand check is logged with the network and the kinds of transaction from the answer", () => {
  const req = { method: "POST", path: "/v1/check", body: { type: "algorand", transactions: ["a", "b"] }, get: () => undefined };
  const body = { verdict: "red", reasons: [{ code: "ALGORAND_REKEY", severity: "red" }], subject: { network: "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=", transactions: [{ type: "pay" }, { type: "axfer" }, { type: "pay" }] } };
  const event = describePresignCall(req, {}, body);
  assert.equal(event.input.type, "algorand");
  assert.equal(event.input.network, "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=");
  assert.equal(event.input.txType, "pay,axfer");
  assert.equal(event.input.txCount, 2);
  const refused = describePresignCall(req, {}, { error: "invalid_request", verdict: null });
  assert.equal(refused.input.network, undefined, "a refused request has no subject");
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

test("usage log: a wallet screen is logged with the address, its format and the codes that are not context", () => {
  const req = { method: "GET", path: "/v1/screen", query: { address: "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81" }, get: () => undefined };
  const body = { verdict: "red", grade: "AVOID", address: { format: "tron" }, reasons: [{ code: "SANCTIONED_ADDRESS", severity: "red" }, { code: "REPUTATION_NOT_COVERED", severity: "info" }] };
  assert.deepEqual(describePresignCall(req, {}, body), {
    route: "screen",
    via: "api",
    input: { format: "tron", target: "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81" },
    result: { verdict: "red", grade: "AVOID", reasons: "SANCTIONED_ADDRESS", error: undefined },
  });
  assert.equal(describePresignCall(req, {}, { error: "invalid_request", verdict: null }).result.verdict, "none");
});

test("usage log: an MCP answer written as a Uint8Array is read (the verdict is logged)", async () => {
  const written = [];
  const fetchFn = async (url, opts = {}) => {
    if ((opts.method || "GET") === "GET") return new Response("{}", { status: 404 });
    written.push(Buffer.from(JSON.parse(opts.body).content, "base64").toString("utf8"));
    return Response.json({}, { status: 201 });
  };
  const usageLog = createUsageLog({ service: "presign", env: { USAGE_LOG_TOKEN: "t" }, fetchFn, log: { warn() {}, error() {} } });
  const app = express();
  app.use(usageLog.middleware(describePresignCall));
  // Like the MCP transport: raw end() with a Uint8Array, no res.json.
  app.post("/mcp", express.json(), (_req, res) => {
    const reply = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify({ verdict: "green", grade: "SAFE" }) }] } };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(new TextEncoder().encode(JSON.stringify(reply)));
  });
  const server = app.listen(0);
  const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "token_quick_verdict", arguments: { chain: "base", address: "0xabc" } } };
  await fetch(`http://127.0.0.1:${server.address().port}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(call) });
  await new Promise((r) => setTimeout(r, 30));
  await usageLog.flush();
  server.close();
  const event = JSON.parse(written[0].trim());
  assert.equal(event.route, "token_quick_verdict");
  assert.deepEqual(event.result, { verdict: "green", grade: "SAFE" });
});
