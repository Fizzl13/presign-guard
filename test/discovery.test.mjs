// Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402Routes } from "../src/presign-guard.js";
import { openApi, wellKnown } from "../src/discovery.js";

const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const SOLANA = { network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", payTo: "ATWJ82T8nRdQwZnaysB68N5EpaSvLRsQP4h6eWmaJBH9" };

test("paid routes carry Bazaar metadata and the right prices", () => {
  const routes = x402Routes(PAY_TO, "eip155:8453");
  assert.equal(routes["POST /v1/check"].accepts[0].price, "$0.01");
  assert.equal(routes["POST /v1/check/explain"].accepts[0].price, "$0.03");
  for (const [key, r] of Object.entries(routes)) {
    assert.equal(r.extensions.bazaar.info.input.method, key.split(" ")[0]);
    assert.ok(r.extensions.bazaar.schema);
    assert.equal(r.serviceName, "presign-guard");
  }
});

test("token verdict: $0.01 on Base, plus Solana only when a Solana wallet is set", () => {
  const baseOnly = x402Routes(PAY_TO, "eip155:8453")["GET /v1/token"];
  assert.deepEqual(baseOnly.accepts.map((a) => [a.network, a.price]), [["eip155:8453", "$0.01"]]);
  const both = x402Routes(PAY_TO, "eip155:8453", SOLANA)["GET /v1/token"];
  assert.deepEqual(both.accepts.map((a) => [a.network, a.payTo]), [["eip155:8453", PAY_TO], [SOLANA.network, SOLANA.payTo]]);
  assert.deepEqual(both.extensions.bazaar.info.input.queryParams, { chain: "solana", address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" });
  // The pre-sign checks stay Base only.
  assert.equal(x402Routes(PAY_TO, "eip155:8453", SOLANA)["POST /v1/check"].accepts.length, 1);
});

test("openapi and well-known list all paid routes", () => {
  const spec = openApi("https://example.test", "eip155:8453", ["eip155:8453", SOLANA.network]);
  assert.deepEqual(Object.keys(spec.paths), ["/v1/check", "/v1/check/explain", "/v1/token", "/v1/approvals"]);
  assert.deepEqual(spec.paths["/v1/check"].post["x-payment-info"].networks, ["eip155:8453"]);
  assert.deepEqual(spec.paths["/v1/token"].get["x-payment-info"].networks, ["eip155:8453", SOLANA.network]);
  assert.deepEqual(spec.paths["/v1/token"].get.parameters.map((p) => p.name), ["chain", "address"]);
  assert.deepEqual(spec.paths["/v1/approvals"].get["x-payment-info"].networks, ["eip155:8453", SOLANA.network]);
  assert.deepEqual(spec.paths["/v1/approvals"].get.parameters.map((p) => p.name), ["chain", "address"]);
  assert.deepEqual(wellKnown("https://example.test").resources,
    ["https://example.test/v1/check", "https://example.test/v1/check/explain", "https://example.test/v1/token", "https://example.test/v1/approvals"]);
});

test("wallet approvals: $0.02 on Base, plus Solana when a Solana wallet is set, with GET query metadata", () => {
  const baseOnly = x402Routes(PAY_TO, "eip155:8453")["GET /v1/approvals"];
  assert.deepEqual(baseOnly.accepts.map((a) => [a.network, a.price]), [["eip155:8453", "$0.02"]]);
  const both = x402Routes(PAY_TO, "eip155:8453", SOLANA)["GET /v1/approvals"];
  assert.deepEqual(both.accepts.map((a) => [a.network, a.payTo]), [["eip155:8453", PAY_TO], [SOLANA.network, SOLANA.payTo]]);
  assert.deepEqual(both.extensions.bazaar.info.input.queryParams, { chain: "ethereum", address: "0x28c6c06298d514db089934071355e5743bf21d60" });
});
