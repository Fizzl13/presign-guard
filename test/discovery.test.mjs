// Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402Routes } from "../src/presign-guard.js";
import { openApi, wellKnown } from "../src/discovery.js";

const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";

test("paid routes carry Bazaar metadata and the right prices", () => {
  const routes = x402Routes(PAY_TO, "eip155:8453");
  assert.equal(routes["POST /v1/check"].accepts[0].price, "$0.01");
  assert.equal(routes["POST /v1/check/explain"].accepts[0].price, "$0.03");
  for (const r of Object.values(routes)) {
    assert.equal(r.extensions.bazaar.info.input.method, "POST");
    assert.ok(r.extensions.bazaar.schema);
    assert.equal(r.serviceName, "presign-guard");
  }
});

test("openapi and well-known list both paid routes", () => {
  const spec = openApi("https://example.test", "eip155:8453");
  assert.deepEqual(Object.keys(spec.paths), ["/v1/check", "/v1/check/explain"]);
  assert.deepEqual(spec.paths["/v1/check"].post["x-payment-info"].networks, ["eip155:8453"]);
  assert.deepEqual(wellKnown("https://example.test").resources,
    ["https://example.test/v1/check", "https://example.test/v1/check/explain"]);
});
