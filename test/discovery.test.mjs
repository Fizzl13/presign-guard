// Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { x402Routes } from "../src/presign-guard.js";
import { agentRegistration, openApi, wellKnown } from "../src/discovery.js";

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
    // Discovery lists such as GoPlausible's name the seller from this.
    assert.equal(r.extensions["x402-merchant"].info.name, "Fizzl");
    assert.equal(r.extensions["x402-merchant"].info.logo, "https://fizzl.eu/logo-512.png");
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

test("every operation summary fits pay.sh: 63 characters or fewer, starting with a verb", () => {
  const spec = openApi("https://example.test", "eip155:8453", ["eip155:8453", SOLANA.network]);
  for (const [path, ops] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(ops)) {
      assert.ok(op.summary.length <= 63, `${method.toUpperCase()} ${path}: ${op.summary.length} chars`);
      assert.match(op.summary, /^(Check|Find|Get)\b/, `${method.toUpperCase()} ${path}: starts with a verb`);
    }
  }
});

test("wallet approvals: $0.02 on Base, plus Solana when a Solana wallet is set, with GET query metadata", () => {
  const baseOnly = x402Routes(PAY_TO, "eip155:8453")["GET /v1/approvals"];
  assert.deepEqual(baseOnly.accepts.map((a) => [a.network, a.price]), [["eip155:8453", "$0.02"]]);
  const both = x402Routes(PAY_TO, "eip155:8453", SOLANA)["GET /v1/approvals"];
  assert.deepEqual(both.accepts.map((a) => [a.network, a.payTo]), [["eip155:8453", PAY_TO], [SOLANA.network, SOLANA.payTo]]);
  assert.deepEqual(both.extensions.bazaar.info.input.queryParams, { chain: "ethereum", address: "0x28c6c06298d514db089934071355e5743bf21d60" });
});

test("signed verdicts are advertised: receipt in every paid response schema, guidance and the signer link", () => {
  const spec = openApi("https://x.test", "eip155:8453");
  const schemas = [
    spec.paths["/v1/check"].post.responses[200].content["application/json"].schema,
    spec.paths["/v1/check/explain"].post.responses[200].content["application/json"].schema,
    spec.paths["/v1/token"].get.responses[200].content["application/json"].schema,
    spec.paths["/v1/approvals"].get.responses[200].content["application/json"].schema,
  ];
  for (const s of schemas) {
    assert.equal(s.properties.receipt.properties.algorithm.enum[0], "eip191-canonical-json-v1");
    assert.ok(!s.required.includes("receipt"), "optional: unsigned when no signer is configured");
  }
  assert.match(spec.info["x-guidance"], /presign-guard-signer\.json/);
  assert.match(spec.info["x-guidance"], /POST \/v1\/verify/);
  assert.equal(wellKnown("https://x.test").signer, "https://x.test/.well-known/presign-guard-signer.json");
});

test("agent registration (ERC-8004, Metaplex Agent Registry): web and MCP on the given origin", () => {
  const a = agentRegistration("https://presign-guard.fizzl.eu");
  assert.equal(a.type, "https://eips.ethereum.org/EIPS/eip-8004#registration-v1");
  assert.deepEqual(a.services.map((x) => [x.name, x.endpoint]), [["web", "https://presign-guard.fizzl.eu/"], ["MCP", "https://presign-guard.fizzl.eu/mcp"]]);
  assert.equal(a.image, "https://presign-guard.fizzl.eu/media/og.jpg");
  assert.equal(a.active, true);
  assert.equal(a.x402Support, true);
  assert.deepEqual(a.registrations, [{ agentId: "9NN5M9jSUv2opiU47huXeRunHvJa1DdEAtapLtrJbnG4", agentRegistry: "solana:101:metaplex" }, { agentId: 97520, agentRegistry: "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432" }]);
});

test("usage log: reads of the agent registration are logged as discovery", async () => {
  const { describePresignCall } = await import("../src/usage.js");
  const d = describePresignCall({ method: "GET", path: "/.well-known/agent-registration.json", query: {}, get: () => undefined }, { statusCode: 200 }, {});
  assert.deepEqual(d, { route: "agent registration", via: "discovery", input: {}, result: { status: 200 } });
});

test("credit packs show up in OpenAPI and /.well-known/x402 only when they are on", () => {
  const off = openApi("https://pg.test", "eip155:8453");
  assert.equal(off.paths["/v1/credits/100"], undefined);
  assert.doesNotMatch(off.info["x-guidance"], /x-credit-key/);
  const on = openApi("https://pg.test", "eip155:8453", ["eip155:8453"], { credits: true });
  assert.equal(on.paths["/v1/credits/100"].get["x-payment-info"].price.amount, "0.80");
  assert.equal(on.paths["/v1/credits/1000"].get["x-payment-info"].price.amount, "7.00");
  assert.match(on.info["x-guidance"], /x-credit-key/);
  assert.equal(wellKnown("https://pg.test").credits, undefined);
  assert.equal(wellKnown("https://pg.test", { credits: true }).credits.header, "x-credit-key");
});

test("Bazaar curation metadata: serviceName, category, iconUrl and tags in /.well-known/x402 and on every paid route", () => {
  const w = wellKnown("https://presign-guard.fizzl.eu");
  assert.equal(w.serviceName, "presign-guard");
  assert.equal(w.category, "security");
  assert.equal(w.iconUrl, "https://presign-guard.fizzl.eu/media/icon.png");
  assert.ok(w.tags.includes("sanctions"));
  for (const [route, config] of Object.entries(x402Routes("0x6B0F4651eD42893ab58139938175E4a69f175F25", "eip155:8453", null))) {
    assert.equal(config.serviceName, "presign-guard", route);
    assert.equal(config.iconUrl, "https://presign-guard.fizzl.eu/media/icon.png", route);
    assert.ok(config.tags.length > 0, route);
  }
});
