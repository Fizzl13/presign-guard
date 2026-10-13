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
  // The pre-sign checks too: they cover Solana transactions, so Solana agents pay them on Solana.
  assert.deepEqual(x402Routes(PAY_TO, "eip155:8453", SOLANA)["POST /v1/check"].accepts.map((a) => a.network), ["eip155:8453", SOLANA.network]);
  assert.equal(x402Routes(PAY_TO, "eip155:8453")["POST /v1/check"].accepts.length, 1);
});

test("openapi and well-known list all paid routes", () => {
  const spec = openApi("https://example.test", "eip155:8453", ["eip155:8453", SOLANA.network]);
  assert.deepEqual(Object.keys(spec.paths), ["/v1/check", "/v1/check/explain", "/v1/token", "/v1/approvals", "/v1/screen", "/v1/sanctions"]);
  assert.deepEqual(spec.paths["/v1/check"].post["x-payment-info"].networks, ["eip155:8453", SOLANA.network]);
  assert.deepEqual(spec.paths["/v1/token"].get["x-payment-info"].networks, ["eip155:8453", SOLANA.network]);
  assert.deepEqual(spec.paths["/v1/token"].get.parameters.map((p) => p.name), ["chain", "address"]);
  assert.deepEqual(spec.paths["/v1/approvals"].get["x-payment-info"].networks, ["eip155:8453", SOLANA.network]);
  assert.deepEqual(spec.paths["/v1/approvals"].get.parameters.map((p) => p.name), ["chain", "address"]);
  assert.deepEqual(spec.paths["/v1/screen"].get["x-payment-info"].networks, ["eip155:8453", SOLANA.network]);
  assert.deepEqual(spec.paths["/v1/screen"].get.parameters.map((p) => p.name), ["address"]);
  const resources = wellKnown("https://example.test").resources;
  assert.deepEqual(resources.map((r) => r.url),
    ["https://example.test/v1/check", "https://example.test/v1/check/explain", "https://example.test/v1/token", "https://example.test/v1/approvals", "https://example.test/v1/screen"]);
  assert.deepEqual(resources.map((r) => r.method), ["POST", "POST", "GET", "GET", "GET"]);
  // The XRPL AI Hub lists each resource by its name and description, and the service by the top-level name.
  assert.equal(new Set(resources.map((r) => r.name)).size, resources.length, "names are unique");
  for (const r of resources) {
    assert.ok(r.name.length > 0 && r.name.length <= 40, r.url);
    assert.ok(r.description.length >= 40 && r.description.length <= 200, r.url);
  }
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
  assert.deepEqual(on.paths["/v1/credits"].get.security, [], "the free price list is declared public");
  assert.equal(on.paths["/v1/credits/100"].get.security, undefined, "the packs stay paid");
  assert.equal(wellKnown("https://pg.test").credits, undefined);
  assert.equal(wellKnown("https://pg.test", { credits: true }).credits.header, "x-credit-key");
});

test("x402scan: contact e-mail, and the free routes declared public while the paid ones are not", () => {
  const spec = openApi("https://pg.test", "eip155:8453");
  assert.equal(spec.info.contact.email, "Fizzl13@protonmail.com");
  assert.match(spec["x-agentcash-provenance"].ownershipProofs[0], /^0x[0-9a-f]{130}$/, "the payout wallet's ownership proof for x402scan");
  assert.deepEqual(spec.paths["/v1/sanctions"].get.security, []);
  for (const [path, ops] of Object.entries(spec.paths)) {
    for (const op of Object.values(ops)) if (op["x-payment-info"]) assert.equal(op.security, undefined, path);
  }
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

test("openapi /v1/check: chainId required for the EVM types only, and the simulation field in the answer", async () => {
  const { default: Ajv2020 } = await import("ajv/dist/2020.js");
  const { changesFromLogs } = await import("../src/simulate.js");
  const ajv = new Ajv2020({ strict: false });
  const spec = openApi("https://example.test", "eip155:8453", ["eip155:8453", SOLANA.network]);
  for (const path of ["/v1/check", "/v1/check/explain"]) {
    const op = spec.paths[path].post;
    const input = ajv.compile(op.requestBody.content["application/json"].schema);
    assert.equal(input({ type: "approval", token: "0x1", spender: "0x2", amount: "1" }), false, `${path}: approval without chainId`);
    assert.equal(input({ type: "approval", chainId: 8453, token: "0x1", spender: "0x2", amount: "1" }), true);
    assert.equal(input({ type: "signature", typedData: {} }), false, `${path}: signature without chainId`);
    assert.equal(input({ type: "solana", transaction: "AQ==" }), true, `${path}: solana needs no chainId`);
    assert.equal(input({ type: "message", message: "hello" }), true);
    assert.equal(input({ type: "xrpl", tx: { TransactionType: "Payment" } }), true);
    assert.equal(input({ type: "solana" }), false, `${path}: solana without transaction`);
    assert.equal(input({ type: "xrpl", network: "xrpl:0" }), false, `${path}: xrpl without tx`);
    assert.equal(input({ type: "message" }), false, `${path}: message without message`);

    const schema = op.responses[200].content["application/json"].schema;
    const output = ajv.compile(schema);
    const item = schema.properties.simulation.properties.changes.items.properties;
    const T = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    const pad = (a) => "0x" + a.slice(2).padStart(64, "0");
    const evm = changesFromLogs([{ address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", topics: [T, pad("0x1111111111111111111111111111111111111111"), pad("0x2222222222222222222222222222222222222222")], data: pad("0x0f4240") }], 8453);
    const solana = [
      { type: "sol", account: "W", change: -0.000005, lamports: "-5000" },
      { type: "token", account: "A", mint: "M", change: -1.5, raw: "-1500000", decimals: 6 },
      { type: "owner", account: "A", mint: "M", from: "W", to: "X" },
      { type: "delegate", account: "A", mint: "M", delegate: "D", amount: null },
      { type: "closed", account: "A", mint: "M" },
    ];
    for (const c of [...evm, ...solana]) for (const k of Object.keys(c)) assert.ok(item[k], `${path}: simulation change field ${k} is in the schema`);
    assert.equal(output({ verdict: "green", reasons: [], simulation: { ok: true, changes: evm, gasUsed: "21000", source: "base" } }), true, JSON.stringify(output.errors));
    assert.equal(output({ verdict: "red", reasons: [], simulation: { ok: true, changes: solana, partial: true, fee: 0.000005 } }), true, JSON.stringify(output.errors));
  }
});

test("the bazaar schema in the 402 header: every field, type and enum of the full schema, short descriptions, small", async () => {
  const { bazaarExtension, BAZAAR_INPUT_SCHEMA, INPUT_SCHEMA } = await import("../src/discovery.js");
  assert.deepEqual(Object.keys(BAZAAR_INPUT_SCHEMA.properties), Object.keys(INPUT_SCHEMA.properties));
  for (const [k, v] of Object.entries(INPUT_SCHEMA.properties)) {
    const b = BAZAAR_INPUT_SCHEMA.properties[k];
    assert.deepEqual({ ...b, description: undefined }, { ...v, description: undefined }, `${k}: same type, enum and limits`);
    assert.ok(b.description.length <= 90, `${k}: short description`);
  }
  assert.deepEqual(BAZAAR_INPUT_SCHEMA.required, INPUT_SCHEMA.required);
  // The whole 402 header (base64) stays well under Node's 16 KB limit: the bazaar part was 8 KB of it.
  assert.ok(JSON.stringify(bazaarExtension()).length < 4500, `bazaar extension ${JSON.stringify(bazaarExtension()).length} characters`);
});
