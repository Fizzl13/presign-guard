// A paid MCP tool must not ask the facilitators again: initialize() empties the supported kinds
// the HTTP paywall shares, and with a facilitator down at that moment every paid route answered
// 500 until a restart (x402 Doctor, 14 Oct 2026, 04:11–04:17 UTC).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import express from "express";
import { x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createMcpRouter } from "../src/mcp.js";

const BASE = "eip155:8453";
const SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const PAY_TO_SOLANA = "ATWJ82T8nRdQwZnaysB68N5EpaSvLRsQP4h6eWmaJBH9";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

const servers = [];
const listen = (handler) => new Promise((resolve) => {
  const s = http.createServer(handler).listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${s.address().port}`));
  servers.push(s);
});
after(() => servers.forEach((s) => s.close()));

test("a paid MCP tool reuses the supported kinds from the start while a facilitator is down", async () => {
  const facilitator = { down: false, asked: 0 };
  const facilitatorUrl = await listen((req, res) => {
    facilitator.asked++;
    if (facilitator.down) { res.statusCode = 503; return res.end("down"); }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      kinds: [{ x402Version: 2, scheme: "exact", network: BASE }, { x402Version: 2, scheme: "exact", network: SOLANA, extra: { feePayer: "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4" } }],
      extensions: [],
      signers: {},
    }));
  });
  const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient({ url: facilitatorUrl }))
    .register(BASE, new ExactEvmScheme())
    .register(SOLANA, new ExactSvmScheme());
  await resourceServer.initialize(); // what the HTTP paywall does at start
  const app = express();
  app.use(createMcpRouter({ resourceServer, network: BASE, payTo: PAY_TO, solana: { network: SOLANA, payTo: PAY_TO_SOLANA } }));
  const base = await listen(app);

  facilitator.down = true;
  const asked = facilitator.asked;
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));
  const result = await client.callTool({ name: "token_verdict", arguments: { chain: "base", address: USDC } });
  await client.close();

  // The paywall's kinds are still there: an HTTP 402 can still be built for Base and Solana.
  const quote = await resourceServer.buildPaymentRequirements({ scheme: "exact", price: "$0.01", network: BASE, payTo: PAY_TO });
  assert.equal(quote[0].network, BASE);
  assert.equal(facilitator.asked, asked, "the facilitator was not asked again");
  assert.ok(result.isError, "the unpaid call answers with its price");
  const challenge = result.structuredContent || JSON.parse(result.content[0].text);
  assert.deepEqual(challenge.accepts.map((a) => a.network).sort(), [BASE, SOLANA].sort());
});

test("a paid MCP tool asks the facilitators when nothing is loaded yet", async () => {
  let asked = 0;
  const facilitatorUrl = await listen((req, res) => {
    asked++;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ kinds: [{ x402Version: 2, scheme: "exact", network: BASE }], extensions: [], signers: {} }));
  });
  const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient({ url: facilitatorUrl })).register(BASE, new ExactEvmScheme());
  const app = express();
  app.use(createMcpRouter({ resourceServer, network: BASE, payTo: PAY_TO }));
  const base = await listen(app);
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));
  const result = await client.callTool({ name: "token_verdict", arguments: { chain: "base", address: USDC } });
  await client.close();
  assert.equal(asked, 1);
  assert.deepEqual((result.structuredContent || JSON.parse(result.content[0].text)).accepts.map((a) => a.network), [BASE]);
});
