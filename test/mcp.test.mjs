// MCP endpoint (/mcp) without network access: a real MCP client (and a real x402
// MCP client paying on Base) against the router, a mock facilitator that really
// verifies the EIP-3009 signature, and GoPlus/RPC mocked through globalThis.fetch.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import express from "express";
import { verifyTypedData } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { x402ResourceServer } from "@x402/express";
import { ExactEvmScheme as ServerEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { wrapMCPClientWithPayment } from "@x402/mcp";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { createMcpRouter, FREE_CALLS_PER_HOUR } from "../src/mcp.js";

const BASE = "eip155:8453";
const PAY_TO = "0x6B0F4651eD42893ab58139938175E4a69f175F25";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const EOA = "0xbad0000000000000000000000000000000000001";
const APPROVAL = { type: "approval", chainId: 8453, token: USDC, spender: PERMIT2, amount: "1000000" };

const realFetch = globalThis.fetch;
const state = { verify: 0, settle: 0, goplus: 0 };
const servers = [];
let baseUrl;

function listenJson(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(async (req, res) => {
      let body = "";
      for await (const chunk of req) body += chunk;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(await handler(req, body ? JSON.parse(body) : null)));
    }).listen(0, "127.0.0.1", () => resolve(s));
    servers.push(s);
  });
}

async function facilitator(req, body) {
  if (req.url === "/supported") return { kinds: [{ x402Version: 2, scheme: "exact", network: BASE }], extensions: [], signers: {} };
  const { paymentPayload, paymentRequirements: reqs } = body;
  const { authorization, signature } = paymentPayload.payload;
  const valid = await verifyTypedData({
    address: authorization.from,
    domain: { name: reqs.extra.name, version: reqs.extra.version, chainId: 8453, verifyingContract: reqs.asset },
    types: { TransferWithAuthorization: [
      { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
    ] },
    primaryType: "TransferWithAuthorization",
    message: authorization,
    signature,
  });
  const ok = valid && authorization.to === reqs.payTo && BigInt(authorization.value) >= BigInt(reqs.amount);
  if (req.url === "/verify") {
    state.verify++;
    return ok ? { isValid: true, payer: authorization.from } : { isValid: false, invalidReason: "invalid_signature", payer: authorization.from };
  }
  state.settle++;
  return { success: true, transaction: "0xsettled", network: BASE, payer: authorization.from };
}

// GoPlus: everything a verified contract except EOA; USDC on the trust list.
function mockGoplus(u) {
  state.goplus++;
  if (u.includes("/token_security/")) {
    const a = new URL(u).searchParams.get("contract_addresses").toLowerCase();
    const result = a === USDC.toLowerCase() ? { [a]: { token_symbol: "USDC", is_open_source: "1", is_proxy: "1", trust_list: "1", buy_tax: "0", sell_tax: "0" } } : {};
    return new Response(JSON.stringify({ code: 1, message: "OK", result }));
  }
  const result = u.includes("/address_security/") ? { phishing_activities: "0" } : { is_contract: u.includes(EOA) ? "0" : "1", is_open_source: "1", malicious_behavior: [] };
  return new Response(JSON.stringify({ code: 1, message: "OK", result }));
}

before(async () => {
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.includes("gopluslabs")) return mockGoplus(u);
    if (u.includes("api.anthropic.com")) return new Response(JSON.stringify({ content: [{ type: "text", text: "Plain explanation." }] }));
    if (/publicnode\.com|mainnet\.base\.org|arbitrum\.io/.test(u)) {
      const address = JSON.parse(opts.body).params[0].toLowerCase();
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: address === EOA ? "0x" : "0x6080604052" }));
    }
    return realFetch(url, opts);
  };
  process.env.ANTHROPIC_API_KEY = "test-key";
  const fac = await listenJson(facilitator);
  const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient({ url: `http://127.0.0.1:${fac.address().port}` })).register(BASE, new ServerEvmScheme());
  const app = express();
  app.use(createMcpRouter({ resourceServer, network: BASE, payTo: PAY_TO }));
  const s = await new Promise((resolve) => { const x = app.listen(0, "127.0.0.1", () => resolve(x)); });
  servers.push(s);
  baseUrl = `http://127.0.0.1:${s.address().port}`;
});
after(() => { servers.forEach((s) => s.close()); globalThis.fetch = realFetch; });
beforeEach(() => { state.verify = 0; state.settle = 0; state.goplus = 0; });

async function mcpClient() {
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`)));
  return client;
}

test("lists a free quick check and two paid tools with their prices", async () => {
  const client = await mcpClient();
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ["presign_check", "presign_check_explain", "presign_quick_check"]);
  assert.match(tools.find((t) => t.name === "presign_check").description, /\$0\.01/);
  assert.match(tools.find((t) => t.name === "presign_check_explain").description, /\$0\.03/);
  assert.deepEqual(tools.find((t) => t.name === "presign_check").inputSchema.required.sort(), ["chainId", "type"]);
  await client.close();
});

test("free quick check: the verdict only", async () => {
  const client = await mcpClient();
  const green = JSON.parse((await client.callTool({ name: "presign_quick_check", arguments: APPROVAL })).content[0].text);
  assert.equal(green.verdict, "green");
  assert.equal(green.reasons, undefined, "no reasons in the free tool");
  const red = JSON.parse((await client.callTool({ name: "presign_quick_check", arguments: { ...APPROVAL, spender: EOA, amount: (2n ** 256n - 1n).toString() } })).content[0].text);
  assert.equal(red.verdict, "red");
  await client.close();
});

test("paid tool without payment: a $0.01 challenge on Base with Bazaar MCP metadata, nothing checked yet", async () => {
  const client = await mcpClient();
  const result = await client.callTool({ name: "presign_check", arguments: APPROVAL });
  assert.ok(result.isError);
  const challenge = result.structuredContent || JSON.parse(result.content[0].text);
  assert.deepEqual(challenge.accepts.map((a) => [a.network, a.amount, a.payTo]), [[BASE, "10000", PAY_TO]]);
  assert.equal(challenge.extensions.bazaar.info.input.toolName, "presign_check");
  assert.equal(state.goplus, 0, "no lookups before payment");
  await client.close();
});

test("paid tool: invalid input is refused before any payment request", async () => {
  const client = await mcpClient();
  const result = await client.callTool({ name: "presign_check", arguments: { type: "approval", chainId: 8453, token: "nope", spender: PERMIT2, amount: "1" } });
  assert.ok(result.isError);
  assert.doesNotMatch(result.content[0].text, /accepts/);
  await client.close();
});

test("paid tools: a real signed Base payment returns the full verdict and settles once", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const payments = new x402Client((_v, accepts) => accepts[0]).register(BASE, new ExactEvmScheme(account));
  const client = wrapMCPClientWithPayment(new Client({ name: "paying-agent", version: "1.0.0" }), payments, { autoPayment: true });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`)));
  const result = await client.callTool("presign_check", APPROVAL);
  assert.ok(!result.isError, JSON.stringify(result.content));
  const data = JSON.parse(result.content[0].text);
  assert.equal(data.verdict, "green");
  assert.ok(Array.isArray(data.reasons));
  assert.equal(result.paymentMade, true);
  assert.deepEqual([state.verify, state.settle], [1, 1]);
  const explained = await client.callTool("presign_check_explain", { ...APPROVAL, lang: "nl" });
  const e = JSON.parse(explained.content[0].text);
  assert.deepEqual([e.verdict, e.explanation.lang, e.explanation.text], ["green", "nl", "Plain explanation."]);
  await client.close();
});

test("free quick check is rate limited", async () => {
  const client = await mcpClient();
  let last;
  for (let i = 0; i < FREE_CALLS_PER_HOUR + 1; i++) last = await client.callTool({ name: "presign_quick_check", arguments: APPROVAL });
  assert.ok(last.isError);
  assert.match(last.content[0].text, /Free limit reached/);
  await client.close();
});
