// MCP server (Streamable HTTP, stateless) on POST /mcp, so MCP clients (Claude,
// Cursor, agent frameworks) and MCP directories can find and use presign-guard.
//
// Five tools:
// - presign_quick_check and token_quick_verdict (free, rate-limited together):
//   the verdict only, green/orange/red.
// - presign_check ($0.01) and presign_check_explain ($0.03), via x402: the same
//   as POST /v1/check and /v1/check/explain, paid inside the MCP call
//   (_meta["x402/payment"]) at the same price and to the same payout wallet.
// - token_verdict ($0.01, Base or Solana): the same as GET /v1/token.
//
// Invalid input is refused before payment; a failed check is not charged.

import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createPaymentWrapper } from "@x402/mcp";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { parseRequest, analyze, explain } from "./presign-guard.js";
import { tokenVerdict, parseTokenRequest } from "./token-verdict.js";
import {
  ROUTES, TOKEN_ROUTE, INPUT_SCHEMA, INPUT_EXAMPLE, TOKEN_INPUT_SCHEMA, TOKEN_INPUT_EXAMPLE,
  serviceMetadata, tokenServiceMetadata,
} from "./discovery.js";

export const VERSION = "1.1.0";
export const FREE_CALLS_PER_HOUR = 10;

const CHAINS = INPUT_SCHEMA.properties.chainId.enum;

// What the agent is about to sign; the same fields as the HTTP body.
const CHECK_INPUT = {
  type: z.enum(["approval", "transaction", "signature"]).describe("What the agent is about to sign"),
  chainId: z.number().int().describe(`EVM chain id: ${CHAINS.join(", ")} (8453 = Base)`),
  token: z.string().optional().describe("approval: the token contract"),
  spender: z.string().optional().describe("approval: who gets the allowance"),
  amount: z.string().optional().describe("approval: amount in base units (0 = revoke)"),
  to: z.string().optional().describe("transaction: the target contract"),
  data: z.string().optional().describe("transaction: 0x-prefixed calldata"),
  value: z.string().optional().describe("transaction: native value in wei"),
  typedData: z.union([z.record(z.any()), z.string()]).optional().describe("signature: the exact eth_signTypedData_v4 payload (Permit, Permit2, EIP-3009 x402 payment, Seaport)"),
};
const EXPLAIN_INPUT = { ...CHECK_INPUT, lang: z.enum(["en", "nl"]).optional().describe("Language of the explanation (default en)") };

const TOKEN_INPUT = {
  chain: z.enum(TOKEN_INPUT_SCHEMA.properties.chain.enum).describe("Chain the token lives on"),
  address: z.string().describe("Solana mint address (base58) or EVM token contract (0x...)"),
};

const text = (value) => ({ content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] });
const toolError = (message) => ({ ...text(message), isError: true });

export function createRateLimiter(limit, windowMs) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (recent.length >= limit) {
      hits.set(key, recent);
      return false;
    }
    recent.push(now);
    hits.set(key, recent);
    if (hits.size > 10000) hits.clear();
    return true;
  };
}

// Same checks as the HTTP route: a 400 is refused before any payment.
function validate(args) {
  const { lang, ...body } = args;
  try {
    return { request: parseRequest(body) };
  } catch (err) {
    return { error: err.message || "invalid request" };
  }
}

function validateToken(args) {
  try {
    return { request: parseTokenRequest(args) };
  } catch (err) {
    return { error: err.message || "invalid request" };
  }
}

const CHECK_DISCOVERY = { inputSchema: { type: "object", properties: INPUT_SCHEMA.properties, required: INPUT_SCHEMA.required }, example: INPUT_EXAMPLE };

const PAID_TOOLS = [
  {
    name: "presign_check",
    route: "/v1/check",
    title: "Pre-sign risk check",
    input: CHECK_INPUT,
    validate,
    discovery: CHECK_DISCOVERY,
    summary: "Green/orange/red verdict with reason codes before an agent signs an EVM transaction, token approval or EIP-712 signature.",
    description: (price) =>
      `Paid (${price} USDC via x402 on Base): call this before you sign. Send the transaction, token approval or EIP-712 signature (Permit, Permit2, EIP-3009 x402 payment, Seaport) your agent is about to sign; get back green, orange or red with reason codes: who gets access, whether the spender or recipient is flagged or unverified, unlimited allowances, and the token itself (honeypot, fake look-alike, high tax). Only proceed on green; on orange ask your user; never sign on red. Same as POST /v1/check.`,
    run: (request) => analyze(request),
  },
  {
    name: "presign_check_explain",
    route: "/v1/check/explain",
    title: "Pre-sign risk check with explanation",
    input: EXPLAIN_INPUT,
    validate,
    discovery: CHECK_DISCOVERY,
    summary: "The same verdict plus a short plain-language explanation for a person, in English or Dutch.",
    description: (price) =>
      `Paid (${price} USDC via x402 on Base): the same verdict and reason codes as presign_check, plus a 3 to 5 sentence plain-language explanation a person can read before approving (lang en or nl). Same as POST /v1/check/explain.`,
    run: async (request, args) => {
      const result = await analyze(request);
      const lang = args.lang === "nl" ? "nl" : "en";
      return { ...result, explanation: { lang, text: await explain(result, lang) } };
    },
  },
  {
    name: "token_verdict",
    route: TOKEN_ROUTE.path,
    title: "Token verdict",
    input: TOKEN_INPUT,
    validate: validateToken,
    discovery: { inputSchema: TOKEN_INPUT_SCHEMA, example: TOKEN_INPUT_EXAMPLE },
    metadata: tokenServiceMetadata,
    solana: true,
    summary: "Is this token safe to buy, hold or accept? Verdict, grade, reason codes, one-line summary and market data for a Solana or EVM token.",
    description: (price) =>
      `Paid (${price} USDC via x402 on Base or Solana): call this before your agent buys, holds or accepts a token. Send the chain (solana, base, ethereum, arbitrum, optimism, polygon, bsc) and the token address or mint; get back green/orange/red, a grade (SAFE, CAUTION, RISKY, AVOID), reason codes (mint or freeze authority still active, honeypot, tax or transfer fee, LP not locked, low liquidity, new token, concentrated holders, rugged), a one-line summary, and market data (price, liquidity, market cap, 24h volume, age). Same as GET /v1/token.`,
    run: (request) => tokenVerdict(request),
  },
];

const priceOf = (tool) => `$${tool.route === TOKEN_ROUTE.path ? TOKEN_ROUTE.price : ROUTES[tool.route].price}`;

// accepts[] per paid tool, built once the facilitator is reachable.
function paidWrapperFactory({ resourceServer, network, payTo, solana, tool }) {
  let wrapper = null;
  return async () => {
    if (wrapper) return wrapper;
    await resourceServer.initialize();
    const price = priceOf(tool);
    const accepts = await resourceServer.buildPaymentRequirements({ scheme: "exact", price, network, payTo });
    if (tool.solana && solana?.payTo) {
      accepts.push(...await resourceServer.buildPaymentRequirements({ scheme: "exact", price, network: solana.network, payTo: solana.payTo }));
    }
    wrapper = createPaymentWrapper(resourceServer, {
      accepts,
      resource: { url: `mcp://tool/${tool.name}`, description: tool.summary, mimeType: "application/json", ...(tool.metadata ?? serviceMetadata) },
      extensions: declareDiscoveryExtension({
        toolName: tool.name,
        description: tool.summary,
        transport: "streamable-http",
        inputSchema: tool.discovery.inputSchema,
        example: tool.discovery.example,
      }),
    });
    return wrapper;
  };
}

function buildServer({ paidWrappers, allowFree }) {
  const server = new McpServer({ name: "presign-guard", version: VERSION });

  server.registerTool(
    "presign_quick_check",
    {
      title: "Quick pre-sign verdict (free)",
      description:
        `Free: the green/orange/red verdict only, for a transaction, token approval or EIP-712 signature your agent is about to sign. Limited to ${FREE_CALLS_PER_HOUR} calls per hour. For the reason codes and details use presign_check ($0.01); for a plain-language explanation presign_check_explain ($0.03).`,
      inputSchema: CHECK_INPUT,
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async (args) => {
      if (!allowFree()) return toolError(`Free limit reached (${FREE_CALLS_PER_HOUR}/hour). Use presign_check ($0.01 USDC via x402) or POST https://presign-guard.onrender.com/v1/check.`);
      const checked = validate(args);
      if (checked.error) return toolError(checked.error);
      try {
        const r = await analyze(checked.request);
        return text({ verdict: r.verdict, note: "Verdict only. presign_check ($0.01) returns the reasons and details." });
      } catch (err) {
        return toolError(`could not check: ${err.message}`);
      }
    }
  );

  server.registerTool(
    "token_quick_verdict",
    {
      title: "Quick token verdict (free)",
      description:
        `Free: the green/orange/red verdict and grade only, for a Solana or EVM token your agent is about to buy, hold or accept. Limited to ${FREE_CALLS_PER_HOUR} free calls per hour (shared with presign_quick_check). For the reasons, one-line summary and market data use token_verdict ($0.01).`,
      inputSchema: TOKEN_INPUT,
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async (args) => {
      if (!allowFree()) return toolError(`Free limit reached (${FREE_CALLS_PER_HOUR}/hour). Use token_verdict ($0.01 USDC via x402) or GET https://presign-guard.onrender.com/v1/token.`);
      const checked = validateToken(args);
      if (checked.error) return toolError(checked.error);
      try {
        const r = await tokenVerdict(checked.request);
        return text({ verdict: r.verdict, grade: r.grade, note: "Verdict only. token_verdict ($0.01) returns the reasons, summary and market data." });
      } catch (err) {
        return toolError(`could not check: ${err.message}`);
      }
    }
  );

  for (const tool of PAID_TOOLS) {
    const getPaid = paidWrappers[tool.name];
    const price = priceOf(tool);
    server.registerTool(
      tool.name,
      {
        title: `${tool.title} (${price} via x402)`,
        description: tool.description(price),
        inputSchema: tool.input,
        annotations: { readOnlyHint: true, openWorldHint: true },
      },
      async (args, extra) => {
        const checked = tool.validate(args); // before the payment step
        if (checked.error) return toolError(checked.error);
        let paid;
        try {
          paid = await getPaid();
        } catch (err) {
          return toolError(`payments unavailable: ${err.message}`);
        }
        return paid(async () => {
          try {
            return text(await tool.run(checked.request, args));
          } catch (err) {
            return toolError(`could not check: ${err.message}`); // not charged
          }
        })(args, extra);
      }
    );
  }
  return server;
}

// Express router for POST /mcp (stateless: a server and transport per request).
export function createMcpRouter({ resourceServer, network, payTo, solana = null }) {
  const router = express.Router();
  const paidWrappers = Object.fromEntries(PAID_TOOLS.map((tool) => [tool.name, paidWrapperFactory({ resourceServer, network, payTo, solana, tool })]));
  const limiter = createRateLimiter(FREE_CALLS_PER_HOUR, 60 * 60 * 1000);

  router.post("/mcp", express.json({ limit: "64kb" }), async (req, res) => {
    const server = buildServer({ paidWrappers, allowFree: () => limiter(req.ip) });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("[mcp] error:", err);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "internal error" }, id: null });
    }
  });
  router.all("/mcp", (_req, res) => {
    res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed; POST JSON-RPC to /mcp" }, id: null });
  });
  return router;
}
