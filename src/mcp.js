// MCP server (Streamable HTTP, stateless) on POST /mcp, so MCP clients (Claude,
// Cursor, agent frameworks) and MCP directories can find and use presign-guard.
//
// Three tools:
// - presign_quick_check (free, rate-limited): the verdict only, green/orange/red.
// - presign_check ($0.01) and presign_check_explain ($0.03), via x402: the same
//   as POST /v1/check and /v1/check/explain, paid inside the MCP call
//   (_meta["x402/payment"]) at the same price and to the same payout wallet.
//
// Invalid input is refused before payment; a failed check is not charged.

import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createPaymentWrapper } from "@x402/mcp";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { parseRequest, analyze, explain } from "./presign-guard.js";
import { ROUTES, INPUT_SCHEMA, INPUT_EXAMPLE, serviceMetadata } from "./discovery.js";

export const VERSION = "1.0.0";
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

const PAID_TOOLS = [
  {
    name: "presign_check",
    route: "/v1/check",
    title: "Pre-sign risk check",
    input: CHECK_INPUT,
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
    summary: "The same verdict plus a short plain-language explanation for a person, in English or Dutch.",
    description: (price) =>
      `Paid (${price} USDC via x402 on Base): the same verdict and reason codes as presign_check, plus a 3 to 5 sentence plain-language explanation a person can read before approving (lang en or nl). Same as POST /v1/check/explain.`,
    run: async (request, args) => {
      const result = await analyze(request);
      const lang = args.lang === "nl" ? "nl" : "en";
      return { ...result, explanation: { lang, text: await explain(result, lang) } };
    },
  },
];

// accepts[] per paid tool, built once the facilitator is reachable.
function paidWrapperFactory({ resourceServer, network, payTo, tool }) {
  let wrapper = null;
  return async () => {
    if (wrapper) return wrapper;
    await resourceServer.initialize();
    const accepts = await resourceServer.buildPaymentRequirements({ scheme: "exact", price: `$${ROUTES[tool.route].price}`, network, payTo });
    wrapper = createPaymentWrapper(resourceServer, {
      accepts,
      resource: { url: `mcp://tool/${tool.name}`, description: tool.summary, mimeType: "application/json", ...serviceMetadata },
      extensions: declareDiscoveryExtension({
        toolName: tool.name,
        description: tool.summary,
        transport: "streamable-http",
        inputSchema: { type: "object", properties: INPUT_SCHEMA.properties, required: INPUT_SCHEMA.required },
        example: INPUT_EXAMPLE,
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

  for (const tool of PAID_TOOLS) {
    const getPaid = paidWrappers[tool.name];
    const price = `$${ROUTES[tool.route].price}`;
    server.registerTool(
      tool.name,
      {
        title: `${tool.title} (${price} via x402)`,
        description: tool.description(price),
        inputSchema: tool.input,
        annotations: { readOnlyHint: true, openWorldHint: true },
      },
      async (args, extra) => {
        const checked = validate(args); // before the payment step
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
export function createMcpRouter({ resourceServer, network, payTo }) {
  const router = express.Router();
  const paidWrappers = Object.fromEntries(PAID_TOOLS.map((tool) => [tool.name, paidWrapperFactory({ resourceServer, network, payTo, tool })]));
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
