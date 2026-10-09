// MCP server (Streamable HTTP, stateless) on POST /mcp, so MCP clients (Claude,
// Cursor, agent frameworks) and MCP directories can find and use presign-guard.
//
// Six tools:
// - presign_quick_check and token_quick_verdict (free, rate-limited together):
//   the verdict only, green/orange/red.
// - presign_check ($0.01) and presign_check_explain ($0.03), via x402: the same
//   as POST /v1/check and /v1/check/explain, paid inside the MCP call
//   (_meta["x402/payment"]) at the same price and to the same payout wallet.
// - token_verdict ($0.01, Base or Solana): the same as GET /v1/token.
// - wallet_approvals ($0.02, Base or Solana): the same as GET /v1/approvals.
//
// Invalid input is refused before payment; a failed check is not charged.

import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createPaymentWrapper } from "@x402/mcp";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { merchantExtension } from "./merchant.js";
import { parseRequest, analyze, explain } from "./presign-guard.js";
import { isXrplRequest, parseXrplRequest, analyzeXrpl, XRPL_NETWORKS } from "./xrpl.js";
import { xrplAccept } from "./xrpl-facilitator.js";
import { algorandAccept } from "./algorand.js";
import { tokenVerdict, parseTokenRequest } from "./token-verdict.js";
import { walletApprovals, parseApprovalsRequest } from "./approvals.js";
import { paymentOf } from "./receipt.js";
import {
  ROUTES, TOKEN_ROUTE, APPROVALS_ROUTE, INPUT_SCHEMA, INPUT_EXAMPLE, TOKEN_INPUT_SCHEMA, TOKEN_INPUT_EXAMPLE,
  APPROVALS_INPUT_SCHEMA, APPROVALS_INPUT_EXAMPLE, serviceMetadata, tokenServiceMetadata, approvalsServiceMetadata,
} from "./discovery.js";

export const VERSION = "1.3.0";
export const FREE_CALLS_PER_HOUR = 10;

const CHAINS = INPUT_SCHEMA.properties.chainId.enum;

// What the agent is about to sign; the same fields as the HTTP body.
const CHECK_INPUT = {
  type: z.enum(["approval", "transaction", "signature", "xrpl"]).describe("What the agent is about to sign; xrpl = an unsigned XRP Ledger transaction in tx"),
  chainId: z.number().int().optional().describe(`EVM chain id, required for approval, transaction and signature: ${CHAINS.join(", ")} (8453 = Base)`),
  network: z.enum(Object.keys(XRPL_NETWORKS)).optional().describe("xrpl: xrpl:0 (mainnet, default) or xrpl:1 (testnet)"),
  tx: z.record(z.any()).optional().describe("xrpl: the unsigned transaction JSON (TransactionType, Account, Destination, Amount, …)"),
  token: z.string().optional().describe("approval: the token contract"),
  spender: z.string().optional().describe("approval: who gets the allowance"),
  amount: z.string().optional().describe("approval: amount in base units (0 = revoke)"),
  to: z.string().optional().describe("transaction: the target contract"),
  data: z.string().optional().describe("transaction: 0x-prefixed calldata"),
  value: z.string().optional().describe("transaction: native value in wei"),
  typedData: z.union([z.record(z.any()), z.string()]).optional().describe("signature: the exact eth_signTypedData_v4 payload (Permit, Permit2, EIP-3009 x402 payment, Seaport)"),
  origin: z.string().optional().describe("optional: the site asking for the signature or transaction (URL or hostname); a domain under 30 days old is orange"),
};
const EXPLAIN_INPUT = { ...CHECK_INPUT, lang: z.enum(["en", "nl"]).optional().describe("Language of the explanation (default en)") };

const TOKEN_INPUT = {
  chain: z.enum(TOKEN_INPUT_SCHEMA.properties.chain.enum).describe("Chain the token lives on"),
  address: z.string().describe("Solana mint address (base58) or EVM token contract (0x...)"),
};

const APPROVALS_INPUT = {
  chain: z.enum(APPROVALS_INPUT_SCHEMA.properties.chain.enum).describe("EVM chain to audit"),
  address: z.string().describe("Wallet address (0x...)"),
};

const text = (value) => ({ content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] });
const toolError = (message) => ({ ...text(message), isError: true });
// A successful answer: the JSON as text (for clients that read text) and as structuredContent (matching the tool's outputSchema).
const json = (value) => (value && typeof value === "object" && !Array.isArray(value) ? { ...text(value), structuredContent: value } : text(value));

// Output schemas: the fields an agent acts on. Extra fields are allowed (passthrough), so new fields never break a call.
// MCP clients validate structuredContent even on an error result, and an unpaid call to a paid tool answers with
// x402's payment requirement as structuredContent ({ x402Version, accepts, ... }): so every field of a paid tool's
// schema is optional, and that answer passes as well.
const VERDICT = z.enum(["green", "orange", "red"]).describe("green: go ahead; orange: ask the user; red: do not sign or buy");
const REASONS = z.array(z.object({
  code: z.string().describe("Reason code, e.g. SPENDER_FLAGGED, UNLIMITED_ALLOWANCE, TOKEN_HONEYPOT"),
  severity: z.string().optional().describe("info, warn or critical"),
  subject: z.string().optional().describe("The address or item the reason is about"),
}).passthrough()).describe("Why the verdict is what it is");
const RECEIPT = z.record(z.string(), z.unknown()).describe("Signed receipt (EIP-191) binding the verdict to your arguments");
const GRADE = z.string().describe("SAFE, CAUTION, RISKY or AVOID");
const PAID = {
  version: z.string().nullable().optional(),
  verdict: VERDICT.nullable().optional().describe("green: go ahead; orange: ask the user; red: do not sign or buy (absent on the payment requirement)"),
  reasons: REASONS.nullable().optional(),
  receipt: RECEIPT.nullable().optional(),
  accepts: z.array(z.record(z.string(), z.unknown())).nullable().optional().describe("Only on an unpaid call: the x402 payment options"),
};
const obj = (shape) => z.object(shape).passthrough();
const OUTPUT = {
  presign_quick_check: obj({ verdict: VERDICT, note: z.string().optional() }),
  token_quick_verdict: obj({ verdict: VERDICT, grade: GRADE.optional(), note: z.string().optional() }),
  presign_check: obj(PAID),
  presign_check_explain: obj({
    ...PAID,
    explanation: z.object({ lang: z.string(), text: z.string() }).nullable().optional().describe("Plain-language explanation for a person"),
  }),
  token_verdict: obj({ ...PAID, grade: GRADE.nullable().optional(), one_liner: z.string().nullable().optional().describe("One-line summary") }),
  wallet_approvals: obj({
    ...PAID,
    grade: GRADE.nullable().optional(),
    one_liner: z.string().nullable().optional().describe("One-line summary"),
    approvals: z.array(z.record(z.string(), z.unknown())).nullable().optional().describe("Every open ERC-20 allowance with its spender"),
    revokeUrl: z.string().nullable().optional().describe("revoke.cash link for this wallet"),
  }),
};

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

// Same checks as the HTTP route: a 400 is refused before any payment. An XRP Ledger transaction
// (type "xrpl") has its own parser and rules (xrpl.js).
async function validate(args) {
  const { lang, ...body } = args;
  try {
    return { request: isXrplRequest(body) ? { xrpl: await parseXrplRequest(body) } : parseRequest(body) };
  } catch (err) {
    return { error: err.message || "invalid request" };
  }
}
const check = (request) => (request.xrpl ? analyzeXrpl(request.xrpl) : analyze(request));

function validateToken(args) {
  try {
    return { request: parseTokenRequest(args) };
  } catch (err) {
    return { error: err.message || "invalid request" };
  }
}

function validateApprovals(args) {
  try {
    return { request: parseApprovalsRequest(args) };
  } catch (err) {
    return { error: err.message || "invalid request" };
  }
}

// Valid example arguments per tool, in tools/list as _meta.examples (zod 3 schemas
// cannot carry JSON Schema examples): agents and checkers such as x402 Doctor
// can send a well-formed call instead of guessing.
const examplesMeta = (example) => ({ examples: [example] });

const CHECK_DISCOVERY = { inputSchema: { type: "object", properties: INPUT_SCHEMA.properties, required: INPUT_SCHEMA.required }, example: INPUT_EXAMPLE };

const PAID_TOOLS = [
  {
    name: "presign_check",
    route: "/v1/check",
    title: "Pre-sign risk check",
    input: CHECK_INPUT,
    validate,
    discovery: CHECK_DISCOVERY,
    summary: "Green/orange/red verdict with reason codes before an agent signs an EVM transaction, token approval, EIP-712 signature or XRP Ledger transaction.",
    description: (price) =>
      `Paid (${price} USDC via x402 on Base): call this before you sign. Send the transaction, token approval or EIP-712 signature (Permit, Permit2, EIP-3009 x402 payment, Seaport) your agent is about to sign; get back green, orange or red with reason codes: who gets access, whether the spender or recipient is flagged, sanctioned (OFAC SDN) or unverified, unlimited allowances, and the token itself (honeypot, fake look-alike, high tax). On the XRP Ledger (type xrpl, the unsigned tx JSON): account takeovers (SetRegularKey, SignerListSet, disabling the master key), fake RLUSD, partial payments, missing destination tags, trust-line and issuer risks, and DEX offers far below market. Only proceed on green; on orange ask your user; never sign on red. Same as POST /v1/check.`,
    run: (request) => check(request),
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
      const result = await check(request);
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
  {
    name: "wallet_approvals",
    route: APPROVALS_ROUTE.path,
    title: "Wallet approval audit",
    input: APPROVALS_INPUT,
    validate: validateApprovals,
    discovery: { inputSchema: APPROVALS_INPUT_SCHEMA, example: APPROVALS_INPUT_EXAMPLE },
    metadata: approvalsServiceMetadata,
    solana: true,
    summary: "Which open token approvals could drain this wallet? Every ERC-20 allowance with who the spender is, a verdict, and the ones to revoke.",
    description: (price) =>
      `Paid (${price} USDC via x402 on Base or Solana): audit the open token approvals of an EVM wallet (base, ethereum, arbitrum, optimism, polygon, bsc), for example your agent's own wallet as a periodic check. Get back green/orange/red, a grade, a one-line summary and every ERC-20 allowance with its spender: flagged malicious (red), a plain wallet, on a doubt list, an unverified contract or an unlimited allowance to a spender not on the GoPlus trust list (orange), plus which ones to revoke and a revoke.cash link. NFT approvals are not covered. Same as GET /v1/approvals.`,
    run: (request) => walletApprovals(request),
  },
];

const OTHER_ROUTES = { [TOKEN_ROUTE.path]: TOKEN_ROUTE, [APPROVALS_ROUTE.path]: APPROVALS_ROUTE };
const priceOf = (tool) => `$${(OTHER_ROUTES[tool.route] ?? ROUTES[tool.route]).price}`;

// accepts[] per paid tool, built once the facilitator is reachable.
function paidWrapperFactory({ resourceServer, network, payTo, solana, xrpl, algorand, tool }) {
  let wrapper = null;
  return async () => {
    if (wrapper) return wrapper;
    await resourceServer.initialize();
    const price = priceOf(tool);
    const accepts = await resourceServer.buildPaymentRequirements({ scheme: "exact", price, network, payTo });
    if (tool.solana && solana?.payTo) {
      accepts.push(...await resourceServer.buildPaymentRequirements({ scheme: "exact", price, network: solana.network, payTo: solana.payTo }));
    }
    for (const x of xrplAccept(xrpl, price, `mcp ${tool.name}`)) accepts.push(...await resourceServer.buildPaymentRequirements(x));
    for (const x of algorandAccept(algorand, price)) accepts.push(...await resourceServer.buildPaymentRequirements(x));
    wrapper = createPaymentWrapper(resourceServer, {
      accepts,
      resource: { url: `mcp://tool/${tool.name}`, description: tool.summary, mimeType: "application/json", ...(tool.metadata ?? serviceMetadata) },
      extensions: {
        ...declareDiscoveryExtension({
          toolName: tool.name,
          description: tool.summary,
          transport: "streamable-http",
          inputSchema: tool.discovery.inputSchema,
          example: tool.discovery.example,
        }),
        ...merchantExtension,
      },
    });
    return wrapper;
  };
}

function buildServer({ paidWrappers, allowFree, signer = null, feedback = null, caller = {} }) {
  const server = new McpServer({ name: "presign-guard", version: VERSION });

  server.registerTool(
    "presign_quick_check",
    {
      title: "Quick pre-sign verdict (free)",
      description:
        `Free: the green/orange/red verdict only, for a transaction, token approval, EIP-712 signature or XRP Ledger transaction (type xrpl) your agent is about to sign. Limited to ${FREE_CALLS_PER_HOUR} calls per hour. For the reason codes and details use presign_check ($0.01); for a plain-language explanation presign_check_explain ($0.03).`,
      inputSchema: CHECK_INPUT,
      outputSchema: OUTPUT.presign_quick_check,
      annotations: { readOnlyHint: true, openWorldHint: true },
      _meta: examplesMeta(INPUT_EXAMPLE),
    },
    async (args) => {
      if (!allowFree()) return toolError(`Free limit reached (${FREE_CALLS_PER_HOUR}/hour). Use presign_check ($0.01 USDC via x402) or POST https://presign-guard.fizzl.eu/v1/check.`);
      const checked = await validate(args);
      if (checked.error) return toolError(checked.error);
      try {
        const r = await check(checked.request);
        return json({ verdict: r.verdict, note: "Verdict only. presign_check ($0.01) returns the reasons and details." });
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
      outputSchema: OUTPUT.token_quick_verdict,
      annotations: { readOnlyHint: true, openWorldHint: true },
      _meta: examplesMeta(TOKEN_INPUT_EXAMPLE),
    },
    async (args) => {
      if (!allowFree()) return toolError(`Free limit reached (${FREE_CALLS_PER_HOUR}/hour). Use token_verdict ($0.01 USDC via x402) or GET https://presign-guard.fizzl.eu/v1/token.`);
      const checked = validateToken(args);
      if (checked.error) return toolError(checked.error);
      try {
        const r = await tokenVerdict(checked.request);
        return json({ verdict: r.verdict, grade: r.grade, note: "Verdict only. token_verdict ($0.01) returns the reasons, summary and market data." });
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
        description: `${tool.description(price)} The answer carries a signed receipt (EIP-191, bound to your arguments) that proves later which verdict you got.`,
        inputSchema: tool.input,
        outputSchema: OUTPUT[tool.name],
        annotations: { readOnlyHint: true, openWorldHint: true },
        _meta: examplesMeta(tool.discovery.example),
      },
      async (args, extra) => {
        const checked = await tool.validate(args); // before the payment step
        if (checked.error) return toolError(checked.error);
        let paid;
        try {
          paid = await getPaid();
        } catch (err) {
          return toolError(`payments unavailable: ${err.message}`);
        }
        return paid(async () => {
          try {
            const result = await tool.run(checked.request, args);
            // Signed like the HTTP answers (receipt.js): route "mcp <tool>", input = the tool arguments.
            const payment = paymentOf(extra && extra._meta && extra._meta["x402/payment"]);
            return json(signer && result && typeof result === "object" ? await signer.sign(result, { route: `mcp ${tool.name}`, input: args, payment }) : result);
          } catch (err) {
            return toolError(`could not check: ${err.message}`); // not charged
          }
        })(args, extra);
      }
    );
  }
  if (feedback) {
    server.registerTool(
      feedback.mcpTool.name,
      {
        title: feedback.mcpTool.title,
        description: feedback.mcpTool.description,
        inputSchema: feedback.mcpShape(z),
        ...(feedback.mcpOutputShape ? { outputSchema: feedback.mcpOutputShape(z) } : {}),
        annotations: { readOnlyHint: false, openWorldHint: false },
        // Marked as an example, so a checker that sends it is easy to spot in the log.
        _meta: examplesMeta({ type: "other", message: "Example report from the tool listing: please ignore." }),
      },
      async (args) => feedback.mcpCall(args, caller)
    );
  }
  return server;
}

// Express router for POST /mcp (stateless: a server and transport per request).
export function createMcpRouter({ resourceServer, network, payTo, solana = null, xrpl = null, algorand = null, signer = null, limiter = createRateLimiter(FREE_CALLS_PER_HOUR, 60 * 60 * 1000), feedback = null }) {
  const router = express.Router();
  const paidWrappers = Object.fromEntries(PAID_TOOLS.map((tool) => [tool.name, paidWrapperFactory({ resourceServer, network, payTo, solana, xrpl, algorand, tool })]));

  router.post("/mcp", express.json({ limit: "64kb" }), async (req, res) => {
    const server = buildServer({ paidWrappers, allowFree: () => limiter(req.ip), signer, feedback, caller: { ip: req.ip, userAgent: req.headers["user-agent"] } });
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
