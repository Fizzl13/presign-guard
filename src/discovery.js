// How agents find and understand the paid routes: Bazaar metadata on the 402,
// the 402 challenge mirrored into the body, /openapi.json and /.well-known/x402.
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";

const EXAMPLE_TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // USDC on Base
const EXAMPLE_SPENDER = "0x000000000022D473030F116dDEE9F6B43aC78BA3"; // Permit2

export const ROUTES = {
  "/v1/check": {
    price: "0.01",
    operationId: "check",
    summary: "Check if a transaction, approval or signature is safe to sign",
  },
  "/v1/check/explain": {
    price: "0.03",
    operationId: "checkAndExplain",
    summary: "Get a pre-sign verdict with a plain-language explanation",
  },
};

// GET /v1/token: a verdict on the token itself (Solana and EVM), paid on Base or Solana.
export const TOKEN_ROUTE = {
  path: "/v1/token",
  price: "0.01",
  operationId: "tokenVerdict",
  summary: "Check if a token is safe to buy, hold or accept (Solana, EVM)",
};

export const TOKEN_INPUT_EXAMPLE = { chain: "solana", address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" }; // BONK

export const TOKEN_INPUT_SCHEMA = {
  type: "object",
  properties: {
    chain: { type: "string", enum: ["solana", "base", "ethereum", "arbitrum", "optimism", "polygon", "bsc"], description: "Chain the token lives on" },
    address: { type: "string", description: "Solana mint address (base58) or EVM token contract (0x...)" },
  },
  required: ["chain", "address"],
};

// Signed verdicts (receipt.js): present when the service has a signer configured.
const RECEIPT_SCHEMA = {
  type: "object",
  description: "Signature over this whole answer (without receipt.signature), so the verdict can be verified later: EIP-191 personal_sign over canonical JSON (sorted keys, compact, ASCII-escaped). Signer addresses: /.well-known/presign-guard-signer.json; free check: POST /v1/verify.",
  properties: {
    request_id: { type: "string" },
    route: { type: "string" },
    input_sha256: { type: "string", description: "sha256 of canonical JSON {route, input}: your body (POST) or query parameters (GET)" },
    payment: {
      type: "object",
      description: "The payment behind this answer, from your x402 payment payload. EVM: payer + EIP-3009 nonce; find the settlement as AuthorizationUsed(payer, nonce) on the asset contract. Solana: payer + sha256 of the signed transaction you sent.",
      properties: {
        network: { type: "string" }, asset: { type: "string" }, amount: { type: "string" }, pay_to: { type: "string" },
        payer: { type: "string" }, nonce: { type: "string" }, transaction_sha256: { type: "string" },
        proof: { type: "string", enum: ["eip3009", "svm-transaction"] },
      },
    },
    cert: {
      type: "object",
      description: "The payout wallet's certificate for this signing key: personal_sign by authority over 'fizzl receipt signer\\nservice: <service>\\nsigner: <signer>\\nvalid_from: <date>'. Pin the payout wallet and a rotated key still verifies.",
      properties: { service: { type: "string" }, signer: { type: "string" }, valid_from: { type: "string" }, authority: { type: "string" }, signature: { type: "string" } },
    },
    signed_at: { type: "string" },
    signer: { type: "string" },
    algorithm: { type: "string", enum: ["eip191-canonical-json-v1"] },
    signature: { type: "string" },
  },
  required: ["request_id", "route", "input_sha256", "signed_at", "signer", "algorithm", "signature"],
};

const TOKEN_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    verdict: { type: "string", enum: ["green", "orange", "red"] },
    grade: { type: "string", enum: ["SAFE", "CAUTION", "RISKY", "AVOID"] },
    one_liner: { type: "string" },
    reasons: {
      type: "array",
      items: {
        type: "object",
        properties: { code: { type: "string" }, severity: { type: "string", enum: ["red", "orange", "info"] }, details: {} },
        required: ["code", "severity"],
      },
    },
    token: { type: "object" },
    market: {
      type: ["object", "null"],
      description: "DexScreener data: priceUsd, liquidityUsd, marketCapUsd, volume24hUsd, firstPairAt, ageSeconds, url",
    },
    sources: { type: "array", items: { type: "string" } },
    checkedAt: { type: "string" },
    receipt: RECEIPT_SCHEMA,
  },
  required: ["verdict", "grade", "one_liner", "reasons"],
};

const TOKEN_OUTPUT_EXAMPLE = {
  verdict: "green",
  grade: "SAFE",
  one_liner: "SAFE: no red flags, $422k liquidity, 3.1 years old",
  reasons: [{ code: "MUTABLE_METADATA", severity: "info" }],
  token: { chain: "solana", address: TOKEN_INPUT_EXAMPLE.address, name: "Bonk", symbol: "Bonk" },
  market: { priceUsd: 0.0000123, liquidityUsd: 422000, marketCapUsd: 1000000000, volume24hUsd: 350000, ageSeconds: 98000000, url: "https://dexscreener.com/solana/..." },
  sources: ["goplus", "dexscreener", "rugcheck"],
};

export const tokenBazaarExtension = () => declareDiscoveryExtension({
  method: "GET",
  input: TOKEN_INPUT_EXAMPLE,
  inputSchema: TOKEN_INPUT_SCHEMA,
  output: { schema: TOKEN_OUTPUT_SCHEMA, example: TOKEN_OUTPUT_EXAMPLE },
});

// GET /v1/approvals: the open ERC-20 allowances of a wallet, and which to revoke.
export const APPROVALS_ROUTE = {
  path: "/v1/approvals",
  price: "0.02",
  operationId: "walletApprovals",
  summary: "Find which open token approvals on a wallet to revoke",
};

export const APPROVALS_INPUT_EXAMPLE = { chain: "ethereum", address: "0x28c6c06298d514db089934071355e5743bf21d60" };

export const APPROVALS_INPUT_SCHEMA = {
  type: "object",
  properties: {
    chain: { type: "string", enum: ["base", "ethereum", "arbitrum", "optimism", "polygon", "bsc"], description: "EVM chain to audit" },
    address: { type: "string", description: "Wallet address (0x...)" },
  },
  required: ["chain", "address"],
};

const APPROVALS_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    verdict: { type: "string", enum: ["green", "orange", "red"] },
    grade: { type: "string", enum: ["SAFE", "CAUTION", "RISKY", "AVOID"] },
    one_liner: { type: "string" },
    reasons: {
      type: "array",
      items: {
        type: "object",
        properties: { code: { type: "string" }, severity: { type: "string", enum: ["red", "orange", "info"] }, details: {} },
        required: ["code", "severity"],
      },
    },
    summary: { type: "object", description: "approvals, tokens, unlimited, toRevoke" },
    approvals: {
      type: "array",
      description: "Per allowance: token, spender (address, name, trusted, contract), amount, approvedAt, severity, codes, revoke",
      items: { type: "object" },
    },
    revokeUrl: { type: "string" },
    checkedAt: { type: "string" },
    receipt: RECEIPT_SCHEMA,
  },
  required: ["verdict", "grade", "one_liner", "reasons", "approvals"],
};

const APPROVALS_OUTPUT_EXAMPLE = {
  verdict: "orange",
  grade: "CAUTION",
  one_liner: "CAUTION: 3 approvals, 1 unlimited; revoke 1",
  reasons: [
    { code: "UNLIMITED_APPROVAL", severity: "orange", details: { count: 1, spenders: ["0x1111111254eeb25477b68fb85ed929f73a960582"] } },
    { code: "STALE_APPROVAL", severity: "info", details: { count: 2, spenders: [EXAMPLE_SPENDER.toLowerCase()] } },
  ],
  summary: { approvals: 3, tokens: 2, unlimited: 1, toRevoke: 1 },
  approvals: [{
    token: { address: EXAMPLE_TOKEN.toLowerCase(), symbol: "USDC", name: "USD Coin" },
    spender: { address: "0x1111111254eeb25477b68fb85ed929f73a960582", name: "AggregationRouterV5", trusted: false, contract: true },
    amount: "unlimited", unlimited: true, approvedAt: "2025-03-01T10:00:00.000Z", severity: "orange",
    codes: [{ code: "UNLIMITED_APPROVAL", severity: "orange" }], revoke: true,
  }],
  revokeUrl: "https://revoke.cash/address/0x...?chainId=8453",
};

export const approvalsBazaarExtension = () => declareDiscoveryExtension({
  method: "GET",
  input: APPROVALS_INPUT_EXAMPLE,
  inputSchema: APPROVALS_INPUT_SCHEMA,
  output: { schema: APPROVALS_OUTPUT_SCHEMA, example: APPROVALS_OUTPUT_EXAMPLE },
});

export const INPUT_EXAMPLE = { type: "approval", chainId: 8453, token: EXAMPLE_TOKEN, spender: EXAMPLE_SPENDER, amount: "1000000" };

export const INPUT_SCHEMA = {
  type: "object",
  properties: {
    type: { type: "string", enum: ["approval", "transaction", "signature"], description: "What the agent is about to sign" },
    chainId: { type: "integer", enum: [1, 10, 56, 137, 8453, 42161] },
    token: { type: "string", description: "approval: token contract" },
    spender: { type: "string", description: "approval: who gets the allowance" },
    amount: { type: "string", description: "approval: amount in base units (0 = revoke)" },
    to: { type: "string", description: "transaction: target contract" },
    data: { type: "string", description: "transaction: 0x-prefixed calldata" },
    value: { type: "string", description: "transaction: native value in wei" },
    typedData: { type: ["object", "string"], description: "signature: the eth_signTypedData_v4 payload (Permit, Permit2, EIP-3009 x402 payment, Seaport)" },
    origin: { type: "string", description: "optional: the site asking for the signature or transaction (URL or hostname); a domain under 30 days old is orange" },
    lang: { type: "string", enum: ["en", "nl"], description: "explain only: language of the explanation (default en)" },
  },
  required: ["type", "chainId"],
};

const OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    verdict: { type: "string", enum: ["green", "orange", "red"] },
    reasons: {
      type: "array",
      items: {
        type: "object",
        properties: {
          code: { type: "string" },
          severity: { type: "string", enum: ["red", "orange", "info"] },
          subject: { type: "string" },
          details: {},
        },
        required: ["code", "severity"],
      },
    },
    subject: { type: "object" },
    explanation: { type: "object", properties: { lang: { type: "string" }, text: { type: "string" } } },
    receipt: RECEIPT_SCHEMA,
  },
  required: ["verdict", "reasons"],
};

const OUTPUT_EXAMPLE = {
  verdict: "orange",
  reasons: [{ code: "UNLIMITED_APPROVAL", severity: "orange", subject: EXAMPLE_SPENDER.toLowerCase(), details: { token: EXAMPLE_TOKEN.toLowerCase() } }],
};

export const bazaarExtension = () => declareDiscoveryExtension({
  method: "POST",
  bodyType: "json",
  input: INPUT_EXAMPLE,
  inputSchema: INPUT_SCHEMA,
  output: { schema: OUTPUT_SCHEMA, example: OUTPUT_EXAMPLE },
});

export const serviceMetadata = { serviceName: "presign-guard", tags: ["wallet-security", "pre-sign", "approvals", "agents"] };
export const tokenServiceMetadata = { serviceName: "presign-guard", tags: ["token-security", "due-diligence", "solana", "base", "agents"] };
export const approvalsServiceMetadata = { serviceName: "presign-guard", tags: ["wallet-security", "approvals", "revoke", "agents"] };

// @x402/express puts the v2 challenge only in the PAYMENT-REQUIRED header and
// sends an empty {} body; some clients read accepts[] from the body.
export function mirrorChallengeIntoBody(_req, res, next) {
  const json = res.json.bind(res);
  res.json = (body) => {
    if (res.statusCode === 402 && !(body && Array.isArray(body.accepts))) {
      const header = res.getHeader("PAYMENT-REQUIRED");
      if (header) {
        try {
          const challenge = JSON.parse(Buffer.from(String(header), "base64").toString("utf8"));
          if (Array.isArray(challenge.accepts)) {
            // the whole challenge: x402 v2 carries resource next to accepts
            body = { ...(body || {}), ...challenge };
          }
        } catch {
          // leave the body as is
        }
      }
    }
    return json(body);
  };
  next();
}

// Prepaid credit packs (src/credits.js), when they are on.
const CREDITS_GUIDANCE = " Calling often? Buy prepaid credits once (GET /v1/credits/100 for $0.80 or /v1/credits/1000 for $7.00, 1 credit = $0.01) and send the returned key in the x-credit-key header instead of paying per call; GET /v1/credits shows prices and, with the header, your balance. When the credits run out you get the normal 402.";
function creditPaths() {
  const pack = (credits, price) => ({
    get: {
      operationId: `buyCredits${credits}`,
      summary: `Buy ${credits} prepaid credits ($${price}); returns a credit key for the x-credit-key header`,
      "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: price }, protocols: ["x402"], asset: "USDC" },
      responses: { 200: { description: "credit_key, credits, expires_at" }, 402: { description: "Payment Required" } },
    },
  });
  return {
    "/v1/credits": { get: { operationId: "credits", summary: "Free: pack prices, credit cost per call, and your balance with the x-credit-key header", responses: { 200: { description: "Prices and balance" }, 404: { description: "Unknown key" } } } },
    "/v1/credits/100": pack(100, "0.80"),
    "/v1/credits/1000": pack(1000, "7.00"),
  };
}

export function openApi(origin, network, tokenNetworks = [network], { credits = false } = {}) {
  const paths = {};
  for (const [path, r] of Object.entries(ROUTES)) {
    paths[path] = {
      post: {
        operationId: r.operationId,
        summary: r.summary,
        "x-payment-info": {
          price: { mode: "fixed", currency: "USD", amount: r.price },
          protocols: ["x402"],
          networks: [network],
          asset: "USDC",
        },
        requestBody: { required: true, content: { "application/json": { schema: INPUT_SCHEMA, example: INPUT_EXAMPLE } } },
        responses: {
          200: { description: "Verdict", content: { "application/json": { schema: OUTPUT_SCHEMA, example: OUTPUT_EXAMPLE } } },
          400: { description: "Invalid request; nothing is charged" },
          402: { description: "Payment Required" },
          503: { description: "A data source is down; nothing is charged, no verdict" },
        },
      },
    };
  }
  paths[TOKEN_ROUTE.path] = {
    get: {
      operationId: TOKEN_ROUTE.operationId,
      summary: TOKEN_ROUTE.summary,
      "x-payment-info": {
        price: { mode: "fixed", currency: "USD", amount: TOKEN_ROUTE.price },
        protocols: ["x402"],
        networks: tokenNetworks,
        asset: "USDC",
      },
      parameters: Object.entries(TOKEN_INPUT_SCHEMA.properties).map(([name, schema]) => ({
        name, in: "query", required: true, schema, example: TOKEN_INPUT_EXAMPLE[name],
      })),
      responses: {
        200: { description: "Verdict", content: { "application/json": { schema: TOKEN_OUTPUT_SCHEMA, example: TOKEN_OUTPUT_EXAMPLE } } },
        400: { description: "Invalid request; nothing is charged" },
        402: { description: "Payment Required" },
        503: { description: "A data source is down; nothing is charged, no verdict" },
      },
    },
  };
  paths[APPROVALS_ROUTE.path] = {
    get: {
      operationId: APPROVALS_ROUTE.operationId,
      summary: APPROVALS_ROUTE.summary,
      "x-payment-info": {
        price: { mode: "fixed", currency: "USD", amount: APPROVALS_ROUTE.price },
        protocols: ["x402"],
        networks: tokenNetworks,
        asset: "USDC",
      },
      parameters: Object.entries(APPROVALS_INPUT_SCHEMA.properties).map(([name, schema]) => ({
        name, in: "query", required: true, schema, example: APPROVALS_INPUT_EXAMPLE[name],
      })),
      responses: {
        200: { description: "Audit", content: { "application/json": { schema: APPROVALS_OUTPUT_SCHEMA, example: APPROVALS_OUTPUT_EXAMPLE } } },
        400: { description: "Invalid request; nothing is charged" },
        402: { description: "Payment Required" },
        503: { description: "GoPlus is down; nothing is charged, no verdict" },
      },
    },
  };
  return {
    openapi: "3.1.0",
    info: {
      title: "presign-guard",
      version: "2.4.0",
      description: "Pre-sign risk check for AI agents: a green/orange/red verdict with reason codes before signing an EVM transaction, approval or EIP-712 signature. Checks the spender or recipient (including OFAC SDN sanctions), the token itself (honeypot, impersonation, high tax) and, with origin, how old the requesting site's domain is. Plus GET /v1/token: a verdict on any Solana or EVM token before buying, holding or accepting it, and GET /v1/approvals: an audit of a wallet's open token approvals with the ones to revoke. Every paid answer carries a signed receipt (EIP-191) binding the verdict to your request, verifiable later.",
      "x-guidance": "Call POST /v1/check with what you are about to sign, before you sign it. Only proceed on green; on orange ask your user; never sign on red. For a signature, pass the exact eth_signTypedData_v4 payload as typedData. Pass origin (the site asking) to catch newly registered phishing domains. Use /v1/check/explain when a person needs the reason in plain language (lang en or nl). Before buying or accepting a token, call GET /v1/token?chain=solana&address=<mint> (or chain=base with a 0x address): the same green/orange/red logic plus a grade, a one-line summary and market data. To clean up a wallet, call GET /v1/approvals?chain=base&address=<wallet>: every open token approval with who the spender is, and which ones to revoke. Keep the receipt field of each answer: it is signed by the address at /.well-known/presign-guard-signer.json and proves which verdict you got for which request; POST /v1/verify checks one for free." + (credits ? CREDITS_GUIDANCE : ""),
    },
    servers: [{ url: origin }],
    paths: credits ? { ...paths, ...creditPaths() } : paths,
  };
}

export function wellKnown(origin, { credits = false } = {}) {
  return {
    ...(credits ? { credits: { info: `${origin}/v1/credits`, packs: { 100: "$0.80", 1000: "$7.00" }, header: "x-credit-key" } } : {}),
    version: 1,
    resources: [...Object.keys(ROUTES), TOKEN_ROUTE.path, APPROVALS_ROUTE.path].map((p) => origin + p),
    x402Version: 2,
    kind: "resource-server",
    name: "presign-guard",
    description: "Pre-sign risk verdicts (green/orange/red) for EVM transactions, approvals and signatures, token verdicts for Solana and EVM tokens, and wallet approval audits. Every paid answer is signed (verifiable receipt).",
    signer: `${origin}/.well-known/presign-guard-signer.json`,
    endpoints: [
      ...Object.entries(ROUTES).map(([p, r]) => ({ url: origin + p, method: "POST", description: r.summary })),
      { url: origin + TOKEN_ROUTE.path, method: "GET", description: TOKEN_ROUTE.summary },
      { url: origin + APPROVALS_ROUTE.path, method: "GET", description: APPROVALS_ROUTE.summary },
    ],
    openapi: `${origin}/openapi.json`,
    docs: "https://github.com/Fizzl13/presign-guard",
  };
}

// Agent registration (ERC-8004 format) for the Metaplex Agent Registry on Solana:
// the document the registered agent points to. registrations gets the asset
// address once the agent is minted.
export function agentRegistration(origin) {
  return {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "presign-guard",
    description: "Pre-sign risk check for AI agents: green/orange/red verdicts for EVM transactions, approvals and Permit/Permit2/Seaport signatures, token verdicts for Solana and EVM tokens (honeypots, mint and freeze powers, permissioned tokens) and wallet approval audits. Signed answers, paid per call over x402 in USDC on Base or Solana.",
    image: `${origin}/media/og.jpg`,
    services: [
      { name: "web", endpoint: `${origin}/` },
      { name: "MCP", endpoint: `${origin}/mcp`, version: "2025-06-18" },
    ],
    active: true,
    x402Support: true,
    registrations: [{ agentId: "9NN5M9jSUv2opiU47huXeRunHvJa1DdEAtapLtrJbnG4", agentRegistry: "solana:101:metaplex" }],
    supportedTrust: [],
  };
}
