// How agents find and understand the paid routes: Bazaar metadata on the 402,
// the 402 challenge mirrored into the body, /openapi.json and /.well-known/x402.
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";

const EXAMPLE_TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // USDC on Base
const EXAMPLE_SPENDER = "0x000000000022D473030F116dDEE9F6B43aC78BA3"; // Permit2

export const ROUTES = {
  "/v1/check": {
    price: "0.01",
    operationId: "check",
    summary: "Pre-sign risk verdict for a transaction, approval or EIP-712 signature",
  },
  "/v1/check/explain": {
    price: "0.03",
    operationId: "checkAndExplain",
    summary: "The same verdict, plus a plain-language explanation in Dutch or English",
  },
};

const INPUT_EXAMPLE = { type: "approval", chainId: 8453, token: EXAMPLE_TOKEN, spender: EXAMPLE_SPENDER, amount: "1000000" };

const INPUT_SCHEMA = {
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
            body = { ...(body || {}), x402Version: challenge.x402Version, accepts: challenge.accepts };
            if (challenge.error) body.error = challenge.error;
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

export function openApi(origin, network) {
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
  return {
    openapi: "3.1.0",
    info: {
      title: "presign-guard",
      version: "2.1.0",
      description: "Pre-sign risk check for AI agents: a green/orange/red verdict with reason codes before signing an EVM transaction, approval or EIP-712 signature. Checks the spender or recipient and the token itself (honeypot, impersonation, high tax).",
      "x-guidance": "Call POST /v1/check with what you are about to sign, before you sign it. Only proceed on green; on orange ask your user; never sign on red. For a signature, pass the exact eth_signTypedData_v4 payload as typedData. Use /v1/check/explain when a person needs the reason in plain language (lang en or nl).",
    },
    servers: [{ url: origin }],
    paths,
  };
}

export function wellKnown(origin) {
  return {
    version: 1,
    resources: Object.keys(ROUTES).map((p) => origin + p),
    x402Version: 2,
    kind: "resource-server",
    name: "presign-guard",
    description: "Pre-sign risk verdicts (green/orange/red) for EVM transactions, approvals and signatures.",
    endpoints: Object.entries(ROUTES).map(([p, r]) => ({ url: origin + p, method: "POST", description: r.summary })),
    openapi: `${origin}/openapi.json`,
    docs: "https://github.com/Fizzl13/presign-guard",
  };
}
