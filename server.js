import express from "express";
import { fileURLToPath } from "node:url";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import { createCheckRouter, x402Routes } from "./src/presign-guard.js";
import { mirrorChallengeIntoBody, openApi, wellKnown } from "./src/discovery.js";
import { createUsageLog, describePresignCall } from "./src/usage.js";
import { createMcpRouter } from "./src/mcp.js";
import { createTokenRouter, validateTokenQuery } from "./src/token-verdict.js";
import { pg1KeyStatusNow } from "./src/pg1.js";

const PORT = Number(process.env.PORT ?? 3000);
const NETWORK = process.env.X402_NETWORK ?? "eip155:84532"; // Base Sepolia by default
const MAINNET = NETWORK === "eip155:8453";
const PUBLIC_URL = (process.env.PUBLIC_URL ?? "https://presign-guard.onrender.com").replace(/\/$/, "");

// Trimmed: a stray space or newline pasted into the dashboard makes every 402 unpayable.
const PAY_TO = process.env.PAY_TO?.trim();
if (!PAY_TO) throw new Error("PAY_TO is required");
if (!/^0x[0-9a-fA-F]{40}$/.test(PAY_TO)) {
  throw new Error(`PAY_TO must be an EVM address: 0x followed by 40 hex characters (got ${PAY_TO.length} characters)`);
}
// Optional: a Solana wallet for USDC payments on Solana (token verdict only).
const PAY_TO_SOLANA = process.env.PAY_TO_SOLANA?.trim() || null;
if (PAY_TO_SOLANA && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(PAY_TO_SOLANA)) {
  throw new Error("PAY_TO_SOLANA must be a Solana address (base58)");
}
const SOLANA_NETWORK = MAINNET ? "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" : "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const SOLANA = PAY_TO_SOLANA ? { network: SOLANA_NETWORK, payTo: PAY_TO_SOLANA } : null;

if (MAINNET && !(process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET)) {
  throw new Error("Mainnet needs CDP_API_KEY_ID and CDP_API_KEY_SECRET for the CDP facilitator");
}

// A facilitator client that only offers the networks `keep` accepts, so the
// next client in the list handles the rest.
function onlyNetworks(client, keep) {
  return {
    verify: (...args) => client.verify(...args),
    settle: (...args) => client.settle(...args),
    async getSupported() {
      const supported = await client.getSupported();
      return { ...supported, kinds: supported.kinds.filter((k) => keep(k.network)) };
    },
  };
}

// Testnet: public x402.org facilitator. Mainnet: Coinbase CDP facilitator for
// Base, PayAI for Solana (when PAY_TO_SOLANA is set).
const facilitators = MAINNET
  ? [
    ...(SOLANA ? [onlyNetworks(new HTTPFacilitatorClient({ url: process.env.SOLANA_FACILITATOR_URL ?? "https://facilitator.payai.network" }), (n) => n.startsWith("solana:"))] : []),
    new HTTPFacilitatorClient(cdpFacilitator),
  ]
  : [new HTTPFacilitatorClient({ url: process.env.FACILITATOR_URL ?? "https://x402.org/facilitator" })];

const resourceServer = new x402ResourceServer(facilitators).register(NETWORK, new ExactEvmScheme());
if (SOLANA) resourceServer.register(SOLANA_NETWORK, new ExactSvmScheme());
const ROUTES = x402Routes(PAY_TO, NETWORK, SOLANA);

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");

// Free routes first, so they never hit the paywall
// pg1Key: whether PG1 accepts PG1_API_KEY (its license status, never the key itself).
app.get("/health", (_req, res) => res.json({ ok: true, network: NETWORK, pg1Key: pg1KeyStatusNow() }));
const HOME = fileURLToPath(new URL("./public/index.html", import.meta.url));
app.get("/", (req, res, next) => (req.accepts(["json", "html"]) === "html" ? res.sendFile(HOME) : next()));
app.get("/", (_req, res) => res.json({
  service: "presign-guard",
  docs: "https://github.com/Fizzl13/presign-guard",
  paid: Object.keys(ROUTES),
  mcp: `${PUBLIC_URL}/mcp`,
  // Directory listings, also here: crawlers that ask for */* get this JSON, not the page.
  listings: {
    smithery: "https://smithery.ai/servers/frits-zwager/presign-guard",
    agentic_market: "https://agentic.market/services/presign-guard-onrender-com",
  },
  openapi: `${PUBLIC_URL}/openapi.json`,
}));
app.use("/media", express.static(fileURLToPath(new URL("./public/media", import.meta.url)), { maxAge: "1d" }));
app.get("/openapi.json", (_req, res) => res.json(openApi(PUBLIC_URL, NETWORK, [NETWORK, ...(SOLANA ? [SOLANA_NETWORK] : [])])));
app.get("/.well-known/x402", (_req, res) => res.json(wellKnown(PUBLIC_URL)));

// Usage log: every check with what was sent, for the dashboard at
// x402-doctor.onrender.com/admin/usage. Does nothing without USAGE_LOG_TOKEN.
// req.body is filled in by the check router before the call is logged.
app.use(createUsageLog({ service: "presign" }).middleware(describePresignCall));

// MCP (POST /mcp): the same checks as tools, paid inside the MCP call via x402.
app.use(createMcpRouter({ resourceServer, network: NETWORK, payTo: PAY_TO, solana: SOLANA }));

app.use(validateTokenQuery);
app.use(mirrorChallengeIntoBody);
app.use(paymentMiddleware(ROUTES, resourceServer));
app.use(createCheckRouter());
app.use(createTokenRouter());

app.listen(PORT, () => console.log(`presign-guard on :${PORT} (${NETWORK}${MAINNET ? ", MAINNET" : ""})`));
