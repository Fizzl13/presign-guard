import express from "express";
import { securityHeaders } from "./src/security-headers.js";
import { nohumansClaim } from "./src/nohumans-claim.js";
import { fileURLToPath } from "node:url";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import { createCheckRouter, x402Routes } from "./src/presign-guard.js";
import { agentRegistration, mirrorChallengeIntoBody, openApi, wellKnown } from "./src/discovery.js";
import { createUsageLog, agentOf, describePresignCall } from "./src/usage.js";
import feedbackModule from "./src/feedback.cjs";
import { createMcpRouter, createRateLimiter, FREE_CALLS_PER_HOUR } from "./src/mcp.js";
import { createTokenQuickRouter } from "./src/token-quick.js";
import { fizzlCors } from "./src/fizzl-cors.js";
import { createTokenRouter, validateTokenQuery } from "./src/token-verdict.js";
import { createApprovalsRouter, validateApprovalsQuery } from "./src/approvals.js";
import { pg1KeyStatusNow } from "./src/pg1.js";
import { x402TrustTxtRoute } from "./src/x402-trust-txt.js";
import { internalAccess, unlessInternal } from "./src/internal.js";
import { createSigner, signPaidResponses, verifyReceipt, ALGORITHM, AUTHORITY, SERVICE } from "./src/receipt.js";
import { readFileSync } from "node:fs";
import { signPageRouter } from "./src/sign-page.js";
import { creditCosts, creditsRouter, packRoutes, payWithCredits, redisStore, CREDIT_HEADER } from "./src/credits.js";
import { trustProxyHops } from "./src/proxy.js";

const PORT = Number(process.env.PORT ?? 3000);
const NETWORK = process.env.X402_NETWORK ?? "eip155:84532"; // Base Sepolia by default
const MAINNET = NETWORK === "eip155:8453";
const PUBLIC_URL = (process.env.PUBLIC_URL ?? "https://presign-guard.fizzl.eu").replace(/\/$/, "");

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
// Prepaid credit packs (src/credits.js): only sold when balances persist in Redis.
let creditStore = null;
if (process.env.CREDITS_REDIS_URL) {
  try { creditStore = await redisStore(process.env.CREDITS_REDIS_URL); } catch (err) { console.warn(`[credits] off: ${err.message}`); }
}
const CREDIT_COSTS = creditCosts(ROUTES);
const PAYWALL_ROUTES = creditStore ? { ...ROUTES, ...packRoutes(NETWORK, PAY_TO, SOLANA) } : ROUTES;
// Signed verdicts (src/receipt.js); unsigned when RECEIPT_SIGNER_SECRET is not set.
const SIGNER = createSigner();

const app = express();
app.set("trust proxy", trustProxyHops());
app.disable("x-powered-by");
app.use(securityHeaders);
app.use(nohumansClaim());

// Free routes first, so they never hit the paywall
// pg1Key: whether PG1 accepts PG1_API_KEY (its license status, never the key itself).
app.get("/health", (_req, res) => res.json({ ok: true, network: NETWORK, pg1Key: pg1KeyStatusNow() }));
const HOME = fileURLToPath(new URL("./public/index.html", import.meta.url));
app.get("/", (req, res, next) => (req.accepts(["json", "html"]) === "html" ? res.sendFile(HOME) : next()));
app.get("/", (_req, res) => res.json({
  service: "presign-guard",
  docs: "https://github.com/Fizzl13/presign-guard",
  paid: Object.keys(ROUTES),
  credits: creditStore ? { packs: `${PUBLIC_URL}/v1/credits`, header: CREDIT_HEADER, costs: CREDIT_COSTS } : null,
  mcp: `${PUBLIC_URL}/mcp`,
  feedback: `POST ${PUBLIC_URL}/feedback`,
  // Directory listings, also here: crawlers that ask for */* get this JSON, not the page.
  listings: {
    smithery: "https://smithery.ai/servers/frits-zwager/presign-guard",
    agentic_market: "https://agentic.market/services/presign-guard-fizzl-eu",
  },
  openapi: `${PUBLIC_URL}/openapi.json`,
  signer: `${PUBLIC_URL}/.well-known/presign-guard-signer.json`,
}));
app.use("/media", express.static(fileURLToPath(new URL("./public/media", import.meta.url)), { maxAge: "1d" }));
app.get("/openapi.json", (_req, res) => res.json(openApi(PUBLIC_URL, NETWORK, [NETWORK, ...(SOLANA ? [SOLANA_NETWORK] : [])])));
app.get("/.well-known/x402", (_req, res) => res.json(wellKnown(PUBLIC_URL)));
app.get("/.well-known/x402-trust.txt", x402TrustTxtRoute());

// Who signs the verdicts, and how to check one (free).
const AUTH = process.env.RECEIPT_AUTHORITY || AUTHORITY;
app.get("/.well-known/presign-guard-signer.json", async (_req, res) => res.json({
  signing: Boolean(SIGNER),
  signers: SIGNER ? SIGNER.signers : [],
  // The payout wallet authorises signing keys; clients can pin it instead of the keys.
  authority: AUTH,
  certificate: SIGNER ? await SIGNER.certificate() : null,
  certificate_format: "personal_sign by the authority over: fizzl receipt signer\\nservice: <service>\\nsigner: <address>\\nvalid_from: <YYYY-MM-DD>",
  sign_certificate: `${PUBLIC_URL}/sign-receipt-key`,
  algorithm: ALGORITHM,
  canonicalization: "js-json-stringify-sorted-utf16-ascii-v1: keys sorted by UTF-16 code units at every level, no whitespace, every code unit from U+007F up as lowercase \\uXXXX, numbers as JavaScript's JSON.stringify writes them (1.0 -> 1, 0.000001 -> 0.000001), UTF-8 bytes. Python's json.dumps matches only for ASCII keys and integers; Python equivalent: https://github.com/Fizzl13/presign-guard/blob/main/examples/canonical.py",
  input_sha256: "sha256 of the canonical JSON of {route, input}: route like 'POST /v1/check' or 'mcp presign_check'; input = the JSON body (POST), the query parameters as strings (GET) or the tool arguments (MCP)",
  verify: `${PUBLIC_URL}/v1/verify`,
}));
// Certificate signing page, also for Doctor (?service=x402-doctor): the payout
// wallet signs on this one site.
const DOCTOR_URL = (process.env.DOCTOR_URL ?? "https://x402-doctor.fizzl.eu").replace(/\/$/, "");
app.use(signPageRouter({
  page: readFileSync(fileURLToPath(new URL("./public/sign-receipt-key.html", import.meta.url)), "utf8"),
  authority: AUTH,
  self: SERVICE,
  localSigner: async () => ({ signing: Boolean(SIGNER), signers: SIGNER ? SIGNER.signers : [], certificate: SIGNER ? await SIGNER.certificate() : null }),
  remotes: { "x402-doctor": `${DOCTOR_URL}/.well-known/x402-doctor-signer.json` },
}));
app.post("/v1/verify", express.json({ limit: "256kb" }), async (req, res) => {
  const { response, route, input } = req.body || {};
  const body = response && typeof response === "object" ? response : req.body;
  res.json(await verifyReceipt(body, { signers: SIGNER ? SIGNER.signers : [], route, input, authority: AUTH }));
});

// Usage log: every check with what was sent, for the dashboard at
// x402-doctor.fizzl.eu/admin/usage. Does nothing without USAGE_LOG_TOKEN.
// req.body is filled in by the check router before the call is logged.
const usageLog = createUsageLog({ service: "presign" });
app.use(usageLog.middleware((req, res, body) => {
  const d = describePresignCall(req, res, body);
  if (d && req.fizzlInternal) return { ...d, via: "internal" };
  if (d && req.fizzlCredits) return { ...d, via: "credits", credits: req.fizzlCredits.cost };
  return d;
}));
// After the usage log, so reads of the registration are logged.
app.get("/.well-known/agent-registration.json", (_req, res) => res.json(agentRegistration(PUBLIC_URL)));

// POST /feedback (and the MCP tool feedback): agents report a bug or a missing
// feature. Free; it lands in the usage log and a person reads it (src/feedback.cjs).
const feedback = feedbackModule.createFeedback({ service: "presign", record: usageLog.record, agentOf });
app.use(feedback.router(express));

// MCP (POST /mcp): the same checks as tools, paid inside the MCP call via x402.
// One free limit per IP for the free MCP tools and GET /v1/token/quick together.
const freeLimiter = createRateLimiter(FREE_CALLS_PER_HOUR, 60 * 60 * 1000);
app.use(createMcpRouter({ resourceServer, network: NETWORK, payTo: PAY_TO, solana: SOLANA, signer: SIGNER, limiter: freeLimiter, feedback }));
// Free token verdict over HTTP, also for the live demo on fizzl.eu (CORS), before the paywall.
app.use("/v1/token/quick", fizzlCors);
app.use(createTokenQuickRouter({ allowFree: (ip) => freeLimiter(ip) }));

app.use(validateTokenQuery);
app.use(validateApprovalsQuery);
app.use(mirrorChallengeIntoBody);
// Our own services (PlainText) skip the paywall with the internal key (src/internal.js).
const isInternal = internalAccess();
app.use((req, _res, next) => { if (isInternal(req)) req.fizzlInternal = true; next(); });
// A valid credit key with enough credits pays the call instead (src/credits.js).
if (creditStore) app.use(payWithCredits({ store: creditStore, costs: CREDIT_COSTS }));
const paywall = unlessInternal((req) => req.fizzlInternal === true, paymentMiddleware(PAYWALL_ROUTES, resourceServer));
app.use((req, res, next) => (req.fizzlCredits ? next() : paywall(req, res, next)));
app.use(signPaidResponses(SIGNER, Object.keys(ROUTES)));
app.use(createCheckRouter());
app.use(createTokenRouter());
app.use(createApprovalsRouter());
if (creditStore) app.use(creditsRouter(express, { store: creditStore, costs: CREDIT_COSTS, publicUrl: PUBLIC_URL }));

app.listen(PORT, () => console.log(`presign-guard on :${PORT} (${NETWORK}${MAINNET ? ", MAINNET" : ""})`));
