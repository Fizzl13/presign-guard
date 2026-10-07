import express from "express";
import { securityHeaders } from "./src/security-headers.js";
import { headGuard } from "./src/head-guard.js";
import { nohumansClaim } from "./src/nohumans-claim.js";
import { fileURLToPath } from "node:url";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { onPublicHost } from "./src/public-host.js";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactXrplScheme } from "@x402/xrpl/exact/server";
import { createXrplFacilitator, XRPL_NETWORK } from "./src/xrpl-facilitator.js";
import { ExactAvmScheme } from "@x402/avm/exact/server";
import { algorandConfig, ALGORAND_NETWORK, ALGORAND_FACILITATOR } from "./src/algorand.js";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import { createCheckRouter, x402Routes } from "./src/presign-guard.js";
import { agentRegistration, mirrorChallengeIntoBody, openApi, wellKnown } from "./src/discovery.js";
import { createUsageLog, agentOf, describePresignCall } from "./src/usage.js";
import feedbackModule from "./src/feedback.cjs";
import mppPayModule from "./src/mpp-pay.cjs";
import { createMppSession, sessionStore } from "./src/mpp-session.js";
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
import { creditCosts, creditsRouter, packRoutes, payWithCredits, redisStore, withCreditsHint, CREDIT_HEADER } from "./src/credits.js";
import { trustProxyHops } from "./src/proxy.js";
import { jevStatus, jevSelfTest } from "./src/jev.js";

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
// XRP Ledger (mainnet only): the same dollar prices in RLUSD to Frits's account (it has the RLUSD trust line),
// settled in-process (src/xrpl-facilitator.js). XRPL_PAY_TO overrides the account, XRPL_PAY_TO=off turns it off.
const XRPL_PAY_TO = process.env.XRPL_PAY_TO === "off" ? null : process.env.XRPL_PAY_TO?.trim() || "r9xmBsRr8Ao7jRgjjxreMiAwGiCK2FGwqw";
const XRPL = MAINNET && XRPL_PAY_TO ? { network: XRPL_NETWORK, payTo: XRPL_PAY_TO } : null;
// Optional: USDC on Algorand (src/algorand.js), mainnet only, when ALGORAND_PAY_TO is set.
const ALGORAND = MAINNET ? algorandConfig() : null;

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
// Base, PayAI for Solana (when PAY_TO_SOLANA is set), GoPlausible for Algorand.
const cdp = new HTTPFacilitatorClient(cdpFacilitator);
const facilitators = MAINNET
  ? [
    ...(SOLANA ? [onlyNetworks(new HTTPFacilitatorClient({ url: process.env.SOLANA_FACILITATOR_URL ?? "https://facilitator.payai.network" }), (n) => n.startsWith("solana:"))] : []),
    ...(ALGORAND ? [onlyNetworks(new HTTPFacilitatorClient({ url: process.env.ALGORAND_FACILITATOR_URL || ALGORAND_FACILITATOR }), (n) => n.startsWith("algorand:"))] : []),
    cdp,
    ...(XRPL ? [createXrplFacilitator({ wsUrl: process.env.XRPL_WS_URL || "wss://xrplcluster.com" })] : []),
  ]
  : [new HTTPFacilitatorClient({ url: process.env.FACILITATOR_URL ?? "https://x402.org/facilitator" })];

const resourceServer = new x402ResourceServer(facilitators).register(NETWORK, new ExactEvmScheme());
if (SOLANA) resourceServer.register(SOLANA_NETWORK, new ExactSvmScheme());
if (XRPL) resourceServer.register(XRPL_NETWORK, new ExactXrplScheme());
if (ALGORAND) resourceServer.register(ALGORAND_NETWORK, new ExactAvmScheme());
const ROUTES = x402Routes(PAY_TO, NETWORK, SOLANA, XRPL, ALGORAND);
// Prepaid credit packs (src/credits.js): only sold when balances persist in Redis.
let creditStore = null;
if (process.env.CREDITS_REDIS_URL) {
  try { creditStore = await redisStore(process.env.CREDITS_REDIS_URL); } catch (err) { console.warn(`[credits] off: ${err.message}`); }
}
const CREDIT_COSTS = creditCosts(ROUTES);
// With packs on, every paid route's description (also in the Bazaar) mentions them.
const PAYWALL_ROUTES = creditStore ? { ...withCreditsHint(ROUTES), ...packRoutes(NETWORK, PAY_TO, SOLANA, XRPL, ALGORAND) } : ROUTES;
// MPP (src/mpp-pay.cjs): the same Base USDC payment for agents that speak MPP, settled by
// CDP like x402. Mainnet only, and only with its own MPP_SECRET. Prices come from ROUTES.
const MPP = MAINNET && process.env.MPP_SECRET
  ? mppPayModule.createMppPay({
    secret: process.env.MPP_SECRET,
    realm: new URL(PUBLIC_URL).host,
    recipient: PAY_TO,
    routes: Object.fromEntries(Object.entries(ROUTES).map(([route, r]) => [route, r.accepts.find((a) => a.network === NETWORK).price])),
    // CDP settles the Base payment (not whichever facilitator happens to be last in the list).
    facilitator: cdp,
    // MPP_TEMPO_RECIPIENT adds the tempo method (USDC.e on Tempo, push mode; MPP_TEMPO_CHAIN 42431 = testnet).
    tempo: process.env.MPP_TEMPO_RECIPIENT ? { recipient: process.env.MPP_TEMPO_RECIPIENT, chainId: Number(process.env.MPP_TEMPO_CHAIN || 4217), rpc: process.env.MPP_TEMPO_RPC || undefined } : null,
  })
  : null;
// MPP sessions (src/mpp-session.js): pay-as-you-go over a Tempo payment channel, one voucher per call, paid out to
// MPP_TEMPO_RECIPIENT. Needs the operator key (MPP_TEMPO_OPERATOR_KEY) and Redis for the channel state.
const MPP_SESSION = MPP?.tempo && process.env.MPP_TEMPO_OPERATOR_KEY && creditStore?.client
  ? createMppSession({
    operatorKey: process.env.MPP_TEMPO_OPERATOR_KEY,
    recipient: process.env.MPP_TEMPO_RECIPIENT,
    secret: process.env.MPP_SECRET,
    realm: new URL(PUBLIC_URL).host,
    publicUrl: PUBLIC_URL,
    chainId: Number(process.env.MPP_TEMPO_CHAIN || 4217),
    rpcUrl: process.env.MPP_TEMPO_RPC || undefined,
    store: sessionStore(creditStore.client),
    routes: Object.fromEntries(Object.entries(ROUTES).map(([route, r]) => [route, r.accepts.find((a) => a.network === NETWORK).price])),
  })
  : null;
if (MPP_SESSION) console.log(`[mpp-session] on: operator ${MPP_SESSION.operator}, paid out to ${MPP_SESSION.recipient}`);
// Signed verdicts (src/receipt.js); unsigned when RECEIPT_SIGNER_SECRET is not set.
const SIGNER = createSigner();

const app = express();
app.set("trust proxy", trustProxyHops());
app.disable("x-powered-by");
app.use(securityHeaders);
// Every HEAD is handled as a GET, so paid routes give their 402 instead of running for free (src/head-guard.js).
app.use(headGuard());
app.use(nohumansClaim());

// Free routes first, so they never hit the paywall
// pg1Key: whether PG1 accepts PG1_API_KEY (its license status, never the key itself).
app.get("/health", (_req, res) => res.json({ ok: true, network: NETWORK, pg1Key: pg1KeyStatusNow(), jev: jevStatus() }));
jevSelfTest().catch(() => {});
const HOME = fileURLToPath(new URL("./public/index.html", import.meta.url));
app.get("/", (req, res, next) => (res.vary("Accept"), req.accepts(["json", "html"]) === "html" ? res.sendFile(HOME) : next()));
// For search engines: the homepage is the one page to index.
app.get("/robots.txt", (_req, res) => res.type("text/plain").send(`User-agent: *\nAllow: /\n\nSitemap: ${PUBLIC_URL}/sitemap.xml\n`));
app.get("/sitemap.xml", (_req, res) => res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${PUBLIC_URL}/</loc></url></urlset>\n`));
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
// Instructions an AI agent can read and follow ("Connect to presign-guard.fizzl.eu/skill.md").
app.get("/favicon.ico", (_req, res) => res.set("cache-control", "public, max-age=86400").sendFile(fileURLToPath(new URL("./public/favicon.ico", import.meta.url))));
app.get("/skill.md", (_req, res) => res.set("cache-control", "public, max-age=300").type("text/markdown; charset=utf-8").sendFile(fileURLToPath(new URL("./public/skill.md", import.meta.url))));
app.get("/openapi.json", (_req, res) => {
  const spec = openApi(PUBLIC_URL, NETWORK, [NETWORK, ...(SOLANA ? [SOLANA_NETWORK] : []), ...(XRPL ? [XRPL_NETWORK] : []), ...(ALGORAND ? [ALGORAND_NETWORK] : [])], { credits: Boolean(creditStore) });
  // MPP discovery for MPPScan: the evm offer on the routes MPP sells (not the credit packs).
  if (MPP) mppPayModule.addMppOffers(spec, { categories: ["security", "payments", "blockchain"], docs: { homepage: PUBLIC_URL, apiReference: `${PUBLIC_URL}/openapi.json`, llms: `${PUBLIC_URL}/skill.md` }, contact: { name: "Fizzl", url: "https://fizzl.eu" }, include: (path, method) => `${method} ${path}` in ROUTES, tempo: MPP.tempo });
  res.json(spec);
});
app.get("/.well-known/x402", (_req, res) => res.json(wellKnown(PUBLIC_URL, { credits: Boolean(creditStore) })));
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
app.use(createMcpRouter({ resourceServer, network: NETWORK, payTo: PAY_TO, solana: SOLANA, xrpl: XRPL, algorand: ALGORAND, signer: SIGNER, limiter: freeLimiter, feedback }));
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
// Challenges (and so the Bazaar listing) name presign-guard.fizzl.eu, also when called on the Render address.
const paywall = unlessInternal((req) => req.fizzlInternal === true, onPublicHost(PUBLIC_URL, paymentMiddleware(PAYWALL_ROUTES, resourceServer)));
if (MPP_SESSION) app.use((req, res, next) => (req.fizzlCredits || req.fizzlInternal ? next() : MPP_SESSION.middleware(req, res, next)));
if (MPP) app.use((req, res, next) => (req.fizzlCredits || req.fizzlInternal || req.mppPaid ? next() : MPP.middleware(req, res, next)));
app.use((req, res, next) => (req.fizzlCredits || req.mppPaid ? next() : paywall(req, res, next)));
app.use(signPaidResponses(SIGNER, Object.keys(ROUTES)));
app.use(createCheckRouter());
app.use(createTokenRouter());
app.use(createApprovalsRouter());
if (creditStore) app.use(creditsRouter(express, { store: creditStore, costs: CREDIT_COSTS, publicUrl: PUBLIC_URL }));

app.listen(PORT, () => console.log(`presign-guard on :${PORT} (${NETWORK}${MAINNET ? ", MAINNET" : ""})`));
