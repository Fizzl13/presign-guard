import express from "express";
import { fileURLToPath } from "node:url";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import { createCheckRouter, x402Routes } from "./src/presign-guard.js";
import { mirrorChallengeIntoBody, openApi, wellKnown } from "./src/discovery.js";

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
if (MAINNET && !(process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET)) {
  throw new Error("Mainnet needs CDP_API_KEY_ID and CDP_API_KEY_SECRET for the CDP facilitator");
}

// Testnet: public x402.org facilitator. Mainnet: Coinbase CDP facilitator.
const facilitatorClient = MAINNET
  ? new HTTPFacilitatorClient(cdpFacilitator)
  : new HTTPFacilitatorClient({ url: process.env.FACILITATOR_URL ?? "https://x402.org/facilitator" });

const resourceServer = new x402ResourceServer(facilitatorClient).register(NETWORK, new ExactEvmScheme());

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");

// Free routes first, so they never hit the paywall
app.get("/health", (_req, res) => res.json({ ok: true, network: NETWORK }));
const HOME = fileURLToPath(new URL("./public/index.html", import.meta.url));
app.get("/", (req, res, next) => (req.accepts(["json", "html"]) === "html" ? res.sendFile(HOME) : next()));
app.get("/", (_req, res) => res.json({
  service: "presign-guard",
  docs: "https://github.com/Fizzl13/presign-guard",
  paid: Object.keys(x402Routes(PAY_TO, NETWORK)),
  openapi: `${PUBLIC_URL}/openapi.json`,
}));
app.use("/media", express.static(fileURLToPath(new URL("./public/media", import.meta.url)), { maxAge: "1d" }));
app.get("/openapi.json", (_req, res) => res.json(openApi(PUBLIC_URL, NETWORK)));
app.get("/.well-known/x402", (_req, res) => res.json(wellKnown(PUBLIC_URL)));

app.use(mirrorChallengeIntoBody);
app.use(paymentMiddleware(x402Routes(PAY_TO, NETWORK), resourceServer));
app.use(createCheckRouter());

app.listen(PORT, () => console.log(`presign-guard on :${PORT} (${NETWORK}${MAINNET ? ", MAINNET" : ""})`));
