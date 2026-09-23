import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import { createCheckRouter, x402Routes } from "./src/presign-guard.js";

const PORT = Number(process.env.PORT ?? 3000);
const NETWORK = process.env.X402_NETWORK ?? "eip155:84532"; // Base Sepolia by default
const MAINNET = NETWORK === "eip155:8453";

if (!process.env.PAY_TO) throw new Error("PAY_TO is required");
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
app.get("/", (_req, res) => res.json({
  service: "presign-guard",
  docs: "https://github.com/Fizzl13/presign-guard",
  paid: Object.keys(x402Routes(process.env.PAY_TO, NETWORK)),
}));

app.use(paymentMiddleware(x402Routes(process.env.PAY_TO, NETWORK), resourceServer));
app.use(createCheckRouter());

app.listen(PORT, () => console.log(`presign-guard on :${PORT} (${NETWORK}${MAINNET ? ", MAINNET" : ""})`));
