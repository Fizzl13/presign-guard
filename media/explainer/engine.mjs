// The check engine for the video: the same code as the live service, without
// the paywall, on localhost only. Serves the homepage and POST /v1/check so the
// recording shows real verdicts (live GoPlus data) without anyone paying.
import express from "express";
import { fileURLToPath } from "node:url";
import { createCheckRouter } from "../../src/presign-guard.js";
import { createTokenRouter, validateTokenQuery } from "../../src/token-verdict.js";

// Local test without network access: GoPlus answers "plain wallet" for 0x6B0F…, "verified contract" otherwise;
// the token video gets a safe, a risky (new, thin) and a trust-list token.
const MOCK_RISKY = "Risky11111111111111111111111111111111111111";
if (process.env.MOCK_GOPLUS === "1") {
  const realFetch = globalThis.fetch;
  const pair = (address, symbol, liq, ageDays) => ({ dexId: "raydium", url: `https://dexscreener.com/solana/${address}`, pairCreatedAt: Date.now() - ageDays * 86400e3,
    baseToken: { address, name: symbol, symbol }, priceUsd: "0.5", liquidity: { usd: liq }, marketCap: liq * 20, volume: { h24: liq / 2 }, info: { socials: [{ type: "twitter" }] } });
  const MARKETS = {
    DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263: [pair("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", "Bonk", 422000, 1400)],
    EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: [pair("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "USDC", 1.6e6, 800)],
    [MOCK_RISKY]: [pair(MOCK_RISKY, "NEWCAT", 19000, 0.1)],
  };
  const off = { status: "0" };
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.includes("dexscreener")) return Response.json(u.includes("token-profiles") ? [{ chainId: "solana", tokenAddress: MOCK_RISKY }] : MARKETS[u.split("/").pop()] ?? []);
    if (u.includes("rugcheck")) return new Response("not found", { status: 404 });
    if (u.includes("/solana/token_security")) {
      const mint = new URL(u).searchParams.get("contract_addresses");
      const usdc = mint.startsWith("EPjF");
      const sec = { mintable: usdc ? { status: "1" } : off, freezable: usdc ? { status: "1" } : off, trusted_token: usdc ? 1 : 0, metadata_mutable: off };
      return Response.json({ code: 1, message: "OK", result: { [mint]: sec } });
    }
    if (!u.includes("gopluslabs")) return realFetch(url, opts);
    const eoa = /0x6b0f4651ed42893ab58139938175e4a69f175f25/i.test(u);
    const result = u.includes("/address_security/") ? {} : { is_contract: eoa ? "0" : "1", is_open_source: "1" };
    return new Response(JSON.stringify({ code: 1, message: "OK", result }));
  };
}

const PORT = Number(process.env.ENGINE_PORT ?? 3100);
const app = express();
app.use(express.static(fileURLToPath(new URL("../../public", import.meta.url))));
app.use(createCheckRouter());
app.use(validateTokenQuery);
app.use(createTokenRouter());
app.listen(PORT, "127.0.0.1", () => console.log(`video engine on http://127.0.0.1:${PORT}`));
