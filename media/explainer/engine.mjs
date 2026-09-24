// The check engine for the video: the same code as the live service, without
// the paywall, on localhost only. Serves the homepage and POST /v1/check so the
// recording shows real verdicts (live GoPlus data) without anyone paying.
import express from "express";
import { fileURLToPath } from "node:url";
import { createCheckRouter } from "../../src/presign-guard.js";

// Local test without network access: GoPlus answers "plain wallet" for 0x6B0F…, "verified contract" otherwise.
if (process.env.MOCK_GOPLUS === "1") {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
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
app.listen(PORT, "127.0.0.1", () => console.log(`video engine on http://127.0.0.1:${PORT}`));
