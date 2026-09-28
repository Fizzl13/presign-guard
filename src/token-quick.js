// GET /v1/token/quick?chain=…&address=…: the free token verdict over HTTP.
// Same answer and the same hourly limit as the free MCP tool token_quick_verdict:
// green/orange/red and the grade only. The reasons, summary and market data stay
// in the paid GET /v1/token ($0.01). Used by the live demo on fizzl.eu.
import express from "express";
import { tokenVerdict, parseTokenRequest } from "./token-verdict.js";
import { FREE_CALLS_PER_HOUR } from "./mcp.js";

export function createTokenQuickRouter({ allowFree, verdict = tokenVerdict }) {
  const router = express.Router();
  router.get("/v1/token/quick", async (req, res) => {
    let request;
    try {
      request = parseTokenRequest(req.query || {});
    } catch (err) {
      return res.status(400).json({ error: err.message || "invalid request" });
    }
    if (!allowFree(req.ip)) {
      return res.status(429).json({ error: `Free limit reached (${FREE_CALLS_PER_HOUR} per hour). The paid check is GET /v1/token ($0.01 via x402).` });
    }
    try {
      const r = await verdict(request);
      res.json({ chain: request.chain, address: request.address, verdict: r.verdict, grade: r.grade, note: "Verdict only. GET /v1/token ($0.01) returns the reasons, summary and market data." });
    } catch (err) {
      res.status(502).json({ error: `could not check: ${err.message}` });
    }
  });
  return router;
}
