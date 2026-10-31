// POST /v1/injection/quick { text, source?, task? }: the free prompt-injection verdict over HTTP.
// Same answer and the same hourly limit as the free MCP tool injection_quick_check: green/orange/red only, for texts
// up to QUICK_MAX_CHARS (two parts for Jev). The reasons, probabilities and longer texts stay in the paid
// POST /v1/injection ($0.01).
import express from "express";
import { checkText, parseInjectionRequest, QUICK_MAX_CHARS } from "./injection.js";
import { FREE_CALLS_PER_HOUR } from "./mcp.js";

export function createInjectionQuickRouter({ allowFree, check = checkText }) {
  const router = express.Router();
  router.post("/v1/injection/quick", express.json({ limit: "48kb" }), async (req, res) => {
    let request;
    try {
      request = parseInjectionRequest(req.body, { maxChars: QUICK_MAX_CHARS });
    } catch (err) {
      return res.status(400).json({ error: err.message || "invalid request" });
    }
    if (!(await allowFree(req.ip, req))) {
      return res.status(429).json({ error: `Free limit reached (${FREE_CALLS_PER_HOUR} per hour). The paid check is POST /v1/injection ($0.01 via x402).` });
    }
    try {
      const r = await check(request);
      res.set("Cache-Control", "no-store").json({ verdict: r.verdict, note: "Verdict only. POST /v1/injection ($0.01) returns the reasons and probabilities, for texts up to 32,000 characters." });
    } catch (err) {
      res.status(err.status === 503 ? 503 : 502).json({ error: `could not check: ${err.message}` });
    }
  });
  return router;
}
