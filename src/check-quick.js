// POST /v1/check/quick { …same body as POST /v1/check }: the free pre-sign verdict over HTTP.
// Same answer and the same hourly limit as the free MCP tool presign_quick_check: green/orange/red only.
// The reasons and details stay in the paid POST /v1/check ($0.01). Used by the "Watch an agent pay" demo on
// fizzl.eu, which checks the payment authorization an agent would sign for a real seller's 402.
import express from "express";
import { FREE_CALLS_PER_HOUR, validateCheckArgs, runCheck } from "./mcp.js";

export function createCheckQuickRouter({ allowFree, validate = validateCheckArgs, check = runCheck }) {
  const router = express.Router();
  router.post("/v1/check/quick", express.json({ limit: "64kb" }), async (req, res) => {
    const checked = await validate(req.body && typeof req.body === "object" ? req.body : {});
    if (checked.error) return res.status(400).json({ error: checked.error });
    if (!(await allowFree(req.ip, req))) {
      return res.status(429).json({ error: `Free limit reached (${FREE_CALLS_PER_HOUR} per hour). The paid check is POST /v1/check ($0.01 via x402).` });
    }
    try {
      const r = await check(checked.request);
      res.set("Cache-Control", "no-store").json({ verdict: r.verdict, note: "Verdict only. POST /v1/check ($0.01) returns the reasons and details." });
    } catch (err) {
      res.status(502).json({ error: `could not check: ${err.message}` });
    }
  });
  return router;
}
