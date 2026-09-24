// What each presign-guard call was about, for the usage log (usage-log.cjs):
// the dashboard at x402-doctor.onrender.com/admin/usage. Null = not logged.
import usageLog from "./usage-log.cjs";

export const { createUsageLog } = usageLog;

const ROUTES = { "/v1/check": "check", "/v1/check/explain": "check + explain" };

function typedDataOf(body) {
  let td = body.typedData;
  if (typeof td === "string") {
    try { td = JSON.parse(td); } catch { return null; }
  }
  return td && typeof td === "object" ? td : null;
}

export function describePresignCall(req, _res, body) {
  if (req.method !== "POST" || !ROUTES[req.path]) return null;
  const input = req.body || {};
  const td = typedDataOf(input);
  const b = body || {};
  return {
    route: ROUTES[req.path],
    via: req.get && req.get("sec-fetch-site") === "same-origin" ? "web" : "api",
    input: {
      type: input.type,
      chainId: input.chainId,
      primaryType: td ? td.primaryType : undefined,
      target: input.to || input.token || (td && td.domain && td.domain.verifyingContract) || undefined,
      spender: input.spender || (td && td.message && (td.message.spender || td.message.to)) || undefined,
      selector: typeof input.data === "string" && input.data.length >= 10 ? input.data.slice(0, 10) : undefined,
      lang: input.lang,
    },
    result: {
      verdict: b.verdict === null ? "none" : b.verdict,
      reasons: Array.isArray(b.reasons) ? b.reasons.filter((r) => r.severity !== "info").map((r) => r.code).join(", ") || undefined : undefined,
      error: b.error,
    },
  };
}
