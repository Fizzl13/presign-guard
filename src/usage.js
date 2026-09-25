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

// An MCP tool call: which tool, the input summary, the verdict and the payment.
function describeMcpCall(req, body) {
  const call = usageLog.mcpToolCall(req.body);
  if (!call) return null; // initialize, tools/list
  const reply = (Array.isArray(body) ? body : [body]).find((r) => r && r.result) || {};
  const text = reply.result && reply.result.content && reply.result.content[0] && reply.result.content[0].text;
  if (reply.result && reply.result.isError && /payment|402/i.test(String(text))) return null; // the price, not a call
  let parsed = null;
  try { parsed = JSON.parse(text); } catch { /* plain text */ }
  const a = call.args || {};
  return {
    route: call.tool,
    via: "mcp",
    input: a.address
      ? { chain: a.chain, target: a.address }
      : { type: a.type, chainId: a.chainId, target: a.to || a.token || undefined, spender: a.spender || undefined, lang: a.lang },
    result: { verdict: parsed && parsed.verdict, grade: parsed && parsed.grade, error: reply.result && reply.result.isError ? String(text).slice(0, 200) : undefined },
    payment: usageLog.mcpPayment(req.body, body),
  };
}

// GET /v1/token: which token, the verdict and grade.
function describeTokenCall(req, body) {
  const q = req.query || {};
  const b = body || {};
  return {
    route: "token",
    via: req.get && req.get("sec-fetch-site") === "same-origin" ? "web" : "api",
    input: { chain: q.chain, target: q.address },
    result: {
      verdict: b.verdict === null ? "none" : b.verdict,
      grade: b.grade,
      reasons: Array.isArray(b.reasons) ? b.reasons.filter((r) => r.severity !== "info").map((r) => r.code).join(", ") || undefined : undefined,
      error: b.error,
    },
  };
}

export function describePresignCall(req, _res, body) {
  if (req.method === "POST" && req.path === "/mcp") return describeMcpCall(req, body);
  if (req.method === "GET" && req.path === "/v1/token") return describeTokenCall(req, body);
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
