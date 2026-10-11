// Address poisoning: an attacker sends a wallet a worthless transfer from an address that starts and ends like one
// the wallet really pays (0xA1b2…9F3e vs 0xA1b2…9F3e with another middle), hoping the agent or person later copies it
// from the history. Before a transfer, the recipients (from the simulation, else the decoded call) are compared
// with the addresses this wallet has sent money to before (Alchemy's alchemy_getAssetTransfers, needs
// ALCHEMY_API_KEY): a recipient that is new but looks like one of them is red. Without the key, or when Alchemy
// doesn't answer, the check is skipped (never a guessed green).
import { ALCHEMY } from "./simulate.js";

const TRANSFER = "0xa9059cbb";
const TRANSFER_FROM = "0x23b872dd";
const lower = (s) => (typeof s === "string" ? s.toLowerCase() : null);

// Same start and same end, different address: at least 3 characters each side and 7 together (after 0x).
export function lookalike(a, b) {
  const x = lower(a)?.slice(2), y = lower(b)?.slice(2);
  if (!x || !y || x === y || x.length !== 40 || y.length !== 40) return false;
  let p = 0; while (p < 40 && x[p] === y[p]) p++;
  let s = 0; while (s < 40 && x[39 - s] === y[39 - s]) s++;
  return p >= 3 && s >= 3 && p + s >= 7;
}

// Who receives value from `from`: what the simulation saw leave the wallet, else the decoded transfer.
export function transferRecipients(req, sim) {
  const me = lower(req.from);
  if (sim?.ok) return [...new Set(sim.changes.filter((c) => c.type === "transfer" && c.from === me && c.to && c.to !== me).map((c) => c.to))];
  const data = lower(req.data) ?? "0x";
  const word = (i) => (data.length >= 10 + 64 * (i + 1) ? "0x" + data.slice(10 + 64 * i + 24, 10 + 64 * (i + 1)) : null);
  if (data.startsWith(TRANSFER)) return [word(0)].filter(Boolean);
  if (data.startsWith(TRANSFER_FROM) && lower(word(0)) === me) return [word(1)].filter(Boolean);
  if (data === "0x" && req.value > 0n && req.target) return [lower(req.target)];
  return [];
}

export function createHistory({ env = process.env, fetch: fetchImpl, timeoutMs = 4000, log = console } = {}) {
  const enabled = Boolean(env.ALCHEMY_API_KEY) && env.ADDRESS_HISTORY !== "off";
  // The addresses `from` has sent ETH or tokens to (the latest 1,000 transfers), or null when unknown.
  async function recipientsOf(chainId, from, { maxCount = 1000 } = {}) {
    if (!enabled || !ALCHEMY[chainId] || !from) return null;
    try {
      const res = await (fetchImpl ?? globalThis.fetch)(`https://${ALCHEMY[chainId]}.g.alchemy.com/v2/${env.ALCHEMY_API_KEY}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "alchemy_getAssetTransfers", params: [{ fromAddress: from, category: ["external", "erc20"], excludeZeroValue: true, order: "desc", maxCount: "0x" + maxCount.toString(16), withMetadata: false }] }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      const answer = await res.json();
      if (!res.ok || answer?.error || !Array.isArray(answer?.result?.transfers)) throw new Error(answer?.error?.message ?? `HTTP ${res.status}`);
      return new Set(answer.result.transfers.map((t) => lower(t.to)).filter(Boolean));
    } catch (err) {
      log.warn?.(`[poisoning] history chain ${chainId}: ${String(err.message).split(env.ALCHEMY_API_KEY).join("…")}`);
      return null;
    }
  }
  return { enabled, recipientsOf };
}

// Reasons for the recipients, given the wallet's past recipients (null: unknown, no reasons).
export function poisoningReasons(history, recipients) {
  if (!history) return [];
  const out = [];
  for (const to of recipients) {
    if (history.has(to)) { out.push({ code: "KNOWN_RECIPIENT", severity: "info", subject: to }); continue; }
    const real = [...history].find((h) => lookalike(h, to));
    out.push(real
      ? { code: "ADDRESS_POISONING", severity: "red", subject: to, details: { lookalikeOf: real, note: "starts and ends like an address this wallet has paid before, but it is another address" } }
      : { code: "NEW_RECIPIENT", severity: "info", subject: to, details: { pastRecipients: history.size } });
  }
  return out;
}

// GET /health: whether the history lookup works (one tiny lookup on Base at startup); the key is never shown.
const status = { selfTest: "not run", at: null };
export function historyStatus(env = process.env) {
  return { on: Boolean(env.ALCHEMY_API_KEY) && env.ADDRESS_HISTORY !== "off", selfTest: status.selfTest, at: status.at };
}
export async function historySelfTest({ env = process.env, fetch: fetchImpl } = {}) {
  if (!env.ALCHEMY_API_KEY) { status.selfTest = "off (no ALCHEMY_API_KEY)"; return status; }
  if (env.ADDRESS_HISTORY === "off") { status.selfTest = "off (ADDRESS_HISTORY=off)"; return status; }
  let why = "no answer";
  const h = createHistory({ env, fetch: fetchImpl, timeoutMs: 8000, log: { warn: (m) => { why = m.replace(/^\[poisoning\] /, "").slice(0, 160); } } });
  const set = await h.recipientsOf(8453, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", { maxCount: 1 });
  status.at = new Date().toISOString();
  status.selfTest = set ? "ok" : `failed (${why})`;
  console.log(`[poisoning] self-test ${status.selfTest}`);
  return status;
}
