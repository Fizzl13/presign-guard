// What a transaction really does to the wallet, before it is signed: eth_simulateV1 (the standard simulation call,
// with traceTransfers) runs it against the latest block, and its logs show every asset that moves (native coin as
// the synthetic 0xEeee… Transfer, ERC-20, ERC-721, ERC-1155) and every approval it sets. Decoding the calldata
// (presign-guard.js) shows what the call says; simulation shows what it does, also inside multicalls, routers and
// EIP-7702 batches. Asked from Alchemy when ALCHEMY_API_KEY is set (its alchemy_simulateAssetChanges was retired
// on 30 Sep 2026), else, or when Alchemy fails, from the chain's public RPC (RPC_URL_<chainId> overrides).
// Needs the sender (`from`); a failure or timeout leaves the check as it was (never a guessed green).

const ALCHEMY = { 1: "eth-mainnet", 10: "opt-mainnet", 56: "bnb-mainnet", 137: "polygon-mainnet", 8453: "base-mainnet", 42161: "arb-mainnet" };
const PUBLIC = {
  1: "https://ethereum-rpc.publicnode.com",
  10: "https://optimism-rpc.publicnode.com",
  56: "https://bsc-rpc.publicnode.com",
  137: "https://polygon-bor-rpc.publicnode.com",
  8453: "https://base-rpc.publicnode.com",
  42161: "https://arbitrum-one-rpc.publicnode.com",
};
export const SIMULATED_CHAINS = Object.keys(PUBLIC).map(Number);
const NATIVE = { 1: "ETH", 10: "ETH", 56: "BNB", 137: "POL", 8453: "ETH", 42161: "ETH" };

const T_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const T_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const T_APPROVAL_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653c200f220920489ca2b5937696c31";
const T_TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const NATIVE_ADDRESS = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const lower = (s) => (typeof s === "string" ? s.toLowerCase() : s ?? null);
const topicAddress = (t) => (typeof t === "string" && t.length === 66 ? "0x" + t.slice(26).toLowerCase() : null);
const word = (data, i) => { const h = String(data || "0x").slice(2 + i * 64, 2 + (i + 1) * 64); return h ? BigInt("0x" + h) : 0n; };

// Log entries to changes: transfers and approvals, in the order they happened.
export function changesFromLogs(logs, chainId) {
  const out = [];
  for (const log of logs || []) {
    const t = log.topics || [];
    const token = lower(log.address);
    if (t[0] === T_TRANSFER && t.length >= 3) {
      if (token === NATIVE_ADDRESS) out.push({ type: "transfer", asset: "native", symbol: NATIVE[chainId] ?? "native", from: topicAddress(t[1]), to: topicAddress(t[2]), rawAmount: word(log.data, 0).toString() });
      else if (t.length === 4) out.push({ type: "transfer", asset: "erc721", token, from: topicAddress(t[1]), to: topicAddress(t[2]), tokenId: BigInt(t[3]).toString() });
      else out.push({ type: "transfer", asset: "erc20", token, from: topicAddress(t[1]), to: topicAddress(t[2]), rawAmount: word(log.data, 0).toString() });
    } else if (t[0] === T_TRANSFER_SINGLE && t.length === 4) {
      out.push({ type: "transfer", asset: "erc1155", token, from: topicAddress(t[2]), to: topicAddress(t[3]), tokenId: word(log.data, 0).toString(), rawAmount: word(log.data, 1).toString() });
    } else if (t[0] === T_APPROVAL && t.length >= 3) {
      if (t.length === 4) out.push({ type: "approve", asset: "erc721", token, from: topicAddress(t[1]), to: topicAddress(t[2]), tokenId: BigInt(t[3]).toString() });
      else out.push({ type: "approve", asset: "erc20", token, from: topicAddress(t[1]), to: topicAddress(t[2]), rawAmount: word(log.data, 0).toString() });
    } else if (t[0] === T_APPROVAL_ALL && t.length === 3 && word(log.data, 0) !== 0n) {
      out.push({ type: "approve", asset: "nft_all", token, from: topicAddress(t[1]), to: topicAddress(t[2]) });
    }
  }
  return out.slice(0, 50);
}

// An ABI string or bytes32 return value as text.
function abiText(hex) {
  const h = String(hex || "0x").slice(2);
  if (!h) return null;
  try {
    if (h.length >= 128) {
      const len = Number(BigInt("0x" + h.slice(64, 128)));
      if (len > 0 && len <= 64) return Buffer.from(h.slice(128, 128 + len * 2), "hex").toString("utf8").replace(/[^\x20-\x7e]/g, "") || null;
    }
    return Buffer.from(h.slice(0, 64), "hex").toString("utf8").replace(/[^\x20-\x7e]/g, "") || null;
  } catch { return null; }
}

export function formatUnits(raw, decimals) {
  const v = BigInt(raw);
  if (!decimals) return v.toString();
  const s = v.toString().padStart(decimals + 1, "0");
  const whole = s.slice(0, -decimals);
  const frac = s.slice(-decimals).replace(/0+$/, "").slice(0, 6);
  return frac ? `${whole}.${frac}` : whole;
}

export function createSimulator({ env = process.env, fetch: fetchImpl, timeoutMs = 4000, log = console } = {}) {
  const enabled = env.SIMULATION !== "off";
  const urls = (chainId) => [
    ...(env.ALCHEMY_API_KEY && ALCHEMY[chainId] ? [{ url: `https://${ALCHEMY[chainId]}.g.alchemy.com/v2/${env.ALCHEMY_API_KEY}`, source: "alchemy" }] : []),
    { url: env[`RPC_URL_${chainId}`] || PUBLIC[chainId], source: "rpc" },
  ];
  const rpc = async (url, body) => {
    const res = await (fetchImpl ?? globalThis.fetch)(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  // Symbols and decimals of the ERC-20s that moved, in one batch (best effort).
  async function tokenMeta(url, tokens) {
    if (!tokens.length) return new Map();
    const calls = tokens.flatMap((t, i) => [
      { jsonrpc: "2.0", id: i * 2, method: "eth_call", params: [{ to: t, data: "0x95d89b41" }, "latest"] },
      { jsonrpc: "2.0", id: i * 2 + 1, method: "eth_call", params: [{ to: t, data: "0x313ce567" }, "latest"] },
    ]);
    try {
      const answers = await rpc(url, calls);
      const byId = new Map((Array.isArray(answers) ? answers : []).map((a) => [a.id, a.result]));
      return new Map(tokens.map((t, i) => {
        const dec = byId.get(i * 2 + 1);
        const decimals = typeof dec === "string" && dec !== "0x" ? Number(BigInt(dec)) : null;
        return [t, { symbol: abiText(byId.get(i * 2))?.slice(0, 16) ?? null, decimals: decimals !== null && decimals <= 36 ? decimals : null }];
      }));
    } catch { return new Map(); }
  }

  // { ok, changes, gasUsed, error, source } or null when off, the chain isn't covered, or no RPC answered.
  async function simulate({ chainId, from, to, data = "0x", value = 0n }) {
    if (!enabled || !PUBLIC[chainId] || !from || !to) return null;
    const body = { jsonrpc: "2.0", id: 1, method: "eth_simulateV1", params: [{ blockStateCalls: [{ calls: [{ from, to, data, value: "0x" + BigInt(value).toString(16) }] }], traceTransfers: true, validation: false }, "latest"] };
    for (const { url, source } of urls(chainId)) {
      try {
        const answer = await rpc(url, body);
        // Too little native coin for the value is an answer about the wallet, not a broken RPC (eth_simulateV1 error code -38014).
        if (answer?.error && (answer.error.code === -38014 || /insufficient funds/i.test(answer.error.message ?? ""))) {
          return { ok: false, changes: [], error: String(answer.error.message ?? "insufficient funds").slice(0, 300), source };
        }
        const call = answer?.result?.[0]?.calls?.[0];
        if (answer?.error || !call) { log.warn?.(`[simulate] ${source} chain ${chainId}: ${answer?.error?.message ?? "no result"}`); continue; }
        const failed = call.status === "0x0";
        const changes = changesFromLogs(call.logs, chainId);
        const tokens = [...new Set(changes.filter((c) => c.asset === "erc20" && c.token).map((c) => c.token))].slice(0, 6);
        const meta = await tokenMeta(url, tokens);
        for (const c of changes) {
          const m = c.token ? meta.get(c.token) : null;
          if (m?.symbol) c.symbol = m.symbol;
          const decimals = c.asset === "native" ? 18 : m?.decimals;
          if (c.rawAmount !== undefined && decimals !== null && decimals !== undefined) c.amount = formatUnits(c.rawAmount, decimals);
        }
        const error = failed ? String(call.error?.message ?? "execution reverted").slice(0, 300) : null;
        return { ok: !failed, changes, ...(call.gasUsed && { gasUsed: String(BigInt(call.gasUsed)) }), ...(error && { error }), source };
      } catch (err) {
        log.warn?.(`[simulate] ${source} chain ${chainId}: ${err.name}: ${err.message}`);
      }
    }
    return null;
  }

  return { enabled, simulate };
}

// Reason codes from a simulation, for the sender `from`. kind is the decoded call's kind (presign-guard.js).
export function simulationReasons(sim, { from, kind }) {
  const out = [];
  if (!sim) return out;
  const me = lower(from);
  if (!sim.ok) {
    out.push({ code: "SIMULATION_FAILS", severity: "orange", subject: me, details: { error: sim.error } });
    return out;
  }
  const decodedApproval = kind === "token_approve" || kind === "approval_for_all";
  for (const c of sim.changes) {
    if (c.type === "approve" && c.from === me && !decodedApproval) {
      // An approval the decoded call doesn't show: set inside a router, multicall or batched (EIP-7702) call.
      out.push({ code: "HIDDEN_APPROVAL", severity: "orange", subject: c.to, details: { token: c.token ?? null, symbol: c.symbol ?? null, asset: c.asset, amount: c.amount ?? c.rawAmount ?? (c.asset === "nft_all" ? "all NFTs of the collection" : null) } });
    }
    if (c.type === "transfer" && c.from === me && (c.asset === "erc721" || c.asset === "erc1155")) {
      out.push({ code: "SIMULATION_NFT_OUT", severity: "orange", subject: c.to, details: { token: c.token ?? null, tokenId: c.tokenId ?? null } });
    }
  }
  const leaves = sim.changes.filter((c) => c.type === "transfer" && c.from === me).map((c) => ({ to: c.to, asset: c.asset, symbol: c.symbol ?? null, amount: c.amount ?? c.rawAmount ?? null }));
  const arrives = sim.changes.filter((c) => c.type === "transfer" && c.to === me).map((c) => ({ from: c.from, asset: c.asset, symbol: c.symbol ?? null, amount: c.amount ?? c.rawAmount ?? null }));
  out.push({ code: "SIMULATED", severity: "info", subject: me, details: { leaves, arrives } });
  return out;
}

// The simulation in words for the intent check (src/jev.js): what leaves the wallet, what arrives, what is approved.
export function simulationEffects(sim, from) {
  if (!sim) return null;
  if (!sim.ok) return { would_fail: sim.error };
  const me = lower(from);
  const line = (c) => `${c.amount ?? c.rawAmount ?? "?"} ${c.symbol ?? c.token ?? c.asset}${c.tokenId ? ` #${c.tokenId}` : ""}`;
  return {
    leaves_wallet: sim.changes.filter((c) => c.type === "transfer" && c.from === me).map((c) => `${line(c)} to ${c.to}`),
    arrives_in_wallet: sim.changes.filter((c) => c.type === "transfer" && c.to === me).map((c) => `${line(c)} from ${c.from}`),
    approvals_set: sim.changes.filter((c) => c.type === "approve" && c.from === me).map((c) => `${line(c)} for ${c.to}`),
  };
}

// Shown in GET /health, so the owner can see simulation works without a paid check: at startup one harmless
// simulation per chain (a zero-value self-transfer). Per chain the source that answered (alchemy or the public
// rpc); the key is never shown.
const status = { on: false, selfTest: "not run", at: null };
export function simulationStatus(env = process.env) {
  return { on: env.SIMULATION !== "off", selfTest: status.selfTest, at: status.at };
}
export async function simulationSelfTest({ env = process.env, fetch: fetchImpl } = {}) {
  if (env.SIMULATION === "off") { status.selfTest = "off (SIMULATION=off)"; return status; }
  const probe = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
  const hide = (m) => (env.ALCHEMY_API_KEY ? String(m).split(env.ALCHEMY_API_KEY).join("…") : String(m));
  const results = await Promise.all(SIMULATED_CHAINS.map(async (chainId) => {
    let why = "no answer";
    const sim = createSimulator({ env, fetch: fetchImpl, timeoutMs: 8000, log: { warn: (m) => { why = hide(m).replace(/^\[simulate\] /, "").slice(0, 160); } } });
    const r = await sim.simulate({ chainId, from: probe, to: probe });
    return { chainId, source: r?.source ?? null, why };
  }));
  status.at = new Date().toISOString();
  const bad = results.filter((r) => !r.source);
  const by = (src) => results.filter((r) => r.source === src).map((r) => r.chainId);
  const parts = [by("alchemy").length && `alchemy: ${by("alchemy").join(", ")}`, by("rpc").length && `public rpc: ${by("rpc").join(", ")}`].filter(Boolean).join("; ");
  status.selfTest = bad.length ? `failed on ${bad.map((r) => `${r.chainId} (${r.why})`).join("; ")}${parts ? ` (ok on ${parts})` : ""}` : `ok (${parts})`;
  console.log(`[simulate] self-test ${status.selfTest}`);
  return status;
}
