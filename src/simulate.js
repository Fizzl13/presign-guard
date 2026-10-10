// What a transaction really does to the wallet, before it is signed: Alchemy's alchemy_simulateAssetChanges runs
// it against the latest block and lists every asset that moves (native coin, ERC-20, NFTs) and every approval it
// sets. Decoding the calldata (presign-guard.js) shows what the call says; simulation shows what it does, also
// inside multicalls, routers and EIP-7702 batches. Needs the sender (`from`) and ALCHEMY_API_KEY; off otherwise,
// and a failure or timeout leaves the check as it was (never a guessed green, never a block on our side).

const NETWORKS = { 1: "eth-mainnet", 10: "opt-mainnet", 137: "polygon-mainnet", 8453: "base-mainnet", 42161: "arb-mainnet" };
export const SIMULATED_CHAINS = Object.keys(NETWORKS).map(Number);

const lower = (s) => (typeof s === "string" ? s.toLowerCase() : s ?? null);

// One change, trimmed to what an agent and the intent check need.
function normalize(c) {
  return {
    type: c.changeType === "APPROVE" ? "approve" : "transfer",
    asset: String(c.assetType || "").toLowerCase(), // native, erc20, erc721, erc1155, special_nft
    ...(c.contractAddress && { token: lower(c.contractAddress) }),
    ...(c.symbol && { symbol: String(c.symbol).slice(0, 16) }),
    ...(c.tokenId !== undefined && c.tokenId !== null && { tokenId: String(c.tokenId) }),
    from: lower(c.from),
    to: lower(c.to),
    ...(c.rawAmount !== undefined && c.rawAmount !== null && { rawAmount: String(c.rawAmount) }),
    ...(c.amount !== undefined && c.amount !== null && { amount: String(c.amount) }),
  };
}

export function createSimulator({ apiKey = process.env.ALCHEMY_API_KEY, fetch: fetchImpl, timeoutMs = 4000, log = console } = {}) {
  const enabled = Boolean(apiKey) && process.env.SIMULATION !== "off";

  // { ok, changes, gasUsed, error } or null when off, the chain isn't covered, or Alchemy didn't answer.
  async function simulate({ chainId, from, to, data = "0x", value = 0n }) {
    if (!enabled || !NETWORKS[chainId] || !from || !to) return null;
    try {
      const res = await (fetchImpl ?? globalThis.fetch)(`https://${NETWORKS[chainId]}.g.alchemy.com/v2/${apiKey}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "alchemy_simulateAssetChanges", params: [{ from, to, data, value: "0x" + BigInt(value).toString(16) }] }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) { log.warn?.(`[simulate] HTTP ${res.status}`); return null; }
      const body = await res.json();
      if (body.error) { log.warn?.(`[simulate] ${body.error.message ?? "error"}`); return null; }
      const r = body.result ?? {};
      const changes = Array.isArray(r.changes) ? r.changes.slice(0, 50).map(normalize) : [];
      const error = r.error ? String(r.error.message ?? r.error).slice(0, 300) : null;
      return { ok: !error, changes, ...(r.gasUsed && { gasUsed: String(r.gasUsed) }), ...(error && { error }) };
    } catch (err) {
      log.warn?.(`[simulate] ${err.name}: ${err.message}`);
      return null;
    }
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
      out.push({ code: "HIDDEN_APPROVAL", severity: "orange", subject: c.to, details: { token: c.token ?? null, symbol: c.symbol ?? null, amount: c.amount ?? c.rawAmount ?? null } });
    }
    if (c.type === "transfer" && c.from === me && ["erc721", "erc1155", "special_nft"].includes(c.asset)) {
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
