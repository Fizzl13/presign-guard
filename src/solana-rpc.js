// A minimal Solana JSON-RPC client for the few reads the token verdict needs.
// SOLANA_RPC_URL overrides the public mainnet endpoint.

const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const RPC_TIMEOUT_MS = 4000;

export async function solanaRpc(method, params) {
  const res = await fetch(SOLANA_RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Solana RPC HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`Solana RPC ${body.error.message ?? "error"}`);
  return body.result?.value ?? null;
}
