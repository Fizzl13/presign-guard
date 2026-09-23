// End-to-end test as a paying agent, on Base Sepolia.
//
//   AGENT_PRIVATE_KEY=0x... CHECK_URL=https://your-service.onrender.com npm run client
//
// Use a throwaway key funded with Base Sepolia test USDC (Circle faucet). Never a real wallet.
// Runs two calls:
//   1. A valid check → expect 200, a verdict, and a settlement receipt.
//   2. An invalid body → expect 400 and NO settlement (you should not be charged).

import { wrapFetchWithPayment, x402Client, decodePaymentResponseHeader } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const { AGENT_PRIVATE_KEY, CHECK_URL } = process.env;
if (!AGENT_PRIVATE_KEY || !CHECK_URL) {
  console.error("Set AGENT_PRIVATE_KEY and CHECK_URL");
  process.exit(1);
}

const account = privateKeyToAccount(AGENT_PRIVATE_KEY);
const client = registerExactEvmScheme(new x402Client(), { signer: account });
const payFetch = wrapFetchWithPayment(fetch, client);

async function call(label, body, path = "/v1/check") {
  const res = await payFetch(new URL(path, CHECK_URL), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const receiptHeader = res.headers.get("payment-response");
  const receipt = receiptHeader ? decodePaymentResponseHeader(receiptHeader) : null;
  const json = await res.json().catch(() => null);

  console.log(`\n=== ${label}`);
  console.log("status:  ", res.status);
  console.log("verdict: ", json?.verdict ?? null);
  console.log("reasons: ", json?.reasons?.map((r) => `${r.code} (${r.severity})`).join(", ") || json?.message);
  console.log("settled: ", receipt ? `${receipt.success ? "yes" : "no"}${receipt.transaction ? ` tx ${receipt.transaction}` : ""}` : "no receipt");
  return { res, json, receipt };
}

console.log("Paying from", account.address);

// Checks USDC on Base mainnet with Permit2 as spender: expect green or orange, not red.
const ok = await call("valid check", {
  type: "approval",
  chainId: 8453, // chain being checked (Base mainnet data); payment still happens on Base Sepolia
  token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  spender: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
  amount: "1000000",
});

const bad = await call("invalid body (should not be charged)", { type: "approval", chainId: 999 });

const pass = ok.res.status === 200 && ok.receipt?.success && bad.res.status === 400 && !bad.receipt?.success;
console.log(`\n${pass ? "PASS" : "CHECK OUTPUT"}: paid for the valid call, not charged for the invalid one.`);
process.exit(pass ? 0 : 1);
