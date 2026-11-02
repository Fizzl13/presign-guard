// NEAR HACKATHON demo: an agent that only signs what presign-guard calls green.
//
//   node near/demo.mjs
//
// No keys, no money: the agent never signs. It asks NEAR Intents' 1Click API for a real quote (dry: true, so nothing
// is created or deposited), builds the intents message it would sign for that swap, and checks it, and five things
// an attacker could slip in instead, with presign-guard before signing. Each case is checked twice:
// - locally, with this repository's code (full reasons, read-only NEAR RPC and NEAR Intents' token prices);
// - live, with the free verdict-only endpoint https://presign-guard.fizzl.eu/v1/check/quick.
// Set NEAR_ACCOUNT to use another account name (default fizzl-demo.near) and PRESIGN_URL for another server.
import { analyze, parseRequest } from "../src/presign-guard.js";

const ACCOUNT = process.env.NEAR_ACCOUNT || "fizzl-demo.near";
const LIVE = (process.env.PRESIGN_URL || "https://presign-guard.fizzl.eu").replace(/\/$/, "");
const WNEAR = "nep141:wrap.near";
const USDC = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const ONE_NEAR = "1000000000000000000000000";
const color = { green: "\x1b[32m", orange: "\x1b[33m", red: "\x1b[31m", dim: "\x1b[2m", off: "\x1b[0m" };

async function quote() {
  const deadline = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const res = await fetch("https://1click.chaindefuser.com/v0/quote", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      dry: true, swapType: "EXACT_INPUT", slippageTolerance: 100, originAsset: WNEAR, destinationAsset: USDC, amount: ONE_NEAR,
      depositType: "INTENTS", refundTo: ACCOUNT, refundType: "INTENTS", recipient: ACCOUNT, recipientType: "INTENTS", deadline,
    }),
  });
  if (!res.ok) throw new Error(`1Click quote: HTTP ${res.status}`);
  return (await res.json()).quote;
}

// The NEP-413 message an agent signs for NEAR Intents.
const message = (intents) => ({
  message: JSON.stringify({ signer_id: ACCOUNT, verifying_contract: "intents.near", deadline: new Date(Date.now() + 10 * 60 * 1000).toISOString(), nonce: Buffer.alloc(32).toString("base64"), intents }),
  recipient: "intents.near",
  nonce: Buffer.alloc(32).toString("base64"),
});

async function live(body) {
  try {
    const res = await fetch(`${LIVE}/v1/check/quick`, { method: "POST", headers: { "content-type": "application/json", "user-agent": "presign-guard-near-demo/1" }, body: JSON.stringify(body) });
    const j = await res.json();
    return j.verdict ?? `error: ${j.error ?? res.status}`;
  } catch (err) {
    return `unreachable (${err.message})`;
  }
}

async function check(title, body) {
  const local = await analyze(parseRequest(body));
  const verdictLive = await live(body);
  const c = color[local.verdict] ?? "";
  console.log(`\n${title}`);
  console.log(`  presign-guard: ${c}${local.verdict.toUpperCase()}${color.off}  ${color.dim}(live ${LIVE.replace("https://", "")}: ${verdictLive})${color.off}`);
  for (const r of local.reasons.filter((x) => x.severity !== "info" || /SWAP|FUNCTION_CALL_KEY/.test(x.code))) {
    console.log(`    ${color[r.severity] ?? ""}${r.severity.padEnd(6)}${color.off} ${r.code}${r.details ? ` ${color.dim}${JSON.stringify(r.details)}${color.off}` : ""}`);
  }
  console.log(`  agent: ${local.verdict === "green" ? `${color.green}signs${color.off}` : local.verdict === "orange" ? `${color.orange}asks its owner first${color.off}` : `${color.red}refuses to sign${color.off}`}`);
  return local.verdict;
}

const q = await quote();
console.log(`NEAR Intents quote (1Click, dry run): 1 wNEAR -> ${q.amountOutFormatted} USDC (at least ${Number(q.minAmountOut) / 1e6}), worth $${Number(q.amountOutUsd).toFixed(2)}`);
console.log(`Agent account: ${ACCOUNT}. Nothing is signed or sent.`);

const honest = [{ intent: "token_diff", diff: { [WNEAR]: `-${ONE_NEAR}`, [USDC]: q.minAmountOut } }];
const results = [];
results.push(await check("1. The swap as quoted", { type: "near", nep413: message(honest) }));
results.push(await check("2. A tampered quote: the agent would get 30% of the value back", { type: "near", nep413: message([{ intent: "token_diff", diff: { [WNEAR]: `-${ONE_NEAR}`, [USDC]: String(Math.floor(Number(q.minAmountOut) * 0.3)) } }]) }));
results.push(await check("3. The same swap with a key slipped in (add_public_key on NEAR Intents)", { type: "near", nep413: message([...honest, { intent: "add_public_key", public_key: "ed25519:5TagutioHgKLh7KZ1VEFBYfgRkPtqnKm9LoMnJMJugxm" }]) }));
results.push(await check("4. Depositing the wNEAR into a look-alike of intents.near", { type: "near", tx: { signerId: ACCOUNT, receiverId: "wrap.near", actions: [{ type: "FunctionCall", params: { methodName: "ft_transfer_call", args: { receiver_id: "intents-near.near", amount: ONE_NEAR, msg: "" }, gas: "100000000000000", deposit: "1" } }] } }));
results.push(await check("5. A prompt injection asks the agent to add a full-access key to its own account", { type: "near", tx: { signerId: ACCOUNT, receiverId: ACCOUNT, actions: [{ type: "AddKey", params: { publicKey: "ed25519:5TagutioHgKLh7KZ1VEFBYfgRkPtqnKm9LoMnJMJugxm", accessKey: { permission: "FullAccess" } } }] } }));
results.push(await check("6. The safe pattern: a function-call key for intents.near only, 0.25 NEAR of gas", { type: "near", tx: { signerId: ACCOUNT, receiverId: ACCOUNT, actions: [{ type: "AddKey", params: { publicKey: "ed25519:5TagutioHgKLh7KZ1VEFBYfgRkPtqnKm9LoMnJMJugxm", accessKey: { permission: { receiverId: "intents.near", methodNames: ["execute_intents"], allowance: "250000000000000000000000" } } } }] } }));

const signed = results.filter((v) => v === "green").length;
console.log(`\nSigned ${signed} of ${results.length}; refused ${results.filter((v) => v === "red").length}.`);
process.exit(0);
