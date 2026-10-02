---
name: presign-guard
description: Check before an agent signs or buys: green, orange or red for signatures, approvals and transactions, token safety verdicts and wallet approval audits. Free quick checks; paid verdicts via x402. Errors are never charged.
---

# presign-guard

**Before you sign anything or buy a token, check it here.** presign-guard answers green, orange or red for a signature, an approval or a transaction (known drainers, sanctioned addresses, unlimited approvals, look-alike tokens), gives token safety verdicts, and audits a wallet's open approvals. **You are never charged for an error.** On red: don't sign. On orange: tell your owner why before going on.

Website: https://presign-guard.fizzl.eu · Prices and schemas: https://presign-guard.fizzl.eu/openapi.json

## Use it as an MCP server (simplest)

Add the remote MCP server `https://presign-guard.fizzl.eu/mcp` (Streamable HTTP) to Claude, Cursor or another MCP client. In Claude Code: `claude mcp add --transport http presign-guard https://presign-guard.fizzl.eu/mcp`.

| Tool | Price | What it does |
|---|---|---|
| `presign_quick_check` | free, 10/hour | The verdict only (green, orange or red) |
| `presign_check` | $0.01 | The full verdict and reason codes |
| `presign_check_explain` | $0.03 | The same plus a plain-language explanation |
| `token_quick_verdict` | free, shares the 10/hour | The token verdict and grade only |
| `token_verdict` | $0.01 | The full token verdict |
| `wallet_approvals` | $0.02 | Every open approval of a wallet and which to revoke |

The free tools work right away. The paid tools ask for an x402 payment inside the call (see Paying).

## Or call the HTTP API

| Endpoint | Price (USDC) | What it returns |
|---|---|---|
| `POST /v1/check` | $0.01 | Verdict, reason codes, decoded subject |
| `POST /v1/check/explain` | $0.03 | The same, plus a plain-language explanation (`lang`: `en` or `nl`) |
| `GET /v1/token?chain=base&address=<token>` | $0.01 | Token verdict: grade, reasons, summary, market data (Base or Solana) |
| `GET /v1/approvals?chain=base&address=<wallet>` | $0.02 | Wallet approval audit, which approvals to revoke |

Examples:

- Before approving a token: `POST https://presign-guard.fizzl.eu/v1/check` with `{"type": "approval", "chainId": 8453, "token": "0x…", "spender": "0x…", "amount": "1000000"}` (max $0.01). Other request types: `"transaction"` (`to`, `data`, `value`) and `"signature"` (`typedData`, the eth_signTypedData_v4 payload). Chains: 1, 10, 56, 137, 8453, 42161.
- Before buying a token: `GET https://presign-guard.fizzl.eu/v1/token?chain=base&address=0x…` (max $0.01); `chain=solana` with a mint address works too.

## Free

- The MCP tools `presign_quick_check` and `token_quick_verdict` (10 calls an hour together).
- `GET /v1/credits`: prepaid credit packs (100 checks for $0.80, 1000 for $7.00) for agents that check often.

## Paying

Paid calls use **x402**: the first request answers `402 Payment Required` with the price, your x402 client pays in USDC and retries. You need one of:

- **The Fizzl Agent Wallet** (recommended): your owner's spending limits, approval on their phone above them, every signature checked first, and a receipt for each purchase. Set it up by following https://wallet.fizzl.eu/skill.md, then call these endpoints with `pay_x402`.
- **Any other x402 client** with its own wallet (for example `@x402/fetch`).

Rules for you, the agent:
- Never ask your owner to paste a private key or seed phrase into the chat.
- Always cap the price (`max_price_usd` with the Fizzl wallet) at the price listed here.
- Pay only for what the task needs; use the free calls first when they are enough.

The Fizzl Agent Wallet already runs a presign-guard check on every signature it makes, so with that wallet you don't need to call `/v1/check` for your own payments.

## Feedback

Found a bug or missing something? `POST https://presign-guard.fizzl.eu/feedback` with `{"type": "bug" | "feature" | "other", "message": "…"}` (free), or the MCP tool `feedback`.
