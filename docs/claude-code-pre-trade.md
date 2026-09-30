# Pre-trade checks for Claude Code agents

Agents that trade on their own (for example through Coinbase for Agents) decide in seconds. This guide adds two checks your agent runs **before** it places an order:

1. **Is the token safe?** [presign-guard](https://presign-guard.fizzl.eu): green, orange or red for a Solana or EVM token (mint or freeze authority, honeypot, transfer tax, unlocked liquidity, very new token).
2. **What does the trend say?** [Ichimoku Signal](https://ichimoku-signal.fizzl.eu): the Ichimoku Cloud signal for the pair (bullish, bearish or neutral; above, in or below the cloud).

Both are MCP servers (Streamable HTTP). They only read data: they never sign, trade or touch a wallet.

## 1. Add the servers to Claude Code

```bash
claude mcp add --transport http presign-guard https://presign-guard.fizzl.eu/mcp
claude mcp add --transport http ichimoku-signal https://ichimoku-signal.fizzl.eu/mcp
```

Or in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "presign-guard": { "type": "http", "url": "https://presign-guard.fizzl.eu/mcp" },
    "ichimoku-signal": { "type": "http", "url": "https://ichimoku-signal.fizzl.eu/mcp" }
  }
}
```

Run `/mcp` in Claude Code to check both are connected.

## 2. The free tools (no wallet needed)

| Tool | Server | Returns | Limit |
|---|---|---|---|
| `token_quick_verdict` | presign-guard | green / orange / red and a grade (SAFE, CAUTION, RISKY, AVOID) | 10 per hour |
| `presign_quick_check` | presign-guard | green / orange / red for a transaction, approval or signature | shares the 10 per hour |
| `ichimoku_trend` | ichimoku-signal | daily trend: signal, cloud position, tenkan/kijun cross | 20 per hour |

That is enough for a first guard rule.

## 3. Tell the agent to use them

Put this in your project's `CLAUDE.md` (adjust to taste):

```markdown
## Before any buy order

1. Call `token_quick_verdict` with the chain and token address.
   - red: do not buy. Tell me why.
   - orange: stop and ask me first.
2. Call `ichimoku_trend` for the pair (e.g. SOL-USDT).
   - bearish and below the cloud: do not open a long without asking me.
3. Show me both results next to the order before you place it.
```

The agent now checks the token and the trend on its own, and stops on red flags instead of trading through them.

## 4. More detail (paid, per call, in USDC)

When the quick answer is not enough, the same servers offer paid tools, paid per call over [x402](https://x402.org) on Base or Solana. No account, no API key.

| Tool | Price | Returns |
|---|---|---|
| `token_verdict` | $0.01 | the reasons, a one-line summary and market data (price, liquidity, age) |
| `ichimoku_signal` | $0.02 | the full signal on any timeframe (1m to 1M) with every line value |
| `price_levels` | $0.05 | support/resistance, ATR, pivots, Fibonacci and a long/short plan |
| `confluence_signal` | $0.15 | six indicators with votes and a combined signal |

Paying needs an MCP client that supports x402 payments (a wallet with USDC). Without one, the paid tools answer with the price and payment details, and nothing is charged. Invalid input is refused before payment, and a failed check is not charged.

The same checks are also plain HTTP endpoints (`GET https://presign-guard.fizzl.eu/v1/token`, `GET https://ichimoku-signal.fizzl.eu/signal/{pair}`) for scripts with an x402 client.

## 5. In your own agent code: check every signature

The rule above works inside Claude Code. If your agent signs with [viem](https://viem.sh) in its own code, the npm package [`presign-guard-wallet`](https://www.npmjs.com/package/presign-guard-wallet) makes the check automatic: every transaction, contract write and typed-data signature (approvals, Permit2, x402 payments) goes past presign-guard first, and a red verdict is never signed.

```js
import { guardWallet } from "presign-guard-wallet";

const wallet = guardWallet(walletClient, { pay, onOrange: "stop" }); // $0.01 per check over x402
await wallet.sendTransaction(tx); // checked, then signed
```

Before paying an unknown x402 API, [`x402-safe-fetch`](https://www.npmjs.com/package/x402-safe-fetch) does the same for payments: a $0.001 preflight from x402 Doctor, and a diagnosis when a payment still fails.

## Notes

- The Ichimoku signal is a technical indicator, not financial advice. A green token verdict means no known trap was found, not that a token is a good investment.
- The token checks use GoPlus, DexScreener and RugCheck. New tokens can have little data: the verdict says so.
- Questions or a missing feature: use the free `feedback` tool on either server.
