---
title: presign-guard
emoji: 🛡️
colorFrom: green
colorTo: blue
sdk: gradio
sdk_version: 6.25.0
app_file: app.py
pinned: false
license: mit
short_description: Safety checks before an AI agent pays, signs or buys (MCP)
tags:
  - mcp-server
  - agents
  - ai-agents
  - wallet-security
  - sanctions
  - x402
---

# presign-guard

Free safety checks for AI agents with a wallet, before they pay, sign or accept a token. Nothing is paid or signed
here, and the Space holds no key. It uses [presign-guard](https://presign-guard.fizzl.eu)'s public data and free tools.

## Tools (also an MCP server)

| Tool | What it does |
|---|---|
| `screen_address(address)` | Is the address on the US Treasury's OFAC SDN list of digital currency addresses (Bitcoin, Ethereum and EVM chains, Tron, Solana with its USDC and USDT token accounts, and more)? A match names the listed entity and its programs. Matched in the Space against presign-guard's open copy of the list, so it's unlimited. |
| `token_quick_verdict(chain, address)` | Green, orange or red, and a grade (SAFE, CAUTION, RISKY, AVOID), for a token on Solana, EVM chains, the XRP Ledger or Algorand: mint and freeze authority, honeypots, taxes, liquidity, age, concentrated holders, rug pulls. |
| `presign_quick_check(request)` | Green, orange or red for what an agent is about to sign: an EVM transaction, a token approval, an EIP-712 signature (Permit, Permit2, orders), an EIP-7702 authorization, a message, a Solana, XRP Ledger, Algorand or Stellar transaction (x402 payment authorizations included). |

The last two share presign-guard's free limit of 10 calls an hour, and this Space counts as one caller. For more, and
for the reasons behind a verdict with a signed receipt, use presign-guard itself ($0.01 a check over x402).

## Use it from an MCP client

- **Hugging Face:** add `x402Fizzl/presign-guard` under [Settings → MCP](https://huggingface.co/settings/mcp), then use the tools from any client connected to the Hugging Face MCP server.
- **Any MCP client** (Claude, Cursor, …): connect to `https://x402fizzl-presign-guard.hf.space/gradio_api/mcp/` (streamable HTTP).

## More

- presign-guard's own MCP server, with the paid checks: `https://presign-guard.fizzl.eu/mcp`.
- A guarded wallet for agents that runs these checks before every signature: [presign-guard-wallet](https://www.npmjs.com/package/presign-guard-wallet).
- How agents handle payment and signing traps, with and without these checks: the [x402 Agent Safety Bench](https://huggingface.co/spaces/x402Fizzl/x402-agent-safety-bench).

Source: [Fizzl13/presign-guard](https://github.com/Fizzl13/presign-guard/tree/main/hf-mcp). By Fizzl, fizzl.eu.
