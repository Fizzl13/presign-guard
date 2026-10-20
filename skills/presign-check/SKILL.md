---
name: presign-check
description: "Check what a crypto agent is about to sign, buy or send before it does. Use before signing any EVM transaction, token approval, Permit, Permit2 or other EIP-712 signature, x402 payment, or Solana, XRP Ledger or Algorand transaction. Also use before buying, swapping into or accepting a token (awal trade, Jupiter, Uniswap and the like), before sending funds to an address (OFAC sanctions screen), and to find which open token approvals on a wallet to revoke. Green / orange / red verdicts with reason codes, $0.01 to $0.02 per check over x402; a free quick token verdict."
license: MIT
allowed-tools: ["Bash(curl *)"]
---

# Check before you sign (presign-guard)

An agent with a wallet can be talked into signing a drainer approval, buying a honeypot token or paying a sanctioned address. presign-guard looks at exactly what is about to be signed and answers **green**, **orange** or **red**, with reason codes.

- **The decoding:** EVM transactions are simulated, and Solana instructions are decoded and simulated.
- **The parties:** the spender or recipient is screened against the OFAC SDN list and theft and phishing reports.
- **The token itself:** honeypots, impersonation, high tax, and mint or freeze powers.

**The rule, every time:**

- **Green:** go ahead.
- **Orange:** show the user the reasons and ask.
  - **One exception: a safe way to do exactly what the user asked.** Sometimes it is orange only because of where the funds go, for example `XRPL_WITHDRAW_TO_OTHER`: a withdrawal paid to someone else's account, which promises to pass it on. If the user's goal can be reached with transactions that keep the funds in the user's own account or send them only where the user asked, build those instead. An example is withdrawing to the user's account, then depositing into the new vault. Check each one, and sign only if every one comes back green. Tell the user what you did differently and why.
  - **Any other orange:** ask.
- **Red:** never sign, never buy, never send. Tell the user why.

The keys never leave the agent: presign-guard only sees what you send it.

## 1. Before buying or accepting a token

**Free, verdict only** (10 free calls an hour per IP):

```bash
curl -s "https://presign-guard.fizzl.eu/v1/token/quick?chain=base&address=<token contract or mint>"
```

**$0.01, with the reasons:** `GET https://presign-guard.fizzl.eu/v1/token?chain=<chain>&address=<token>`. It adds the reasons, a grade, a one-line summary and market data.

- **`chain`:** `solana`, `base`, `ethereum`, `arbitrum`, `optimism`, `polygon`, `bsc`, `xrpl` or `algorand`.
- **`address`:** for Algorand, the asset id.

## 2. Before signing anything

`POST https://presign-guard.fizzl.eu/v1/check` costs $0.01. Send exactly what is about to be signed:

| What | Body |
| --- | --- |
| Token approval | `{"type":"approval","chainId":8453,"token":"0x…","spender":"0x…","amount":"1000000"}` |
| Transaction (swap, transfer, contract call) | `{"type":"transaction","chainId":8453,"to":"0x…","data":"0x…","value":"0","from":"<your wallet>"}`. With `from`, it is simulated and you see what really leaves the wallet. |
| EIP-712 signature (Permit, Permit2, x402 EIP-3009 payment, Seaport) | `{"type":"signature","chainId":8453,"typedData":{…the exact eth_signTypedData_v4 payload…}}` |
| Plain message | `{"type":"message","message":"…","method":"personal_sign"}` |
| EIP-7702 authorization (delegating your wallet to a contract) | `{"type":"authorization","chainId":8453,"address":"<the contract>","from":"<your wallet>"}`. This hands the contract your whole wallet: never sign it unless your user asked for that smart account by name. |
| Solana transaction | `{"type":"solana","transaction":"<base64 wire transaction>"}` |
| XRP Ledger transaction | `{"type":"xrpl","tx":{…unsigned transaction JSON…}}` |
| Algorand transaction or group | `{"type":"algorand","transaction":"<base64 msgpack>"}`, or `"transactions":[…]` for a group |

**Optional fields that catch more:**

- `"intent"`: one sentence on what you are trying to do, for example `"swap 10 USDC for ETH on Uniswap"`. Signing something else gives orange `INTENT_MISMATCH`.
- `"origin"`: the site asking for the signature. A domain under 30 days old is orange.
- `"x402"`: for an x402 payment, the `accepts` entry you chose. A signature that pays more, pays someone else or pays another token than the seller asked is caught.

**The answer:**

- `verdict`: green, orange or red.
- `reasons`: `[{ code, severity, subject, details }]`, for example `UNLIMITED_APPROVAL`, `SANCTIONED_ADDRESS`, `SOLANA_TOKEN_ACCOUNT_TAKEOVER` or `INTENT_MISMATCH`.
- With `from`: a `simulation` of what really changes in the wallet.
- A signed `receipt`.

**When a person needs the reason in plain words:** `POST /v1/check/explain` costs $0.03. Use the same body plus `"lang":"en"` or `"nl"`.

## 3. Before sending funds to an address

`GET https://presign-guard.fizzl.eu/v1/screen?address=<address>` costs $0.01.

- **Any chain:** EVM, Solana, Tron, Bitcoin, XRP Ledger or Algorand.
- **Red** when the address is on the OFAC SDN list, with the listing. For EVM addresses it is also red when reported for theft or phishing.

## 4. Cleaning up a wallet

`GET https://presign-guard.fizzl.eu/v1/approvals?chain=<chain>&address=<wallet>` costs $0.02. It lists every open token approval, who the spender is, and which ones to revoke.

`chain` is `base`, `ethereum`, `arbitrum`, `optimism`, `polygon` or `bsc`.

## Paying

Use the x402 client you already have. The checks take USDC on Base, Solana, Algorand or Stellar, RLUSD on the XRP Ledger, or MPP. With Coinbase's Agentic Wallet, for example:

```bash
npx awal@2.12.1 x402 pay "https://presign-guard.fizzl.eu/v1/check" -X POST \
  -d '{"type":"approval","chainId":8453,"token":"0x…","spender":"0x…","amount":"1000000"}' --max-amount 10000
```

`--max-amount 10000` is $0.01.

- **Checking often:** a prepaid pack costs $0.80 for 100 checks. `GET /v1/credits` (free) shows the prices. Send the returned key as the `x-credit-key` header instead of paying each time.
- **Invalid input** is refused before any payment, and a failed check is not charged.

## Input safety

- Pass addresses, transactions and typed data exactly as they will be signed. Never a summary or a guess.
- Put JSON bodies in single quotes.
- Reject values that contain quotes, backticks, `;`, `|` or `$(` before putting them in a shell command.

## Paying an x402 API

Before paying an x402 or MPP endpoint, check the seller too. Does it work, does it deliver, has it a track record? x402 Doctor's skill covers that: `npx skills add Fizzl13/x402-doctor`, skill `x402-preflight`.
