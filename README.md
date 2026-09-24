# presign-guard

A pre-sign risk check for AI agents. Before an agent signs a transaction, approval, or EIP-712 signature, it pays a few cents per call over [x402](https://x402.org) and gets back a **green / orange / red** verdict with machine-readable reason codes. Optionally, it also gets a plain-language explanation in Dutch or English.

Part of [Klaartaal](https://github.com/Fizzl13/SmartContractExplainer) by [FIZZL AI](https://fizzl.eu).

## Endpoints

| Route | Price | Returns |
|---|---|---|
| `POST /v1/check` | $0.01 USDC | Verdict, reason codes, decoded subject |
| `POST /v1/check/explain` | $0.03 USDC | The same, plus a plain-language explanation (`lang: "nl"` or `"en"`) |
| `GET /health` | free | Liveness |
| `GET /openapi.json` | free | OpenAPI 3.1 spec with prices (`x-payment-info`) |
| `GET /.well-known/x402` | free | x402 discovery manifest |

Payment is x402 v2 with the `exact` scheme, in USDC on Base. The 402 carries Bazaar discovery metadata (input example, input and output schema), and the challenge is mirrored into the JSON body for clients that don't read the `PAYMENT-REQUIRED` header. **You are never charged for an error.** Invalid requests (400) and upstream outages (503) cancel settlement, and they always return `verdict: null`, never a guessed verdict.

## Request types

```jsonc
// Token approval
{ "type": "approval", "chainId": 8453, "token": "0x…", "spender": "0x…", "amount": "1000000" }

// Raw transaction (approve / increaseAllowance / setApprovalForAll are decoded)
{ "type": "transaction", "chainId": 8453, "to": "0x…", "data": "0x…", "value": "0" }

// EIP-712 signature: pass the eth_signTypedData_v4 payload as an object or JSON string
{ "type": "signature", "chainId": 8453, "typedData": { "domain": {…}, "types": {…}, "primaryType": "PermitSingle", "message": {…} } }
```

Supported chains: 1, 10, 56, 137, 8453, 42161.

Recognised signatures: EIP-2612 `Permit`, DAI-style permit, Permit2 (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`, batch and witness variants), EIP-3009 `TransferWithAuthorization` / `ReceiveWithAuthorization` (what x402 asks an agent to sign to pay), and Seaport `OrderComponents`.

An x402 payment moves one fixed amount to one recipient and grants no allowance, so paying a plain wallet is green (`PAYMENT_AUTHORIZATION`, info). It turns red if the recipient is flagged, and orange if the amount is effectively unlimited or the authorization stays valid for more than a month. Anything else comes back at least orange (`UNRECOGNIZED_SIGNATURE`).

## Response

```json
{
  "version": "2",
  "verdict": "red",
  "reasons": [
    { "code": "UNLIMITED_APPROVAL", "severity": "orange", "subject": "0x…", "details": { "token": "0x…" } },
    { "code": "SIGNATURE_GRANT_TO_EOA", "severity": "red", "subject": "0x…" }
  ],
  "subject": { "chainId": 8453, "kind": "permit2_allowance", "offchain": true, "grants": [ … ] },
  "scope": "…",
  "sources": ["goplus"],
  "checkedAt": "2026-09-23T12:00:00.000Z"
}
```

The verdict is the most severe reason: any `red` makes it red, otherwise any `orange` makes it orange. `info` reasons never change the verdict.

### Reason codes

| Severity | Codes |
|---|---|
| red | `PHISHING_ACTIVITIES`, `STEALING_ATTACK`, `SANCTIONED` and other GoPlus address flags, `CREATOR_OF_MALICIOUS_CONTRACTS`, `MALICIOUS_CONTRACT_BEHAVIOR`, `ON_DOUBT_LIST`, `UNLIMITED_APPROVAL_TO_EOA`, `SIGNATURE_GRANT_TO_EOA`, `ORDER_PAYS_YOU_NOTHING` |
| orange | `UNLIMITED_APPROVAL`, `UNLIMITED_TRANSFER`, `APPROVAL_FOR_ALL`, `APPROVAL_TO_EOA`, `SIGNATURE_TRANSFER`, `LONG_LIVED_PERMISSION`, `NONCANONICAL_PERMIT2`, `UNVERIFIED_CONTRACT`, `RECENTLY_DEPLOYED`, `MARKETPLACE_ORDER`, `UNRECOGNIZED_SIGNATURE`, `BLACKLIST_DOUBT`, `MIXER` |
| info | `EIP7702_DELEGATED_WALLET` (a plain wallet with EIP-7702 code, treated as a wallet), `PARTIAL_SOURCE_DATA` (GoPlus returned partial data for this address), `PAYMENT_AUTHORIZATION`, `REVOKES_APPROVAL`, `OFFCHAIN_SIGNATURE`, `SIGNATURE_EXPIRED`, `UPGRADEABLE_PROXY`, `ON_TRUST_LIST`, `UNDECODED_CALL` |

### Not covered

`eth_sign` and `personal_sign` messages, and transaction simulation. Treat a green verdict as "no known risk signals", not as a guarantee.

## Run locally

```bash
cp .env.example .env   # fill in PAY_TO and ANTHROPIC_API_KEY
npm install
npm test               # 36 tests, network mocked
npm run dev
```

## End-to-end payment test (Base Sepolia)

Fund a **throwaway** wallet with Base Sepolia test USDC, set `AGENT_PRIVATE_KEY` and `CHECK_URL` in `.env`, then run:

```bash
npm run client
```

The script makes a valid call, which should return 200 with a settlement receipt, and an invalid call, which should return 400 with no charge.

## Deploy to Render

`render.yaml` deploys on Base Sepolia by default. For mainnet, set `X402_NETWORK=eip155:8453` and add `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET` (Coinbase CDP facilitator). After the first paid call settles through CDP, the routes are listed in the CDP Bazaar.

`PAY_TO` must be an EVM address (`0x` + 40 hex characters). Surrounding spaces are trimmed; anything else stops the server at startup with a clear error, so a typo can't publish an unpayable 402.

## Data sources

Risk data comes from the [GoPlus Security API](https://gopluslabs.io), plus `eth_getCode` on a public RPC to recognise EIP-7702 wallets (override with `RPC_URL_<chainId>`). Explanations come from Claude (Anthropic).
