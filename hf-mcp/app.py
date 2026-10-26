"""presign-guard on Hugging Face: a Gradio app that is also an MCP server.

Three free tools around presign-guard (https://presign-guard.fizzl.eu). Nothing here pays, signs or holds a key: the
paid checks with their reasons ($0.01 over x402) stay on presign-guard itself.

- screen_address: is an address on the OFAC SDN list of digital currency addresses? Matched here, in the Space, against
  presign-guard's open copy of the list (GET /v1/sanctions, read at most once an hour), so it has no call limit.
- token_quick_verdict: green / orange / red and a grade for a token an agent is about to buy, hold or accept
  (GET /v1/token/quick).
- presign_quick_check: green / orange / red for a transaction, approval, signature, EIP-7702 authorization, XRP Ledger
  or Algorand transaction an agent is about to sign (presign-guard's free MCP tool of the same name).

The last two share presign-guard's free limit of 10 calls an hour per caller, and every user of this Space is one caller.
"""

import json
import os
import re
import time

import gradio as gr
import requests

GUARD = os.environ.get("PRESIGN_GUARD_URL", "https://presign-guard.fizzl.eu").rstrip("/")
USER_AGENT = "presign-guard-hf-space/1.0 (+https://huggingface.co/spaces/x402Fizzl/presign-guard)"
TIMEOUT = 60
LIST_TTL = 3600
TOKEN_CHAINS = ["solana", "base", "ethereum", "arbitrum", "optimism", "polygon", "bsc", "robinhood", "xrpl", "algorand"]
SIGN_TYPES = ["approval", "transaction", "signature", "authorization", "message", "solana", "xrpl", "algorand", "stellar"]
EXAMPLE_CHECK = {"type": "approval", "chainId": 8453, "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "spender": "0x1111111254EEB25477B68fb85Ed929f73A960582", "amount": "1000000"}
LIMITED = (
    "presign-guard's free limit is reached for this Space (10 calls an hour, shared by everyone using it). "
    "Try again later, or call presign-guard directly: its MCP server https://presign-guard.fizzl.eu/mcp has the same free tool, "
    "and the paid checks ($0.01 over x402) return the reasons too."
)

_list = {"at": 0, "index": None, "meta": None}


def _get(path, **kwargs):
    """presign-guard's answer as (status, JSON), or (status, {"error": ...}) when it isn't JSON or can't be reached."""
    try:
        res = requests.get(f"{GUARD}{path}", headers={"user-agent": USER_AGENT, "accept": "application/json"}, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as err:
        return 0, {"error": f"presign-guard could not be reached: {err}"}
    try:
        return res.status_code, res.json()
    except ValueError:
        return res.status_code, {"error": f"presign-guard answered HTTP {res.status_code} without JSON"}


def normalize(address):
    """The form the list uses: EVM (0x…) and bech32 (bc1…, ltc1…) lowercased, every other format as written."""
    a = (address or "").strip()
    return a.lower() if re.match(r"^(0x[0-9a-f]{40}|(bc|tb|ltc)1[0-9a-z]{6,87})$", a, re.I) else a


def build_index(data):
    """Address → its entries; a Solana owner's USDC and USDT token accounts point at the owner (a token transfer names
    the token account, not the owner)."""
    index = {}
    for item in data.get("addresses") or []:
        address = normalize(item.get("address"))
        if not address:
            continue
        index[address] = {"entries": item.get("entries") or []}
        for token, account in (item.get("tokenAccounts") or {}).items():
            index[account] = {"entries": item.get("entries") or [], "token_account_of": {"owner": item.get("address"), "token": token}}
    return index


def sanctions_index():
    """The list, read from presign-guard at most once an hour; the last copy stays when a refresh fails."""
    if _list["index"] is not None and time.time() - _list["at"] < LIST_TTL:
        return _list["index"], _list["meta"], None
    status, data = _get("/v1/sanctions")
    if status == 200 and isinstance(data.get("addresses"), list):
        _list.update(at=time.time(), index=build_index(data), meta={k: data.get(k) for k in ("list", "published", "count", "checkedAt")})
        return _list["index"], _list["meta"], None
    if _list["index"] is not None:
        return _list["index"], _list["meta"], None
    return None, None, data.get("error") or f"the list could not be read (HTTP {status})"


def screen_address(address: str) -> dict:
    """Is this address on the OFAC SDN list? Screen a counterparty before your agent pays it, signs for it or accepts its funds.

    Matches the address against every digital currency address on the US Treasury's OFAC SDN list (Bitcoin, Ethereum
    and EVM chains, Tron, Solana with its USDC and USDT token accounts, and more), from presign-guard's open copy of the
    list, which it refreshes from the Treasury every 6 hours. A match names the listed entity and its sanctions programs.
    Free and unlimited.

    Args:
        address: The address to screen, in its own chain's format (0x…, bc1…, T…, a Solana base58 address, …).
    """
    target = normalize(address)
    if not target or len(target) > 128 or re.search(r"\s", target):
        return {"error": "address must be one blockchain address"}
    index, meta, error = sanctions_index()
    if index is None:
        return {"error": error}
    hit = index.get(target)
    out = {"address": target, "listed": bool(hit), "list": meta}
    if hit:
        out["entries"] = [{k: e.get(k) for k in ("name", "type", "programs", "currency", "uid") if e.get(k) is not None} for e in hit["entries"]]
        if hit.get("token_account_of"):
            out["token_account_of"] = hit["token_account_of"]
        out["advice"] = "Don't pay, sign for or accept funds from this address: dealing with it can break US sanctions law."
    else:
        out["note"] = "Not on the list. The list covers addresses OFAC names; it says nothing about addresses that merely traded with them."
    return out


def token_quick_verdict(chain: str, address: str) -> dict:
    """A quick green / orange / red verdict and a grade (SAFE, CAUTION, RISKY, AVOID) for a token your agent is about to buy, hold or accept.

    presign-guard checks mint and freeze authority, honeypots, taxes and transfer fees, liquidity, the token's age,
    concentrated holders and rug pulls. This free version returns the verdict and grade only; the reasons, a one-line
    summary and market data are in presign-guard's paid GET /v1/token ($0.01 over x402).

    Args:
        chain: The chain the token lives on: solana, base, ethereum, arbitrum, optimism, polygon, bsc, robinhood, xrpl or algorand.
        address: A Solana mint (base58), an EVM token contract (0x…), an XRPL token as CURRENCY.rIssuer, or an Algorand asset id.
    """
    chain = (chain or "").strip().lower()
    address = (address or "").strip()
    if chain not in TOKEN_CHAINS:
        return {"error": f"chain must be one of: {', '.join(TOKEN_CHAINS)}"}
    if not address:
        return {"error": "address is required"}
    status, body = _get("/v1/token/quick", params={"chain": chain, "address": address})
    if status == 429:
        return {"error": LIMITED}
    return body if status == 200 or "error" in body else {"error": f"HTTP {status}", **body}


def presign_quick_check(request: str) -> dict:
    """A quick green / orange / red verdict for what your agent is about to sign, before it signs.

    Covers EVM transactions, token approvals, EIP-712 signatures (Permit, Permit2, orders), EIP-7702 authorizations,
    plain messages, Solana transactions, XRP Ledger transactions (including Batch, delegation and MPTs) and Algorand
    transactions. This free version returns the verdict only; the reason codes are in presign-guard's paid check
    ($0.01 over x402, POST https://presign-guard.fizzl.eu/v1/check), which also signs a receipt.

    Args:
        request: What the agent is about to sign, as JSON with a "type" (approval, transaction, signature, authorization, message, solana, xrpl, algorand or stellar) and its fields, for example {"type":"approval","chainId":8453,"token":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","spender":"0x1111111254EEB25477B68fb85Ed929f73A960582","amount":"1000000"}, or {"type":"xrpl","tx":{"TransactionType":"Payment",…}}.
    """
    try:
        args = json.loads(request) if isinstance(request, str) else request
    except ValueError as err:
        return {"error": f"request must be JSON: {err}"}
    if not isinstance(args, dict) or args.get("type") not in SIGN_TYPES:
        return {"error": f"request must be a JSON object whose type is one of: {', '.join(SIGN_TYPES)}"}
    return call_tool("presign_quick_check", args)


def call_tool(name, args):
    """Call a tool on presign-guard's MCP server (stateless; it answers plain JSON or one SSE event) and unwrap the result."""
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
    try:
        res = requests.post(f"{GUARD}/mcp", json=call, headers={"user-agent": USER_AGENT, "accept": "application/json, text/event-stream"}, timeout=TIMEOUT)
        text = res.text
        if text.startswith("event:") or "\ndata:" in text:
            text = next((line[5:].strip() for line in text.splitlines() if line.startswith("data:")), "")
        data = json.loads(text)
    except (requests.RequestException, ValueError) as err:
        return {"error": f"presign-guard could not be reached: {err}"}
    if data.get("error"):
        return {"error": data["error"].get("message", "presign-guard refused the call")}
    result = data.get("result") or {}
    message = " ".join(c.get("text", "") for c in result.get("content") or [] if c.get("type") == "text")
    if result.get("isError"):
        return {"error": LIMITED if "Free limit" in message else message or "presign-guard could not check this"}
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    try:
        return json.loads(message)
    except ValueError:
        return {"error": "presign-guard answered without a verdict"}


ABOUT = f"""# presign-guard

Free safety checks for AI agents with a wallet, before they pay, sign or accept a token. Nothing is paid or signed here.
These three tools are also an **MCP server**: add this Space in your [Hugging Face MCP settings](https://huggingface.co/settings/mcp),
or connect any MCP client to `https://x402fizzl-presign-guard.hf.space/gradio_api/mcp/`.

The full checks, with every reason and a signed receipt, are on [{GUARD.replace('https://', '')}]({GUARD}) ($0.01 over x402).
"""

with gr.Blocks(title="presign-guard") as demo:
    gr.Markdown(ABOUT)
    with gr.Tab("Screen an address"):
        addr_in = gr.Textbox(label="Address", placeholder="0x…, bc1…, T…, or a Solana address")
        addr_out = gr.JSON(label="OFAC SDN list")
        gr.Button("Screen", variant="primary").click(screen_address, [addr_in], addr_out, api_name="screen_address")
    with gr.Tab("Token"):
        chain_in = gr.Dropdown(choices=TOKEN_CHAINS, value="solana", label="Chain")
        token_in = gr.Textbox(label="Token", placeholder="mint, 0x contract, CURRENCY.rIssuer or asset id")
        token_out = gr.JSON(label="Verdict")
        gr.Button("Check", variant="primary").click(token_quick_verdict, [chain_in, token_in], token_out, api_name="token_quick_verdict")
    with gr.Tab("Before signing"):
        sign_in = gr.Code(label="What the agent is about to sign (JSON)", language="json", value=json.dumps(EXAMPLE_CHECK, indent=2))
        sign_out = gr.JSON(label="Verdict")
        gr.Button("Check", variant="primary").click(presign_quick_check, [sign_in], sign_out, api_name="presign_quick_check")

if __name__ == "__main__":
    demo.launch(mcp_server=True)
