"""Canonical JSON for Fizzl signed receipts, in Python (no dependencies).

The signed bytes follow JavaScript, not Python's json.dumps: profile
js-json-stringify-sorted-utf16-ascii-v1.
- object keys sorted by UTF-16 code units, at every level (U+10000 sorts
  before U+E000);
- no whitespace, "," between entries, ":" between key and value;
- strings as JSON.stringify escapes them, then every code unit from U+007F up
  as lowercase \\uXXXX (a non-BMP character becomes two surrogate escapes);
- numbers as JSON.stringify writes them: 1.0 -> 1, 0.000001 -> 0.000001,
  1e-7 -> 1e-7, 1e21 -> 1e+21;
- then UTF-8 bytes.

json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True) gives the
same bytes only for ASCII keys and integers; it writes 1.0 and 1e-06.

    from canonical import canonical, verify_receipt
    verify_receipt(answer)  # -> the signer address (needs eth-account)
"""
import json
from decimal import Decimal


def js_number(x):
    """A number as JavaScript's JSON.stringify writes it."""
    if isinstance(x, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(x, int):
        if abs(x) <= 2**53 - 1:
            return str(x)
        x = float(x)  # beyond 2^53 JavaScript holds a double: mirror its rounding
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"
    sign, raw, exp = Decimal(repr(x)).as_tuple()  # repr: shortest round-trip digits, like JS
    k = exp + len(raw)  # the value is 0.DIGITS x 10^k
    digits = "".join(map(str, raw)).rstrip("0")
    n = len(digits)
    out = "-" if sign else ""
    if n <= k <= 21:
        out += digits + "0" * (k - n)
    elif 0 < k <= 21:
        out += digits[:k] + "." + digits[k:]
    elif -6 < k <= 0:
        out += "0." + "0" * (-k) + digits
    else:
        e = k - 1
        out += digits[0] + ("." + digits[1:] if n > 1 else "") + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return out


def js_string(s):
    """JSON.stringify escaping, then every code unit from U+007F up as lowercase \\uXXXX."""
    return json.dumps(s, ensure_ascii=True).replace("\x7f", "\\u007f")


def canonical(v):
    """The canonical JSON text of a parsed JSON value."""
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return js_number(v)
    if isinstance(v, str):
        return js_string(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(js_string(k) + ":" + canonical(v[k]) for k in keys) + "}"
    raise TypeError(f"not JSON: {type(v).__name__}")


def verify_receipt(answer):
    """The address that signed a Fizzl answer (EIP-191 personal_sign), or an exception.

    Compare it with answer["receipt"]["signer"] and with the published signers.
    """
    from eth_account import Account
    from eth_account.messages import encode_defunct

    receipt = dict(answer["receipt"])
    signature = receipt.pop("signature")
    message = canonical({**answer, "receipt": receipt})
    return Account.recover_message(encode_defunct(text=message), signature=signature)
