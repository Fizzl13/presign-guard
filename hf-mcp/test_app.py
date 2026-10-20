"""Offline tests for the Space (app.py): the sanctions index, the input checks and the unwrapping of presign-guard's
answers. presign-guard is never called."""

import unittest
from unittest import mock

import app

LIST = {
    "list": "OFAC SDN", "published": "2026-10-15", "count": 3, "checkedAt": "2026-10-20T08:04:23Z",
    "addresses": [
        {"address": "0x0330070fd38ec3bb94f58fa55d40368271e9e54a", "entries": [{"uid": 1, "name": "EXAMPLE ENTITY", "type": "Entity", "programs": ["DPRK4"], "currency": "ETH"}]},
        {"address": "bc1qexampleexampleexampleexample0", "entries": [{"uid": 2, "name": "EXAMPLE BTC", "type": "Entity", "programs": ["CYBER2"], "currency": "XBT"}]},
        {"address": "42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi", "entries": [{"uid": 3, "name": "EXAMPLE SOL", "type": "Individual", "programs": ["SDGT"], "currency": "SOL"}],
         "tokenAccounts": {"USDC": "B1jUqZENAXMJxBu3pX9v1yq2QDtMeXz1CUiFMr9hsi4f"}},
    ],
}


class Screen(unittest.TestCase):
    def setUp(self):
        app._list.update(at=0, index=None, meta=None)

    def test_matches_in_the_list_format_and_through_token_accounts(self):
        with mock.patch.object(app, "_get", return_value=(200, LIST)) as get:
            evm = app.screen_address("0x0330070FD38EC3BB94F58FA55D40368271E9E54A")
            btc = app.screen_address(" BC1QEXAMPLEEXAMPLEEXAMPLEEXAMPLE0 ")
            usdc = app.screen_address("B1jUqZENAXMJxBu3pX9v1yq2QDtMeXz1CUiFMr9hsi4f")
            sol_lower = app.screen_address("42rlpacwzpx3vyymxsueqsogfynbdqxk298edsnoyohi")
            clean = app.screen_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
        self.assertEqual(get.call_count, 1, "the list is read once and kept for an hour")
        self.assertTrue(evm["listed"])
        self.assertEqual(evm["entries"][0]["programs"], ["DPRK4"])
        self.assertTrue(btc["listed"], "bech32 is matched lowercased")
        self.assertEqual(usdc["token_account_of"], {"owner": "42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi", "token": "USDC"})
        self.assertFalse(sol_lower["listed"], "base58 is case-sensitive")
        self.assertFalse(clean["listed"])
        self.assertEqual(clean["list"]["published"], "2026-10-15")

    def test_a_failed_refresh_keeps_the_last_list(self):
        with mock.patch.object(app, "_get", return_value=(200, LIST)):
            app.screen_address("0x0330070fd38ec3bb94f58fa55d40368271e9e54a")
        app._list["at"] = 0
        with mock.patch.object(app, "_get", return_value=(503, {"error": "list_loading"})):
            self.assertTrue(app.screen_address("0x0330070fd38ec3bb94f58fa55d40368271e9e54a")["listed"])
        app._list.update(at=0, index=None, meta=None)
        with mock.patch.object(app, "_get", return_value=(503, {"error": "list_loading"})):
            self.assertEqual(app.screen_address("0xabc"), {"error": "list_loading"})

    def test_bad_input(self):
        with mock.patch.object(app, "_get") as get:
            self.assertIn("error", app.screen_address(""))
            self.assertIn("error", app.screen_address("two words"))
            get.assert_not_called()


class Tools(unittest.TestCase):
    def test_token_input_is_checked_and_the_limit_explained(self):
        with mock.patch.object(app, "_get") as get:
            self.assertIn("error", app.token_quick_verdict("dogechain", "x"))
            self.assertIn("error", app.token_quick_verdict("solana", " "))
            get.assert_not_called()
        with mock.patch.object(app, "_get", return_value=(429, {"error": "Free limit reached"})):
            self.assertIn("shared by everyone", app.token_quick_verdict("solana", "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263")["error"])
        with mock.patch.object(app, "_get", return_value=(200, {"verdict": "orange", "grade": "CAUTION"})) as get:
            self.assertEqual(app.token_quick_verdict("SOLANA", "Dez")["verdict"], "orange")
        self.assertEqual(get.call_args.kwargs["params"], {"chain": "solana", "address": "Dez"})

    def test_presign_request_must_be_a_typed_json_object(self):
        with mock.patch.object(app, "call_tool") as call:
            self.assertIn("must be JSON", app.presign_quick_check("{not json")["error"])
            self.assertIn("type is one of", app.presign_quick_check('{"type":"teleport"}')["error"])
            self.assertIn("type is one of", app.presign_quick_check("[1]")["error"])
            call.assert_not_called()
        with mock.patch.object(app, "call_tool", return_value={"verdict": "green"}) as call:
            self.assertEqual(app.presign_quick_check('{"type":"xrpl","tx":{"TransactionType":"Payment"}}'), {"verdict": "green"})
        call.assert_called_once_with("presign_quick_check", {"type": "xrpl", "tx": {"TransactionType": "Payment"}})

    def test_mcp_answers_are_unwrapped(self):
        def answer(body):
            res = mock.Mock(text=body)
            return mock.patch.object(app.requests, "post", return_value=res)
        with answer('{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"verdict":"red","note":"n"},"content":[]}}'):
            self.assertEqual(app.call_tool("presign_quick_check", {}), {"verdict": "red", "note": "n"})
        with answer('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"verdict\\":\\"orange\\"}"}]}}\n'):
            self.assertEqual(app.call_tool("presign_quick_check", {}), {"verdict": "orange"})
        with answer('{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"Free limit reached (10/hour)."}]}}'):
            self.assertIn("shared by everyone", app.call_tool("presign_quick_check", {})["error"])
        with answer('{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"chainId is required"}]}}'):
            self.assertEqual(app.call_tool("presign_quick_check", {}), {"error": "chainId is required"})


if __name__ == "__main__":
    unittest.main()
