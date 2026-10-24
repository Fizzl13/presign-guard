#!/bin/sh
# An Open Wallet Standard (OWS) custom executable policy: presign-guard judges every transaction, typed-data
# signature and message an agent token asks OWS to sign, before OWS decrypts the key. OWS writes the PolicyContext
# to stdin and reads { "allow": …, "reason": … } from stdout; presign-guard answers in that shape.
#
# Put a credit key (GET https://presign-guard.fizzl.eu/v1/credits/100, $0.80 for 100 checks) in ~/.ows/presign-guard.key.
# No key or no credits left: the 402 says so with "allow": false. presign-guard unreachable or slower than 4.8 s: curl fails,
# and OWS denies. Fail closed.
exec curl -s --max-time 4.8 -X POST https://presign-guard.fizzl.eu/v1/check \
  -H 'content-type: application/json' \
  -H "x-credit-key: $(cat "$HOME/.ows/presign-guard.key")" \
  --data-binary @-
