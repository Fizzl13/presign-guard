# Explainer video

A ~55-second narrated walkthrough of presign-guard.

- `script.json`: the narration, one segment per scene (captions use the same text).
- `tts.py`: the voice (Kokoro, open weights); `--engine silent` for timing tests.
- `engine.mjs`: the same check code as the live service, without the paywall, on localhost.
  The verdicts in the video are real (live GoPlus data) and nobody pays.
- `record.js`: drives a real browser through the homepage, timed to the voice. It stops if a
  preset does not give the expected verdict (unlimited approval orange, permit to a wallet red,
  x402 payment green). The price in the agent scene comes from the live 402.
- `build.py`: mixes the voice onto the recording (loudness -16 LUFS), writes the MP4,
  captions (SRT) and a poster frame.

`token.json` is a ~45-second update about the token verdict (`GET /v1/token`): real
verdicts on live data (Bonk SAFE, a token launched today RISKY, USDC SAFE with its issuer
powers as context), checked against the narration before recording. Pick it as the
workflow's script; it publishes to the `token-video` branch as
`presign-guard-token.mp4`. Locally: `SCRIPT=token.json` for tts.py, record.js and build.py.

`screen.json` is a ~60-second video about the wallet sanctions screen (`GET /v1/screen`), made for
the x402 Foundation grant application: real verdicts from the same screen code on the US
Treasury's SDN list (a Tron address of Bank Markazi red, vitalik.eth green, a Lazarus Group
address red and reported for theft), GoPlus's live answer for the same Tron address
(`sanctioned: "0"`), the live 402 price, the free open list, and a real $0.01 payment for the
same call on Base. `record.js` stops if any of those no longer match the narration. It is the
workflow's default and publishes to the `screen-video` branch as `presign-guard-sanctions.mp4`.

Run it with the **Explainer video** workflow (Actions tab). The result is published to the
`explainer-video` branch and attached to the run.

Local test without network access:

```sh
python tts.py --engine silent
MOCK_GOPLUS=1 node engine.mjs &
MOCK_LIVE=1 node record.js
python build.py
```
