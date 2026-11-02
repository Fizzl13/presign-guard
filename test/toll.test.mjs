// Toll (t0ll.xyz) as a source in /v1/token: the summary keeps only known fields, the key goes in x-toll-pass,
// failures are reported and skipped, and Toll's findings never change the verdict.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { tollCheck, summarizeToll, tollLink, clearTollCache, TOLL_CHAINS } from "../src/toll.js";

const TOKEN = "0xff9e86e6b21fd688027981bee4b64c8b6b804ed3";
const MINT = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
// Cut down from Toll's real answer for this token (2 Nov 2026).
const BODY = {
  token: TOKEN, sym: "TOLL", name: "Toll",
  headline: "Declared bundle of 1 wallet · 8 flagged wallets bought 5.9% · dev holds 1.2%",
  dev: { kin: { devs: 0, funder: "0x1111111111111111111111111111111111111111", launches: 0 }, addr: "0x5388872a6bbb5fd94533a4dab2a7a1cab02fa5bc", launches: 1, graduated: 0, secret: "x" },
  early: { snipers: 0, snipe_pct: 0, bundle_pct: 1.2, first_block_pct: 2.5, flagged: { wallets: 8, bought_pct: 5.9 } },
  flags: [
    { good: true, text: "the only wallet exempt from the opening tax is the dev's own", when: "launch" },
    { good: false, note: true, text: "first launch from this dev", when: "launch" },
    { good: false, text: "the dev sold 40% of supply in the first minute", when: "launch" },
    { text: "" },
  ],
  tally: { combined: { against: 1, careful: 1, clear: 1 } },
  quota: { left: 9 },
};

beforeEach(() => clearTollCache());

test("toll: covers Robinhood Chain, Solana and BSC; links to the token's page", () => {
  assert.deepEqual(Object.keys(TOLL_CHAINS).sort(), ["bsc", "robinhood", "solana"]);
  assert.equal(tollLink("robinhood", TOKEN), `https://t0ll.xyz/check/${TOKEN}`);
  assert.equal(tollLink("solana", MINT), `https://t0ll.xyz/sol/check/${MINT}`);
});

test("toll: the summary copies known fields only and labels each finding", () => {
  const s = summarizeToll(BODY, "robinhood", TOKEN);
  assert.equal(s.source, "Toll");
  assert.equal(s.link, `https://t0ll.xyz/check/${TOKEN}`);
  assert.deepEqual(s.dev, { address: "0x5388872a6bbb5fd94533a4dab2a7a1cab02fa5bc", launches: 1, graduated: 0, funder: "0x1111111111111111111111111111111111111111" });
  assert.equal(s.early_buyers.flagged_wallets, 8);
  assert.deepEqual(s.findings.map((f) => f.kind), ["good", "note", "against"]);
  assert.deepEqual(s.tally, { against: 1, careful: 1, clear: 1 });
  assert.ok(!JSON.stringify(s).includes("secret") && !("quota" in s));
});

test("toll: sends the partner key as x-toll-pass, asks once per token, and caches a whole answer", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => { seen.push({ url: String(url), headers: init.headers }); return Response.json(BODY); };
  const env = { TOLL_PASS: "key-123" };
  const a = await tollCheck("robinhood", TOKEN.toUpperCase().replace("0X", "0x"), { env, fetchImpl });
  const b = await tollCheck("robinhood", TOKEN, { env, fetchImpl });
  assert.ok(a.data && b.data);
  assert.equal(seen.length, 1, "second ask comes from the cache");
  assert.match(seen[0].url, /^https:\/\/t0ll\.xyz\/api\/check\?addr=.*&chain=rh&wait=1$/);
  assert.equal(seen[0].headers["x-toll-pass"], "key-123");
  const c = await tollCheck("solana", MINT, { env: {}, fetchImpl });
  assert.ok(c.data);
  assert.match(seen[1].url, /chain=sol/);
  assert.ok(!("x-toll-pass" in seen[1].headers), "no key, no header");
});

test("toll: still reading, rate limited, down or off is an error, never thrown and not cached", async () => {
  let status = 202;
  const fetchImpl = async () => (status === 0 ? Promise.reject(new TypeError("fetch failed")) : new Response("{}", { status }));
  assert.equal((await tollCheck("robinhood", TOKEN, { fetchImpl })).error, "still reading");
  status = 429;
  assert.equal((await tollCheck("robinhood", TOKEN, { fetchImpl })).error, "rate limited");
  status = 0;
  assert.equal((await tollCheck("robinhood", TOKEN, { fetchImpl })).error, "unavailable");
  assert.equal((await tollCheck("robinhood", TOKEN, { env: { TOLL: "off" }, fetchImpl: () => assert.fail("asked while off") })).error, "off");
  assert.equal((await tollCheck("base", TOKEN, { fetchImpl: () => assert.fail("base is not Toll's") })).error, "chain not covered by Toll");
});
