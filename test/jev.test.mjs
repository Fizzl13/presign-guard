// Jev second opinion (src/jev.js): Jev decides when sure, Claude decides in between, failures are silent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildQuestions, secondOpinion, jevEnabled, jevSelfTest, jevStatus } from "../src/jev.js";

const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const FAKE = "0x7777000000000000000000000000000000000002";
const env = { TYPESAFE_API_KEY: "ts-test", ANTHROPIC_API_KEY: "an-test" };

// A fetch stub: TypeSafe answers with the given probabilities, Claude with the given booleans.
function stub({ jev = {}, claude = {}, jevStatus = 200 } = {}) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body, headers: init.headers });
    if (url.startsWith("https://api.typesafe.ai/")) {
      if (jevStatus !== 200) return new Response("{}", { status: jevStatus });
      const answers = Object.fromEntries(Object.keys(body.questions).map((id) => [id, { type: "noul", noul: jev[id] ?? 0.02 }]));
      return Response.json({ model: "jev-test", answers, usage: { input_tokens: 1, output_tokens: 1 } });
    }
    return Response.json({ content: [{ type: "text", text: JSON.stringify(claude) }] });
  };
  return { fetch, calls };
}

test("off without a key, or with JEV_CHECK=off", async () => {
  assert.equal(jevEnabled({}), false);
  assert.equal(jevEnabled({ TYPESAFE_API_KEY: "x", JEV_CHECK: "off" }), false);
  const s = stub();
  assert.deepEqual(await secondOpinion({ chainId: 8453, origin: "x.test" }, { env: {}, fetch: s.fetch }), { reasons: [], sources: [] });
  assert.equal(s.calls.length, 0);
});

test("the real USDC is never asked about; a copy is", () => {
  const q = buildQuestions({ chainId: 8453, tokens: [{ address: USDC_BASE, symbol: "USDC", name: "USD Coin" }, { address: FAKE, symbol: "USDC", name: "USD Coin" }] });
  assert.deepEqual(Object.keys(q.questions), ["token_1_impersonates"]);
  assert.equal(q.state.token_1.address, FAKE);
  assert.equal(q.state.well_known_tokens_official_contracts.USDC, USDC_BASE);
  assert.equal(buildQuestions({ chainId: 8453, tokens: [{ address: USDC_BASE, symbol: "USDC" }] }), null);
});

test("Jev sure: orange by jev; in between: Claude decides; low: nothing", async () => {
  const s = stub({ jev: { site_imitates_brand: 0.97, site_lure: 0.6, token_0_impersonates: 0.3 }, claude: { site_lure: true } });
  const r = await secondOpinion({ chainId: 8453, origin: "uniswaap-claim.xyz", tokens: [{ address: FAKE, symbol: "USDC" }] }, { env, fetch: s.fetch });
  assert.deepEqual(r.reasons.map((x) => [x.code, x.severity, x.details.decidedBy]), [["AI_LOOKALIKE_SITE", "orange", "jev"], ["AI_LURE_SITE", "orange", "jev+claude"]]);
  assert.deepEqual(r.sources, ["typesafe-jev", "claude"]);
  assert.equal(s.calls[0].headers.authorization, "Bearer ts-test");
  assert.equal(s.calls[0].body.model, "jev-latest");
  assert.deepEqual(Object.keys(JSON.parse(s.calls[1].body.messages[0].content).questions), ["site_lure"]); // only the in-between one
});

test("Claude says no or is down: the in-between case adds nothing", async () => {
  const s = stub({ jev: { site_imitates_brand: 0.7 }, claude: { site_imitates_brand: false } });
  assert.deepEqual((await secondOpinion({ chainId: 8453, origin: "a.test" }, { env, fetch: s.fetch })).reasons, []);
  const noClaude = stub({ jev: { site_imitates_brand: 0.7 } });
  assert.deepEqual((await secondOpinion({ chainId: 8453, origin: "a.test" }, { env: { TYPESAFE_API_KEY: "k" }, fetch: noClaude.fetch })).reasons, []);
  assert.equal(noClaude.calls.length, 1);
});

test("TypeSafe failing (429, 529, network) is skipped silently", async () => {
  for (const status of [401, 429, 529]) {
    assert.deepEqual(await secondOpinion({ chainId: 8453, origin: "a.test" }, { env, fetch: stub({ jevStatus: status }).fetch }), { reasons: [], sources: [] });
  }
  const broken = async () => { throw new TypeError("fetch failed"); };
  assert.deepEqual(await secondOpinion({ chainId: 8453, origin: "a.test" }, { env, fetch: broken }), { reasons: [], sources: [] });
});

test("self-test for /health: off without a key, ok with an answer, failed on an error", async () => {
  assert.match((await jevSelfTest({ env: {} })).selfTest, /^off/);
  assert.match((await jevSelfTest({ env, fetch: stub({ jev: { site_imitates_brand: 0.97, site_lure: 0.91 } }).fetch })).selfTest, /^ok: brand imitation 97%, lure 91%/);
  assert.equal(jevStatus(env).on, true);
  assert.match((await jevSelfTest({ env, fetch: stub({ jevStatus: 401 }).fetch })).selfTest, /^failed/);
});

test("Solana: the USDC mint is matched exactly (base58 is case-sensitive)", () => {
  assert.equal(buildQuestions({ chainId: "solana", tokens: [{ address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", symbol: "USDC" }] }), null);
  const q = buildQuestions({ chainId: "solana", tokens: [{ address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1V", symbol: "USDC" }] });
  assert.equal(q.state.token_0.address, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1V");
});

test("signature domain: a contract named after Permit2 is asked about; the real Permit2 and tokens are not", async () => {
  const q = buildQuestions({ chainId: 8453, domain: { name: "Permit2", verifyingContract: FAKE } });
  assert.deepEqual(Object.keys(q.questions), ["domain_impersonates"]);
  assert.deepEqual(q.state.signature_domain, { name: "Permit2", verifying_contract: FAKE });
  assert.equal(buildQuestions({ chainId: 8453, domain: { name: "Permit2", verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" } }), null);
  assert.equal(buildQuestions({ chainId: 8453, domain: { name: "USD Coin", verifyingContract: USDC_BASE } }), null);
  // A permit for a token whose name is already asked about is not asked twice.
  const both = buildQuestions({ chainId: 8453, tokens: [{ address: FAKE, symbol: "USDC", name: "USD Coin" }], domain: { name: "USD Coin", verifyingContract: FAKE } });
  assert.deepEqual(Object.keys(both.questions), ["token_0_impersonates"]);
  const s = stub({ jev: { domain_impersonates: 0.94 } });
  const r = await secondOpinion({ chainId: 8453, domain: { name: "Uniswap V3", verifyingContract: FAKE } }, { env, fetch: s.fetch });
  assert.deepEqual(r.reasons.map((x) => [x.code, x.severity, x.subject, x.details.decidedBy]), [["AI_SIGNATURE_IMPERSONATION", "orange", FAKE, "jev"]]);
});
