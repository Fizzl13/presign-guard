// A second opinion on the things fixed rules see badly: does the requesting site's name imitate a known
// crypto brand or lure with free tokens, and does a token's name pretend to be a token it isn't?
// TypeSafe's Jev answers first (a probability, in well under a second). When Jev is clearly sure, its
// answer stands; when it is in between, Claude decides. Either way the result can only ADD an orange
// reason: it never turns a verdict green and never makes one red on its own.
//
// Off unless TYPESAFE_API_KEY is set (JEV_CHECK=off turns it off again). Any failure (timeout, error,
// rate limit) is skipped silently: the rule-based verdict stands as it was.
//
// Env: TYPESAFE_API_KEY, optional JEV_CHECK=off, JEV_SURE (default 0.85), JEV_UNSURE (default 0.5),
//      JEV_TIMEOUT_MS (default 2500), JEV_MODEL (default jev-latest); escalation uses ANTHROPIC_API_KEY.

const API = "https://api.typesafe.ai/v1/systemone";
const num = (v, d) => (Number.isFinite(Number(v)) && v !== undefined && v !== "" ? Number(v) : d);

// Official contracts of the tokens scammers copy most, per chain: a token at one of these addresses is
// the real one and is not asked about.
const OFFICIAL = {
  1: { USDC: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", USDT: "0xdac17f958d2ee523a2206206994597c13d831ec7", WETH: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", DAI: "0x6b175474e89094c44da98b954eedeac495271d0f", WBTC: "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599" },
  8453: { USDC: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", WETH: "0x4200000000000000000000000000000000000006", cbBTC: "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf", EURC: "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42", DAI: "0x50c5725949a6f0c72e6c4a641f24049a917db0cb" },
  42161: { USDC: "0xaf88d065e77c8cc2239327c5edb3a432268e5831", USDT: "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", WETH: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1" },
  10: { USDC: "0x0b2c639c533813f4aa9d7837caf62653d097ff85", USDT: "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58", WETH: "0x4200000000000000000000000000000000000006" },
  137: { USDC: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", USDT: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", WETH: "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619" },
  56: { USDC: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", USDT: "0x55d398326f99059ff775485246999027b3197955" },
  solana: { USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", USDT: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", wSOL: "So11111111111111111111111111111111111111112" },
};
// EVM addresses compare case-insensitively; Solana mints exactly.
const norm = (a) => (/^0x/i.test(String(a)) ? String(a).toLowerCase() : String(a));

export function jevEnabled(env = process.env) {
  return Boolean(env.TYPESAFE_API_KEY) && env.JEV_CHECK !== "off";
}

// The questions for one check. Returns { state, questions, meta } or null when there is nothing to ask.
export function buildQuestions({ chainId, origin = null, tokens = [], skipSite = false, skipTokens = new Set() }) {
  const official = OFFICIAL[chainId] ?? {};
  const officialAddresses = new Set(Object.values(official).map(norm));
  const questions = {};
  const meta = {};
  const state = { chain_id: chainId, well_known_tokens_official_contracts: official };

  if (origin && !skipSite) {
    state.site = origin;
    questions.site_imitates_brand = {
      type: "noul",
      instructions: "The domain `site` asked a crypto wallet user to sign a transaction or signature. Does this domain imitate a well-known crypto project, exchange, wallet or token brand without being that brand's official domain (for example a misspelling, the brand name with extra words, or an unusual top-level domain)?",
      criteria: { true: "The domain copies or closely resembles a known brand it does not belong to", false: "The domain is a brand's own official domain, or does not resemble any known crypto brand" },
    };
    questions.site_lure = {
      type: "noul",
      instructions: "Does the domain `site` itself advertise free tokens, an airdrop, a claim, a giveaway, a reward or a wallet 'fix' or 'verification'?",
      criteria: { true: "The domain name promises something free or urges an urgent wallet action", false: "The domain name makes no such promise" },
    };
    meta.site_imitates_brand = { code: "AI_LOOKALIKE_SITE", subject: origin };
    meta.site_lure = { code: "AI_LURE_SITE", subject: origin };
  }

  tokens.slice(0, 4).forEach((t, i) => {
    if (!t?.address || skipTokens.has(t.address) || officialAddresses.has(norm(t.address))) return;
    if (!t.symbol && !t.name) return;
    const key = `token_${i}`;
    state[key] = { address: norm(t.address), symbol: t.symbol ?? null, name: t.name ?? null };
    questions[`${key}_impersonates`] = {
      type: "noul",
      instructions: `Does the token \`${key}\` present itself, by its symbol or name, as a well-known token or brand it is not? Its contract address is not one of the official contracts in \`well_known_tokens_official_contracts\`.`,
      criteria: { true: "The symbol or name claims to be, or closely copies, a famous token or brand (for example USDC, USDT, ETH or a big project) while it is a different contract", false: "The symbol and name are its own and do not pretend to be another known token" },
    };
    meta[`${key}_impersonates`] = { code: "AI_TOKEN_IMPERSONATION", subject: state[key].address };
  });

  return Object.keys(questions).length ? { state, questions, meta } : null;
}

// Ask Jev. Returns { id: probability } or null on any failure.
export async function askJev({ state, questions }, { env = process.env, fetch: fetchImpl = globalThis.fetch } = {}) {
  try {
    const res = await fetchImpl(API, {
      method: "POST",
      headers: { authorization: `Bearer ${env.TYPESAFE_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: env.JEV_MODEL || "jev-latest", state, questions }),
      signal: AbortSignal.timeout(num(env.JEV_TIMEOUT_MS, 2500)),
    });
    if (!res.ok) { console.warn(`[jev] HTTP ${res.status}`); return null; }
    const body = await res.json();
    const out = {};
    for (const id of Object.keys(questions)) {
      const p = body?.answers?.[id]?.noul;
      if (typeof p === "number" && p >= 0 && p <= 1) out[id] = p;
    }
    return out;
  } catch (err) {
    console.warn(`[jev] ${err.name}: ${err.message}`);
    return null;
  }
}

// Claude decides the in-between cases: one yes/no per question, as JSON. Returns { id: true|false } or {}.
export async function askClaude({ state, questions }, ids, { env = process.env, fetch: fetchImpl = globalThis.fetch } = {}) {
  if (!env.ANTHROPIC_API_KEY || !ids.length) return {};
  const asked = Object.fromEntries(ids.map((id) => [id, questions[id].instructions]));
  try {
    const res = await fetchImpl("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: env.CLAUDE_MODEL ?? "claude-haiku-4-5-20251001",
        max_tokens: 200,
        system: "You review crypto signing requests for phishing signs. Answer each question about the given state with true or false. Be strict: say true only when the sign is clearly there. Reply with only a JSON object mapping each question id to true or false.",
        messages: [{ role: "user", content: JSON.stringify({ state, questions: asked }) }],
      }),
      signal: AbortSignal.timeout(num(env.JEV_TIMEOUT_MS, 2500) * 2),
    });
    if (!res.ok) return {};
    const body = await res.json();
    const text = body?.content?.filter((b) => b.type === "text").map((b) => b.text).join("") ?? "";
    const json = JSON.parse(text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1));
    return Object.fromEntries(ids.filter((id) => typeof json[id] === "boolean").map((id) => [id, json[id]]));
  } catch {
    return {};
  }
}

// The whole second opinion: returns { reasons: [{code, severity, subject, details}], sources: [...] }.
export async function secondOpinion(input, opts = {}) {
  const env = opts.env ?? process.env;
  const empty = { reasons: [], sources: [] };
  if (!jevEnabled(env)) return empty;
  const q = buildQuestions(input);
  if (!q) return empty;
  const probs = await askJev(q, opts);
  if (!probs) return empty;
  const sure = num(env.JEV_SURE, 0.85), unsure = num(env.JEV_UNSURE, 0.5);
  const reasons = [];
  const between = Object.entries(probs).filter(([, p]) => p >= unsure && p < sure).map(([id]) => id);
  const claude = await askClaude(q, between, opts);
  for (const [id, p] of Object.entries(probs)) {
    const { code, subject } = q.meta[id];
    const details = { probability: Math.round(p * 100) / 100 };
    if (p >= sure) reasons.push({ code, severity: "orange", subject, details: { ...details, decidedBy: "jev" } });
    else if (claude[id] === true) reasons.push({ code, severity: "orange", subject, details: { ...details, decidedBy: "jev+claude" } });
  }
  return { reasons, sources: ["typesafe-jev", ...(between.length && Object.keys(claude).length ? ["claude"] : [])] };
}

// Shown in GET /health, so the owner can see Jev works without a paid check (no key, no answers about users).
const status = { on: false, selfTest: "not run", at: null };
export function jevStatus(env = process.env) {
  return { on: jevEnabled(env), selfTest: status.selfTest, at: status.at };
}

// At startup: one known-bad example. "ok" when Jev answers and calls it a brand imitation.
export async function jevSelfTest(opts = {}) {
  const env = opts.env ?? process.env;
  if (!jevEnabled(env)) { status.selfTest = "off (no TYPESAFE_API_KEY)"; return status; }
  const q = buildQuestions({ chainId: 8453, origin: "uniswap-airdrop-claim.xyz" });
  const probs = await askJev(q, { ...opts, env });
  status.at = new Date().toISOString();
  if (!probs || typeof probs.site_imitates_brand !== "number") status.selfTest = "failed: no answer from TypeSafe (key, network or rate limit; see the log)";
  else status.selfTest = `ok: brand imitation ${Math.round(probs.site_imitates_brand * 100)}%, lure ${Math.round((probs.site_lure ?? 0) * 100)}%`;
  console.log(`[jev] self-test ${status.selfTest}`);
  return status;
}
