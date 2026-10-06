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
// Contracts of the protocols whose names permit-phishing copies most, the same address on every EVM chain
// they run on. A signature whose domain.verifyingContract is one of these (or an official token) is not asked about.
const OFFICIAL_PROTOCOLS = {
  Permit2: "0x000000000022d473030f116ddee9f6b43ac78ba3",
  "Seaport 1.5": "0x00000000000000adc04c56bf30ac9d3c0aaf14dc",
  "Seaport 1.6": "0x0000000000000068f116a894984e2db1123eb395",
  "CoW Protocol (GPv2Settlement)": "0x9008d19f58aabd9ed0d60971565aa8510560ab41",
  "UniswapX (ExclusiveDutchOrderReactor)": "0x6000da47483062a0d734ba3dc7576ce6a0b645c4",
  "1inch Aggregation Router v6": "0x111111125421ca6dc452d289314280a0f8842a65",
  "1inch Aggregation Router v5": "0x1111111254eeb25477b68fb85ed929f73a960582",
};
// Code rules for what Jev was weakest at in the calibration of 6 Oct 2026 (60 real dapp domains, 200 real Base
// tokens, made-up phishing): a dapp's domain with its dot turned into a hyphen or with another top-level domain
// (pump-fun.io, revoke-cash.app, jup-ag.net scored 22-51%), and a signature that calls itself by the exact name
// of a famous protocol, wallet or token while its contract is not that one ("Permit2", "Seaport", "Coinbase"
// scored 45-84%). These are decided here, without asking Jev, and are orange like Jev's sure answers.
const DAPP_DOMAINS = [
  "uniswap.org", "opensea.io", "aave.com", "curve.fi", "jup.ag", "raydium.io", "pump.fun", "revoke.cash", "lido.fi", "blur.io",
  "magiceden.io", "1inch.io", "cow.fi", "ens.domains", "metamask.io", "phantom.app", "coinbase.com", "morpho.org",
  "aerodrome.finance", "pancakeswap.finance", "safe.global", "hyperliquid.xyz", "eigenlayer.xyz", "pendle.finance", "ether.fi",
  "across.to", "stargate.finance", "zora.co", "rabby.io", "kraken.com", "binance.com", "etherscan.io", "basescan.org", "dexscreener.com",
];
const PROTOCOL_NAMES = /^(permit2|seaport( \d(\.\d)?)?|opensea|uniswap( v[234])?|uniswapx|uniswap permit2|1inch( .*)?|usd coin|tether usd|metamask|coinbase( wallet)?|cow protocol|gpv2settlement|blur|magic eden|phantom)$/i;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export function lookalikeOf(origin) {
  const host = String(origin || "").toLowerCase().replace(/^[a-z]+:\/\//, "").split(/[/:?#]/)[0];
  if (!host) return null;
  for (const brand of DAPP_DOMAINS) {
    if (host === brand || host.endsWith(`.${brand}`)) return null;
    const [label, ...rest] = brand.split(".");
    const tld = rest.join(".");
    // The brand's label and TLD glued or hyphenated as their own label run (pump-fun.io, app-uniswap-org.xyz),
    // or the brand's label on another TLD as the whole registrable name (jup.ag -> jup.net is not caught: too short).
    const glued = new RegExp(`(^|[.-])${escapeRe(label)}-?${escapeRe(tld.replace(/\./g, "-?"))}([.-]|$)`);
    if (glued.test(host) && label.length + tld.length >= 5) return brand;
  }
  return null;
}
export function protocolNameOf(name) {
  const n = String(name || "").trim();
  return n && PROTOCOL_NAMES.test(n) ? n : null;
}

// EVM addresses compare case-insensitively; Solana mints exactly.
const norm = (a) => (/^0x/i.test(String(a)) ? String(a).toLowerCase() : String(a));

export function jevEnabled(env = process.env) {
  return Boolean(env.TYPESAFE_API_KEY) && env.JEV_CHECK !== "off";
}

// The questions for one check. Returns { state, questions, meta } or null when there is nothing to ask.
export function buildQuestions({ chainId, origin = null, tokens = [], skipSite = false, skipTokens = new Set(), domain = null }) {
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

  // The name a signature request shows the user (EIP-712 domain.name): permit phishing names its own
  // contract "Permit2", "Uniswap" or "USD Coin" so the wallet shows a trusted name.
  const dname = typeof domain?.name === "string" ? domain.name.trim().slice(0, 64) : "";
  const verifying = domain?.verifyingContract ? norm(domain.verifyingContract) : null;
  const protocolAddresses = new Set(Object.values(OFFICIAL_PROTOCOLS));
  const askedAsToken = tokens.some((t) => t?.address && norm(t.address) === verifying && (t.name === dname || t.symbol === dname));
  if (dname && verifying && !officialAddresses.has(verifying) && !protocolAddresses.has(verifying) && !askedAsToken) {
    state.signature_domain = { name: dname, verifying_contract: verifying };
    state.well_known_protocol_contracts = OFFICIAL_PROTOCOLS;
    questions.domain_impersonates = {
      type: "noul",
      instructions: "A wallet shows `signature_domain.name` as the name of the contract asking for a signature. Does that name present itself as a well-known protocol, wallet or token (for example Permit2, Uniswap, OpenSea, Seaport, 1inch, USDC or USD Coin)? The contract `signature_domain.verifying_contract` is not one of the official contracts in `well_known_protocol_contracts` or `well_known_tokens_official_contracts`.",
      criteria: { true: "The name claims to be, or closely copies, a famous protocol, wallet or token it is not", false: "The name is the contract's own and does not pretend to be another known project" },
    };
    meta.domain_impersonates = { code: "AI_SIGNATURE_IMPERSONATION", subject: verifying };
  }

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
  const q = buildQuestions(input);
  if (!q) return { reasons: [], sources: [] };
  // The code rules first (they need no key); what they decide is not asked again.
  const ruled = [];
  const look = q.questions.site_imitates_brand ? lookalikeOf(q.state.site) : null;
  if (look) {
    ruled.push({ code: "AI_LOOKALIKE_SITE", severity: "orange", subject: q.state.site, details: { decidedBy: "rule", imitates: look } });
    delete q.questions.site_imitates_brand;
  }
  const pname = q.questions.domain_impersonates ? protocolNameOf(q.state.signature_domain?.name) : null;
  if (pname) {
    ruled.push({ code: "AI_SIGNATURE_IMPERSONATION", severity: "orange", subject: q.meta.domain_impersonates.subject, details: { decidedBy: "rule", name: pname } });
    delete q.questions.domain_impersonates;
  }
  const empty = { reasons: ruled, sources: ruled.length ? ["rules"] : [] };
  if (!jevEnabled(env) || !Object.keys(q.questions).length) return empty;
  const probs = await askJev(q, opts);
  if (!probs) return empty;
  const sure = num(env.JEV_SURE, 0.85), unsure = num(env.JEV_UNSURE, 0.5);
  const reasons = [...ruled];
  const between = Object.entries(probs).filter(([, p]) => p >= unsure && p < sure).map(([id]) => id);
  const claude = await askClaude(q, between, opts);
  for (const [id, p] of Object.entries(probs)) {
    const { code, subject } = q.meta[id];
    const details = { probability: Math.round(p * 100) / 100 };
    if (p >= sure) reasons.push({ code, severity: "orange", subject, details: { ...details, decidedBy: "jev" } });
    else if (claude[id] === true) reasons.push({ code, severity: "orange", subject, details: { ...details, decidedBy: "jev+claude" } });
  }
  return { reasons, sources: [...(ruled.length ? ["rules"] : []), "typesafe-jev", ...(between.length && Object.keys(claude).length ? ["claude"] : [])] };
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
