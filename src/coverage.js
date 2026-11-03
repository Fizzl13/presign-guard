// What a verdict covered, and what it didn't. A green means "no problem found in what was checked", never more: an
// agent (or its owner) needs to see which checks ran, which couldn't run (a source down, partial data) and which were
// never in reach (a field not sent, something outside presign-guard's scope), so a green isn't read as "safe".
//
// Every /v1/check answer gets:
//   checked:      [{ check, what }]
//   not_checked:  [{ check, because, why, send?, subject? }]
//                 because: "unavailable"  a check that applies couldn't run this time (asking again may help)
//                          "not_sent"     the request lacks a field it needs; `send` names the field to add
//                          "out_of_scope" presign-guard doesn't check this; `why` says what does
//   checks_complete: false when anything is "unavailable"

const UNAVAILABLE = {
  SANCTIONS_SCREEN_UNAVAILABLE: ["sanctions", "The sanctions list couldn't be asked for this address."],
  DOMAIN_AGE_UNAVAILABLE: ["site", "The site's domain age couldn't be looked up."],
  WALLET_AGE_UNAVAILABLE: ["wallet_age", "How long this wallet has existed couldn't be looked up."],
  SIMULATION_UNAVAILABLE: ["simulation", "The simulation didn't answer."],
  ALGORAND_NODE_UNAVAILABLE: ["chain", "The Algorand node didn't answer: on-chain facts (accounts, assets) are missing."],
  STELLAR_NODE_UNAVAILABLE: ["chain", "The Stellar node didn't answer: on-chain facts (accounts, assets) are missing."],
  XRPL_LEDGER_UNAVAILABLE: ["chain", "The XRP Ledger didn't answer: on-chain facts (accounts, trust lines) are missing."],
  NEAR_RPC_UNAVAILABLE: ["chain", "The NEAR RPC didn't answer: on-chain facts (accounts, contracts) are missing."],
  V4_CHAIN_UNAVAILABLE: ["uniswap_v4", "The chain didn't answer: the hook was judged by its address only (no proxy check, no position lookup)."],
};

const SOURCES = {
  goplus: "GoPlus security data for the addresses and tokens involved",
  "chain-rpc": "on-chain facts from the chain's RPC (code, proxies)",
  "ofac-sdn": "the OFAC SDN sanctions list",
  pg1: "PG1 (sanctions fallback, domain age, phishing lists)",
  metamask: "MetaMask's site scanner",
  alchemy: "Alchemy (simulation, this wallet's past recipients)",
  rules: "presign-guard's own rules for this request type",
  "typesafe-jev": "TypeSafe Jev's second opinion",
  claude: "a second model on borderline cases",
  "solana-rpc": "the Solana RPC",
  "xrpl-ledger": "the XRP Ledger",
  horizon: "Stellar Horizon",
  algod: "the Algorand node",
  "algorand-indexer": "the Algorand indexer",
  "near-rpc": "the NEAR RPC",
};

const DOCTOR = "x402 Doctor checks the seller: its 402, payout address and track record (POST https://x402-doctor.fizzl.eu/api/v1/preflight).";

const has = (reasons, code) => reasons.some((r) => r.code === code);
const subjectsOf = (reasons, code) => [...new Set(reasons.filter((r) => r.code === code).map((r) => r.subject))];

// The fields that hold up for every request type: what couldn't run, and checks_complete.
function finish(checked, notChecked) {
  const seen = new Set();
  const not_checked = notChecked.filter((n) => {
    const k = `${n.check}|${n.because}|${n.subject ?? ""}|${n.why}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { checked, not_checked, checks_complete: !not_checked.some((n) => n.because === "unavailable") };
}

function unavailableFrom(reasons) {
  const out = [];
  for (const r of reasons) {
    const u = UNAVAILABLE[r.code];
    if (u) out.push({ check: u[0], because: "unavailable", why: u[1], ...(r.subject && { subject: r.subject }) });
    if (r.code === "PARTIAL_SOURCE_DATA") out.push({ check: "reputation", because: "unavailable", why: "GoPlus returned partial data: some flags may be missing.", subject: r.subject });
    if (r.code === "SITE_REPUTATION_UNAVAILABLE") out.push({ check: "site", because: "unavailable", why: `Not every phishing list answered (${(r.details?.sources ?? []).join(", ") || "unknown"}).`, subject: r.subject });
  }
  return out;
}

// EVM transactions, approvals and signatures (analyzeAny in presign-guard.js), from what the check had in hand.
// facts: { simulation (the answer or null), simulationReason ("not_sent" | "out_of_scope" | "unavailable" | "off"),
//          history (true when this wallet's past recipients were read), intentSources }
export function evmCoverage(req, reasons, facts = {}) {
  const checked = [];
  const not = unavailableFrom(reasons);
  const subjects = new Set([req.target, ...req.grants.map((g) => g.spender)].filter(Boolean));
  const tokens = new Set(req.grants.filter((g) => !g.allForAll && g.token).map((g) => g.token));
  const payment = req.grants.some((g) => g.mode === "payment");

  checked.push({ check: "permissions", what: "What signing grants: allowances, transfer rights and payments, their amounts, spenders and expiry." });
  if (subjects.size) checked.push({ check: "reputation", what: `GoPlus address and contract security for ${subjects.size} address${subjects.size === 1 ? "" : "es"}, and whether contracts have published source.` });
  if (tokens.size) checked.push({ check: "tokens", what: `Token security for ${tokens.size} token${tokens.size === 1 ? "" : "s"}: honeypots, transfer tax, copies, pause and blacklist controls.` });
  if (has(reasons, "SANCTIONS_SCREENED") || has(reasons, "SANCTIONED_ADDRESS")) checked.push({ check: "sanctions", what: "The addresses against the OFAC SDN sanctions list." });
  if (has(reasons, "WALLET_AGE") || has(reasons, "NEW_WALLET_SPENDER")) checked.push({ check: "wallet_age", what: "How long the plain wallet that gets access has existed." });

  if (req.origin) {
    if (!(has(reasons, "DOMAIN_AGE_UNAVAILABLE") && has(reasons, "SITE_REPUTATION_UNAVAILABLE"))) {
      checked.push({ check: "site", what: `The requesting site (${req.origin}): phishing lists, look-alikes and domain age.` });
    }
  } else {
    not.push({ check: "site", because: "not_sent", send: "origin", why: "No origin: the site that asked for the signature wasn't checked against phishing lists and look-alikes." });
  }

  // Simulation: transactions only (a signature does nothing on-chain until someone uses it).
  if (!req.offchain) {
    if (facts.simulation) checked.push({ check: "simulation", what: "Simulated against the latest block: what leaves the wallet, what arrives, and approvals set inside the call." });
    else if (facts.simulationReason === "not_sent") not.push({ check: "simulation", because: "not_sent", send: "from", why: "No from: the transaction wasn't simulated, so hidden approvals or transfers inside the call weren't looked for." });
    else if (facts.simulationReason === "out_of_scope") not.push({ check: "simulation", because: "out_of_scope", why: "This chain's nodes don't run eth_simulateV1: what the call does was judged from its decoding only." });
    else if (facts.simulationReason === "off") not.push({ check: "simulation", because: "out_of_scope", why: "Simulation is switched off on this server." });
    else not.push({ check: "simulation", because: "unavailable", why: "The simulation didn't answer in time." });
  }

  checked.push({ check: "lookalikes", what: `Recipients and spenders against look-alikes of well-known contracts${facts.history ? " and of the addresses this wallet has paid before" : ""}.` });
  if (!facts.history) {
    not.push(req.from
      ? { check: "address_history", because: "unavailable", why: "This wallet's past recipients couldn't be read on this chain: a look-alike of someone it paid before can't be spotted." }
      : { check: "address_history", because: "not_sent", send: "from", why: "No from: recipients weren't compared with the addresses this wallet has paid before (address poisoning)." });
  }

  if (has(reasons, "UNDECODED_CALL")) {
    not.push({ check: "call", because: "out_of_scope", why: facts.simulation ? "The call isn't decoded: only the simulation shows what it does." : "The call isn't decoded and wasn't simulated: what it does inside the contract is unknown." });
  }
  if (reasons.some((r) => r.code === "UPGRADEABLE_PROXY" && r.details?.confirmed === false)) {
    for (const s of subjectsOf(reasons, "UPGRADEABLE_PROXY")) not.push({ check: "proxy", because: "unavailable", subject: s, why: "Whether this contract can be upgraded couldn't be confirmed (the chain didn't answer)." });
  }

  if (reasons.some((r) => r.code.startsWith("V4_"))) {
    checked.push({ check: "uniswap_v4", what: "Uniswap v4: what each pool's hook may do (from its address), swap and withdrawal limits, and whether the hook can be upgraded." });
    if (has(reasons, "V4_HOOK")) not.push({ check: "hook_code", because: "out_of_scope", why: "A hook's permissions come from its address; what its code does with them isn't read." });
  }

  if (req.x402) checked.push({ check: "x402", what: "The payment against the seller's own 402: payTo, amount, asset, network and timeout." });
  else if (payment) not.push({ check: "x402", because: "not_sent", send: "x402", why: "No x402 requirements: the payment wasn't compared with what the seller asked." });
  if (payment) not.push({ check: "seller", because: "out_of_scope", why: `Whether the seller delivers what is paid for. ${DOCTOR}` });

  if (req.mandate) {
    checked.push({ check: "mandate", what: "This payment against the agent's mandate." });
    not.push({ check: "mandate_cap", because: "out_of_scope", why: "Cumulative spend against the mandate's cap: only this one payment is checked." });
  }

  if (req.intent) {
    if (facts.intentSources?.length) checked.push({ check: "intent", what: "The agent's stated intent against what signing does." });
    else not.push({ check: "intent", because: "unavailable", why: "The intent check didn't answer." });
  } else {
    not.push({ check: "intent", because: "not_sent", send: "intent", why: "No intent: whether signing does what the agent meant wasn't checked." });
  }

  return finish(checked, not);
}

// Every other request type (messages, EIP-7702, Solana, XRPL, Algorand, Stellar, NEAR): the sources that answered,
// and the checks that said they couldn't run.
export function genericCoverage(result) {
  const checked = (result.sources ?? []).map((s) => ({ check: s, what: SOURCES[s] ?? s }));
  return finish(checked, unavailableFrom(result.reasons ?? []));
}

// Adds checked, not_checked and checks_complete to a result that doesn't have them yet.
export function withCoverage(result) {
  if (!result || !Array.isArray(result.reasons) || result.checked) return result;
  return Object.assign(result, genericCoverage(result));
}
