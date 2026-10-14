// The OFAC SDN list's digital currency addresses, straight from the US Treasury.
//
// OFAC publishes the addresses of sanctioned persons as "Digital Currency Address - <XBT|ETH|TRX|USDT|SOL|XRP|…>"
// ids on their SDN entries. This module downloads the full SDN list (SDN.XML, ~30 MB), keeps only those
// addresses, and answers exact-match lookups from memory. It re-checks every few hours with If-Modified-Since,
// so an unchanged list costs a 304. The last good list stays in use when a refresh fails.
//
// Why our own copy and not only PG1/GoPlus: GoPlus answers sanctioned=0 for OFAC-listed Tron, Solana and XRPL
// addresses, and PG1 screens EVM addresses. The Treasury file covers every currency OFAC lists.

import { address, getAddressEncoder, getProgramDerivedAddress } from "@solana/kit";

const SDN_URL = () => process.env.OFAC_SDN_URL || "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";
const REFRESH_MS = 6 * 60 * 60 * 1000;      // OFAC publishes irregularly, often several times a week
const FETCH_TIMEOUT_MS = 90 * 1000;          // a ~30 MB file
export const STALE_MS = 3 * 24 * 60 * 60 * 1000; // no successful check for this long: the answer says so
const MIN_ADDRESSES = 100;                   // fewer means a broken file, not a shorter list (over 1,000 in 2026)

// A Solana token transfer names the recipient's token account, not the recipient, so a denylist of owners alone
// misses it (Privy's x402 sanctions recipe screens TransferChecked.destination, for one). The open list carries, per
// listed Solana address, its associated token accounts for the stablecoins agents pay with (SPL Token program).
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const STABLECOIN_MINTS = { USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", USDT: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" };

let state = null;    // { index: Map<key, entry[]>, tokenAccounts: Map<key, { USDC, USDT }>, addresses, published, checkedAt, lastModified }
let loading = null;  // the running load, shared by everyone who waits for it
let lastError = null;
let lastAttempt = 0; // a screen without a list starts a load, at most once a minute
const RETRY_MS = 60 * 1000;

// The lookup key: EVM and bech32 addresses are case-insensitive, base58 and the rest are not.
export function addressKey(address) {
  const a = String(address).trim();
  if (/^0x[0-9a-f]{40}$/i.test(a) || /^(bc1|ltc1|tb1)[0-9a-z]+$/i.test(a)) return a.toLowerCase();
  return a;
}

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };
const decode = (s) => s.replace(/&(amp|lt|gt|quot|apos);/g, (_, e) => ENTITIES[e]).trim();
const tag = (chunk, name) => {
  const m = chunk.match(new RegExp(`<${name}>([^<]*)</${name}>`));
  return m ? decode(m[1]) : null;
};

// SDN.XML → { index, addresses, published }. Only entries with a digital currency address are read.
export function parseSdnXml(xml) {
  const index = new Map();
  let addresses = 0;
  const date = /<Publish_Date>(\d{2})\/(\d{2})\/(\d{4})<\/Publish_Date>/.exec(xml);
  const published = date ? `${date[3]}-${date[1]}-${date[2]}` : null;
  const MARK = "Digital Currency Address - ";
  let pos = 0;
  let lastStart = -1;
  while ((pos = xml.indexOf(MARK, pos)) !== -1) {
    const start = xml.lastIndexOf("<sdnEntry>", pos);
    const end = xml.indexOf("</sdnEntry>", pos);
    if (start === -1 || end === -1) break;
    pos = end;
    if (start === lastStart) continue;
    lastStart = start;
    const chunk = xml.slice(start, end);
    const head = chunk.slice(0, chunk.indexOf("<programList>") === -1 ? 400 : chunk.indexOf("<programList>"));
    const name = [tag(head, "firstName"), tag(head, "lastName")].filter(Boolean).join(" ");
    const programs = [...chunk.matchAll(/<program>([^<]*)<\/program>/g)].map((m) => decode(m[1]));
    const entry = { uid: Number(tag(head, "uid")) || null, name, type: tag(head, "sdnType"), programs };
    for (const m of chunk.matchAll(/<id>([\s\S]*?)<\/id>/g)) {
      const type = tag(m[1], "idType");
      const number = tag(m[1], "idNumber");
      if (!type?.startsWith(MARK) || !number) continue;
      const key = addressKey(number);
      const list = index.get(key) ?? [];
      if (!list.some((e) => e.uid === entry.uid)) list.push({ ...entry, currency: type.slice(MARK.length) });
      index.set(key, list);
      addresses += 1;
    }
  }
  return { index, addresses, published };
}

// The associated token account of `owner` for each stablecoin mint: { USDC, USDT }.
export async function associatedTokenAccounts(owner) {
  const encoder = getAddressEncoder();
  const accounts = {};
  for (const [symbol, mint] of Object.entries(STABLECOIN_MINTS)) {
    const [account] = await getProgramDerivedAddress({
      programAddress: address(ASSOCIATED_TOKEN_PROGRAM),
      seeds: [encoder.encode(address(owner)), encoder.encode(address(TOKEN_PROGRAM)), encoder.encode(address(mint))],
    });
    accounts[symbol] = account;
  }
  return accounts;
}

// Token accounts for every address listed as SOL; one that is not a valid Solana address gets none.
async function solanaTokenAccounts(index) {
  const accounts = new Map();
  for (const [key, entries] of index) {
    if (!entries.some((e) => e.currency === "SOL")) continue;
    try { accounts.set(key, await associatedTokenAccounts(key)); } catch { /* listed as published, without token accounts */ }
  }
  return accounts;
}

// Download (or re-check) the list. Resolves to the state, or null when there is none yet.
export function loadSdn({ fetchImpl = fetch, now = () => Date.now() } = {}) {
  if (loading) return loading;
  lastAttempt = now();
  loading = (async () => {
    const headers = state?.lastModified ? { "if-modified-since": state.lastModified } : {};
    try {
      const res = await fetchImpl(SDN_URL(), { headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (res.status === 304 && state) {
        state = { ...state, checkedAt: now() };
        lastError = null;
        return state;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const parsed = parseSdnXml(await res.text());
      if (parsed.addresses < MIN_ADDRESSES) throw new Error(`only ${parsed.addresses} addresses in the file`);
      state = { ...parsed, tokenAccounts: await solanaTokenAccounts(parsed.index), checkedAt: now(), lastModified: res.headers.get("last-modified") };
      lastError = null;
      console.log(`[ofac] SDN list loaded: ${parsed.addresses} addresses, published ${parsed.published}`);
    } catch (err) {
      lastError = err?.name === "TimeoutError" ? "timeout" : String(err?.message ?? err).slice(0, 120);
      console.warn(`[ofac] SDN list refresh failed: ${lastError}${state ? " (keeping the last good list)" : ""}`);
    }
    return state;
  })().finally(() => { loading = null; });
  return loading;
}

// The first load at start-up, then a re-check every few hours (unref'd: never keeps the process alive).
export function startOfacSync(opts) {
  loadSdn(opts);
  setInterval(() => loadSdn(opts), REFRESH_MS).unref();
}

// For /health: never waits.
export function ofacStatus() {
  if (state) return { addresses: state.addresses, published: state.published, checkedAt: new Date(state.checkedAt).toISOString(), ...(lastError && { lastError }) };
  return loading ? "loading" : lastError ? `unavailable (${lastError})` : "off";
}

// Exact-match screen: { listed, matches, published, checkedAt, stale } or null when no list can be had. Without a
// list, a running load is waited for, or a new one started (at most once a minute while the Treasury site fails).
export async function screenOfac(address, { now = () => Date.now() } = {}) {
  const s = state ?? (loading ? await loading : now() - lastAttempt > RETRY_MS ? await loadSdn({ now }) : null);
  return s ? lookup(s, address, now) : null;
}

// For the checks: the list in memory, without waiting or loading (null until the start-up load is done).
export function screenOfacLoaded(address, { now = () => Date.now() } = {}) {
  return state ? lookup(state, address, now) : null;
}

// The parties a transaction pays, hands control to or trades with, screened at once: a red SANCTIONED_ADDRESS per
// listed address, else one info SANCTIONS_SCREENED (how many addresses, the list's date); no list in memory: one info
// SANCTIONS_SCREEN_UNAVAILABLE. Returns { reasons, used }.
export function partySanctionsReasons(addresses, { exclude = [], now } = {}) {
  const parties = [...new Set(addresses.filter((a) => typeof a === "string" && a.length >= 20 && !exclude.includes(a)))];
  if (!parties.length) return { reasons: [], used: false };
  if (!state) return { reasons: [{ code: "SANCTIONS_SCREEN_UNAVAILABLE", severity: "info", details: { list: "OFAC SDN", addresses: parties.length } }], used: false };
  const reasons = [];
  for (const address of parties) {
    const sc = lookup(state, address, now);
    if (sc.listed) reasons.push({ code: "SANCTIONED_ADDRESS", severity: "red", subject: address, details: { list: "OFAC SDN", matches: sc.matches.map(({ name, programs, currency }) => ({ name, programs, currency })), listSynced: sc.published } });
  }
  if (!reasons.length) reasons.push({ code: "SANCTIONS_SCREENED", severity: "info", details: { list: "OFAC SDN", listed: false, addresses: parties.length, listSynced: state.published } });
  return { reasons, used: true };
}

function lookup(s, address, now = () => Date.now()) {
  const matches = s.index.get(addressKey(address)) ?? [];
  return {
    listed: matches.length > 0,
    matches: matches.map(({ uid, name, type, programs, currency }) => ({ uid, name, type, programs, currency })),
    published: s.published,
    checkedAt: new Date(s.checkedAt).toISOString(),
    addresses: s.addresses,
    stale: now() - s.checkedAt > STALE_MS,
  };
}

// The whole list for GET /v1/sanctions (free, open data): every address with its SDN entry, sorted, Solana addresses
// with their stablecoin token accounts, or null before the first load. Built once per loaded list.
let exported = null;
export function sanctionsList() {
  if (!state) return null;
  if (exported?.state === state) return exported.body;
  const addresses = [...state.index.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([address, entries]) => ({
    address,
    entries: entries.map(({ uid, name, type, programs, currency }) => ({ uid, name, type, programs, currency })),
    ...(state.tokenAccounts?.has(address) && { tokenAccounts: state.tokenAccounts.get(address) }),
  }));
  const body = {
    list: "OFAC SDN",
    source: "US Treasury, Office of Foreign Assets Control: Specially Designated Nationals list (SDN.XML), digital currency addresses",
    published: state.published,
    checkedAt: new Date(state.checkedAt).toISOString(),
    count: addresses.length,
    match: "exact; EVM and bech32 addresses lowercased, all others as published",
    tokenAccounts: "Solana addresses carry their associated token accounts for USDC and USDT (SPL Token program): a token transfer names that account, not the owner, so screen both",
    addresses,
  };
  exported = { state, body };
  return body;
}

export function resetOfac() { state = null; loading = null; lastError = null; lastAttempt = 0; }
