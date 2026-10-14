// Wallet screen (GET /v1/screen) and the OFAC SDN list (src/ofac.js), without network: the Treasury file is a
// small fixture in the real SDN.XML layout, GoPlus and PG1 are mocked through globalThis.fetch.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { parseSdnXml, loadSdn, screenOfac, addressKey, resetOfac, ofacStatus, sanctionsList } from "../src/ofac.js";
import { parseScreenRequest, addressFormat, screenAddress, validateScreenQuery, createScreenRouter } from "../src/screen.js";
import { resetPg1 } from "../src/pg1.js";
import { SDN_XML, TRON, SOL, XRP, ETH, BTC } from "./fixtures/sdn.mjs";

const CLEAN_EVM = "0x1000000000000000000000000000000000000001";
const THIEF = "0x1000000000000000000000000000000000000002";
const MIXER = "0x1000000000000000000000000000000000000003";
const DOWN = "0x1000000000000000000000000000000000000004";
const ALGO = "VCMJKWOY5P5P7SKMZFFOCEROPJCZOTIJMNIYNUCKH7LRO45JMJP6UYBIJA";

const realFetch = globalThis.fetch;
let treasuryCalls = 0;
let treasuryDown = false;
let notModified = false;
let goplusDown = false;
let pg1Listed = null; // null: PG1 down
const goplusFlags = { [THIEF]: { stealing_attack: "1", phishing_activities: "1", data_source: "SlowMist" }, [MIXER]: { mixer: "1" }, [ETH.toLowerCase()]: { sanctioned: "1", stealing_attack: "1", data_source: "SlowMist,BlockSec" } };

function fakeFetch(url, opts = {}) {
  const u = String(url);
  if (u.includes("ofac.treas.gov")) {
    treasuryCalls++;
    if (treasuryDown) return Promise.resolve(new Response("down", { status: 503 }));
    if (notModified && opts.headers?.["if-modified-since"]) return Promise.resolve(new Response(null, { status: 304 }));
    return Promise.resolve(new Response(SDN_XML, { headers: { "last-modified": "Fri, 09 Oct 2026 14:01:28 GMT" } }));
  }
  if (u.includes("gopluslabs.io")) {
    const address = u.match(/address_security\/(0x[0-9a-f]{40})/)?.[1];
    if (goplusDown || address === DOWN) return Promise.resolve(new Response("down", { status: 502 }));
    const result = { cybercrime: "0", money_laundering: "0", phishing_activities: "0", stealing_attack: "0", sanctioned: "0", mixer: "0", blacklist_doubt: "0", data_source: "", ...goplusFlags[address] };
    return Promise.resolve(Response.json({ code: 1, message: "ok", result }));
  }
  if (u.includes("pg1")) {
    if (pg1Listed === null) return Promise.resolve(new Response("down", { status: 503 }));
    const out = { listed: pg1Listed, matches: pg1Listed ? [{ sdn_name: "LAZARUS GROUP", programs: ["DPRK3"], sdn_uid: 27307 }] : [], list_last_synced: "2026-10-10" };
    return Promise.resolve(Response.json({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(out) }] } }));
  }
  return Promise.reject(new Error(`unexpected fetch ${u}`));
}

beforeEach(() => {
  globalThis.fetch = fakeFetch;
  resetOfac();
  resetPg1();
  treasuryCalls = 0;
  treasuryDown = false;
  notModified = false;
  goplusDown = false;
  pg1Listed = null;
});
after(() => { globalThis.fetch = realFetch; });

const codes = (r) => r.reasons.map((x) => `${x.severity}:${x.code}`);
const screen = (address) => screenAddress(parseScreenRequest({ address }));

test("parse: the SDN file's digital currency addresses, with the entry's name and programs", () => {
  const p = parseSdnXml(SDN_XML);
  assert.equal(p.published, "2026-10-09");
  assert.equal(p.addresses, 117);
  assert.deepEqual(p.index.get(TRON), [{ uid: 4632, name: "BANK MARKAZI JOMHOURI ISLAMI IRAN", type: "Entity", programs: ["IRAN", "SDGT"], currency: "TRX" }]);
  assert.equal(p.index.get(SOL)[0].name, "Rolan SOKOLOVSKI");
  assert.equal(p.index.get(SOL)[0].type, "Individual");
  assert.equal(p.index.get(BTC)[0].name, "SHPS SHELBIT & CO", "XML entities decoded");
  assert.equal(p.index.get(ETH.toLowerCase()).length, 1, "one entry listed under ETH and USDT counts once");
  assert.equal(p.index.get("someone@example.com"), undefined, "other id types are not addresses");
});

test("lookup keys: EVM and bech32 ignore case, base58 does not", () => {
  assert.equal(addressKey(ETH), ETH.toLowerCase());
  assert.equal(addressKey(BTC.toUpperCase()), BTC);
  assert.equal(addressKey(TRON), TRON);
  assert.notEqual(addressKey(TRON.toLowerCase()), TRON);
});

test("formats: the address tells the chain", () => {
  assert.equal(addressFormat(ETH), "evm");
  assert.equal(addressFormat(TRON), "tron");
  assert.equal(addressFormat(SOL), "solana");
  assert.equal(addressFormat(XRP), "xrpl");
  assert.equal(addressFormat(BTC), "bitcoin");
  assert.equal(addressFormat("37fKFZQGMqdBkjSUub1jCDWGgSHwv9VxfZ"), "bitcoin");
  assert.equal(addressFormat(ALGO), "algorand");
  assert.equal(addressFormat("LeKvNdNEzgQkzVVnRdV3fAu2DSF1nLsNw6"), "other", "Litecoin");
  assert.throws(() => parseScreenRequest({ address: "0x12" }), /wallet address/);
  assert.throws(() => parseScreenRequest({ address: "<script>alert(1)</script>xxxxxxxxxx" }), /wallet address/);
  assert.throws(() => parseScreenRequest({}), /wallet address/);
});

test("a listed Tron, Solana or XRPL address is red with its SDN entry; GoPlus is not asked for them", async () => {
  for (const [address, name, currency] of [[TRON, "BANK MARKAZI JOMHOURI ISLAMI IRAN", "TRX"], [SOL, "Rolan SOKOLOVSKI", "SOL"], [XRP, "CHATEX", "XRP"]]) {
    const r = await screen(address);
    assert.equal(r.verdict, "red", address);
    assert.equal(r.grade, "AVOID");
    assert.equal(r.reasons[0].code, "SANCTIONED_ADDRESS");
    assert.equal(r.sanctions.matches[0].name, name);
    assert.equal(r.sanctions.matches[0].currency, currency);
    assert.equal(r.sanctions.published, "2026-10-09");
    assert.deepEqual(r.sources, ["ofac-sdn"]);
    assert.ok(codes(r).includes("info:REPUTATION_NOT_COVERED"));
    assert.match(r.one_liner, new RegExp(`^AVOID: on the OFAC SDN list \\(${name}\\)`));
  }
  assert.equal(treasuryCalls, 1, "the list is downloaded once");
});

test("a listed EVM address in any case is red once; GoPlus's own sanctioned flag folds into it", async () => {
  const r = await screen(ETH.toUpperCase().replace("0X", "0x"));
  assert.equal(r.verdict, "red");
  const sanctioned = r.reasons.filter((x) => /SANCTIONED/.test(x.code));
  assert.equal(sanctioned.length, 1);
  assert.deepEqual(sanctioned[0].details.alsoFlaggedBy, ["goplus"]);
  assert.ok(codes(r).includes("red:STEALING_ATTACK"));
  assert.deepEqual(r.sources, ["ofac-sdn", "goplus"]);
});

test("EVM: a clean address is green with what was screened; theft reports are red, a mixer orange", async () => {
  const clean = await screen(CLEAN_EVM);
  assert.equal(clean.verdict, "green");
  assert.deepEqual(codes(clean), ["info:SANCTIONS_SCREENED", "info:NO_REPORTS"]);
  assert.equal(clean.reasons[0].details.published, "2026-10-09");
  assert.equal(clean.one_liner, "SAFE: not on the OFAC SDN list (published 2026-10-09), no scam or theft reports");
  const thief = await screen(THIEF);
  assert.equal(thief.verdict, "red");
  assert.ok(codes(thief).includes("red:STEALING_ATTACK"));
  assert.equal(thief.reasons[0].details.reportedBy, "SlowMist");
  assert.match(thief.one_liner, /^AVOID: reported for phishing, reported for theft|^AVOID: reported for theft/);
  const mixer = await screen(MIXER);
  assert.equal(mixer.verdict, "orange");
  assert.equal(mixer.grade, "CAUTION");
  assert.equal(mixer.one_liner, "CAUTION: mixer use reported");
});

test("non-EVM clean address: green on sanctions, and it says scam reports are not covered", async () => {
  const r = await screen(ALGO);
  assert.equal(r.verdict, "green");
  assert.deepEqual(codes(r), ["info:SANCTIONS_SCREENED", "info:REPUTATION_NOT_COVERED"]);
  assert.match(r.one_liner, /scam reports not covered for Algorand$/);
});

test("GoPlus down: the sanctions answer stands, with REPUTATION_UNAVAILABLE", async () => {
  const r = await screen(DOWN);
  assert.equal(r.verdict, "green");
  assert.ok(codes(r).includes("info:REPUTATION_UNAVAILABLE"));
  assert.deepEqual(r.sources, ["ofac-sdn"]);
});

test("no list: PG1 stands in for EVM; nothing at all is a 503 (no verdict, nothing charged)", async () => {
  treasuryDown = true;
  pg1Listed = true;
  const r = await screen(CLEAN_EVM);
  assert.equal(r.verdict, "red");
  assert.equal(r.sanctions.source, "pg1");
  assert.equal(r.sanctions.matches[0].name, "LAZARUS GROUP");
  await assert.rejects(screen(TRON), (err) => err.status === 503);
  resetPg1();
  pg1Listed = null;
  await assert.rejects(screen("0x1000000000000000000000000000000000000009"), (err) => err.status === 503);
  assert.match(String(ofacStatus()), /unavailable/);
});

test("refresh: a 304 keeps the list, a failed refresh keeps the last good list, a broken file is refused", async () => {
  await loadSdn();
  assert.equal(ofacStatus().addresses, 117);
  notModified = true;
  await loadSdn();
  assert.equal(treasuryCalls, 2);
  assert.equal(ofacStatus().addresses, 117);
  treasuryDown = true;
  await loadSdn();
  assert.equal((await screenOfac(TRON)).listed, true);
  assert.match(ofacStatus().lastError, /503/);
  resetOfac();
  const tiny = await loadSdn({ fetchImpl: async () => new Response(SDN_XML.replace(/<sdnEntry>[\s\S]*?FILLER[\s\S]*?<\/sdnEntry>/g, "")) });
  assert.equal(tiny, null, "fewer than 100 addresses is a broken file");
});

test("the open list (GET /v1/sanctions): every address with its entries, sorted; null before the first load", async () => {
  assert.equal(sanctionsList(), null);
  await loadSdn();
  const list = sanctionsList();
  assert.equal(list.list, "OFAC SDN");
  assert.equal(list.published, "2026-10-09");
  assert.equal(list.count, list.addresses.length);
  assert.equal(list.count, 116, "117 ids, one address listed twice (ETH and USDT)");
  const tron = list.addresses.find((a) => a.address === TRON);
  assert.deepEqual(tron.entries, [{ uid: 4632, name: "BANK MARKAZI JOMHOURI ISLAMI IRAN", type: "Entity", programs: ["IRAN", "SDGT"], currency: "TRX" }]);
  assert.ok(list.addresses.some((a) => a.address === ETH.toLowerCase()), "EVM lowercased");
  const keys = list.addresses.map((a) => a.address);
  assert.deepEqual(keys, [...keys].sort(), "sorted");
  assert.equal(sanctionsList(), list, "built once per loaded list");
});

test("the open list: a Solana address carries its USDC and USDT token accounts (a token transfer names those, not the owner)", async () => {
  await loadSdn();
  const list = sanctionsList();
  // Checked against findAssociatedTokenPda from @solana-program/token.
  assert.deepEqual(list.addresses.find((a) => a.address === SOL).tokenAccounts, {
    USDC: "B1jUqZENAXMJxBu3pX9v1yq2QDtMeXz1CUiFMr9hsi4f",
    USDT: "DBbBgTWUw4ZBHSoJqxqMxbBVwjzjFeG5ABWKJW2Ah5ZL",
  });
  assert.equal(list.addresses.find((a) => a.address === TRON).tokenAccounts, undefined, "only Solana addresses");
  assert.match(list.tokenAccounts, /screen both/);
});

test("a list without a successful check for days is marked stale", async () => {
  let t = Date.UTC(2026, 9, 10);
  await loadSdn({ now: () => t });
  t += 4 * 86400 * 1000;
  assert.equal((await screenOfac(TRON, { now: () => t })).stale, true);
});

test("route: 400 before the paywall for a bad address, the screen behind it", async () => {
  const app = express();
  app.use(validateScreenQuery);
  app.use((req, res, next) => (req.headers["x-paid"] ? next() : res.status(402).json({})));
  app.use(createScreenRouter());
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    globalThis.fetch = realFetch;
    const bad = await fetch(`${base}/v1/screen?address=nope`);
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, "invalid_request");
    const probe = await fetch(`${base}/v1/screen`);
    assert.equal(probe.status, 402, "a bare probe gets the price");
    globalThis.fetch = (url, opts) => (String(url).startsWith(base) ? realFetch(url, opts) : fakeFetch(url, opts));
    const ok = await fetch(`${base}/v1/screen?address=${TRON}`, { headers: { "x-paid": "1" } });
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).verdict, "red");
  } finally {
    server.close();
  }
});
