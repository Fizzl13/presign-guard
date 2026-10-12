// The parties of a Solana, XRPL or Algorand check against the OFAC SDN list (src/ofac.js partySanctionsReasons), with
// the list loaded from the test fixture: no network, no money.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as k from "@solana/kit";
import algosdk from "algosdk";
import { loadSdn, resetOfac, partySanctionsReasons } from "../src/ofac.js";
import { analyze, parseRequest } from "../src/presign-guard.js";
import { parseXrplRequest, analyzeXrpl } from "../src/xrpl.js";
import { SDN_XML, SOL, XRP, TRON } from "./fixtures/sdn.mjs";

// No Algorand address is on the real list; this one is made up for the test, in an extra SDN entry.
const ALGO_LISTED = algosdk.generateAccount().addr.toString();
const XML = SDN_XML.replace("</sdnList>", `  <sdnEntry>
    <uid>990001</uid>
    <lastName>TEST ENTITY</lastName>
    <sdnType>Entity</sdnType>
    <programList>
      <program>TEST</program>
    </programList>
    <idList>
      <id>
        <uid>990002</uid>
        <idType>Digital Currency Address - ALGO</idType>
        <idNumber>${ALGO_LISTED}</idNumber>
      </id>
    </idList>
  </sdnEntry>
</sdnList>`);

const realFetch = globalThis.fetch;
before(async () => { await loadSdn({ fetchImpl: async () => new Response(XML) }); });
after(() => { resetOfac(); globalThis.fetch = realFetch; });

const sanctionCodes = (reasons) => reasons.filter((r) => /SANCTION/.test(r.code)).map((r) => `${r.severity}:${r.code}`);

test("parties: a red SANCTIONED_ADDRESS per listed party, else one SANCTIONS_SCREENED; the wallet itself is left out", () => {
  const hit = partySanctionsReasons([TRON, "rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv", TRON, null, "short"], { exclude: [] });
  assert.equal(hit.used, true);
  assert.deepEqual(sanctionCodes(hit.reasons), ["red:SANCTIONED_ADDRESS"]);
  assert.deepEqual(hit.reasons[0].details, { list: "OFAC SDN", matches: [{ name: "BANK MARKAZI JOMHOURI ISLAMI IRAN", programs: ["IRAN", "SDGT"], currency: "TRX" }], listSynced: "2026-10-09" });
  const clean = partySanctionsReasons(["rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"]);
  assert.deepEqual(clean.reasons, [{ code: "SANCTIONS_SCREENED", severity: "info", details: { list: "OFAC SDN", listed: false, addresses: 2, listSynced: "2026-10-09" } }]);
  assert.deepEqual(partySanctionsReasons([TRON], { exclude: [TRON] }).reasons, [], "your own wallet is not a party");
});

test("no list in memory: SANCTIONS_SCREEN_UNAVAILABLE (info), never a guess", async () => {
  resetOfac();
  try {
    const r = partySanctionsReasons([TRON]);
    assert.equal(r.used, false);
    assert.deepEqual(sanctionCodes(r.reasons), ["info:SANCTIONS_SCREEN_UNAVAILABLE"]);
  } finally {
    await loadSdn({ fetchImpl: async () => new Response(XML) });
  }
});

// XRPL: a stand-in ledger where every account exists with no flags.
const ME = "rMnHeutYALco8RYFVcmuU4BCgSzBpPEh32";
const OTHER = "rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv";
const ledger = async (_url, init) => {
  const { method, params: [p] } = JSON.parse(init.body);
  const result = method === "account_info" ? { account_data: { Account: p.account, Flags: 0 } } : { lines: [] };
  return new Response(JSON.stringify({ result }));
};
const xrpl = async (tx) => analyzeXrpl(await parseXrplRequest({ type: "xrpl", tx: { Account: ME, ...tx } }), { fetchImpl: ledger });

test("XRPL: a payment to a listed destination is red with the SDN entry; a clean one is screened (info); issuers count", async () => {
  const red = await xrpl({ TransactionType: "Payment", Destination: XRP, Amount: "1000000" });
  assert.equal(red.verdict, "red");
  const hit = red.reasons.find((r) => r.code === "SANCTIONED_ADDRESS");
  assert.equal(hit.subject, XRP);
  assert.equal(hit.details.matches[0].name, "CHATEX");
  assert.ok(red.sources.includes("ofac-sdn"));
  const clean = await xrpl({ TransactionType: "Payment", Destination: OTHER, Amount: "1000000" });
  assert.deepEqual(sanctionCodes(clean.reasons), ["info:SANCTIONS_SCREENED"]);
  assert.equal(clean.reasons.find((r) => r.code === "SANCTIONS_SCREENED").details.addresses, 1);
  const trust = await xrpl({ TransactionType: "TrustSet", LimitAmount: { currency: "USD", issuer: XRP, value: "100" } });
  assert.ok(sanctionCodes(trust.reasons).includes("red:SANCTIONED_ADDRESS"), "a trust line to a listed issuer");
  const key = await xrpl({ TransactionType: "SetRegularKey", RegularKey: XRP });
  assert.equal(key.reasons.filter((r) => r.code === "SANCTIONED_ADDRESS").length, 1);
});

// Solana: a stand-in RPC. tokenAccounts: address → owner, for the token accounts the transaction writes to.
const W = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
const MY_TA = "2ocS3orPq3jyszjsJ4NozKWyhdotr3csDjAizmkj65aH";
const THEIR_TA = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM = "11111111111111111111111111111111";
const R = k.AccountRole;
const A = (a, role) => ({ address: k.address(a), role });
function build(ixs) {
  let m = k.createTransactionMessage({ version: 0 });
  m = k.setTransactionMessageFeePayer(k.address(W), m);
  m = k.setTransactionMessageLifetimeUsingBlockhash({ blockhash: SYSTEM, lastValidBlockHeight: 0n }, m);
  for (const ix of ixs) m = k.appendTransactionMessageInstruction(ix, m);
  return k.getBase64EncodedWireTransaction(k.compileTransaction(m));
}
const solTransfer = (to) => { const d = new Uint8Array(12); new DataView(d.buffer).setUint32(0, 2, true); new DataView(d.buffer).setBigUint64(4, 1000000n, true); return { programAddress: k.address(SYSTEM), accounts: [A(W, R.WRITABLE_SIGNER), A(to, R.WRITABLE)], data: d }; };
const tokenTransfer = () => { const d = new Uint8Array(9); d[0] = 3; new DataView(d.buffer).setBigUint64(1, 5n, true); return { programAddress: k.address(TOKEN), accounts: [A(MY_TA, R.WRITABLE), A(THEIR_TA, R.WRITABLE), A(W, R.READONLY_SIGNER)], data: d }; };
function rpc(tokenAccounts = {}) {
  const parsed = (address, amount) => (tokenAccounts[address] ? { lamports: 2039280, owner: TOKEN, data: { parsed: { type: "account", info: { owner: tokenAccounts[address], mint: USDC, tokenAmount: { amount: String(amount), decimals: 6, uiAmountString: String(amount / 1e6) } } } } } : { lamports: 1_000_000_000, owner: SYSTEM, data: ["", "base64"] });
  return async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    if (method === "getMultipleAccounts") return Response.json({ result: { value: params[0].map((a) => parsed(a, 100)) } });
    if (method === "simulateTransaction") return Response.json({ result: { value: { err: null, fee: 5000, accounts: params[1].accounts.addresses.map((a) => parsed(a, 95)) } } });
    return Response.json({ error: { message: "unexpected" } });
  };
}
const solana = async (ixs, tokenAccounts) => {
  globalThis.fetch = rpc(tokenAccounts);
  try { return await analyze(parseRequest({ type: "solana", transaction: build(ixs) })); } finally { globalThis.fetch = realFetch; }
};

test("Solana: SOL to a listed address is red; a token transfer is red when the recipient token account's owner is listed", async () => {
  const red = await solana([solTransfer(SOL)]);
  assert.equal(red.verdict, "red");
  assert.equal(red.reasons.find((r) => r.code === "SANCTIONED_ADDRESS").subject, SOL);
  assert.ok(red.sources.includes("ofac-sdn"));
  // The instruction only names the recipient's token account; the simulation reads who owns it.
  const viaToken = await solana([tokenTransfer()], { [MY_TA]: W, [THEIR_TA]: SOL });
  const hit = viaToken.reasons.find((r) => r.code === "SANCTIONED_ADDRESS");
  assert.equal(hit?.subject, SOL);
  assert.equal(hit.details.matches[0].currency, "SOL");
  const clean = await solana([tokenTransfer()], { [MY_TA]: W, [THEIR_TA]: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" });
  assert.deepEqual(sanctionCodes(clean.reasons), ["info:SANCTIONS_SCREENED"]);
});

// Algorand: a stand-in node that knows no assets and simulates every group as fine.
const ALGO_W = algosdk.generateAccount().addr.toString();
const MAINNET = Buffer.from("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=", "base64");
const sp = { fee: 1000, minFee: 1000, flatFee: true, firstValid: 1000, lastValid: 2000, genesisHash: MAINNET, genesisID: "mainnet-v1.0" };
const b64 = (t) => Buffer.from(algosdk.encodeUnsignedTransaction(t)).toString("base64");
const node = async (url) => {
  const u = new URL(url);
  if (u.pathname === "/v2/transactions/simulate") return Response.json({ "txn-groups": [{ "txn-results": [{ "txn-result": {} }] }] });
  if (/^\/v2\/accounts\/[A-Z2-7]+$/.test(u.pathname)) return Response.json({ amount: 5_000_000 });
  return new Response("{}", { status: 404 });
};

test("Algorand: a payment to a listed receiver is red; a clean one is screened (info)", async () => {
  globalThis.fetch = node;
  try {
    const pay = (receiver) => b64(algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: ALGO_W, receiver, amount: 1_000_000, suggestedParams: sp }));
    const red = await analyze(parseRequest({ type: "algorand", transaction: pay(ALGO_LISTED) }));
    assert.equal(red.verdict, "red");
    assert.equal(red.reasons.find((r) => r.code === "SANCTIONED_ADDRESS").details.matches[0].name, "TEST ENTITY");
    assert.ok(red.sources.includes("ofac-sdn"));
    const clean = await analyze(parseRequest({ type: "algorand", transaction: pay(algosdk.generateAccount().addr.toString()) }));
    assert.deepEqual(sanctionCodes(clean.reasons), ["info:SANCTIONS_SCREENED"]);
  } finally {
    globalThis.fetch = realFetch;
  }
});
