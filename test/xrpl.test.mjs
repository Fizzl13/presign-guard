// XRPL pre-sign rules (src/xrpl.js) against a stand-in ledger: account takeover, account delete, partial payments,
// fake RLUSD, destinations that refuse, issuers that claw back, escrows, NFT giveaways, unknown types.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isXrplAddress, parseXrplRequest, analyzeXrpl } from "../src/xrpl.js";

const ME = "rMnHeutYALco8RYFVcmuU4BCgSzBpPEh32";
const OTHER = "rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv";
const RIPPLE = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";
const FAKE = "rrrrrrrrrrrrrrrrrrrrBZbvji";
const RLUSD = "524C555344000000000000000000000000000000";

// accounts: address -> { flags, transferRate } or null (= not found); lines: address -> [currency…]
function ledger({ accounts = {}, lines = {}, down = false } = {}) {
  return async (_url, init) => {
    if (down) throw new Error("node down");
    const { method, params: [p] } = JSON.parse(init.body);
    let result;
    if (method === "account_info") {
      const a = accounts[p.account];
      result = a === undefined || a === null ? { error: "actNotFound" } : { account_data: { Account: p.account, Flags: a.flags ?? 0, ...(a.transferRate && { TransferRate: a.transferRate }) } };
    } else result = { lines: (lines[p.account] || []).map((currency) => ({ account: p.peer, currency })) };
    return new Response(JSON.stringify({ result }));
  };
}
const run = async (tx, opts = {}, body = {}) => analyzeXrpl(await parseXrplRequest({ type: "xrpl", tx: { Account: ME, ...tx }, ...body }), { fetchImpl: ledger(opts) });
const codes = (r) => r.reasons.map((x) => `${x.severity}:${x.code}`);

test("addresses and requests: checksum, required fields, network", async () => {
  assert.equal(isXrplAddress(ME), true);
  assert.equal(isXrplAddress(ME.slice(0, -1) + "3"), false);
  await assert.rejects(parseXrplRequest({ type: "xrpl" }), /tx is required/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { TransactionType: "Payment", Account: "0xabc" } }), /Account/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", network: "xrpl:9", tx: { TransactionType: "Payment", Account: ME } }), /network/);
});

test("account takeover is red: regular key, signer list, master key off; account delete is red", async () => {
  assert.deepEqual(codes(await run({ TransactionType: "SetRegularKey", RegularKey: OTHER })), ["red:XRPL_REGULAR_KEY_CHANGE"]);
  const sl = await run({ TransactionType: "SignerListSet", SignerQuorum: 1, SignerEntries: [{ SignerEntry: { Account: OTHER, SignerWeight: 1 } }] });
  assert.equal(sl.verdict, "red"); assert.deepEqual(sl.reasons[0].details.signers, [OTHER]);
  assert.equal((await run({ TransactionType: "AccountSet", SetFlag: 4 })).verdict, "red");
  const del = await run({ TransactionType: "AccountDelete", Destination: OTHER }, { accounts: { [OTHER]: {} } });
  assert.deepEqual(codes(del), ["red:XRPL_ACCOUNT_DELETE"]);
});

test("payments: a plain XRP payment is green; partial payment, fake RLUSD, refusing or tag-needing destinations are flagged", async () => {
  const ok = await run({ TransactionType: "Payment", Destination: OTHER, Amount: "15000" }, { accounts: { [OTHER]: {} } });
  assert.equal(ok.verdict, "green"); assert.deepEqual(ok.sources, ["xrpl-ledger"]);
  assert.ok(codes(await run({ TransactionType: "Payment", Destination: OTHER, Amount: "15000", Flags: 0x00020000 }, { accounts: { [OTHER]: {} } })).includes("orange:XRPL_PARTIAL_PAYMENT"));
  const fake = await run({ TransactionType: "Payment", Destination: OTHER, Amount: { currency: RLUSD, issuer: FAKE, value: "5" } }, { accounts: { [OTHER]: {} } });
  assert.equal(fake.verdict, "red"); assert.equal(fake.reasons[0].code, "XRPL_FAKE_RLUSD");
  assert.ok(codes(await run({ TransactionType: "Payment", Destination: OTHER, Amount: "15000" }, { accounts: { [OTHER]: { flags: 0x00020000 } } })).includes("orange:XRPL_DESTINATION_TAG_MISSING"));
  assert.equal((await run({ TransactionType: "Payment", Destination: OTHER, Amount: "15000", DestinationTag: 7 }, { accounts: { [OTHER]: { flags: 0x00020000 } } })).verdict, "green");
  assert.ok(codes(await run({ TransactionType: "Payment", Destination: OTHER, Amount: "15000" }, { accounts: { [OTHER]: { flags: 0x01000000 } } })).includes("orange:XRPL_DESTINATION_REFUSES"));
  assert.ok(codes(await run({ TransactionType: "Payment", Destination: OTHER, Amount: "15000" })).includes("orange:XRPL_DESTINATION_NOT_ACTIVATED"));
  const rl = { TransactionType: "Payment", Destination: OTHER, Amount: { currency: RLUSD, issuer: RIPPLE, value: "1" } };
  assert.ok(codes(await run(rl, { accounts: { [OTHER]: {} } })).includes("orange:XRPL_DESTINATION_NO_TRUSTLINE"));
  assert.equal((await run(rl, { accounts: { [OTHER]: {} }, lines: { [OTHER]: [RLUSD] } })).verdict, "green");
});

test("trust lines: clawback, frozen issuer, transfer fee, fake RLUSD; Ripple's RLUSD is green", async () => {
  const ts = (issuer, currency = "USD") => ({ TransactionType: "TrustSet", LimitAmount: { currency, issuer, value: "1000" } });
  const real = await run(ts(RIPPLE, RLUSD), { accounts: { [RIPPLE]: { flags: 0x80000000 } } });
  assert.equal(real.verdict, "green", "Ripple's RLUSD has clawback by design: info, not orange");
  assert.deepEqual(codes(real), ["info:XRPL_ISSUER_CAN_CLAW_BACK"]);
  assert.equal((await run(ts(FAKE, RLUSD))).reasons[0].code, "XRPL_FAKE_RLUSD");
  const claw = await run(ts(OTHER), { accounts: { [OTHER]: { flags: 0x80000000 | 0x00400000, transferRate: 1_020_000_000 } } });
  assert.deepEqual(codes(claw), ["orange:XRPL_ISSUER_CAN_CLAW_BACK", "orange:XRPL_ISSUER_FROZEN", "orange:XRPL_TRANSFER_FEE"]);
  assert.equal(claw.reasons[2].details.feePercent, 2);
});

test("escrow to someone else, NFT for nothing and unknown types are orange; a ledger outage is info", async () => {
  assert.equal((await run({ TransactionType: "EscrowCreate", Destination: OTHER, Amount: "1000000", FinishAfter: 900000000 })).reasons[0].code, "XRPL_ESCROW_TO_OTHER");
  assert.equal((await run({ TransactionType: "NFTokenCreateOffer", NFTokenID: "00", Amount: "0", Flags: 1 })).reasons[0].code, "XRPL_NFT_GIVEAWAY");
  assert.equal((await run({ TransactionType: "Clawback" })).reasons[0].code, "XRPL_TX_NOT_ANALYZED");
  assert.equal((await run({ TransactionType: "OfferCreate" })).verdict, "green");
  const down = await analyzeXrpl(await parseXrplRequest({ type: "xrpl", tx: { TransactionType: "Payment", Account: ME, Destination: OTHER, Amount: "15000" } }), { fetchImpl: ledger({ down: true }) });
  assert.deepEqual(codes(down), ["info:XRPL_LEDGER_UNAVAILABLE"]);
});

test("DEX orders: the token bought is screened, a limit far below the book or AMM is orange, no market is orange", async () => {
  // Stand-in DEX: an AMM pool of 1,000,000 XRP and 1,500,000 RLUSD (1.5 RLUSD per XRP), no order book.
  const dex = ({ pool = true, accounts = { [RIPPLE]: {} } } = {}) => async (_u, init) => {
    const { method, params: [p] } = JSON.parse(init.body);
    let result;
    if (method === "account_info") result = accounts[p.account] ? { account_data: { Account: p.account, Flags: 0 } } : { error: "actNotFound" };
    else if (method === "book_offers") result = { offers: [] };
    else if (method === "amm_info") {
      const xrpFirst = p.asset.currency === "XRP";
      result = pool ? { amm: xrpFirst ? { amount: "1000000000000", amount2: { currency: RLUSD, issuer: RIPPLE, value: "1500000" } } : { amount: { currency: RLUSD, issuer: RIPPLE, value: "1500000" }, amount2: "1000000000000" } } : { error: "actNotFound" };
    } else result = {};
    return new Response(JSON.stringify({ result }));
  };
  const offer = (value) => ({ type: "xrpl", tx: { TransactionType: "OfferCreate", Account: ME, TakerGets: "100000000", TakerPays: { currency: RLUSD, issuer: RIPPLE, value } } });
  assert.equal((await analyzeXrpl(await parseXrplRequest(offer("149")), { fetchImpl: dex() })).verdict, "green");
  const low = await analyzeXrpl(await parseXrplRequest(offer("100")), { fetchImpl: dex() });
  assert.deepEqual(codes(low), ["orange:XRPL_OFFER_FAR_BELOW_MARKET"]);
  assert.equal(low.reasons[0].details.source, "AMM pool");
  assert.equal(low.reasons[0].details.worseByPct, 33.3);
  assert.deepEqual(codes(await analyzeXrpl(await parseXrplRequest(offer("100")), { fetchImpl: dex({ pool: false }) })), ["orange:XRPL_NO_MARKET"]);
  const deposit = { type: "xrpl", tx: { TransactionType: "AMMDeposit", Account: ME, Asset: { currency: "XRP" }, Asset2: { currency: "USD", issuer: OTHER }, Amount2: { currency: "USD", issuer: OTHER, value: "5" } } };
  assert.ok(codes(await analyzeXrpl(await parseXrplRequest(deposit), { fetchImpl: dex() })).includes("orange:XRPL_ISSUER_NOT_FOUND"), "an XRP asset is not looked up as a token; the unknown issuer is");
});
