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
// mpts: issuance id -> { Flags, TransferFee, MPTokenMetadata }; holdings: "id|account" -> { Flags }; channels: id -> { Destination }
function ledger({ accounts = {}, lines = {}, credentials = {}, mpts = {}, holdings = {}, channels = {}, down = false } = {}) {
  return async (_url, init) => {
    if (down) throw new Error("node down");
    const { method, params: [p] } = JSON.parse(init.body);
    let result;
    if (method === "ledger_entry" && p.payment_channel) {
      const c = channels[p.payment_channel];
      result = c ? { node: { LedgerEntryType: "PayChannel", ...c } } : { error: "entryNotFound" };
    } else if (method === "ledger_entry" && p.mpt_issuance) {
      const m = mpts[p.mpt_issuance];
      result = m ? { node: { LedgerEntryType: "MPTokenIssuance", Flags: 0, ...m } } : { error: "entryNotFound" };
    } else if (method === "ledger_entry" && p.mptoken) {
      const h = holdings[`${p.mptoken.mpt_issuance_id}|${p.mptoken.account}`];
      result = h ? { node: { LedgerEntryType: "MPToken", Flags: 0, ...h } } : { error: "entryNotFound" };
    } else if (method === "ledger_entry" && p.credential) {
      const c = credentials[`${p.credential.subject}|${p.credential.issuer}|${p.credential.credential_type}`];
      result = c ? { node: { LedgerEntryType: "Credential", Subject: p.credential.subject, Issuer: p.credential.issuer, CredentialType: p.credential.credential_type, ...c } } : { error: "entryNotFound" };
    } else if (method === "account_info") {
      const a = accounts[p.account];
      result = a === undefined || a === null ? { error: "actNotFound" } : { account_data: { Account: p.account, Flags: a.flags ?? 0, ...(a.transferRate && { TransferRate: a.transferRate }) } };
    } else result = { lines: (lines[p.account] || []).map((currency) => ({ account: p.peer, currency })) };
    return new Response(JSON.stringify({ result }));
  };
}
const run = async (tx, opts = {}, body = {}) => analyzeXrpl(await parseXrplRequest({ type: "xrpl", tx: { Account: ME, ...tx }, ...body }), { fetchImpl: ledger(opts) });
// The OFAC context line (SANCTIONS_SCREENED, or SANCTIONS_SCREEN_UNAVAILABLE without a list) is left out here:
// the sanctions screen of the parties is tested in check-sanctions.test.mjs.
const codes = (r) => r.reasons.filter((x) => !/^SANCTIONS_SCREEN/.test(x.code)).map((x) => `${x.severity}:${x.code}`);

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
  assert.equal((await run({ TransactionType: "XChainCommit" })).reasons[0].code, "XRPL_TX_NOT_ANALYZED");
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

test("token names: an RLUSD look-alike (RLUSD2, RLUSDC, RL-USD) is orange by rule, without TypeSafe; Ripple's RLUSD and other names are not", async () => {
  const { rlusdLookalike } = await import("../src/jev.js");
  assert.deepEqual(["RLUSD2", "RLUSDC", "RL-USD", "R1USD", "rlusd.x"].map(rlusdLookalike), ["RLUSD", "RLUSD", "RLUSD", "RLUSD", "RLUSD"]);
  assert.deepEqual(["RLUSD", "USD", "SOLO", "XRPUSD"].map(rlusdLookalike), [null, null, null, null]);
  const hex = (t) => Buffer.from(t).toString("hex").toUpperCase().padEnd(40, "0");
  const prev = process.env.TYPESAFE_API_KEY; delete process.env.TYPESAFE_API_KEY;
  try {
    const copy = await run({ TransactionType: "Payment", Destination: OTHER, Amount: { currency: hex("RLUSD2"), issuer: FAKE, value: "5" } }, { accounts: { [OTHER]: {}, [FAKE]: {} }, lines: { [OTHER]: [hex("RLUSD2")] } });
    const r = copy.reasons.find((x) => x.code === "AI_TOKEN_IMPERSONATION");
    assert.ok(r, codes(copy).join());
    assert.deepEqual([r.severity, r.subject, r.details.decidedBy, r.details.imitates], ["orange", `RLUSD2.${FAKE}`, "rule", "RLUSD"]);
    assert.equal(copy.verdict, "orange");
    // A trust line to an RLUSDC token, too.
    const trust = await run({ TransactionType: "TrustSet", LimitAmount: { currency: hex("RLUSDC"), issuer: FAKE, value: "1000" } }, { accounts: { [FAKE]: {} } });
    assert.ok(codes(trust).includes("orange:AI_TOKEN_IMPERSONATION"), codes(trust).join());
    // Ripple's own RLUSD and an ordinary token name: no name reason.
    const real = await run({ TransactionType: "Payment", Destination: OTHER, Amount: { currency: RLUSD, issuer: RIPPLE, value: "5" } }, { accounts: { [OTHER]: {}, [RIPPLE]: {} }, lines: { [OTHER]: [RLUSD] } });
    assert.ok(!codes(real).some((c) => c.endsWith("AI_TOKEN_IMPERSONATION")), codes(real).join());
    const solo = await run({ TransactionType: "Payment", Destination: OTHER, Amount: { currency: hex("SOLO"), issuer: FAKE, value: "5" } }, { accounts: { [OTHER]: {}, [FAKE]: {} }, lines: { [OTHER]: [hex("SOLO")] } });
    assert.ok(!codes(solo).some((c) => c.endsWith("AI_TOKEN_IMPERSONATION")));
  } finally { if (prev !== undefined) process.env.TYPESAFE_API_KEY = prev; }
});

test("token names: with TypeSafe set up, Jev judges other names (a USDC from some issuer); Ripple's RLUSD is never asked", async () => {
  const hex = (t) => Buffer.from(t).toString("hex").toUpperCase().padEnd(40, "0");
  const saved = { key: process.env.TYPESAFE_API_KEY, fetch: globalThis.fetch };
  const asked = [];
  process.env.TYPESAFE_API_KEY = "ts_test";
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://api.typesafe.ai/")) {
      const body = JSON.parse(init.body);
      asked.push(body);
      return Response.json({ answers: Object.fromEntries(Object.keys(body.questions).map((id) => [id, { noul: body.state[id.replace(/_impersonates$/, "")]?.symbol === "USD" ? 0.1 : 0.95 }])) });
    }
    return saved.fetch(url, init);
  };
  try {
    const usdc = await run({ TransactionType: "TrustSet", LimitAmount: { currency: "USD", issuer: FAKE, value: "1000" } }, { accounts: { [FAKE]: {} } });
    assert.ok(!codes(usdc).includes("orange:AI_TOKEN_IMPERSONATION"), "a plain USD IOU is not a copy (Jev 10%)");
    const fake = await run({ TransactionType: "TrustSet", LimitAmount: { currency: hex("USDC"), issuer: FAKE, value: "1000" } }, { accounts: { [FAKE]: {} } });
    const r = fake.reasons.find((x) => x.code === "AI_TOKEN_IMPERSONATION");
    assert.deepEqual([r?.severity, r?.subject, r?.details.decidedBy, r?.details.probability], ["orange", `USDC.${FAKE}`, "jev", 0.95]);
    assert.ok(fake.sources.includes("typesafe-jev"));
    assert.equal(asked.at(-1).state.chain_id, "xrpl");
    assert.deepEqual(asked.at(-1).state.well_known_tokens_official_contracts, { RLUSD: `RLUSD.${RIPPLE}` });
    const n = asked.length;
    await run({ TransactionType: "TrustSet", LimitAmount: { currency: RLUSD, issuer: RIPPLE, value: "1000" } }, { accounts: { [RIPPLE]: {} } });
    assert.equal(asked.length, n, "Ripple's RLUSD is not asked about");
  } finally {
    globalThis.fetch = saved.fetch;
    if (saved.key === undefined) delete process.env.TYPESAFE_API_KEY; else process.env.TYPESAFE_API_KEY = saved.key;
  }
});

test("credentials (XLS-70): issuing one for another account is orange; accepting is info, or orange when it would fail", async () => {
  const KYC = Buffer.from("KYC").toString("hex").toUpperCase();
  const issue = await run({ TransactionType: "CredentialCreate", Subject: OTHER, CredentialType: KYC });
  assert.deepEqual(codes(issue), ["orange:XRPL_CREDENTIAL_ISSUE"]);
  assert.equal(issue.reasons[0].details.credentialType, "KYC");
  assert.equal((await run({ TransactionType: "CredentialCreate", Subject: ME, CredentialType: KYC })).verdict, "green");

  const accept = { TransactionType: "CredentialAccept", Issuer: OTHER, CredentialType: KYC };
  const key = `${ME}|${OTHER}|${KYC}`;
  const ok = await run(accept, { accounts: { [OTHER]: {} }, credentials: { [key]: { Flags: 0 } } });
  assert.equal(ok.verdict, "green"); assert.deepEqual(codes(ok), ["info:XRPL_CREDENTIAL_ACCEPT"]);
  assert.deepEqual(codes(await run(accept, { accounts: { [OTHER]: {} } })), ["orange:XRPL_CREDENTIAL_NOT_FOUND"]);
  assert.deepEqual(codes(await run(accept, { accounts: { [OTHER]: {} }, credentials: { [key]: { Flags: 0x00010000 } } })), ["orange:XRPL_CREDENTIAL_ALREADY_ACCEPTED"]);
  assert.deepEqual(codes(await run(accept, { accounts: { [OTHER]: {} }, credentials: { [key]: { Flags: 0, Expiration: 100 } } })), ["orange:XRPL_CREDENTIAL_EXPIRED"]);
  assert.deepEqual(codes(await run(accept)), ["orange:XRPL_ISSUER_NOT_FOUND"]);
  assert.deepEqual(codes(await run(accept, { down: true })), ["info:XRPL_LEDGER_UNAVAILABLE"]);

  assert.equal((await run({ TransactionType: "CredentialDelete", Issuer: OTHER, CredentialType: KYC })).verdict, "green");
  assert.equal((await run({ TransactionType: "PermissionedDomainSet", AcceptedCredentials: [] })).verdict, "green");
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { TransactionType: "CredentialAccept", Account: ME, Issuer: OTHER, CredentialType: "KYC" } }), /CredentialType must be hex/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { TransactionType: "CredentialCreate", Account: ME, Subject: "rNotAnAddress", CredentialType: KYC } }), /Subject/);
});

const THIRD = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
const INNER = 0x40000000; // tfInnerBatchTxn
const batch = (flags, ...inner) => ({ TransactionType: "Batch", Flags: flags, RawTransactions: inner.map((t) => ({ RawTransaction: { Account: ME, Flags: INNER, Fee: "0", SigningPubKey: "", ...t } })) });

test("Batch (XLS-56): every inner transaction is judged, so a takeover can't hide in one", async () => {
  const pay = { TransactionType: "Payment", Destination: OTHER, Amount: "15000" };
  const plain = await run(batch(0x00010000, pay, { ...pay, Amount: "20000" }), { accounts: { [OTHER]: {} } });
  assert.equal(plain.verdict, "green");
  assert.deepEqual(codes(plain), ["info:XRPL_BATCH"]);
  assert.deepEqual(plain.reasons[0].details, { mode: "tfAllOrNothing", transactions: ["Payment", "Payment"] });

  const hidden = await run(batch(0x00080000, pay, { TransactionType: "SetRegularKey", RegularKey: OTHER }), { accounts: { [OTHER]: {} } });
  assert.equal(hidden.verdict, "red");
  const r = hidden.reasons.find((x) => x.code === "XRPL_REGULAR_KEY_CHANGE");
  assert.equal(r.details.inner, 1);
  assert.equal(r.details.account, undefined, "the signer's own inner transaction");

  // The same refusing destination in two inner payments: a reason for each, by its place.
  const tagged = await run(batch(0x00080000, pay, pay), { accounts: { [OTHER]: { flags: 0x00020000 } } });
  assert.deepEqual(tagged.reasons.filter((x) => x.code === "XRPL_DESTINATION_TAG_MISSING").map((x) => x.details.inner), [0, 1]);
  // xrpl.js flag objects are read too.
  assert.equal((await run({ ...batch(0, pay, pay), Flags: { tfAllOrNothing: true } }, { accounts: { [OTHER]: {} } })).verdict, "green");
});

test("Batch: another account's part without all-or-nothing is orange; its takeover is red, with the account", async () => {
  const mine = { TransactionType: "Payment", Destination: OTHER, Amount: "5000000" };
  const theirs = { TransactionType: "Payment", Account: OTHER, Destination: ME, Amount: "5000000" };
  const accounts = { [OTHER]: {}, [ME]: {} };
  const swap = await run({ ...batch(0x00080000, mine, theirs), BatchSigners: [{ BatchSigner: { Account: OTHER, SigningPubKey: "" } }] }, { accounts });
  assert.deepEqual(codes(swap), ["info:XRPL_BATCH", "orange:XRPL_BATCH_NOT_ATOMIC"]);
  assert.deepEqual(swap.reasons[1].details.accounts, [ME, OTHER]);
  assert.equal(swap.reasons[1].details.mode, "tfIndependent");
  for (const flags of [0x00020000, 0x00040000]) assert.equal((await run(batch(flags, mine, theirs), { accounts })).verdict, "orange");
  assert.equal((await run(batch(0x00010000, mine, theirs), { accounts })).verdict, "green", "all or nothing: both parts or neither");

  const takeover = await run(batch(0x00010000, mine, { TransactionType: "AccountDelete", Account: OTHER, Destination: THIRD }), { accounts: { ...accounts, [THIRD]: {} } });
  const del = takeover.reasons.find((x) => x.code === "XRPL_ACCOUNT_DELETE");
  assert.deepEqual([del.severity, del.details.inner, del.details.account], ["red", 1, OTHER]);
});

test("Batch: the request must be one the ledger accepts", async () => {
  const pay = { TransactionType: "Payment", Destination: OTHER, Amount: "15000" };
  const parse = (tx) => parseXrplRequest({ type: "xrpl", tx: { Account: ME, ...tx } });
  await assert.rejects(parse(batch(0x00010000, pay)), /2 to 8 transactions/);
  await assert.rejects(parse(batch(0x00010000, ...Array(9).fill(pay))), /2 to 8 transactions/);
  await assert.rejects(parse({ TransactionType: "Batch", Flags: 0x00010000 }), /RawTransactions/);
  await assert.rejects(parse(batch(0x00010000, pay, batch(0x00010000, pay, pay))), /can't contain another Batch/);
  await assert.rejects(parse(batch(0, pay, pay)), /exactly one batch mode/);
  await assert.rejects(parse(batch(0x00010000 | 0x00080000, pay, pay)), /exactly one batch mode/);
  await assert.rejects(parse(batch(0x00010000, pay, { ...pay, Destination: "rNope" })), /RawTransactions\[1\]\.RawTransaction\.Destination/);
  await assert.rejects(parse({ ...batch(0x00010000, pay, pay), BatchSigners: [{ BatchSigner: { Account: "0xabc" } }] }), /BatchSigners\[0\]/);
});

test("DelegateSet (XLS-75): permissions that move funds are red, others orange, removing them is info", async () => {
  const delegate = (...values) => ({ TransactionType: "DelegateSet", Authorize: OTHER, Permissions: values.map((PermissionValue) => ({ Permission: { PermissionValue } })) });
  const accounts = { [OTHER]: {} };
  const pay = await run(delegate("Payment", "TrustlineAuthorize"), { accounts });
  assert.deepEqual(codes(pay), ["red:XRPL_DELEGATE_FUNDS"]);
  assert.deepEqual([pay.reasons[0].subject, pay.reasons[0].details.movesFunds, pay.reasons[0].details.permissions], [OTHER, ["Payment"], ["Payment", "TrustlineAuthorize"]]);
  for (const v of ["CheckCreate", "EscrowCreate", "PaymentChannelCreate", "OfferCreate", "NFTokenAcceptOffer", "PaymentMint", 1, 17]) {
    assert.equal((await run(delegate(v), { accounts })).verdict, "red", String(v));
  }
  assert.deepEqual((await run(delegate(1), { accounts })).reasons[0].details.permissions, ["Payment"], "a number is a transaction type's code + 1");
  const domain = await run(delegate("AccountDomainSet", 65537), { accounts });
  assert.deepEqual(codes(domain), ["orange:XRPL_DELEGATE_SET"]);
  assert.deepEqual(domain.reasons[0].details.permissions, ["AccountDomainSet", "TrustlineAuthorize"]);
  const removed = await run(delegate(), { accounts });
  assert.equal(removed.verdict, "green"); assert.deepEqual(codes(removed), ["info:XRPL_DELEGATE_REMOVED"]);
  assert.ok(codes(await run(delegate("AccountDomainSet"))).includes("orange:XRPL_DELEGATE_NOT_FOUND"), "a delegate that doesn't exist: it fails");

  // Inside a Batch, too.
  const inBatch = await run(batch(0x00010000, { TransactionType: "Payment", Destination: OTHER, Amount: "15000" }, delegate("Payment")), { accounts });
  assert.equal(inBatch.reasons.find((x) => x.code === "XRPL_DELEGATE_FUNDS").details.inner, 1);

  const parse = (tx) => parseXrplRequest({ type: "xrpl", tx: { Account: ME, ...tx } });
  await assert.rejects(parse(delegate("SetRegularKey")), /SetRegularKey can't be delegated/);
  await assert.rejects(parse(delegate(6)), /SetRegularKey can't be delegated/);
  await assert.rejects(parse(delegate("Payment", "Payment")), /twice/);
  await assert.rejects(parse(delegate(...Array.from({ length: 11 }, (_, i) => `P${i}`))), /at most 10/);
  await assert.rejects(parse({ ...delegate("Payment"), Authorize: ME }), /Authorize is required/);
  await assert.rejects(parse({ TransactionType: "DelegateSet", Authorize: OTHER }), /Permissions/);
  await assert.rejects(parse({ ...delegate("Payment"), Authorize: "rNope" }), /Authorize must be a valid XRPL address/);
});


// An MPT issuance ID is the issuer's sequence (4 bytes) and account ID (20 bytes).
const mptId = (address, seq = 42) => seq.toString(16).toUpperCase().padStart(8, "0") + Buffer.from(accountId(address)).toString("hex").toUpperCase();
function accountId(address) {
  const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
  let n = 0n;
  for (const ch of address) n = n * 58n + BigInt(ALPHABET.indexOf(ch));
  return Buffer.from(n.toString(16).padStart(50, "0"), "hex").subarray(1, 21);
}
const meta = (o) => Buffer.from(JSON.stringify(o)).toString("hex").toUpperCase();

test("MPTs (XLS-33): issuer, ticker and the metadata of the xrpl.org example", async () => {
  const { mptIssuer, mptTicker } = await import("../src/xrpl.js");
  assert.equal(mptIssuer(mptId(OTHER)), OTHER);
  assert.equal(mptIssuer(mptId(FAKE, 7)), FAKE, "an address with leading zero bytes");
  assert.equal(mptIssuer("nope"), null);
  assert.equal(mptTicker({ MPTokenMetadata: meta({ t: "GOLD", n: "Gold" }) }), "GOLD", "compact keys");
  assert.equal(mptTicker({ MPTokenMetadata: "7B227469636B6572223A20225442494C4C222C20226E616D65223A2022542D42696C6C205969656C6420546F6B656E227D" }), "TBILL");
  assert.equal(mptTicker({ MPTokenMetadata: "ZZ" }), null);
  assert.equal(mptTicker({}), null);
});

test("MPTs: opting in gets the issuer checks; a fake RLUSD ticker is red; letting someone hold yours is fine", async () => {
  const id = mptId(OTHER);
  const optIn = { TransactionType: "MPTokenAuthorize", MPTokenIssuanceID: id };
  const plain = await run(optIn, { mpts: { [id]: { MPTokenMetadata: meta({ ticker: "GOLD" }) } } });
  assert.equal(plain.verdict, "green", codes(plain).join());
  const risky = await run(optIn, { mpts: { [id]: { Flags: 0x40 | 0x01, TransferFee: 2500, MPTokenMetadata: meta({ ticker: "GOLD" }) } } });
  assert.deepEqual(codes(risky), ["orange:XRPL_ISSUER_CAN_CLAW_BACK", "orange:XRPL_ISSUER_FROZEN", "orange:XRPL_TRANSFER_FEE"]);
  assert.deepEqual([risky.reasons[0].subject, risky.reasons[0].details.token, risky.reasons[2].details.feePercent], [OTHER, "GOLD", 2.5]);
  assert.deepEqual(codes(await run(optIn)), ["orange:XRPL_MPT_NOT_FOUND"]);
  assert.deepEqual(codes(await run(optIn, { down: true })), ["info:XRPL_LEDGER_UNAVAILABLE"]);

  const fake = await run(optIn, { mpts: { [id]: { MPTokenMetadata: meta({ ticker: "RLUSD" }) } } });
  assert.equal(fake.verdict, "red"); assert.equal(fake.reasons[0].code, "XRPL_FAKE_RLUSD");
  const rippleId = mptId(RIPPLE);
  const real = await run({ ...optIn, MPTokenIssuanceID: rippleId }, { mpts: { [rippleId]: { Flags: 0x40, MPTokenMetadata: meta({ ticker: "RLUSD" }) } } });
  assert.deepEqual(codes(real), ["info:XRPL_ISSUER_CAN_CLAW_BACK"], "Ripple's own: clawback by design");

  // The issuer authorising a holder, or a holder leaving: nothing to check. Issuer housekeeping is fine too.
  assert.equal((await run({ ...optIn, Holder: THIRD })).verdict, "green");
  assert.equal((await run({ ...optIn, Flags: 1 })).verdict, "green");
  for (const t of ["MPTokenIssuanceCreate", "MPTokenIssuanceSet", "MPTokenIssuanceDestroy"]) assert.equal((await run({ TransactionType: t })).verdict, "green", t);

  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { TransactionType: "MPTokenAuthorize", Account: ME } }), /MPTokenIssuanceID must be 48 hex/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...optIn, Account: ME, Holder: "rNope" } }), /Holder/);
});

test("MPTs: a payment that would fail is orange (locked, not transferable, destination not opted in or not authorised)", async () => {
  const id = mptId(THIRD);
  const pay = { TransactionType: "Payment", Destination: OTHER, Amount: { mpt_issuance_id: id, value: "100" } };
  const ok = { accounts: { [OTHER]: {} }, mpts: { [id]: { Flags: 0x20, MPTokenMetadata: meta({ ticker: "GOLD" }) } }, holdings: { [`${id}|${OTHER}`]: {} } };
  const good = await run(pay, ok);
  assert.equal(good.verdict, "green", codes(good).join());
  assert.deepEqual(good.subject.amount, pay.Amount, "an MPT amount is shown as it is");

  assert.deepEqual(codes(await run(pay, { ...ok, holdings: {} })), ["orange:XRPL_DESTINATION_NO_MPTOKEN"]);
  assert.deepEqual(codes(await run(pay, { ...ok, mpts: { [id]: { Flags: 0 } } })), ["orange:XRPL_MPT_NOT_TRANSFERABLE"]);
  assert.equal((await run({ ...pay, Destination: THIRD }, { ...ok, accounts: { [THIRD]: {} }, mpts: { [id]: { Flags: 0 } } })).verdict, "green", "back to the issuer is always allowed");
  assert.deepEqual(codes(await run(pay, { ...ok, mpts: { [id]: { Flags: 0x20 | 0x01 } } })), ["orange:XRPL_MPT_LOCKED"]);
  assert.deepEqual(codes(await run(pay, { ...ok, mpts: { [id]: { Flags: 0x20 | 0x04 } } })), ["orange:XRPL_DESTINATION_NOT_AUTHORIZED"]);
  assert.equal((await run(pay, { ...ok, mpts: { [id]: { Flags: 0x20 | 0x04 } }, holdings: { [`${id}|${OTHER}`]: { Flags: 0x02 } } })).verdict, "green");
  const lockedHolder = await run(pay, { ...ok, holdings: { [`${id}|${OTHER}`]: { Flags: 0x01 } } });
  assert.deepEqual([codes(lockedHolder), lockedHolder.reasons[0].subject], [["orange:XRPL_MPT_LOCKED"], OTHER]);
  assert.deepEqual(codes(await run(pay, { mpts: ok.mpts })), ["orange:XRPL_DESTINATION_NOT_ACTIVATED"], "no account, no holding lookup");
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...pay, Account: ME, Amount: { mpt_issuance_id: "12", value: "1" } } }), /mpt_issuance_id must be 48 hex/);
});

test("checks and payment channels to someone else are orange; everyday types without risk are green", async () => {
  const check = await run({ TransactionType: "CheckCreate", Destination: OTHER, SendMax: "5000000" });
  assert.deepEqual(codes(check), ["orange:XRPL_CHECK_TO_OTHER"]);
  assert.equal(check.reasons[0].details.sendMax, "5000000");
  const channel = await run({ TransactionType: "PaymentChannelCreate", Destination: OTHER, Amount: "10000000", SettleDelay: 86400, PublicKey: "ED" + "00".repeat(32) });
  assert.deepEqual(codes(channel), ["orange:XRPL_CHANNEL_TO_OTHER"]);
  const id = "AB".repeat(32);
  const fund = await run({ TransactionType: "PaymentChannelFund", Channel: id, Amount: "1000000" }, { channels: { [id]: { Account: ME, Destination: OTHER } } });
  assert.deepEqual([codes(fund), fund.reasons[0].subject, fund.reasons[0].details.channel], [["orange:XRPL_CHANNEL_TO_OTHER"], OTHER, id]);
  assert.deepEqual(codes(await run({ TransactionType: "PaymentChannelFund", Channel: id, Amount: "1000000" })), ["orange:XRPL_CHANNEL_NOT_FOUND"]);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { TransactionType: "PaymentChannelFund", Account: ME, Channel: "12", Amount: "1" } }), /Channel must be/);
  for (const t of ["PaymentChannelClaim", "DepositPreauth", "Clawback", "AMMClawback", "AMMDelete", "DIDSet", "DIDDelete", "OracleSet", "OracleDelete", "NFTokenModify"]) {
    assert.equal((await run({ TransactionType: t })).verdict, "green", t);
  }
});
