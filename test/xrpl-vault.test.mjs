// XRPL vaults (XLS-65) and lending (XLS-66) in the pre-sign check (src/xrpl.js), against a stand-in ledger: deposits
// into lending vaults, fixed-term funds and vaults with a paper loss, withdrawals to another account, loan terms that
// cost the borrower too much, loan payments that would fail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseXrplRequest, analyzeXrpl, loanCost } from "../src/xrpl.js";

const ME = "rMnHeutYALco8RYFVcmuU4BCgSzBpPEh32";
const OTHER = "rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv";
const OWNER = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
const PSEUDO = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const RIPPLE = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";
const FAKE = "rrrrrrrrrrrrrrrrrrrrBZbvji";
const RLUSD = "524C555344000000000000000000000000000000";
const rlusd = (value, issuer = RIPPLE) => ({ currency: RLUSD, issuer, value });
const id = (n) => String(n).repeat(64).slice(0, 64);
const VAULT = id("A"), BROKER = id("B"), LOAN = id("C");
const now = () => Math.floor(Date.now() / 1000) - 946684800;
const DAY = 86400;

// entries: ledger index -> node; owned: address -> [nodes]; accounts: address -> { flags } (missing = not found)
function ledger({ entries = {}, owned = {}, accounts = {} } = {}) {
  return async (_url, init) => {
    const { method, params: [p] } = JSON.parse(init.body);
    let result;
    if (method === "ledger_entry" && p.index) result = entries[p.index] ? { node: entries[p.index] } : { error: "entryNotFound" };
    else if (method === "ledger_entry") result = { error: "entryNotFound" };
    else if (method === "account_objects") result = { account_objects: owned[p.account] ?? [] };
    else if (method === "account_info") {
      const a = accounts[p.account];
      result = a ? { account_data: { Account: p.account, Flags: a.flags ?? 0 } } : { error: "actNotFound" };
    } else result = {};
    return new Response(JSON.stringify({ result }));
  };
}
const run = async (tx, opts = {}) => analyzeXrpl(await parseXrplRequest({ type: "xrpl", tx: { Account: ME, ...tx } }), { fetchImpl: ledger(opts) });
const codes = (r) => r.reasons.filter((x) => !/^SANCTIONS_SCREEN/.test(x.code)).map((x) => `${x.severity}:${x.code}`);
const reason = (r, code) => r.reasons.find((x) => x.code === code);

const vault = (fields = {}) => ({ LedgerEntryType: "Vault", Owner: OWNER, Account: PSEUDO, Asset: { currency: RLUSD, issuer: RIPPLE }, AssetsTotal: "1000", AssetsAvailable: "1000", LossUnrealized: "0", ShareMPTID: "00000001" + "AB".repeat(20), Flags: 0, ...fields });
const issuer = { [RIPPLE]: { flags: 0x80000000 } };
const deposit = { TransactionType: "VaultDeposit", VaultID: VAULT, Amount: rlusd("100") };

test("requests: vault, broker and loan IDs are 64 hex; loan terms within the ledger's limits", async () => {
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { Account: ME, TransactionType: "VaultDeposit", Amount: "1" } }), /VaultID is required/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { Account: ME, TransactionType: "VaultDeposit", VaultID: "abc", Amount: "1" } }), /VaultID must be/);
  const loan = { Account: ME, TransactionType: "LoanSet", LoanBrokerID: BROKER, PrincipalRequested: "100" };
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...loan, PrincipalRequested: "0" } }), /PrincipalRequested/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...loan, InterestRate: 100001 } }), /InterestRate/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...loan, LoanOriginationFee: "101" } }), /LoanOriginationFee/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...loan, PaymentInterval: 3600, GracePeriod: 7200 } }), /GracePeriod/);
  await assert.rejects(parseXrplRequest({ type: "xrpl", tx: { ...loan, Counterparty: "0xabc" } }), /Counterparty/);
});

test("a deposit into a plain RLUSD vault is green; a vault that doesn't exist or holds another asset fails", async () => {
  const ok = await run(deposit, { entries: { [VAULT]: vault() }, accounts: issuer });
  assert.equal(ok.verdict, "green", JSON.stringify(ok.reasons));
  assert.deepEqual(codes(ok), ["info:XRPL_ISSUER_CAN_CLAW_BACK"]);
  assert.deepEqual(codes(await run(deposit, { accounts: issuer })), ["orange:XRPL_VAULT_NOT_FOUND"]);
  const xrpVault = await run(deposit, { entries: { [VAULT]: vault({ Asset: { currency: "XRP" } }) }, accounts: issuer });
  assert.ok(codes(xrpVault).includes("orange:XRPL_VAULT_WRONG_ASSET"));
  assert.equal(reason(xrpVault, "XRPL_VAULT_WRONG_ASSET").details.vaultAsset, "XRP");
});

test("a vault of fake RLUSD is red; a token whose issuer can claw back is orange", async () => {
  const fake = await run({ ...deposit, Amount: rlusd("100", FAKE) }, { entries: { [VAULT]: vault({ Asset: { currency: RLUSD, issuer: FAKE } }) }, accounts: { [FAKE]: {} } });
  assert.equal(fake.verdict, "red");
  assert.ok(codes(fake).includes("red:XRPL_FAKE_RLUSD"));
  const usd = { currency: "USD", issuer: OTHER };
  const claw = await run({ ...deposit, Amount: { ...usd, value: "5" } }, { entries: { [VAULT]: vault({ Asset: usd }) }, accounts: { [OTHER]: { flags: 0x80000000 } } });
  assert.deepEqual(codes(claw), ["orange:XRPL_ISSUER_CAN_CLAW_BACK"]);
});

test("a lending vault: deposits are lent out unsecured; first-loss cover and the share lent out are shown", async () => {
  const lending = vault({ AssetsTotal: "1000", AssetsAvailable: "400" });
  const brokerNode = { LedgerEntryType: "LoanBroker", Owner: OWNER, VaultID: VAULT, DebtTotal: "600", CoverAvailable: "60" };
  const r = await run(deposit, { entries: { [VAULT]: lending }, owned: { [PSEUDO]: [brokerNode, { LedgerEntryType: "MPToken" }] }, accounts: issuer });
  assert.equal(r.verdict, "orange");
  const lends = reason(r, "XRPL_VAULT_LENDS");
  assert.equal(lends.subject, OWNER);
  assert.equal(lends.details.loanBrokers, 1);
  assert.equal(lends.details.lentOutPct, 60);
  assert.equal(lends.details.firstLossCoverPct, 10);
  assert.match(lends.details.effect, /without collateral/);
});

test("a vault with a paper loss: deposits are orange, withdrawals info", async () => {
  const lossy = vault({ AssetsTotal: "1000", AssetsAvailable: "200", LossUnrealized: "250" });
  const r = await run(deposit, { entries: { [VAULT]: lossy }, accounts: issuer });
  assert.equal(reason(r, "XRPL_VAULT_PAPER_LOSS").severity, "orange");
  assert.equal(reason(r, "XRPL_VAULT_PAPER_LOSS").details.lossPct, 25);
  const w = await run({ TransactionType: "VaultWithdraw", VaultID: VAULT, Amount: rlusd("100") }, { entries: { [VAULT]: lossy } });
  assert.equal(reason(w, "XRPL_VAULT_PAPER_LOSS").severity, "info");
});

test("a fixed-term fund: deposits lock until redemption, close after subscription; withdrawals blocked in between", async () => {
  const fund = (sub, red) => vault({ VaultKind: 1, SubscriptionDate: now() + sub, RedemptionDate: now() + red });
  const open = await run(deposit, { entries: { [VAULT]: fund(10 * DAY, 200 * DAY) }, accounts: issuer });
  const lock = reason(open, "XRPL_VAULT_LOCKUP");
  assert.equal(lock.severity, "orange");
  assert.ok(lock.details.redemptionFrom > lock.details.subscriptionEnds);
  assert.ok(codes(await run(deposit, { entries: { [VAULT]: fund(-DAY, 200 * DAY) }, accounts: issuer })).includes("orange:XRPL_VAULT_CLOSED"));
  const withdraw = { TransactionType: "VaultWithdraw", VaultID: VAULT, Amount: rlusd("10") };
  assert.ok(codes(await run(withdraw, { entries: { [VAULT]: fund(-DAY, 200 * DAY) } })).includes("orange:XRPL_VAULT_LOCKED"));
  assert.equal((await run(withdraw, { entries: { [VAULT]: fund(-200 * DAY, -DAY) } })).verdict, "green");
});

test("deposits that fail: private vault (info), over the maximum", async () => {
  const priv = await run(deposit, { entries: { [VAULT]: vault({ Flags: 0x00010000 }) }, accounts: issuer });
  assert.ok(codes(priv).includes("info:XRPL_VAULT_PRIVATE"));
  assert.ok(codes(await run(deposit, { entries: { [VAULT]: vault({ AssetsMaximum: "1050" }) }, accounts: issuer })).includes("orange:XRPL_VAULT_FULL"));
});

test("withdrawals: to another account is orange; more than is available fails; shares can be redeemed", async () => {
  const w = { TransactionType: "VaultWithdraw", VaultID: VAULT, Amount: rlusd("100") };
  const other = await run({ ...w, Destination: OTHER }, { entries: { [VAULT]: vault() }, accounts: { [OTHER]: {} } });
  assert.deepEqual(codes(other), ["orange:XRPL_WITHDRAW_TO_OTHER"]);
  assert.ok(codes(await run({ ...w, Destination: OTHER }, { entries: { [VAULT]: vault() } })).includes("orange:XRPL_DESTINATION_NOT_FOUND"));
  assert.equal((await run({ ...w, Destination: ME }, { entries: { [VAULT]: vault() } })).verdict, "green");
  assert.ok(codes(await run(w, { entries: { [VAULT]: vault({ AssetsAvailable: "40" }) } })).includes("orange:XRPL_VAULT_ILLIQUID"));
  const shares = await run({ ...w, Amount: { mpt_issuance_id: vault().ShareMPTID, value: "5000" } }, { entries: { [VAULT]: vault({ AssetsAvailable: "40" }) } });
  assert.equal(shares.verdict, "green", JSON.stringify(shares.reasons));
  const cover = await run({ TransactionType: "LoanBrokerCoverWithdraw", LoanBrokerID: BROKER, Amount: rlusd("5"), Destination: OTHER }, { accounts: { [OTHER]: {} } });
  assert.deepEqual(codes(cover), ["orange:XRPL_WITHDRAW_TO_OTHER"]);
});

test("loan cost: amortized payments, fees, effective yearly rate", () => {
  const plain = loanCost({ PrincipalRequested: "1000", InterestRate: 10000, PaymentTotal: 12, PaymentInterval: 30 * DAY });
  assert.equal(plain.effectivePct, 10);
  assert.ok(Math.abs(plain.payment - 87.85) < 0.01);
  const fees = loanCost({ PrincipalRequested: "1000", InterestRate: 10000, PaymentTotal: 12, PaymentInterval: 30 * DAY, LoanOriginationFee: "50", LoanServiceFee: "2" });
  assert.equal(fees.received, 950);
  assert.ok(fees.effectivePct > 20 && fees.effectivePct < 30);
  assert.equal(loanCost({ PrincipalRequested: "100" }).effectivePct, 0);
});

test("a loan: terms are shown; a costly one is orange; the borrower is the account that isn't the broker's owner", async () => {
  const broker = { LedgerEntryType: "LoanBroker", Owner: OWNER, VaultID: VAULT, Account: PSEUDO };
  const ledgerState = { entries: { [BROKER]: broker, [VAULT]: vault() }, accounts: { [ME]: {}, [OWNER]: {} } };
  const fair = { TransactionType: "LoanSet", LoanBrokerID: BROKER, PrincipalRequested: "500", InterestRate: 8000, PaymentTotal: 6, PaymentInterval: 30 * DAY, GracePeriod: 5 * DAY };
  const ok = await run(fair, ledgerState);
  assert.equal(ok.verdict, "green", JSON.stringify(ok.reasons));
  const terms = reason(ok, "XRPL_LOAN_TERMS");
  assert.equal(terms.details.borrower, ME);
  assert.equal(terms.details.lender, OWNER);
  assert.equal(terms.details.token, "RLUSD");
  assert.equal(terms.details.every, "30 days");
  assert.equal(terms.details.interestRatePct, 8);
  // The broker's owner sends it, naming the borrower.
  const fromLender = await run({ ...fair, Account: OWNER, Counterparty: ME }, ledgerState);
  assert.equal(reason(fromLender, "XRPL_LOAN_TERMS").details.borrower, ME);
  // 5% origination fee, a service fee and a weekly schedule: far above 36% a year.
  const costly = await run({ ...fair, LoanOriginationFee: "25", LoanServiceFee: "5", PaymentInterval: 7 * DAY, GracePeriod: DAY }, ledgerState);
  const c = reason(costly, "XRPL_LOAN_COSTLY");
  assert.equal(c.severity, "orange");
  assert.ok(c.details.effectiveAnnualPct > 36);
  assert.equal(c.details.borrowerReceives, 475);
});

test("loans that fail: no broker, nobody owns it, no borrower named, borrower missing, vault short, fund out of term", async () => {
  const broker = { LedgerEntryType: "LoanBroker", Owner: OWNER, VaultID: VAULT };
  const loan = { TransactionType: "LoanSet", LoanBrokerID: BROKER, PrincipalRequested: "500", PaymentInterval: 30 * DAY, PaymentTotal: 3 };
  assert.deepEqual(codes(await run(loan)), ["orange:XRPL_LOAN_BROKER_NOT_FOUND"]);
  const state = (v = vault()) => ({ entries: { [BROKER]: broker, [VAULT]: v }, accounts: { [ME]: {}, [OWNER]: {} } });
  assert.ok(codes(await run({ ...loan, Counterparty: OTHER }, state())).includes("orange:XRPL_LOAN_NOT_THE_BROKER"));
  assert.ok(codes(await run({ ...loan, Account: OWNER }, state())).includes("orange:XRPL_LOAN_NO_BORROWER"));
  assert.ok(codes(await run({ ...loan, Account: OWNER, Counterparty: OTHER }, state())).includes("orange:XRPL_BORROWER_NOT_FOUND"));
  assert.ok(codes(await run(loan, state(vault({ AssetsAvailable: "100" })))).includes("orange:XRPL_VAULT_ILLIQUID"));
  const fund = (sub, red) => vault({ VaultKind: 1, SubscriptionDate: now() + sub, RedemptionDate: now() + red });
  assert.ok(codes(await run(loan, state(fund(DAY, 300 * DAY)))).includes("orange:XRPL_LOAN_OUTSIDE_TERM"), "still in subscription");
  assert.ok(codes(await run(loan, state(fund(-DAY, 60 * DAY)))).includes("orange:XRPL_LOAN_OUTSIDE_TERM"), "ends after redemption");
  assert.equal((await run(loan, state(fund(-DAY, 300 * DAY)))).verdict, "green");
});

test("loan payments: the amount due; another's loan, a paid-off loan or a late payment without the flag fail", async () => {
  const loanNode = (fields = {}) => ({ LedgerEntryType: "Loan", Borrower: ME, LoanBrokerID: BROKER, PeriodicPayment: "84.5", LoanServiceFee: "1", PaymentRemaining: 5, NextPaymentDueDate: now() + 10 * DAY, ...fields });
  const pay = { TransactionType: "LoanPay", LoanID: LOAN, Amount: rlusd("85.5") };
  const ok = await run(pay, { entries: { [LOAN]: loanNode() } });
  assert.equal(ok.verdict, "green");
  assert.equal(reason(ok, "XRPL_LOAN_PAYMENT").details.paymentDue, 85.5);
  assert.deepEqual(codes(await run(pay)), ["orange:XRPL_LOAN_NOT_FOUND"]);
  assert.deepEqual(codes(await run(pay, { entries: { [LOAN]: loanNode({ Borrower: OTHER }) } })), ["orange:XRPL_LOAN_NOT_YOURS"]);
  assert.deepEqual(codes(await run(pay, { entries: { [LOAN]: loanNode({ PaymentRemaining: 0 }) } })), ["orange:XRPL_LOAN_PAID_OFF"]);
  const late = loanNode({ NextPaymentDueDate: now() - DAY, LatePaymentFee: "3" });
  assert.ok(codes(await run(pay, { entries: { [LOAN]: late } })).includes("orange:XRPL_LOAN_PAYMENT_LATE"));
  const flagged = await run({ ...pay, Flags: 0x00040000 }, { entries: { [LOAN]: late } });
  assert.equal(flagged.verdict, "green");
  assert.equal(reason(flagged, "XRPL_LOAN_PAYMENT").details.latePaymentFee, "3");
});

test("the owner's own vault and broker transactions, and issuer clawbacks, are judged benign", async () => {
  for (const tx of [
    { TransactionType: "VaultCreate", Asset: { currency: "XRP" } },
    { TransactionType: "VaultSet", VaultID: VAULT },
    { TransactionType: "LoanBrokerSet", VaultID: VAULT },
    { TransactionType: "LoanBrokerCoverDeposit", LoanBrokerID: BROKER, Amount: rlusd("10") },
    { TransactionType: "LoanManage", LoanID: LOAN, Flags: 0x00010000 },
    { TransactionType: "LoanDelete", LoanID: LOAN },
    { TransactionType: "VaultClawback", VaultID: VAULT, Holder: OTHER },
  ]) assert.equal((await run(tx)).verdict, "green", tx.TransactionType);
});

test("inside a Batch a vault withdrawal to another account is still caught", async () => {
  const r = await run({
    TransactionType: "Batch", Flags: 0x00010000,
    RawTransactions: [
      { RawTransaction: { TransactionType: "Payment", Account: ME, Destination: OTHER, Amount: "1000000" } },
      { RawTransaction: { TransactionType: "VaultWithdraw", Account: ME, VaultID: VAULT, Amount: rlusd("100"), Destination: OTHER } },
    ],
  }, { entries: { [VAULT]: vault() }, accounts: { [OTHER]: {} } });
  const w = reason(r, "XRPL_WITHDRAW_TO_OTHER");
  assert.equal(w.details.inner, 1);
});
