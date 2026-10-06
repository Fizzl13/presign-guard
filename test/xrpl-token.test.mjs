// The XRPL token verdict (chain "xrpl" on /v1/token) against a stand-in ledger and DexScreener.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTokenRequest, tokenVerdict } from "../src/token-verdict.js";

const RIPPLE = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";
const ISSUER = "rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv";
const RLUSD = "524C555344000000000000000000000000000000";
const realFetch = globalThis.fetch;
// DexScreener answers no pairs unless given; the ledger is a separate stand-in.
function stubDex(pairs = []) { globalThis.fetch = async () => new Response(JSON.stringify(pairs)); }
const node = (account, signerLists = []) => async (_u, init) => {
  const { params: [p] } = JSON.parse(init.body);
  const result = account === null ? { error: "actNotFound" } : { account_data: { Account: p.account, ...account }, signer_lists: signerLists };
  return new Response(JSON.stringify({ result }));
};
const verdict = (address, account, opts = {}) => tokenVerdict(parseTokenRequest({ chain: "xrpl", address }), Date.now(), { fetchImpl: node(account, opts.signerLists) });
const codes = (r) => r.reasons.map((x) => `${x.severity}:${x.code}`);
test.afterEach(() => { globalThis.fetch = realFetch; });

test("parse: CURRENCY.rIssuer, names longer than 3 become 40 hex, XRP and bad issuers refused", () => {
  assert.deepEqual(parseTokenRequest({ chain: "xrpl", address: `RLUSD.${RIPPLE}` }), { chain: "xrpl", address: `${RLUSD}.${RIPPLE}`, currency: RLUSD, issuer: RIPPLE });
  assert.equal(parseTokenRequest({ chain: "xrpl", address: `SOLO.${ISSUER}` }).currency, "534F4C4F00000000000000000000000000000000");
  assert.equal(parseTokenRequest({ chain: "xrpl", address: `USD.${ISSUER}` }).currency, "USD");
  assert.throws(() => parseTokenRequest({ chain: "xrpl", address: `XRP.${ISSUER}` }), /native/);
  assert.throws(() => parseTokenRequest({ chain: "xrpl", address: `USD.${ISSUER.slice(0, -1)}3` }), /CURRENCY\.rIssuer/);
  assert.throws(() => parseTokenRequest({ chain: "xrpl", address: ISSUER }), /CURRENCY\.rIssuer/);
});

test("Ripple's RLUSD is green with its powers as info; a token called RLUSD from someone else is red", async () => {
  stubDex([{ chainId: "xrpl", baseToken: { address: `${RLUSD}.${RIPPLE}`, name: "RLUSD", symbol: "RLUSD" }, liquidity: { usd: 4_500_000 }, priceUsd: "1", pairCreatedAt: Date.now() - 300 * 86400e3 }]);
  const real = await verdict(`RLUSD.${RIPPLE}`, { Flags: 0x80000000 | 0x00100000 }, { signerLists: [{ SignerQuorum: 3 }] });
  assert.equal(real.verdict, "green");
  assert.match(real.one_liner, /Ripple's RLUSD/);
  assert.ok(codes(real).includes("info:CLAWBACK_ENABLED") && codes(real).includes("info:MINT_AUTHORITY_ACTIVE"), "a signer list means it is not blackholed");
  stubDex();
  const fake = await verdict(`RLUSD.${ISSUER}`, { Flags: 0 });
  assert.equal(fake.verdict, "red");
  assert.equal(fake.reasons[0].code, "TOKEN_IMPERSONATION");
});

test("issuer powers: global freeze and a missing issuer are red; clawback, require-auth, minting and fees orange; blackholed is info", async () => {
  stubDex();
  assert.equal((await verdict(`FRZ.${ISSUER}`, { Flags: 0x00400000 })).reasons[0].code, "TOKEN_FROZEN");
  assert.equal((await verdict(`GON.${ISSUER}`, null)).reasons[0].code, "TOKEN_ISSUER_NOT_FOUND");
  const risky = await verdict(`RSK.${ISSUER}`, { Flags: 0x80000000 | 0x00040000, TransferRate: 1_150_000_000 });
  for (const c of ["orange:CLAWBACK_ENABLED", "orange:PERMISSIONED_TOKEN", "orange:MINT_AUTHORITY_ACTIVE", "orange:HIGH_TRANSFER_FEE", "orange:NO_DEX_MARKET"]) assert.ok(codes(risky).includes(c), c);
  assert.equal(risky.reasons.find((r) => r.code === "HIGH_TRANSFER_FEE").details.feePct, 15);
  const fixed = await verdict(`FIX.${ISSUER}`, { Flags: 0x00100000 | 0x00200000, RegularKey: "rrrrrrrrrrrrrrrrrrrrBZbvji" });
  assert.ok(codes(fixed).includes("info:ISSUER_BLACKHOLED"));
  assert.ok(!codes(fixed).some((c) => c.endsWith("MINT_AUTHORITY_ACTIVE") || c.endsWith("FREEZE_AUTHORITY_ACTIVE")));
});
