// TapeOut checks (src/tapeout.js) on X Layer, without network: the chain is a fake JSON-RPC that answers the
// factory, opener, SiteRegistry, DomainBinding and container reads. Addresses are TapeKit's X Layer deployment;
// processor 196 (circuit #2, container 0x0a9b…) is a real one with a live site.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeAbiParameters, encodeFunctionData, parseAbi, toFunctionSelector } from "viem";
import { tapeoutReasons, TAPEOUT, TAPEOUT_CHAINS } from "../src/tapeout.js";

const X = TAPEOUT[196];
const PROCESSOR = "0xb00f10bb4b2f32c561bf90e205e543d0a2395971";
const CONTAINER = "0x0a9b3c5b9266da4c4e1e363ba14925328cbcd36e";
const HOLDER = "0xb98caf9b4cebb4b6a3609a1672eaf28d9baeed79";
const BUYER = "0x2222222222222222222222222222222222222222";
const SPENDER = "0x3333333333333333333333333333333333333333";
const NOW = Math.floor(Date.UTC(2026, 9, 27) / 1000);
const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const ABI = parseAbi([
  "function transferFrom(address from, address to, uint256 tokenId)",
  "function safeTransferFrom(address from, address to, uint256 tokenId)",
  "function approve(address to, uint256 tokenId)",
  "function setApprovalForAll(address operator, bool approved)",
  "function execute(address to, uint256 value, bytes data, uint8 operation)",
  "function putFile(address container, string path, string contentType, bytes32 sha256Hash, bytes data)",
  "function setOperator(address container, address op, uint256 ttl)",
  "function bind(string name, address container, uint256 months)",
]);
const enc = (functionName, args) => encodeFunctionData({ abi: ABI, functionName, args });
const word = (types, values) => encodeAbiParameters(types.map((type) => ({ type })), values);
const sel = (sig) => toFunctionSelector(sig);

// A fake chain: { balance, files, paidUntil, fee, impl } shape what the reads answer.
function chain({ balance = 0n, files = 0n, paidUntil = 0, fee = 10n ** 15n, impl = {}, containerOpened = true } = {}) {
  const seen = [];
  const rpc = async (chainId, requests) => {
    assert.equal(chainId, 196);
    return requests.map(([method, params]) => {
      seen.push(method);
      if (method === "eth_getBalance") return `0x${balance.toString(16)}`;
      if (method === "eth_getStorageAt") return word(["address"], [impl[params[0]] ?? X.pinned[params[0]][0]]);
      const { to, data } = params[0];
      const s = data.slice(0, 10);
      if (to === X.factory && s === sel("isCPU(address)")) return word(["bool"], [`0x${data.slice(34)}` === PROCESSOR]);
      if (to === X.registry && s === sel("isOpenedContainer(address)")) return word(["bool"], [containerOpened && `0x${data.slice(34)}` === CONTAINER]);
      if (to === X.registry && s === sel("pathCount(address)")) return word(["uint256"], [files]);
      if (to === X.opener && s === sel("accountOf(address,uint256)")) return word(["address"], [CONTAINER]);
      if (to === X.opener && s === sel("isOpened(address,uint256)")) return word(["bool"], [true]);
      if (to === X.binding && s === sel("containerPaidUntil(address)")) return word(["uint40"], [paidUntil]);
      if (to === X.binding && s === sel("monthlyFee()")) return word(["uint256"], [fee]);
      if (to === PROCESSOR && s === sel("name()")) return word(["string"], ["Test Processor"]);
      return null; // revert
    });
  };
  return { rpc, seen };
}
const codes = (rs) => rs.map((r) => `${r.code}:${r.severity}`);

test("TapeOut runs on X Layer, Base and BNB Smart Chain", () => {
  assert.deepEqual(TAPEOUT_CHAINS.sort((a, b) => a - b), [56, 196, 8453]);
});

test("transferFrom of a circuit into its own container is red: locked for good", async () => {
  const { rpc } = chain({ balance: 5n * 10n ** 17n, files: 6n, paidUntil: NOW + 86400 * 365 });
  const rs = await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("transferFrom", [HOLDER, CONTAINER, 2n]), from: HOLDER }, { rpc, now: NOW });
  assert.deepEqual(codes(rs), ["TAPEOUT_CIRCUIT_LOCKED_FOREVER:red"]);
  assert.equal(rs[0].details.container, CONTAINER);
  assert.equal(rs[0].details.siteFiles, 6);
  assert.equal(rs[0].details.balance, (5n * 10n ** 17n).toString());
  assert.equal(rs[0].details.currency, "OKB");
  assert.equal(rs[0].details.processorName, "Test Processor");
});

test("transferring a circuit whose container holds coins, a site or a paid name is orange, with what goes along", async () => {
  const { rpc } = chain({ files: 6n, paidUntil: NOW + 86400 * 30 });
  const rs = await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("safeTransferFrom", [HOLDER, BUYER, 2n]) }, { rpc, now: NOW });
  assert.deepEqual(codes(rs), ["TAPEOUT_CIRCUIT_TRANSFER:orange"]);
  assert.equal(rs[0].subject, BUYER);
  assert.equal(rs[0].details.siteFiles, 6);
  assert.equal(rs[0].details.namePaidUntil, "2026-11-26");
});

test("transferring an empty circuit is only an info line", async () => {
  const { rpc } = chain();
  const rs = await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("transferFrom", [HOLDER, BUYER, 2n]) }, { rpc, now: NOW });
  assert.deepEqual(codes(rs), ["TAPEOUT_CIRCUIT_TRANSFER:info"]);
});

test("an approval on a processor hands over containers: one circuit, or all of them", async () => {
  const { rpc } = chain({ balance: 1n });
  const one = await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("approve", [SPENDER, 2n]) }, { rpc, now: NOW });
  assert.deepEqual(codes(one), ["TAPEOUT_CIRCUIT_APPROVAL:orange"]);
  const all = await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("setApprovalForAll", [SPENDER, true]) }, { rpc, now: NOW });
  assert.deepEqual(codes(all), ["TAPEOUT_ALL_CIRCUITS_APPROVAL:orange"]);
  const revoke = await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("setApprovalForAll", [SPENDER, false]) }, { rpc, now: NOW });
  assert.deepEqual(revoke, []);
});

test("a call through a container: a delegatecall is red; a plain call is judged from the container", async () => {
  const { rpc } = chain({ files: 1n });
  const delegate = await tapeoutReasons({ chainId: 196, to: CONTAINER, data: enc("execute", [SPENDER, 0n, "0x", 1]) }, { rpc, now: NOW });
  assert.deepEqual(codes(delegate), ["TAPEOUT_CONTAINER_DELEGATECALL:red"]);
  const usdt = "0x1e4a5963abfd975d8c9021ce480b42188849d41d";
  const unlimited = encodeFunctionData({ abi: parseAbi(["function approve(address,uint256)"]), functionName: "approve", args: [SPENDER, 2n ** 256n - 1n] });
  const approve = await tapeoutReasons({ chainId: 196, to: CONTAINER, data: enc("execute", [usdt, 0n, unlimited, 0]) }, { rpc, now: NOW });
  assert.deepEqual(codes(approve), ["TAPEOUT_CONTAINER_CALL:info", "TAPEOUT_CONTAINER_UNLIMITED_APPROVAL:orange"]);
  // The container sends its own circuit into itself: the nested check sees it.
  const self = await tapeoutReasons({ chainId: 196, to: CONTAINER, data: enc("execute", [PROCESSOR, 0n, enc("transferFrom", [CONTAINER, CONTAINER, 2n]), 0]) }, { rpc, now: NOW });
  assert.deepEqual(codes(self), ["TAPEOUT_CONTAINER_CALL:info", "TAPEOUT_CIRCUIT_LOCKED_FOREVER:red"]);
  assert.equal(self[1].details.via, CONTAINER);
});

test("SiteRegistry: another site operator is orange (long-lived marked), writing files is info", async () => {
  const { rpc } = chain();
  const op = await tapeoutReasons({ chainId: 196, to: X.registry, data: enc("setOperator", [CONTAINER, SPENDER, 90n * 86400n]), from: HOLDER }, { rpc, now: NOW });
  assert.deepEqual(codes(op), ["TAPEOUT_SITE_OPERATOR:orange"]);
  assert.equal(op[0].details.longLived, true);
  const self = await tapeoutReasons({ chainId: 196, to: X.registry, data: enc("setOperator", [CONTAINER, HOLDER, 3600n]), from: HOLDER }, { rpc, now: NOW });
  assert.deepEqual(self, []);
  const put = await tapeoutReasons({ chainId: 196, to: X.registry, data: enc("putFile", [CONTAINER, "/index.html", "text/html", `0x${"00".repeat(32)}`, "0x3c68746d6c3e"]) }, { rpc, now: NOW });
  assert.deepEqual(codes(put), ["TAPEOUT_SITE_WRITE:info"]);
  assert.equal(put[0].details.path, "/index.html");
});

test("DomainBinding.bind: the exact fee is an info line (not refundable); another amount is orange", async () => {
  const fee = 10n ** 15n;
  const { rpc } = chain({ fee });
  const ok = await tapeoutReasons({ chainId: 196, to: X.binding, data: enc("bind", ["fizzl.tape", CONTAINER, 3n]), value: 3n * fee }, { rpc, now: NOW });
  assert.deepEqual(codes(ok), ["TAPEOUT_NAME_PAYMENT:info"]);
  assert.equal(ok[0].details.refundable, false);
  const over = await tapeoutReasons({ chainId: 196, to: X.binding, data: enc("bind", ["fizzl.tape", CONTAINER, 3n]), value: 10n * fee }, { rpc, now: NOW });
  assert.deepEqual(codes(over), ["TAPEOUT_NAME_FEE_MISMATCH:orange"]);
  assert.equal(over[0].details.expected, (3n * fee).toString());
});

test("a core contract running other code than the reviewed version is orange", async () => {
  const { rpc } = chain({ impl: { [X.registry]: "0x9999999999999999999999999999999999999999" } });
  const rs = await tapeoutReasons({ chainId: 196, to: X.registry, data: enc("putFile", [CONTAINER, "/a", "text/plain", `0x${"00".repeat(32)}`, "0x61"]) }, { rpc, now: NOW });
  assert.deepEqual(codes(rs), ["TAPEOUT_CONTRACT_CHANGED:orange", "TAPEOUT_SITE_WRITE:info"]);
});

test("other contracts, other chains and an unreachable chain add nothing", async () => {
  const { rpc } = chain();
  assert.deepEqual(await tapeoutReasons({ chainId: 196, to: BUYER, data: enc("transferFrom", [HOLDER, BUYER, 1n]) }, { rpc, now: NOW }), []);
  assert.deepEqual(await tapeoutReasons({ chainId: 1, to: PROCESSOR, data: enc("transferFrom", [HOLDER, CONTAINER, 2n]) }, { rpc, now: NOW }), []);
  const down = async () => { throw new Error("rpc down"); };
  assert.deepEqual(await tapeoutReasons({ chainId: 196, to: PROCESSOR, data: enc("transferFrom", [HOLDER, CONTAINER, 2n]) }, { rpc: down, now: NOW }), []);
});
