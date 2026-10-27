// TapeOut (tapeout.io): circuits, containers and on-chain websites (DeWEB) on X Layer, Base and BNB Smart Chain.
//
// A TapeOut processor is an ERC-721 contract made by one factory; each NFT on it is a circuit. Every circuit has a
// container: its ERC-6551 account (opener.accountOf(processor, id)), which can hold coins and tokens, owns the
// circuit's website in SiteRegistry and its paid on-chain name in DomainBinding. Whoever holds the circuit NFT
// controls all of that. So signing a TapeOut transaction can hand over much more than the call shows:
// - transferring a circuit hands over its container: the coins and tokens in it, its website and its paid name;
// - transferFrom of a circuit into its own container locks it for good: the container then owns the NFT that
//   controls it, and nobody can ever move either again (safeTransferFrom refuses this; plain transferFrom doesn't,
//   checked with eth_simulateV1 on X Layer on 27 Oct 2026);
// - an approval on a processor lets the operator take circuits, and with them their containers;
// - a call through a container (ERC-6551 execute) is judged by what it does from the container: a delegatecall
//   runs foreign code as the container;
// - SiteRegistry.setOperator lets another address rewrite the website; DomainBinding.bind pays a non-refundable fee
//   that must match months x monthlyFee exactly.
// Calls to the core contracts are also checked against the implementations TapeKit pins (kernel/src/config.js):
// a proxy that runs other code than the reviewed version is orange.
// Addresses and interfaces: TapeKit's SPEC.md Appendix B and kernel/src/config.js (github.com/TapeOutProtocol/TapeKit).

import { decodeFunctionData, decodeFunctionResult, encodeFunctionData, parseAbi } from "viem";
import { rpcBatch } from "./presign-guard.js";

const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

// Base and X Layer share one deployment (same deployer, same nonces). The factory implementations differ per chain
// since the 22 Oct 2026 freeze.
const L2 = {
  factory: "0x1f09daefa827f02cbb40967cc91b259763760761",
  opener: "0x536add8f30f03b69f6fbf29d425a816a0dc50106",
  registry: "0xd6efb7adcc9c83dc4924ad56f6a8e4e969b9adb6",
  binding: "0x68809fd2fb343aa57d0aeb7f33defe477c9666f9",
};
export const TAPEOUT = {
  196: {
    ...L2, name: "X Layer", currency: "OKB",
    pinned: {
      [L2.factory]: ["0xb41c1e7602eb5734be2430b72178ccb814a5293d"],
      [L2.registry]: ["0xa85c4143d1d4a77f54b8e4ecc9e6d1418afea45f"],
      [L2.binding]: ["0x5ebf29b80789e548907c707530c3c7607c4347df"],
    },
  },
  8453: {
    ...L2, name: "Base", currency: "ETH",
    pinned: {
      [L2.factory]: ["0xefc6b7eaea35a4894c980b74cb1d5d468ae2b4d4"],
      [L2.registry]: ["0xa85c4143d1d4a77f54b8e4ecc9e6d1418afea45f"],
      [L2.binding]: ["0x5ebf29b80789e548907c707530c3c7607c4347df"],
    },
  },
  56: {
    name: "BNB Smart Chain", currency: "BNB",
    factory: "0x68224f668083c29e9800be2a646d42d18cedf7e2",
    opener: "0x021745de2f42a7839d96f2d3634d0294487d81f1",
    registry: "0xd006ffdd5ae313b17729621a00999cd3c71ce5e6",
    binding: "0x861ee183de2bbe4a6ecf9d15812c123b566a3db7",
    pinned: {
      "0x68224f668083c29e9800be2a646d42d18cedf7e2": ["0x77080dd83c16bdf6d71055c3a191fc890b5a8fe2"],
      "0xd006ffdd5ae313b17729621a00999cd3c71ce5e6": ["0x1d279d138a4d803378a7d4557c056f1bed53c261"],
      "0x861ee183de2bbe4a6ecf9d15812c123b566a3db7": ["0xaa226181a6588d3f9ac0035e5f3dbaf311039bce", "0x4e8684eaea48b524245b2191dee451eaa1c1ca94"],
    },
  },
};
export const TAPEOUT_CHAINS = Object.keys(TAPEOUT).map(Number);

const CALL_ABI = parseAbi([
  // processor (ERC-721)
  "function transferFrom(address from, address to, uint256 tokenId)",
  "function safeTransferFrom(address from, address to, uint256 tokenId)",
  "function safeTransferFrom(address from, address to, uint256 tokenId, bytes data)",
  "function approve(address to, uint256 tokenId)",
  "function setApprovalForAll(address operator, bool approved)",
  // container (ERC-6551 account)
  "function execute(address to, uint256 value, bytes data, uint8 operation)",
  // SiteRegistry
  "function putFile(address container, string path, string contentType, bytes32 sha256Hash, bytes data)",
  "function appendChunk(address container, string path, uint256 expectIndex, bytes data)",
  "function removeFile(address container, string path)",
  "function setFallback(address container, string path)",
  "function setOperator(address container, address op, uint256 ttl)",
  // DomainBinding
  "function bind(string name, address container, uint256 months)",
  "function unbind(string name, address container)",
]);
const READ_ABI = parseAbi([
  "function isCPU(address) view returns (bool)",
  "function accountOf(address circuits, uint256 tokenId) view returns (address)",
  "function isOpened(address circuits, uint256 tokenId) view returns (bool)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function name() view returns (string)",
  "function token() view returns (uint256 chainId, address tokenContract, uint256 tokenId)",
  "function pathCount(address container) view returns (uint256)",
  "function isOpenedContainer(address container) view returns (bool)",
  "function containerPaidUntil(address container) view returns (uint40)",
  "function monthlyFee() view returns (uint256)",
]);
const call = (to, functionName, args = []) => ["eth_call", [{ to, data: encodeFunctionData({ abi: READ_ABI, functionName, args }) }, "latest"]];
const result = (functionName, raw) => {
  if (typeof raw !== "string" || raw === "0x") return undefined;
  try { return decodeFunctionResult({ abi: READ_ABI, functionName, data: raw }); } catch { return undefined; }
};
const lower = (a) => String(a).toLowerCase();
const LONG_TTL_SECONDS = 31 * 86400;

function decode(data) {
  if (typeof data !== "string" || data.length < 10) return null;
  try { return decodeFunctionData({ abi: CALL_ABI, data }); } catch { return null; }
}

// What a container holds: { container, opened, balance (wei), files, paidUntil }. Read in one batch.
async function containerOf(chainId, processor, tokenId, rpc) {
  const c = TAPEOUT[chainId];
  const [account, opened] = await rpc(chainId, [call(c.opener, "accountOf", [processor, tokenId]), call(c.opener, "isOpened", [processor, tokenId])]);
  const container = result("accountOf", account);
  if (!container) return null;
  const [balance, files, paid] = await rpc(chainId, [
    ["eth_getBalance", [container, "latest"]],
    call(c.registry, "pathCount", [container]),
    call(c.binding, "containerPaidUntil", [container]),
  ]);
  return {
    container: lower(container),
    opened: result("isOpened", opened) === true,
    balance: typeof balance === "string" ? BigInt(balance) : null,
    files: result("pathCount", files) ?? null,
    paidUntil: Number(result("containerPaidUntil", paid) ?? 0),
  };
}

// The holdings in words-ready form, and whether there is anything to lose.
function holdings(h, currency, now) {
  const out = {
    container: h.container,
    ...(h.balance !== null && { balance: h.balance.toString(), currency }),
    ...(h.files !== null && { siteFiles: Number(h.files) }),
    ...(h.paidUntil > now && { namePaidUntil: new Date(h.paidUntil * 1000).toISOString().slice(0, 10) }),
  };
  const valuable = (h.balance ?? 0n) > 0n || (h.files ?? 0n) > 0n || h.paidUntil > now;
  return { out, valuable };
}

// Reasons for one EVM transaction on a TapeOut chain: [{ code, severity, subject, details }]. Never throws: when the
// chain can't be asked, the transaction is left to the general checks.
export async function tapeoutReasons({ chainId, to, data, value = 0n, from }, { rpc = rpcBatch, now = Math.floor(Date.now() / 1000) } = {}) {
  const c = TAPEOUT[chainId];
  if (!c || !to) return [];
  const target = lower(to);
  const reasons = [];
  const add = (code, severity, subject, details) => reasons.push({ code, severity, subject, ...(details ? { details } : {}) });
  try {
    // A core contract that runs other code than the reviewed version.
    if (c.pinned[target]) {
      const [slot] = await rpc(chainId, [["eth_getStorageAt", [target, IMPL_SLOT, "latest"]]]);
      if (typeof slot === "string") {
        const impl = `0x${slot.slice(-40)}`.toLowerCase();
        if (!c.pinned[target].includes(impl)) add("TAPEOUT_CONTRACT_CHANGED", "orange", target, { implementation: impl, reviewed: c.pinned[target] });
      }
    }
    const call0 = decode(data);
    if (!call0) return reasons;
    const { functionName, args } = call0;

    if (target === c.registry) {
      const container = lower(args[0]);
      if (functionName === "setOperator") {
        const [, op, ttl] = args;
        if (!from || lower(op) !== lower(from)) {
          add("TAPEOUT_SITE_OPERATOR", "orange", lower(op), { container, ttlSeconds: Number(ttl), ...(ttl > BigInt(LONG_TTL_SECONDS) && { longLived: true }) });
        }
      } else {
        add("TAPEOUT_SITE_WRITE", "info", container, { action: functionName, path: String(args[1] ?? "") });
      }
      return reasons;
    }

    if (target === c.binding) {
      const container = lower(args[1]);
      if (functionName === "bind") {
        const months = BigInt(args[2]);
        const [feeRaw] = await rpc(chainId, [call(c.binding, "monthlyFee")]);
        const fee = result("monthlyFee", feeRaw);
        const details = { name: String(args[0]), container, months: Number(months), paid: value.toString(), currency: c.currency, ...(fee !== undefined && { monthlyFee: fee.toString() }) };
        if (fee !== undefined && value !== months * fee) add("TAPEOUT_NAME_FEE_MISMATCH", "orange", container, { ...details, expected: (months * fee).toString() });
        else add("TAPEOUT_NAME_PAYMENT", "info", container, { ...details, refundable: false });
      } else if (functionName === "unbind") {
        add("TAPEOUT_NAME_UNBIND", "info", container, { name: String(args[0]), refundable: false });
      }
      return reasons;
    }

    // A circuit NFT or a container: ask the factory and the registry in one batch.
    const [isCpuRaw, isContainerRaw] = await rpc(chainId, [call(c.factory, "isCPU", [target]), call(c.registry, "isOpenedContainer", [target])]);

    if (result("isCPU", isCpuRaw) === true) {
      const [nameRaw] = await rpc(chainId, [call(target, "name")]);
      const processor = { processor: target, ...(result("name", nameRaw) && { processorName: result("name", nameRaw).slice(0, 64) }) };
      if (functionName === "setApprovalForAll") {
        if (args[1]) add("TAPEOUT_ALL_CIRCUITS_APPROVAL", "orange", lower(args[0]), processor);
        return reasons;
      }
      const tokenId = functionName === "approve" ? args[1] : args[2];
      const h = await containerOf(chainId, target, tokenId, rpc);
      if (!h) return reasons;
      const { out, valuable } = holdings(h, c.currency, now);
      const circuit = { ...processor, circuitId: tokenId.toString(), ...out };
      if (functionName === "approve") {
        if (lower(args[0]) !== "0x0000000000000000000000000000000000000000") add("TAPEOUT_CIRCUIT_APPROVAL", valuable ? "orange" : "info", lower(args[0]), circuit);
        return reasons;
      }
      // transferFrom / safeTransferFrom
      const recipient = lower(args[1]);
      if (recipient === h.container) {
        add("TAPEOUT_CIRCUIT_LOCKED_FOREVER", "red", recipient, { ...circuit, method: functionName });
      } else {
        add("TAPEOUT_CIRCUIT_TRANSFER", valuable ? "orange" : "info", recipient, circuit);
      }
      return reasons;
    }

    if (result("isOpenedContainer", isContainerRaw) === true && functionName === "execute") {
      const [inner, innerValue, innerData, operation] = args;
      const details = { container: target, to: lower(inner), value: innerValue.toString(), currency: c.currency, operation: Number(operation) };
      if (Number(operation) !== 0) {
        add("TAPEOUT_CONTAINER_DELEGATECALL", "red", lower(inner), details);
        return reasons;
      }
      add("TAPEOUT_CONTAINER_CALL", "info", lower(inner), details);
      // What the container itself would sign: the same checks, from the container.
      const nested = await tapeoutReasons({ chainId, to: inner, data: innerData, value: innerValue, from: target }, { rpc, now });
      for (const r of nested) reasons.push({ ...r, details: { ...(r.details || {}), via: target } });
      const innerCall = decode(innerData);
      if (innerCall?.functionName === "setApprovalForAll" && innerCall.args[1]) add("TAPEOUT_CONTAINER_APPROVAL_FOR_ALL", "orange", lower(innerCall.args[0]), { container: target, collection: lower(inner) });
      if (innerCall?.functionName === "approve" && BigInt(innerCall.args[1]) >= 2n ** 255n) add("TAPEOUT_CONTAINER_UNLIMITED_APPROVAL", "orange", lower(innerCall.args[0]), { container: target, token: lower(inner) });
    }
  } catch {
    return reasons; // the chain couldn't be asked: what was found so far
  }
  return reasons;
}
