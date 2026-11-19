// TapeRelay signatures (TapeOut circuit containers' relay servers: file storage and messages). The holder's wallet
// signs EIP-712 messages in the "TapeRelay" domain (version 1, chainId of the circuit's chain), from the published
// client @taperelay/client 0.1.0-test (src/core.mjs TYPE_DEFS, src/session.mjs, src/devkey.mjs):
// - ScopedDelegation: a session key that acts for the circuit's container for up to one day;
// - DeveloperKey: the same for up to 366 days, meant for a backend or CI, and the only kind that can carry "release"
//   (delete files);
// - Revocation: ends a session or developer key;
// - Request, Notice, SelfNotice, Pointer, EncryptionKey, SelfEncryptionKey: one request or message, nothing granted.
// An agent asked to sign a delegation should know what it hands over, for how long, and to which key.

export const TAPERELAY_DOMAIN = "TapeRelay";

const SESSION_MAX_SECONDS = 86400;
const DEV_KEY_MAX_SECONDS = 31622400; // 366 days
const SCOPES = new Set(["objects", "send", "inbox", "pointers", "release", "admit"]);
const SESSION_SCOPES = new Set(["objects", "send", "inbox", "pointers", "admit"]);
export const SCOPE_TEXT = {
  objects: "store and read files", send: "send messages", inbox: "read the inbox", pointers: "change named pointers",
  release: "delete files", admit: "admit others",
};
const MESSAGE_TYPES = new Set(["Request", "Notice", "SelfNotice", "Pointer", "EncryptionKey", "SelfEncryptionKey"]);

// Circuit names as the protocol writes them: "<id>.<area>.<processor>.tape", no area for BNB Smart Chain
// (circuit.mjs: area 2 is X Layer, 3 is Base).
const NAME_RE = /^([1-9][0-9]*)\.(?:([1-9][0-9]*)\.)?(0|[1-9][0-9]*)\.tape$/;
const AREA_CHAIN = { 2: 196, 3: 8453 };
export function circuitChain(name) {
  if (typeof name !== "string" || name.length > 64) return null;
  const m = NAME_RE.exec(name);
  if (!m) return null;
  return m[2] === undefined ? 56 : AREA_CHAIN[m[2]] ?? null;
}

const str = (v, max = 200) => (typeof v === "string" ? v.slice(0, max) : null);
const num = (v) => {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return v;
  if (typeof v === "string" && /^[0-9]{1,16}$/.test(v)) return Number(v);
  return null;
};
const addr = (v) => (typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v) ? v.toLowerCase() : null);

// The parsed part of a TapeRelay signature, or null when the domain isn't TapeRelay.
export function parseTapeRelay(primaryType, domain, message) {
  if (domain?.name !== TAPERELAY_DOMAIN) return null;
  const account = str(message.account, 64);
  if (primaryType === "ScopedDelegation" || primaryType === "DeveloperKey") {
    const scopes = Array.isArray(message.scopes) ? message.scopes.filter((s) => typeof s === "string").map((s) => s.slice(0, 32)).slice(0, 16) : [];
    const servers = Array.isArray(message.servers) ? message.servers.filter((s) => typeof s === "string").map((s) => s.slice(0, 120)).slice(0, 16) : [];
    return {
      kind: "taperelay_delegation",
      taperelay: {
        type: primaryType, account, accountChainId: circuitChain(account), sessionKey: addr(message.sessionKey),
        scopes, servers, app: str(message.app, 64) || "", note: primaryType === "DeveloperKey" ? str(message.note, 200) || "" : undefined,
        notBefore: num(message.notBefore), expires: num(message.expires),
      },
    };
  }
  if (primaryType === "Revocation") {
    return { kind: "taperelay_revocation", taperelay: { type: primaryType, account, sessionKey: addr(message.sessionKey), revokedAt: num(message.revokedAt) } };
  }
  if (MESSAGE_TYPES.has(primaryType)) {
    return { kind: "taperelay_message", taperelay: { type: primaryType, account: account ?? str(message.from, 120) } };
  }
  return null;
}

// Reasons for a parsed TapeRelay signature. add(code, severity, subject, details); chainId is the request's chain,
// which the domain's chainId already matches.
export function tapeRelayReasons(req, add, chainId, now = Math.floor(Date.now() / 1000)) {
  const t = req.taperelay;
  if (!t) return;
  if (req.kind === "taperelay_revocation") {
    add("TAPERELAY_REVOCATION", "info", t.sessionKey, { account: t.account });
    return;
  }
  if (req.kind === "taperelay_message") {
    add("TAPERELAY_MESSAGE", "info", null, { primaryType: t.type, account: t.account });
    return;
  }
  const devKey = t.type === "DeveloperKey";
  const seconds = t.expires !== null && t.notBefore !== null ? t.expires - t.notBefore : null;
  const details = {
    account: t.account, scopes: t.scopes, can: t.scopes.map((s) => SCOPE_TEXT[s] || s), servers: t.servers,
    ...(t.app && { app: t.app }), ...(devKey && t.note && { note: t.note }),
    ...(t.expires !== null && { expiresAt: t.expires }), ...(seconds !== null && { days: Math.round((seconds / 86400) * 10) / 10 }),
  };
  // A developer key acts for the container for up to a year, from any machine that has it: the user should choose
  // that, not an agent on its own.
  add(devKey ? "TAPERELAY_DEVELOPER_KEY" : "TAPERELAY_SESSION_KEY", devKey ? "orange" : "info", t.sessionKey, details);
  if (t.scopes.includes("release")) add("TAPERELAY_DELETE_SCOPE", "orange", t.sessionKey, { account: t.account });
  const allowed = devKey ? SCOPES : SESSION_SCOPES;
  const unknown = t.scopes.filter((s) => !allowed.has(s));
  if (unknown.length || !t.scopes.length) add("TAPERELAY_UNKNOWN_SCOPE", "orange", t.sessionKey, { scopes: unknown });
  const max = devKey ? DEV_KEY_MAX_SECONDS : SESSION_MAX_SECONDS;
  if (seconds === null || seconds <= 0 || seconds > max) add("TAPERELAY_LIFETIME", "orange", t.sessionKey, { seconds, maxSeconds: max });
  if (!t.sessionKey) add("TAPERELAY_MALFORMED", "orange", null, { field: "sessionKey" });
  if (t.accountChainId === null) add("TAPERELAY_ACCOUNT_MISMATCH", "orange", null, { account: t.account, reason: "not a circuit name" });
  else if (t.accountChainId !== chainId) add("TAPERELAY_ACCOUNT_MISMATCH", "orange", null, { account: t.account, accountChainId: t.accountChainId, chainId });
  if (t.expires !== null && t.expires < now) add("SIGNATURE_EXPIRED", "info", t.sessionKey);
}
