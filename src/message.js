// Plain message signatures (personal_sign and eth_sign): what the message says, in a form the checks in
// presign-guard.js can use. personal_sign shows the wallet text (or hex bytes); eth_sign signs a raw 32-byte hash,
// which can be a transaction, an order or a permit in disguise, which is why wallets turned it off. A sign-in
// message (EIP-4361, "Sign-In with Ethereum") names the site it is for; a site that shows another site's sign-in
// message is a phishing site relaying a login.

const MAX_MESSAGE_CHARS = 16384;

// The text of a message, or null when it is not readable text (binary data, a hash). Hex is decoded as UTF-8.
export function decodeMessage(message) {
  if (typeof message !== "string" || !message.length || message.length > MAX_MESSAGE_CHARS) {
    throw new Error(`message must be the text or 0x-hex being signed (up to ${MAX_MESSAGE_CHARS} characters)`);
  }
  if (!/^0x([0-9a-fA-F]{2})*$/.test(message)) return { text: message, bytes: Buffer.byteLength(message, "utf8"), hex: false };
  const buf = Buffer.from(message.slice(2), "hex");
  const text = buf.toString("utf8");
  // Readable: valid UTF-8 that round-trips, with no control characters other than tab and newlines.
  const readable = buf.length > 0 && Buffer.from(text, "utf8").equals(buf) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text);
  return { text: readable ? text : null, bytes: buf.length, hex: true };
}

// A Sign-In with Ethereum message (EIP-4361), or null.
export function parseSignIn(text) {
  if (typeof text !== "string") return null;
  const head = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\S+) wants you to sign in with your Ethereum account:\r?\n(0x[0-9a-fA-F]{40})\r?\n/.exec(text);
  if (!head) return null;
  const field = (name) => new RegExp(`^${name}: (.+)$`, "m").exec(text)?.[1]?.trim() ?? null;
  const chainId = Number(field("Chain ID"));
  return {
    ...(head[1] && { scheme: head[1] }),
    domain: head[2],
    address: head[3],
    uri: field("URI"),
    chainId: Number.isInteger(chainId) && chainId > 0 ? chainId : null,
    nonce: field("Nonce"),
    issuedAt: field("Issued At"),
    expirationTime: field("Expiration Time"),
  };
}

// The host of a SIWE domain or URI, lowercase, without port or a leading "www.", for comparing with the origin.
export function siteOf(value) {
  if (typeof value !== "string" || !value) return null;
  try {
    const host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`).hostname.toLowerCase();
    return host.replace(/^www\./, "") || null;
  } catch {
    return null;
  }
}
