// Fizzl Pass phase 2 (src/fizzl-pass.js): a valid X-Fizzl-Pass proof gets the tier's higher free limit, per pass.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createPassVerifier, limitKeyOf, LIMIT_FACTOR } from "../src/fizzl-pass.js";
import { createRateLimiter } from "../src/mcp.js";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const jwks = { keys: [{ kty: "OKP", crv: "Ed25519", kid: "k1", x: publicKey.export({ format: "jwk" }).x }] };
function proof(claims) {
  const body = `fzp1.${Buffer.from(JSON.stringify({ kid: "k1", ...claims })).toString("base64url")}`;
  return `${body}.${crypto.sign(null, Buffer.from(body), privateKey).toString("base64url")}`;
}

test("a valid pass counts per pass with the tier's factor; none, broken or expired counts per IP", async () => {
  const pass = createPassVerifier({ keys: jwks });
  const token = proof({ tier: "bronze", until: Date.now() + 86400000 });
  const held = await limitKeyOf(pass, { ip: "1.1.1.1", headers: { "x-fizzl-pass": token } });
  assert.match(held.key, /^pass:[0-9a-f]{16}$/);
  assert.equal(held.factor, LIMIT_FACTOR.bronze);
  assert.deepEqual(await limitKeyOf(pass, { ip: "1.1.1.1", headers: {} }), { key: "1.1.1.1", factor: 1, claims: null });
  assert.equal((await limitKeyOf(pass, { ip: "1.1.1.1", headers: { "x-fizzl-pass": proof({ tier: "bronze", until: Date.now() - 1 }) } })).factor, 1);
  assert.equal((await limitKeyOf(pass, { ip: "1.1.1.1", headers: { "x-fizzl-pass": "fzp1.a.b" } })).factor, 1);
});

test("the limiter gives a pass holder the tier's multiple of the free calls", () => {
  const limiter = createRateLimiter(2, 60000);
  assert.equal(limiter("ip"), true);
  assert.equal(limiter("ip"), true);
  assert.equal(limiter("ip"), false);
  for (let i = 0; i < 2 * LIMIT_FACTOR.bronze; i++) assert.equal(limiter("pass:abc", LIMIT_FACTOR.bronze), true);
  assert.equal(limiter("pass:abc", LIMIT_FACTOR.bronze), false);
});
