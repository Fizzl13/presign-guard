import { test } from "node:test";
import assert from "node:assert/strict";
import { onPublicHost } from "../src/public-host.js";

const seen = (req) => `${req.protocol}://${req.headers.host}${req.originalUrl}`;
const run = (host, protocol = "https") => new Promise((done) => {
  let url;
  const req = { headers: { host }, originalUrl: "/v1/token?chain=base", protocol };
  Object.setPrototypeOf(req, { get protocol() { return protocol; } });
  delete req.protocol;
  onPublicHost("https://presign-guard.fizzl.eu", (r, _res, next) => { url = seen(r); next(); })(req, {}, () => done({ url, after: seen(req) }));
});

test("public host: the paywall sees fizzl.eu for requests on the Render address, and only the paywall", async () => {
  assert.deepEqual(await run("presign-guard.onrender.com", "http"), { url: "https://presign-guard.fizzl.eu/v1/token?chain=base", after: "http://presign-guard.onrender.com/v1/token?chain=base" });
  assert.equal((await run("presign-guard.fizzl.eu")).url, "https://presign-guard.fizzl.eu/v1/token?chain=base");
  assert.equal((await run("localhost:3000", "http")).url, "http://localhost:3000/v1/token?chain=base"); // local runs stay as they are
});
