import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { securityHeaders } from "../src/security-headers.js";

test("security headers on every response, the 402 included", async () => {
  const app = express();
  app.use(securityHeaders);
  app.get("/v1/check", (_req, res) => res.status(402).json({}));
  app.get("/", (_req, res) => res.send("home"));
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const path of ["/v1/check", "/"]) {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff", path);
      assert.equal(res.headers.get("x-frame-options"), "DENY", path);
      assert.match(res.headers.get("content-security-policy"), /frame-ancestors 'none'/, path);
      assert.match(res.headers.get("strict-transport-security"), /max-age=31536000/, path);
    }
  } finally {
    server.close();
  }
});
