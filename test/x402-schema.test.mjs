// Strict x402 clients parse the 402 with @x402/core's schema: the resource metadata of every paid route has to pass
// it (for example at most 5 tags; x402 Doctor's preflight route failed on a sixth on 12 Oct 2026).
import { test } from "node:test";
import assert from "node:assert/strict";
import { ResourceInfoSchema } from "@x402/core/schemas";
import { x402Routes } from "../src/presign-guard.js";

test("every paid route's resource metadata passes @x402/core's schema", () => {
  const routes = Object.entries(x402Routes("0x6B0F4651eD42893ab58139938175E4a69f175F25", "eip155:8453"));
  assert.ok(routes.length >= 5);
  for (const [key, r] of routes) {
    const path = key.split(" ")[1];
    const parsed = ResourceInfoSchema.safeParse({ url: `https://presign-guard.fizzl.eu${path}`, description: r.description, mimeType: r.mimeType, serviceName: r.serviceName, tags: r.tags, iconUrl: r.iconUrl });
    assert.ok(parsed.success, `${key}: ${JSON.stringify(parsed.error?.issues)}`);
  }
});

test("the schema check would catch a sixth tag", () => {
  const parsed = ResourceInfoSchema.safeParse({ url: "https://presign-guard.fizzl.eu/v1/check", tags: ["a", "b", "c", "d", "e", "f"] });
  assert.equal(parsed.success, false);
});
