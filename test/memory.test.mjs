import { test } from "node:test";
import assert from "node:assert/strict";
import { memoryStatus } from "../src/memory.js";

test("memory for /health: whole megabytes, the heap below V8's limit, and the uptime", () => {
  const s = memoryStatus();
  for (const k of ["rss_mb", "heap_mb", "heap_total_mb", "heap_limit_mb", "external_mb"]) assert.ok(Number.isInteger(s.memory[k]) && s.memory[k] >= 0, k);
  assert.ok(s.memory.heap_limit_mb > s.memory.heap_mb);
  assert.ok(Number.isInteger(s.uptime_s) && s.uptime_s >= 0);
});
