// examples/canonical.py produces the same bytes as canonicalJson (the signed bytes).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../src/receipt.js";

const dir = fileURLToPath(new URL("../examples", import.meta.url));
const cases = [
  0.000001, 1.0, 1.5e-5, 1e-7, 123.456, 1e21, 1.5e21, 0.1, -0.5, -1e-7, 100, 5e-324, 1.7976931348623157e308, 0, 12345678901234567890,
  { "\u{10000}": 1, "": 2, b: 3, a: [1.0, "x\u007fy", "é", "tab\t", "ctl\u001f", "😀"] },
  { price: 0.00001234, liquidity: 1520000.0, name: "Ünïcødé", nested: { z: null, y: true, x: false } },
  Array.from({ length: 300 }, (_, i) => (Math.sin(i + 1) * 10 ** ((i % 50) - 25))),
];

test("examples/canonical.py matches canonicalJson byte for byte", (t) => {
  const run = spawnSync("python3", ["-c", "import json,sys;from canonical import canonical;print(json.dumps([canonical(c) for c in json.load(sys.stdin)]))"], { cwd: dir, input: JSON.stringify(cases), encoding: "utf8" });
  if (run.error && run.error.code === "ENOENT") return t.skip("python3 not installed");
  assert.equal(run.status, 0, run.stderr);
  const py = JSON.parse(run.stdout);
  cases.forEach((c, i) => assert.equal(py[i], canonicalJson(c), `case ${i}`));
});
