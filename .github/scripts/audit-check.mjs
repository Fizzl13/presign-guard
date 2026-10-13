// Weekly dependency audit (Dependabot alerts are off). Reads `npm audit --json` and the lockfile and
// prints, as Markdown for an issue, the high and critical findings a production install can reach.
// Findings reachable only through a package named in IGNORE (comma-separated) are left out: @x402/paywall
// bundles browser wallet libraries (WalletConnect, Reown) that the server never runs.
// Usage: node audit-check.mjs audit.json package-lock.json > report.md (empty output = nothing to report)
import { readFileSync } from "node:fs";

const [auditPath, lockPath] = process.argv.slice(2);
const audit = JSON.parse(readFileSync(auditPath, "utf8"));
if (audit.error) throw new Error(`npm audit failed: ${audit.error.summary || JSON.stringify(audit.error)}`);
const pkgs = JSON.parse(readFileSync(lockPath, "utf8")).packages || {};
const ignore = new Set((process.env.IGNORE || "").split(",").map((s) => s.trim()).filter(Boolean));

// Where Node finds `name` when `from` requires it: the nearest node_modules on the way up to the root.
const resolve = (from, name) => {
  for (let dir = from; ; ) {
    const path = (dir ? `${dir}/` : "") + `node_modules/${name}`;
    if (pkgs[path]) return path;
    if (!dir) return null;
    const i = dir.lastIndexOf("/node_modules/");
    dir = i === -1 ? "" : dir.slice(0, i);
  }
};

// Every installed path a production install reaches from the root, skipping ignored packages.
const reached = new Set();
const root = pkgs[""] || {};
const queue = Object.keys({ ...root.dependencies, ...root.optionalDependencies }).map((n) => [n, ""]);
while (queue.length) {
  const [name, from] = queue.pop();
  if (ignore.has(name)) continue;
  const path = resolve(from, name);
  if (!path || reached.has(path)) continue;
  reached.add(path);
  const e = pkgs[path];
  for (const dep of Object.keys({ ...e.dependencies, ...e.optionalDependencies, ...e.peerDependencies })) queue.push([dep, path]);
}

const rank = { critical: 0, high: 1 };
const found = Object.values(audit.vulnerabilities || {})
  .filter((v) => v.severity in rank && (v.nodes || []).some((n) => reached.has(n)))
  .sort((a, b) => rank[a.severity] - rank[b.severity] || a.name.localeCompare(b.name));
if (found.length) {
  const fix = (f) => (f === true ? "update available" : f && f.name ? `fix needs ${f.name}@${f.version}${f.isSemVerMajor ? " (major)" : ""}` : "no fix yet");
  const lines = found.map((v) => {
    const advisories = [...new Map(v.via.filter((x) => typeof x === "object").map((x) => [x.url, `[${x.title}](${x.url})`])).values()];
    const through = v.via.filter((x) => typeof x === "string");
    return `- **${v.name}** ${v.severity}, ${v.range}: ${advisories.join("; ") || `through ${through.join(", ")}`}. ${fix(v.fixAvailable)}.`;
  });
  console.log(`The weekly \`npm audit\` found ${found.length} high or critical finding(s) in production dependencies${ignore.size ? ` (not counting what only ${[...ignore].join(", ")} pulls in)` : ""}:\n\n${lines.join("\n")}\n\nFix with \`npm install <package>@<fixed version>\` or \`npm audit fix --omit=dev\`, run the tests, and open a PR. This issue closes itself after a clean weekly run.`);
}
