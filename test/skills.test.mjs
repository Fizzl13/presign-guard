// The Agent Skill in skills/ (installable with `npx skills add Fizzl13/presign-guard`): valid frontmatter per the
// Agent Skills format, and every presign-guard route it tells an agent to call exists.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";

const root = new URL("../skills/", import.meta.url);
const source = ["../server.js", "../src/discovery.js", "../src/token-quick.js"].map((p) => readFileSync(new URL(p, import.meta.url), "utf8")).join("\n");
const skills = readdirSync(root).filter((d) => existsSync(new URL(`${d}/SKILL.md`, root)));

test("skills: presign-check is there", () => {
  assert.deepEqual(skills, ["presign-check"]);
});

for (const dir of skills) {
  const text = readFileSync(new URL(`${dir}/SKILL.md`, root), "utf8");

  test(`${dir}: frontmatter name matches the folder, description within 1024 characters`, () => {
    const front = /^---\n([\s\S]*?)\n---\n/.exec(text);
    assert.ok(front, "starts with YAML frontmatter");
    const name = /^name:\s*(.+)$/m.exec(front[1])[1].trim();
    assert.equal(name, dir);
    assert.match(name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
    const description = JSON.parse(/^description:\s*(".*")$/m.exec(front[1])[1]);
    assert.ok(description.length > 50 && description.length <= 1024, `description is ${description.length} characters`);
  });

  test(`${dir}: every presign-guard route it names exists`, () => {
    const routes = [...text.matchAll(/(?:presign-guard\.fizzl\.eu|`(?:GET|POST) )(\/v1\/[a-z0-9/_-]+)/g)].map((m) => m[1]);
    assert.ok(routes.length >= 5);
    for (const route of new Set(routes)) assert.ok(source.includes(`"${route}"`), `${route} is served`);
  });
}
