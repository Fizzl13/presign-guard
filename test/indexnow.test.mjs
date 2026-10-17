// IndexNow (src/indexnow.cjs): the pages are submitted once, only on Render, for this host only; llms.txt is in place,
// and the homepage describes itself in JSON-LD.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import indexNow from "../src/indexnow.cjs";

const { INDEXNOW_KEY, pingIndexNow, scheduleIndexNow } = indexNow;
const quiet = { log() {}, warn() {} };
const HOST = "presign-guard.fizzl.eu";

test("pingIndexNow posts host, key, key location and this host's URLs once each", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, body: JSON.parse(init.body) }); return new Response("", { status: 202 }); };
  assert.equal(await pingIndexNow({ host: HOST, urls: [`https://${HOST}/`, `https://${HOST}/`, "https://evil.example/", `https://${HOST}/llms.txt`], fetchImpl, log: quiet }), 202);
  assert.equal(calls[0].url, "https://api.indexnow.org/indexnow");
  assert.deepEqual(calls[0].body, { host: HOST, key: INDEXNOW_KEY, keyLocation: `https://${HOST}/${INDEXNOW_KEY}.txt`, urlList: [`https://${HOST}/`, `https://${HOST}/llms.txt`] });
  assert.equal(await pingIndexNow({ host: HOST, urls: [`https://${HOST}/`], fetchImpl: async () => { throw new Error("down"); }, log: quiet }), null);
});

test("scheduleIndexNow runs only on Render, and INDEXNOW=off turns it off", async () => {
  let pinged = 0;
  const fetchImpl = async () => { pinged += 1; return new Response("", { status: 200 }); };
  assert.equal(scheduleIndexNow({ env: {}, host: HOST, urls: [`https://${HOST}/`], fetchImpl, log: quiet }), null);
  assert.equal(scheduleIndexNow({ env: { RENDER: "true", INDEXNOW: "off" }, host: HOST, urls: [`https://${HOST}/`], fetchImpl, log: quiet }), null);
  assert.ok(scheduleIndexNow({ env: { RENDER: "true" }, host: HOST, urls: [`https://${HOST}/`], delayMs: 5, fetchImpl, log: quiet }));
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(pinged, 1);
});

test("llms.txt follows llmstxt.org: a title, a summary, and the agent links", () => {
  const text = fs.readFileSync(new URL("../public/llms.txt", import.meta.url), "utf8");
  assert.match(text, /^# presign-guard\n\n> /);
  assert.match(text, /https:\/\/presign-guard\.fizzl\.eu\/skill\.md/);
  assert.match(text, /https:\/\/presign-guard\.fizzl\.eu\/openapi\.json/);
});

test("the homepage carries valid JSON-LD with the per-check price", () => {
  const html = fs.readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
  const ld = JSON.parse(html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
  assert.equal(ld["@type"], "WebApplication");
  assert.equal(ld.url, "https://presign-guard.fizzl.eu/");
  assert.equal(ld.offers[0].price, "0.01");
});
