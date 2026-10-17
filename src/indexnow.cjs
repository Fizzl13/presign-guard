// IndexNow (indexnow.org): tells Bing and the other IndexNow engines which pages a site has, so AI search that runs
// on Bing (ChatGPT search, Copilot) can find them without waiting for a crawl. The key is public by design: the
// engines check it at https://<host>/<key>.txt (a route in server.js).
//
// Pinged once per start on Render (RENDER=true), a few minutes after the server listens, with the sitemap's URLs
// plus the pages for agents. The same file is copied into each Fizzl service.

'use strict';

const INDEXNOW_KEY = '650907e6c0f02d595776fc4aa223d763';
const ENDPOINT = 'https://api.indexnow.org/indexnow';

// The <loc> URLs of a sitemap.
function sitemapUrls(xml) {
  return [...String(xml || '').matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map((m) => m[1]);
}

// One submission: { host, key, keyLocation, urlList }. Resolves to the HTTP status, or null when it failed.
async function pingIndexNow({ host, urls, key = INDEXNOW_KEY, fetchImpl = fetch, log = console }) {
  const urlList = [...new Set(urls)].filter((u) => new URL(u).host === host).slice(0, 10000);
  if (!urlList.length) return null;
  try {
    const res = await fetchImpl(ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ host, key, keyLocation: `https://${host}/${key}.txt`, urlList }),
      signal: AbortSignal.timeout(15000),
    });
    log.log(`[indexnow] ${urlList.length} URLs for ${host}: HTTP ${res.status}`);
    return res.status;
  } catch (err) {
    log.warn(`[indexnow] ${host}: ${err.message}`);
    return null;
  }
}

// On Render only: ping after delayMs (the new instance is live by then). Returns the timer, or null.
function scheduleIndexNow({ env = process.env, host, urls, delayMs = 3 * 60 * 1000, ...rest }) {
  if (env.RENDER !== 'true' || env.INDEXNOW === 'off') return null;
  const timer = setTimeout(() => pingIndexNow({ host, urls: typeof urls === 'function' ? urls() : urls, ...rest }), delayMs);
  timer.unref?.();
  return timer;
}

module.exports = { INDEXNOW_KEY, sitemapUrls, pingIndexNow, scheduleIndexNow };
