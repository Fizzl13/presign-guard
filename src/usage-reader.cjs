// Copied from x402-doctor lib/usage-reader.js (the reader next to the usage-log.cjs writer every Fizzl service has).
// presign-guard uses only load(), to read its refusal counts back after a restart (src/refusal-log.js).
//
// Reads the usage log (see usage-log.js) back from the private GitHub repo
// for /admin/usage. Files are cached by blob sha, so a refresh only
// downloads the files that changed: since 25 Oct 2026 one per service and UTC hour
// (events/<service>/<day>/<HH>.jsonl), so mostly just the current hour's; before, one per day
// (events/<service>/<day>.jsonl). Both are read.

'use strict';

const API = 'https://api.github.com';
const MAX_EVENTS = 20000;
// A log file's path: service, day, and the hour for an hourly file.
const LOG_FILE = /^events\/([^/]+)\/(\d{4}-\d{2}-\d{2})(?:\.jsonl|\/(\d{2})\.jsonl)$/;
const logFile = (path) => {
  const m = LOG_FILE.exec(path);
  return m ? { service: m[1], date: m[2], hour: m[3] ?? null } : null;
};

function createUsageReader({ env = process.env, fetchFn = globalThis.fetch, now = () => Date.now() } = {}) {
  const token = env.USAGE_LOG_TOKEN;
  const repo = env.USAGE_LOG_REPO || 'Fizzl13/usage-log';
  const headers = {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'usage-reader',
  };
  const blobs = new Map(); // sha -> parsed events

  async function getJson(url, accept) {
    const res = await fetchFn(url, { headers: accept ? { ...headers, accept } : headers });
    if (res.status === 404 || res.status === 409) return null; // missing or empty repo
    if (!res.ok) throw new Error(`GitHub HTTP ${res.status} for ${url.replace(API, '')}`);
    return accept ? res.text() : res.json();
  }

  function parseLines(text) {
    const events = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        events.push(JSON.parse(line));
      } catch {
        // skip a damaged line
      }
    }
    return events;
  }

  // A day file's events, downloaded once per version: /api/stats runs load() and summarizeAll() together and
  // both want today's files, so a download already under way is shared instead of started again.
  const downloading = new Map(); // sha -> Promise<events>
  function blobEvents(sha) {
    if (blobs.has(sha)) return Promise.resolve(blobs.get(sha));
    if (!downloading.has(sha)) {
      downloading.set(sha, getJson(`${API}/repos/${repo}/git/blobs/${sha}`, 'application/vnd.github.raw+json')
        .then((text) => parseLines(text || ''))
        .finally(() => downloading.delete(sha)));
    }
    return downloading.get(sha);
  }

  // service: only that service's day files (events/<service>/), e.g. the small trust-submit log.
  async function load({ days = 30, max = MAX_EVENTS, service } = {}) {
    if (!token) return { configured: false, repo, events: [] };
    const fromIso = new Date(now() - days * 86400000).toISOString();
    const from = fromIso.slice(0, 10);
    const tree = await getJson(`${API}/repos/${repo}/git/trees/HEAD?recursive=1`);
    const files = ((tree && tree.tree) || [])
      .filter((f) => f.type === 'blob' && logFile(f.path))
      .map((f) => ({ ...f, ...logFile(f.path) }))
      .filter((f) => f.date >= from)
      .filter((f) => !service || f.service === service);

    // Newest day first, stopping once there are max events: the answer is the newest max events, and every
    // event in an older day's files is older than those (a file holds the events of its own UTC day or hour). The
    // admin page asks 30 days but shows 20,000 events, about one day of traffic now; parsing all 30 days at once
    // could take the 512 MB instance down (13 Oct 2026).
    const dates = [...new Set(files.map((f) => f.date))].sort().reverse();
    const events = [];
    const errors = [];
    const used = new Set();
    let stoppedEarly = false;
    for (const [i, date] of dates.entries()) {
      if (events.length >= max) { stoppedEarly = i < dates.length; break; }
      await Promise.all(files.filter((f) => f.date === date).map(async (f) => {
        used.add(f.sha);
        try {
          if (!blobs.has(f.sha)) blobs.set(f.sha, await blobEvents(f.sha));
          for (const e of blobs.get(f.sha)) if (e && typeof e.t === 'string' && e.t >= fromIso) events.push(e); // not push(...): a big day file would overflow the stack
        } catch (err) {
          errors.push(`${f.path}: ${err.message}`);
        }
      }));
    }
    // Keep only the file versions this load used. Today's files get a new sha every few minutes, and
    // keeping the old versions leaked ~7 MB per /api/stats refresh until the 512 MB instance crashed
    // (13 Oct 2026). Older days keep their sha, so they stay cached.
    for (const sha of blobs.keys()) if (!used.has(sha)) blobs.delete(sha);

    events.sort((a, b) => (a.t < b.t ? 1 : -1));
    return { configured: true, repo, days, from: fromIso, truncated: stoppedEarly || events.length > max, events: events.slice(0, max), errors };
  }

  // A small summary per log file (e.g. counts) for the whole log, without
  // keeping its events: summarize(events, { service, date }) runs once per
  // file version. A day has one file, or one per hour: callers add them up per day.
  // key: one cache per kind of summary (the public stats' day counts, the admin page's payments), so two callers
  // with different summarize functions never get each other's summaries. from: only files of that day or later.
  const summaries = new Map(); // `${key} ${sha}` -> summary
  async function summarizeAll(summarize, { key = 'default', from = null } = {}) {
    if (!token) return { configured: false, files: [] };
    const tree = await getJson(`${API}/repos/${repo}/git/trees/HEAD?recursive=1`);
    const all = ((tree && tree.tree) || []).filter((f) => f.type === 'blob' && logFile(f.path));
    const files = from ? all.filter((f) => logFile(f.path).date >= from) : all;
    const out = [];
    // A few files at a time: at startup every file is new, and reading them all at once raises the peak.
    const summarizeOne = async (f) => {
      const { service, date } = logFile(f.path);
      try {
        const k = `${key} ${f.sha}`;
        if (!summaries.has(k)) {
          const events = await blobEvents(f.sha);
          summaries.set(k, summarize(events, { service, date }));
        }
        out.push({ service, date, summary: summaries.get(k) });
      } catch {
        // skip a file that can't be read right now
      }
    };
    for (let i = 0; i < files.length; i += 4) await Promise.all(files.slice(i, i + 4).map(summarizeOne));
    // Drop this key's summaries of file versions that are gone (today's files change every few minutes).
    const current = new Set(all.map((f) => f.sha));
    for (const k of summaries.keys()) {
      const [kk, sha] = k.split(' ');
      if (kk === key && !current.has(sha)) summaries.delete(k);
    }
    return { configured: true, files: out };
  }

  // A small text file of the log repo (scripts/known.json), cached for 10 minutes; null when missing.
  const texts = new Map(); // path -> { at, text }
  async function readText(path) {
    if (!token) return null;
    const hit = texts.get(path);
    if (hit && now() - hit.at < 600000) return hit.text;
    const text = await getJson(`${API}/repos/${repo}/contents/${path}`, 'application/vnd.github.raw+json');
    texts.set(path, { at: now(), text });
    return text;
  }

  return { configured: Boolean(token), load, summarizeAll, readText };
}

module.exports = { createUsageReader, logFile };
