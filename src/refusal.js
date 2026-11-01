// The same as x402-doctor's lib/refusal.js (ESM copy). The refusal extension (draft, x402-foundation/x402#4087): a buyer that decides not to pay tells the seller why.
//
// Seller side: the 402 names where refusals go,
//   extensions.refusal = { info: { url, version }, schema }
// and the seller takes short reports there (POST, answered 204). Buyer side: when a check says "don't pay", the buyer
// posts { x402Version, resource, offer: { hash, acceptIndex }, reason, detail?, checkedAt, by?, signature? } to that
// url, fire-and-forget. offer.hash is the sha256 of the refused accepts[] entry in canonical JSON (keys sorted, no
// spaces), so the seller knows which terms were refused without the buyer sending them back.
//
// A report is untrusted input. Unsigned it is a hint; with signature { type: "eip191", signer, value } over
// signingMessage(report) it shows a real wallet sent it. Nothing about the buyer is required.
//
// Buyers only send to a url on the same site as the resource (same host, or the same last two host labels, except on
// shared hosting domains), so a 402 can't turn buyers into a flood against someone else's server.
import crypto from 'node:crypto';

const VERSION = '0.1-draft';
const PATH = '/.well-known/x402-refusal';
const ISSUE = 'https://github.com/x402-foundation/x402/issues/4087';
const REASONS = {
  price_above_limit: "the price is above the buyer's spend limit",
  price_changed: 'the price differs from what the buyer saw before',
  payto_changed: 'payTo differs from what the buyer saw before',
  payto_unverified: 'payTo could not be tied to the seller',
  network_unsupported: 'none of the offered networks are usable by the buyer',
  asset_unsupported: 'none of the offered assets are usable by the buyer',
  challenge_invalid: 'the 402 could not be parsed or broke the spec',
  terms_mismatch: 'two forms of the challenge disagree on terms',
  timeout_too_short: 'maxTimeoutSeconds was too short for the buyer to settle',
  screening_hit: 'the payTo or asset matched a sanctions or risk list',
  policy_blocked: 'another wallet or owner policy blocked it',
  other: 'none of the above; see detail',
};
const DETAIL_MAX = 200;

// x402 Doctor preflight reason codes, as a refusal reason (null: no 402 to refuse, or not a reason to refuse).
const FROM_PREFLIGHT = {
  over_budget: 'price_above_limit',
  price_changed: 'price_changed',
  payto_changed: 'payto_changed',
  payto_sanctioned: 'screening_hit',
  invalid_challenge: 'challenge_invalid',
  challenge_mismatch: 'terms_mismatch',
  resource_mismatch: 'terms_mismatch',
  price_above_advertised: 'terms_mismatch',
  price_far_above_advertised: 'terms_mismatch',
  network_not_offered: 'network_unsupported',
  no_payable_option: 'network_unsupported',
  testnet_only: 'network_unsupported',
  unknown_asset: 'asset_unsupported',
  price_very_high: 'policy_blocked',
  suspicious_amount: 'policy_blocked',
  not_https: 'policy_blocked',
  unreliable_history: 'policy_blocked',
  charged_without_answer: 'policy_blocked',
};

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().filter((k) => value[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
const offerHash = (accept) => crypto.createHash('sha256').update(canonical(accept)).digest('hex');

// The full report schema, served at the seller's endpoint (GET).
const REPORT_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  description: `Why a buyer did not pay (draft: ${ISSUE}). POST it to the refusal url; best effort, never blocks the buyer.`,
  properties: {
    x402Version: { type: 'integer' },
    resource: { type: 'string', format: 'uri' },
    offer: { type: 'object', properties: { hash: { type: 'string', pattern: '^[0-9a-f]{64}$' }, acceptIndex: { type: 'integer', minimum: 0 } }, required: ['hash'] },
    reason: { type: 'string', enum: Object.keys(REASONS) },
    detail: { type: 'string', maxLength: DETAIL_MAX },
    checkedAt: { type: 'string', format: 'date-time' },
    by: { type: 'string', maxLength: 100 },
    signature: { type: 'object', properties: { type: { const: 'eip191' }, signer: { type: 'string' }, value: { type: 'string' } }, required: ['type', 'signer', 'value'] },
  },
  required: ['x402Version', 'resource', 'offer', 'reason', 'checkedAt'],
};

// The extension entry a seller puts in its 402: kept small (402 headers are size-limited); GET info.url has the rest.
function refusalExtension(publicUrl) {
  return {
    refusal: {
      info: { url: `${String(publicUrl).replace(/\/$/, '')}${PATH}`, version: VERSION },
      schema: { type: 'object', required: REPORT_SCHEMA.required, description: 'Full schema and reason codes: GET info.url' },
    },
  };
}

// Hosting domains where every customer gets a subdomain, and two-label country suffixes: there the last two labels
// don't mean the same owner, so only the exact host counts.
const SHARED = new Set(['onrender.com', 'vercel.app', 'netlify.app', 'herokuapp.com', 'workers.dev', 'pages.dev', 'github.io', 'fly.dev', 'railway.app', 'replit.app', 'repl.co', 'web.app', 'firebaseapp.com', 'appspot.com', 'deno.dev', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'ngrok-free.app', 'ngrok.io', 'trycloudflare.com', 'glitch.me', 'koyeb.app', 'up.railway.app', 'co.uk', 'org.uk', 'com.au', 'co.jp', 'com.br', 'co.nz', 'co.za', 'com.cn', 'co.in']);
const sameSite = (a, b) => {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  if (x === y) return true;
  const base = (h) => h.split('.').slice(-2).join('.');
  return base(x) === base(y) && !SHARED.has(base(x));
};

// Where a buyer may send a refusal for this 402: the advertised https url on the resource's own site, or null.
function refusalTarget(challenge, resourceUrl) {
  const raw = challenge?.extensions?.refusal?.info?.url;
  if (typeof raw !== 'string') return null;
  try {
    const target = new URL(raw);
    const resource = new URL(resourceUrl);
    const local = ['localhost', '127.0.0.1'].includes(target.hostname);
    if (target.protocol !== 'https:' && !local) return null;
    return sameSite(target.hostname, resource.hostname) ? target.href : null;
  } catch {
    return null;
  }
}

// What a signature covers: every field the seller acts on.
const signingMessage = (r) => ['x402 refusal', `resource: ${r.resource}`, `offer: ${r.offer?.hash}`, `reason: ${r.reason}`, `checkedAt: ${r.checkedAt}`].join('\n');

// The report a buyer sends (unsigned; add signature yourself when you want it to count as a wallet's).
function refusalReport({ resource, accept, acceptIndex = null, reason, detail = null, by = null, x402Version = 2, now = new Date() }) {
  if (!REASONS[reason]) throw new Error(`unknown refusal reason ${reason}`);
  return {
    x402Version,
    resource,
    offer: { hash: offerHash(accept), ...(Number.isInteger(acceptIndex) ? { acceptIndex } : {}) },
    reason,
    ...(detail ? { detail: String(detail).slice(0, DETAIL_MAX) } : {}),
    checkedAt: now.toISOString(),
    ...(by ? { by: String(by).slice(0, 100) } : {}),
  };
}

// A received report, checked; { error } when it is not usable. ownHost: only reports about this seller's resources.
function parseRefusal(body, { ownHost = null, now = Date.now() } = {}) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  if (!Number.isInteger(b.x402Version)) return { error: 'x402Version must be an integer' };
  let resource;
  try { resource = new URL(String(b.resource)); } catch { return { error: 'resource must be the URL that answered 402' }; }
  if (String(b.resource).length > 2048) return { error: 'resource is too long' };
  if (ownHost && !sameSite(resource.hostname, ownHost)) return { error: `resource is not a resource of ${ownHost}` };
  if (!b.offer || typeof b.offer !== 'object' || !/^[0-9a-f]{64}$/.test(String(b.offer.hash))) return { error: 'offer.hash must be the sha256 (hex) of the refused accepts[] entry in canonical JSON' };
  if (b.offer.acceptIndex !== undefined && !(Number.isInteger(b.offer.acceptIndex) && b.offer.acceptIndex >= 0)) return { error: 'offer.acceptIndex must be a non-negative integer' };
  if (!REASONS[b.reason]) return { error: `reason must be one of ${Object.keys(REASONS).join(', ')}` };
  if (b.detail !== undefined && (typeof b.detail !== 'string' || b.detail.length > DETAIL_MAX)) return { error: `detail must be text of at most ${DETAIL_MAX} characters` };
  if (b.by !== undefined && (typeof b.by !== 'string' || b.by.length > 100)) return { error: 'by must be text of at most 100 characters' };
  const at = Date.parse(b.checkedAt);
  if (!Number.isFinite(at) || Math.abs(now - at) > 24 * 3600 * 1000) return { error: 'checkedAt must be an ISO time within a day of now' };
  if (b.signature !== undefined) {
    const s = b.signature;
    if (!s || s.type !== 'eip191' || !/^0x[0-9a-fA-F]{40}$/.test(String(s.signer)) || !/^0x[0-9a-fA-F]+$/.test(String(s.value))) return { error: 'signature must be { type: "eip191", signer, value }' };
  }
  return { report: { x402Version: b.x402Version, resource: resource.href, offer: { hash: b.offer.hash, ...(b.offer.acceptIndex !== undefined ? { acceptIndex: b.offer.acceptIndex } : {}) }, reason: b.reason, ...(b.detail ? { detail: b.detail } : {}), checkedAt: new Date(at).toISOString(), ...(b.by ? { by: b.by } : {}), ...(b.signature ? { signature: b.signature } : {}) } };
}

async function signedBy(report) {
  if (!report.signature) return null;
  const { verifyMessage } = await import('viem');
  // The message is built from the report as sent (before normalising), so the buyer signs exactly what it posts.
  const ok = await verifyMessage({ address: report.signature.signer, message: signingMessage(report), signature: report.signature.value }).catch(() => false);
  return ok ? report.signature.signer.toLowerCase() : false;
}

// The seller's endpoint: GET says what it takes and what came in (counts per resource and reason, last 30 days, since
// the last restart); POST takes a report (204). record(report, { signer }) is called for every accepted report.
function createRefusalRoutes({ publicUrl, record = () => {}, perHour = 30, days = 30, now = () => Date.now() } = {}) {
  const ownHost = new URL(publicUrl).hostname;
  const seen = [];
  const hits = new Map();
  const allow = (key) => {
    const t = now();
    const recent = (hits.get(key) || []).filter((x) => t - x < 3600 * 1000);
    if (recent.length >= perHour) return false;
    recent.push(t);
    hits.set(key, recent);
    if (hits.size > 10000) hits.clear();
    return true;
  };
  const counts = () => {
    const since = now() - days * 86400 * 1000;
    while (seen.length && seen[0].at < since) seen.shift();
    const out = {};
    for (const s of seen) {
      const r = (out[s.resource] ||= { total: 0, signed: 0, reasons: {} });
      r.total++;
      if (s.signed) r.signed++;
      r.reasons[s.reason] = (r.reasons[s.reason] || 0) + 1;
    }
    return out;
  };
  return {
    get(_req, res) {
      res.set('Cache-Control', 'public, max-age=60').json({ extension: 'refusal', version: VERSION, spec: ISSUE, how: `POST a report here (JSON, see schema) when you decide not to pay one of ${ownHost}'s 402s. Answered 204. Best effort: never wait for it.`, reasons: REASONS, schema: REPORT_SCHEMA, received: { days, since_restart: true, by_resource: counts() } });
    },
    async post(req, res) {
      if (!allow(req.ip)) return res.status(429).json({ error: 'too many refusals from this address; try again later' });
      const parsed = parseRefusal(req.body, { ownHost, now: now() });
      if (parsed.error) return res.status(400).json({ error: parsed.error });
      const raw = req.body;
      const signer = raw.signature ? await signedBy(raw) : null;
      if (signer === false) return res.status(400).json({ error: 'the signature does not match signer for this report' });
      seen.push({ at: now(), resource: parsed.report.resource, reason: parsed.report.reason, signed: Boolean(signer) });
      if (seen.length > 50000) seen.shift();
      res.locals.refusal = { reason: parsed.report.reason, signed: Boolean(signer), resource: new URL(parsed.report.resource).pathname };
      try { record(parsed.report, { signer }); } catch { /* recording never fails the report */ }
      res.status(204).end();
    },
  };
}

// Buyer side: send a ready refusal ({ url, report }, as a preflight returns it) fire-and-forget. At most one per
// resource and reason a day; never throws and never waits long. Redirects are refused, so a report only reaches the
// url on the seller's own site that refusalTarget() allowed.
function createRefusalSender({ fetchImpl, by = null, timeoutMs = 5000, now = () => Date.now(), log = console } = {}) {
  const sent = new Map();
  return {
    send(refusal) {
      if (!refusal || !refusal.url || !refusal.report) return Promise.resolve(false);
      const key = `${refusal.report.resource} ${refusal.report.reason}`;
      const t = now();
      if (t - (sent.get(key) || -Infinity) < 86400 * 1000) return Promise.resolve(false);
      sent.set(key, t);
      if (sent.size > 5000) sent.clear();
      const report = by ? { ...refusal.report, by } : refusal.report;
      return Promise.resolve()
        .then(() => fetchImpl(refusal.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(report), redirect: 'error', signal: AbortSignal.timeout(timeoutMs) }))
        .then((r) => r.status >= 200 && r.status < 300)
        .catch((err) => { log.warn?.(`[refusal] could not send to ${refusal.url}: ${err.message}`); return false; });
    },
  };
}

export { createRefusalSender, REPORT_SCHEMA, REASONS, FROM_PREFLIGHT, VERSION, PATH, ISSUE, canonical, offerHash, refusalExtension, refusalTarget, refusalReport, parseRefusal, signingMessage, createRefusalRoutes };
