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
// signingMessage(report) it shows a real wallet sent it. Nothing about the buyer is required, and "by" is best left out
// unless the buyer wants to be identified. A screening_hit must be signed: unsigned, anyone could flag a seller with
// made-up sanctions hits, so the endpoint refuses it. Even signed it only shows that one wallet says so.
//
// "Couldn't check" is not "checked and failed": a check that could not complete (a lookup that didn't answer, a list
// that wasn't loaded) is check_unavailable, with detail naming the check (payto_binding, screening or trust). It says
// nothing about the seller, and a seller can count it apart or ignore it. payto_unverified then only means the check
// ran and found nothing tying payTo to the seller, and screening_hit only an actual match.
//
// A buyer's limits are the owner's private policy (hamburgchan on #4087): detail never carries limits, balances, budgets
// or other policy values. For the policy reasons (price_above_limit, policy_blocked, trust_low) detail is left out unless
// the owner turned it on, and then it is a fixed category: price_above_limit says which limit (per_call, daily, total),
// never how high it is. A signature shows which wallet or checker sent a report, not that the owner agreed to disclose
// anything; whether to send refusals at all is the owner's choice.
//
// Buyers only send to a url on the same site as the resource (same host, or the same last two host labels, except on
// shared hosting domains), so a 402 can't turn buyers into a flood against someone else's server.
import crypto from 'node:crypto';

const VERSION = '0.4-draft';
const PATH = '/.well-known/x402-refusal';
const ISSUE = 'https://github.com/x402-foundation/x402/issues/4087';
const REASONS = {
  price_above_limit: 'the price is above a buyer spend limit; detail, if the owner allows it, says which: "per_call", "daily" or "total" (never the limit itself)',
  price_changed: 'the price differs from what the buyer saw before',
  payto_changed: 'payTo differs from what the buyer saw before',
  payto_unverified: 'the buyer checked and found nothing tying payTo to the seller (detail "unbound")',
  network_unsupported: 'none of the offered networks are usable by the buyer',
  asset_unsupported: 'none of the offered assets are usable by the buyer',
  challenge_invalid: 'the 402 could not be parsed or broke the spec',
  terms_mismatch: 'two forms of the challenge disagree on terms',
  timeout_too_short: 'maxTimeoutSeconds was too short for the buyer to settle',
  screening_hit: 'the payTo or asset matched a sanctions or risk list',
  trust_low: 'the buyer\'s trust or reputation check said no; detail "unknown" (no history yet) or "score" (scored too low)',
  check_unavailable: 'a check the buyer needed could not complete (a lookup did not answer, a list was not loaded); says nothing about the seller. detail starts with the check: "payto_binding", "screening" or "trust"',
  policy_blocked: 'another wallet or owner policy blocked it',
  other: 'none of the above; see detail',
};
const DETAIL_MAX = 200;
// Reasons a report must be signed for (unsigned they are refused).
const SIGNED_ONLY = new Set(['screening_hit']);
// The policy reasons: detail only with the owner's consent, and only a category.
const POLICY_REASONS = ['price_above_limit', 'policy_blocked', 'trust_low'];
// price_above_limit's detail, when there is one: which limit was hit.
const LIMIT_KINDS = ['per_call', 'daily', 'total'];
const LIMIT_DETAIL = new RegExp(`^(${LIMIT_KINDS.join('|')})$`);
// An amount in a policy reason's detail ("$0.05", "0.05 USDC", "limit 5"): a limit or budget leaking.
const AMOUNT = /\$\s?\d|\d\s?(usd|usdc|usdt|rlusd|eur|dollars?)\b|\b(limit|budget|balance|cap|max)\b[^a-z]*\d/i;
// check_unavailable's detail starts with one of these: which check could not complete.
const UNAVAILABLE_CHECKS = ['payto_binding', 'screening', 'trust'];
const UNAVAILABLE_DETAIL = new RegExp(`^(${UNAVAILABLE_CHECKS.join('|')})(\\b|$)`);

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
  unreliable_history: 'trust_low',
  charged_without_answer: 'trust_low',
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
    by: { type: 'string', maxLength: 100, description: 'Optional: the buyer\'s client or checker. Leave it out unless the buyer wants to be identified.' },
    signature: { type: 'object', description: 'EIP-191 signature over the signing message (lines "x402 refusal", "resource: …", "offer: …", "reason: …", "checkedAt: …"). Required for screening_hit.', properties: { type: { const: 'eip191' }, signer: { type: 'string' }, value: { type: 'string' } }, required: ['type', 'signer', 'value'] },
  },
  required: ['x402Version', 'resource', 'offer', 'reason', 'checkedAt'],
  allOf: [
    { if: { properties: { reason: { enum: [...SIGNED_ONLY] } }, required: ['reason'] }, then: { required: ['signature'] } },
    { if: { properties: { reason: { const: 'check_unavailable' } }, required: ['reason'] }, then: { required: ['detail'], properties: { detail: { pattern: UNAVAILABLE_DETAIL.source } } } },
    { if: { properties: { reason: { const: 'price_above_limit' } }, required: ['reason'] }, then: { properties: { detail: { enum: LIMIT_KINDS } } } },
  ],
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
// A policy reason's detail that would disclose the owner's policy: price_above_limit's detail is a category or nothing,
// and no policy reason carries an amount. Null when fine.
function policyDetailError(reason, detail) {
  if (!POLICY_REASONS.includes(reason) || detail === undefined || detail === null || detail === '') return null;
  if (reason === 'price_above_limit' && !LIMIT_DETAIL.test(String(detail))) return `price_above_limit's detail, if any, is which limit was hit: ${LIMIT_KINDS.join(', ')} (never the limit itself)`;
  if (AMOUNT.test(String(detail))) return `a ${reason} report's detail must not contain limits, budgets or other amounts: they are the owner's private policy`;
  return null;
}

function refusalReport({ resource, accept, acceptIndex = null, reason, detail = null, by = null, x402Version = 2, now = new Date() }) {
  if (!REASONS[reason]) throw new Error(`unknown refusal reason ${reason}`);
  if (reason === 'check_unavailable' && !UNAVAILABLE_DETAIL.test(String(detail ?? ''))) throw new Error(`check_unavailable needs a detail starting with ${UNAVAILABLE_CHECKS.join(', ')}`);
  const policy = policyDetailError(reason, detail);
  if (policy) throw new Error(policy);
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
  if (b.reason === 'check_unavailable' && !UNAVAILABLE_DETAIL.test(String(b.detail ?? ''))) return { error: `a check_unavailable report needs a detail starting with the check that could not complete: ${UNAVAILABLE_CHECKS.join(', ')}` };
  const policy = policyDetailError(b.reason, b.detail);
  if (policy) return { error: policy };
  if (b.by !== undefined && (typeof b.by !== 'string' || b.by.length > 100)) return { error: 'by must be text of at most 100 characters' };
  const at = Date.parse(b.checkedAt);
  if (!Number.isFinite(at) || Math.abs(now - at) > 24 * 3600 * 1000) return { error: 'checkedAt must be an ISO time within a day of now' };
  if (b.signature === undefined && SIGNED_ONLY.has(b.reason)) return { error: `a ${b.reason} report must be signed (signature { type: "eip191", signer, value })` };
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

// The route a report counts under. A buyer's resource URL can carry its own query values or a caller-specific path,
// and the counts are public, so reports are bucketed by a route the seller declares (routes: ['/api/v1/fix',
// '/signal/:pair'], or a function url => template or null), never by the URL as sent. Anything else is "other".
function routeMatcher(routes) {
  if (typeof routes === 'function') return (u) => { try { return routes(u) || null; } catch { return null; } };
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const list = (routes || []).map((t) => ({ t, re: new RegExp(`^${t.split('/').map((s) => (s.startsWith(':') ? '[^/]+' : esc(s))).join('/')}/?$`) }));
  return (u) => list.find((x) => x.re.test(u.pathname))?.t ?? null;
}

// The seller's endpoint: GET says what it takes and what came in (last 30 days, since the last restart): counts per
// route and reason, and per UTC day, route and reason; POST takes a report (204). Counts are kept in memory; history,
// when given, is read once at the start and adds the reports counted before this process (async () => [{ at, resource
// (the route), reason, signed, key? }], e.g. from a log the record hook writes), so a restart doesn't empty the public
// counts. Until it has been read, or without one, GET says since_restart: true. A restored report that is posted again
// still counts once; the per-address cap below starts over, so after a restart an address can add one more that day.
// An exact repost of a report already counted is answered 204 and not counted again. Unsigned reports are capped (Lucian, neomorphic.io): at most one per
// sending address, server UTC day, route and reason, whatever their checkedAt, offer, detail or URL, so one sender
// can't inflate a route's count by varying those. The address is kept only as a salted hash and forgotten with the
// window. They are counted as capped unsigned reports, not buyers: several buyers behind one address count once, and
// senders on many addresses still count more than once. Signed reports are counted apart, once per exact report (a
// signature proves a key, not a unique customer). record(report, { signer, key }) is called for every counted report,
// with resource replaced by its route as well; key names the exact report (a sha256, nothing about the buyer).
function createRefusalRoutes({ publicUrl, routes = [], record = () => {}, history = null, perHour = 30, days = 30, now = () => Date.now() } = {}) {
  const ownHost = new URL(publicUrl).hostname;
  const routeOf = routeMatcher(routes);
  const seen = [];
  const counted = new Set(); // reports already counted (exact reposts are not)
  const contributed = new Map(); // capped unsigned reports: salted hash of address, day, route, reason -> day
  const salt = crypto.randomBytes(16);
  const dayOf = (t) => new Date(t).toISOString().slice(0, 10);
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
    while (seen.length && seen[0].at < since) counted.delete(seen.shift().key);
    const first = dayOf(since);
    for (const [k, day] of contributed) if (day < first) contributed.delete(k);
    const out = {};
    const daily = new Map();
    for (const s of seen) {
      const r = (out[s.resource] ||= { total: 0, signed: 0, reasons: {} });
      r.total++;
      if (s.signed) r.signed++;
      r.reasons[s.reason] = (r.reasons[s.reason] || 0) + 1;
      const day = new Date(s.at).toISOString().slice(0, 10);
      const key = `${day} ${s.resource} ${s.reason}`;
      const d = daily.get(key) || { day, resource: s.resource, reason: s.reason, count: 0, signed: 0 };
      d.count++;
      if (s.signed) d.signed++;
      daily.set(key, d);
    }
    // Newest day first; within a day, most reports first.
    const byDay = [...daily.values()].sort((a, b) => b.day.localeCompare(a.day) || b.count - a.count);
    return { byResource: out, byDay };
  };
  // The reports counted before this process started (history), merged into seen once, oldest first.
  let restored = false;
  const ready = typeof history !== 'function' ? Promise.resolve() : Promise.resolve().then(history).then((list) => {
    if (!Array.isArray(list)) return; // no history to read (e.g. no log configured): since_restart stays true
    const since = now() - days * 86400 * 1000;
    const prior = [];
    for (const [i, h] of list.entries()) {
      const at = typeof h?.at === 'number' ? h.at : Date.parse(h?.at);
      if (!Number.isFinite(at) || at < since || at > now() || !REASONS[h.reason] || typeof h.resource !== 'string' || !h.resource) continue;
      const key = typeof h.key === 'string' && /^[0-9a-f]{64}$/.test(h.key) ? h.key : `history ${i} ${at}`;
      if (counted.has(key)) continue;
      counted.add(key);
      prior.push({ at, key, resource: h.resource.slice(0, 200), reason: h.reason, signed: h.signed === true });
    }
    const merged = prior.concat(seen).sort((a, b) => a.at - b.at);
    seen.length = 0;
    for (const s of merged) seen.push(s);
    while (seen.length > 50000) counted.delete(seen.shift().key);
    restored = true;
  }).catch(() => {});
  return {
    ready,
    get(_req, res) {
      const { byResource, byDay } = counts();
      res.set('Cache-Control', 'public, max-age=60').json({ extension: 'refusal', version: VERSION, spec: ISSUE, how: `POST a report here (JSON, see schema) when you decide not to pay one of ${ownHost}'s 402s. Answered 204. Best effort: never wait for it. A ${[...SIGNED_ONLY].join(' or ')} report must be signed. A check that could not complete is check_unavailable (detail: ${UNAVAILABLE_CHECKS.join(', ')}), not a verdict on the seller. Never put the buyer's limits, budgets or other policy values in detail; price_above_limit's detail, if any, is ${LIMIT_KINDS.join(', ')}.`, reasons: REASONS, schema: REPORT_SCHEMA, received: { days, since_restart: !restored, counted_by: 'route the seller declares (other: none matched); exact reposts count once; unsigned reports are capped at one per sending address, UTC day, route and reason (total minus signed: capped unsigned reports, not buyers); signed reports count once per exact report', by_resource: byResource, by_day: byDay } });
    },
    async post(req, res) {
      if (!allow(req.ip)) return res.status(429).json({ error: 'too many refusals from this address; try again later' });
      const parsed = parseRefusal(req.body, { ownHost, now: now() });
      if (parsed.error) return res.status(400).json({ error: parsed.error });
      const raw = req.body;
      const signer = raw.signature ? await signedBy(raw) : null;
      if (signer === false) return res.status(400).json({ error: 'the signature does not match signer for this report' });
      const route = routeOf(new URL(parsed.report.resource)) || 'other';
      const r = parsed.report;
      const key = crypto.createHash('sha256').update(JSON.stringify([r.resource, r.offer.hash, r.offer.acceptIndex ?? null, r.reason, r.detail ?? null, r.checkedAt, signer || null])).digest('hex');
      if (counted.has(key)) return res.status(204).end();
      if (!signer) {
        const cap = crypto.createHmac('sha256', salt).update(JSON.stringify([String(req.ip || ''), dayOf(now()), route, r.reason])).digest('hex');
        if (contributed.has(cap)) return res.status(204).end();
        contributed.set(cap, dayOf(now()));
        if (contributed.size > 50000) contributed.delete(contributed.keys().next().value);
      }
      counted.add(key);
      seen.push({ at: now(), key, resource: route, reason: r.reason, signed: Boolean(signer) });
      if (seen.length > 50000) counted.delete(seen.shift().key);
      res.locals.refusal = { reason: r.reason, signed: Boolean(signer), resource: route };
      try { record({ ...r, resource: route }, { signer, key }); } catch { /* recording never fails the report */ }
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
      // A seller refuses these unsigned, so an unsigned one isn't sent.
      if (SIGNED_ONLY.has(refusal.report.reason) && !refusal.report.signature) return Promise.resolve(false);
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

export { createRefusalSender, REPORT_SCHEMA, REASONS, SIGNED_ONLY, UNAVAILABLE_CHECKS, POLICY_REASONS, LIMIT_KINDS, FROM_PREFLIGHT, VERSION, PATH, ISSUE, canonical, offerHash, refusalExtension, refusalTarget, refusalReport, parseRefusal, signingMessage, createRefusalRoutes };
