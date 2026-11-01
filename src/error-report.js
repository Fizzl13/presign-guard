// The same as x402-doctor's lib/error-report.js (ESM copy). Error reports to Sentry, without the Sentry SDK (its OpenTelemetry layer costs tens of MB, and these services run in
// 512 MB). Off without SENTRY_DSN.
//
// What is sent: the error's type, message and stack, the service name and version, and for an HTTP request only its
// method and path (no query, no headers, no body, no IP). Payment headers, pass proofs and keys never leave. At most
// maxPerHour reports, and the same error at most once in 10 minutes.
//
//   const reporter = createErrorReporter({ dsn: env.SENTRY_DSN, service: 'x402-doctor', release });
//   app.use(reporter.expressHandler());   // last, after every route: 5xx are reported and answered as JSON
//   reporter.installProcessHooks();       // an uncaught error is reported before the process ends
import crypto from 'node:crypto';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

function parseDsn(dsn) {
  try {
    const u = new URL(String(dsn || '').trim());
    const project = u.pathname.replace(/^\/+|\/+$/g, '');
    if (!u.username || !/^\d+$/.test(project) || !/^https?:$/.test(u.protocol)) return null;
    return { key: u.username, url: `${u.protocol}//${u.host}/api/${project}/envelope/`, dsn: `${u.protocol}//${u.username}@${u.host}/${project}` };
  } catch {
    return null;
  }
}

// Stack lines to Sentry frames, oldest call first.
function framesOf(stack) {
  const frames = [];
  for (const line of String(stack || '').split('\n').slice(1, 40)) {
    const m = /^\s*at (?:(.+?) \()?(.+?):(\d+):(\d+)\)?$/.exec(line);
    if (!m) continue;
    const file = m[2];
    frames.push({ function: m[1] || '<anonymous>', filename: file.replace(`${process.cwd()}/`, '').replace(/^\/opt\/render\/project\/src\//, ''), lineno: Number(m[3]), colno: Number(m[4]), in_app: !/node_modules|node:/.test(file) });
  }
  return frames.reverse();
}

function createErrorReporter({ dsn, service, release = null, environment = 'production', fetchImpl = globalThis.fetch, maxPerHour = 30, now = () => Date.now(), log = console } = {}) {
  const target = parseDsn(dsn);
  const recent = new Map();
  let hour = 0;
  let sent = 0;

  function envelopeOf(err, { req = null, tags = {}, level = 'error' } = {}) {
    const e = err instanceof Error ? err : new Error(String(err));
    const event = {
      event_id: crypto.randomUUID().replace(/-/g, ''),
      timestamp: new Date(now()).toISOString(),
      platform: 'node',
      level,
      server_name: os.hostname(),
      ...(release ? { release: `${service}@${release}` } : {}),
      environment,
      tags: { service, ...tags },
      exception: { values: [{ type: e.name || 'Error', value: String(e.message || e).slice(0, 1000), stacktrace: { frames: framesOf(e.stack) } }] },
      ...(req ? { request: { method: req.method, url: `${req.protocol || 'https'}://${req.hostname || 'localhost'}${String(req.path || req.url || '').split('?')[0]}` } } : {}),
    };
    return `${JSON.stringify({ event_id: event.event_id, sent_at: event.timestamp, dsn: target.dsn })}\n${JSON.stringify({ type: 'event' })}\n${JSON.stringify(event)}`;
  }
  const headers = () => ({ 'content-type': 'application/x-sentry-envelope', 'x-sentry-auth': `Sentry sentry_version=7, sentry_key=${target.key}, sentry_client=fizzl-error-report/1.0` });

  // Whether this error may be sent now: within the hourly budget and not the same as one sent in the last 10 minutes.
  function allowed(err) {
    const t = now();
    if (Math.floor(t / 3600e3) !== hour) { hour = Math.floor(t / 3600e3); sent = 0; }
    if (sent >= maxPerHour) return false;
    const key = `${err?.name}:${String(err?.message).slice(0, 200)}:${String(err?.stack || '').split('\n')[1] || ''}`;
    if (recent.has(key) && t - recent.get(key) < 600e3) return false;
    recent.set(key, t);
    if (recent.size > 500) recent.clear();
    sent += 1;
    return true;
  }

  // Fire and forget; never throws.
  function report(err, context = {}) {
    if (!target || !allowed(err)) return Promise.resolve(false);
    return Promise.resolve()
      .then(() => fetchImpl(target.url, { method: 'POST', headers: headers(), body: envelopeOf(err, context), signal: AbortSignal.timeout(5000) }))
      .then((r) => r.ok)
      .catch((e) => { log.warn?.(`[error-report] could not send: ${e.message}`); return false; });
  }

  // Last middleware: report 5xx errors and answer them as JSON (no stack trace to the caller). 4xx errors from body
  // parsing and the like keep their status and are not reported.
  function expressHandler() {
    return (err, req, res, next) => {
      const status = Number(err?.status || err?.statusCode) || 500;
      if (status >= 500) {
        console.error(`[error] ${req.method} ${req.path}:`, err);
        report(err, { req });
      }
      if (res.headersSent) return next(err);
      res.status(status).json({ error: status >= 500 ? 'internal error' : (err.expose !== false && err.message) || 'bad request' });
    };
  }

  // An uncaught error ends the process right after this hook, so the report is sent from a short-lived child process
  // that the hook waits for (at most 4 seconds). The process still ends as before.
  function installProcessHooks() {
    if (!target) return;
    process.on('uncaughtExceptionMonitor', (err, origin) => {
      if (!allowed(err)) return;
      const script = 'let b="";process.stdin.on("data",(c)=>b+=c).on("end",()=>{const{url,headers,body}=JSON.parse(b);fetch(url,{method:"POST",headers,body}).catch(()=>{}).finally(()=>process.exit(0))})';
      try {
        spawnSync(process.execPath, ['-e', script], { input: JSON.stringify({ url: target.url, headers: headers(), body: envelopeOf(err, { tags: { origin }, level: 'fatal' }) }), timeout: 4000, stdio: ['pipe', 'ignore', 'ignore'] });
      } catch { /* the crash goes on regardless */ }
    });
  }

  return { enabled: Boolean(target), report, expressHandler, installProcessHooks, envelopeOf };
}

export { createErrorReporter, parseDsn, framesOf };
