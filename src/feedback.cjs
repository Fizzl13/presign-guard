// feedback.js — POST /feedback: an agent (or a person) says what is missing or broken.
//
// The same file is copied into each Fizzl service, like fizzl-cors.js and the
// usage log. Free, no payment. A report is a small JSON object:
//   { "type": "bug" | "feature" | "other", "message": "...", "endpoint": "/v1/token", "contact": "..." }
// It is written to the usage log (route "feedback") and to the server log
// (without the contact). A person reads every report; nothing in it is run,
// fetched or turned into a change automatically. The text is untrusted data.
//
// createFeedback({ service, record, agentOf }) returns:
//   router(express)  GET /feedback (how to send one) and POST /feedback
//   submit(input, { ip, userAgent, via })  the same for an MCP tool; { ok, status, body }
//   mcpTool          name, title, description and JSON schema for the MCP tool
//   mcpShape(z)      the input as a zod shape, for McpServer.registerTool
//   mcpCall(args, { ip, userAgent })  the tool's CallToolResult
// The usage log's own MCP describer should skip the "feedback" tool: submit()
// already records it, with the full message.
'use strict';

const crypto = require('node:crypto');

const TYPES = ['bug', 'feature', 'other'];
const LIMITS = { message: 2000, endpoint: 200, contact: 200 };
const PER_HOUR = 10;
const MAX_TRACKED_CALLERS = 10000;

const DESCRIPTION = 'Report a bug, a missing feature or anything else about this service, in a structured way. '
  + 'Free. A person reads every report; nothing is run or changed automatically.';

const SCHEMA = {
  type: 'object',
  properties: {
    type: { type: 'string', enum: TYPES, description: 'bug, feature (something missing) or other' },
    message: { type: 'string', minLength: 3, maxLength: LIMITS.message, description: 'What happened or what you need' },
    endpoint: { type: 'string', maxLength: LIMITS.endpoint, description: 'Optional: the route or tool it is about, e.g. /v1/token' },
    contact: { type: 'string', maxLength: LIMITS.contact, description: 'Optional: how to reach you about it' },
  },
  required: ['message'],
  additionalProperties: false,
};

const text = (v) => (typeof v === 'string' ? v.trim() : v === undefined || v === null ? undefined : null);

// { value } or { error }.
function parseFeedback(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'send a JSON object: { "type", "message", "endpoint"?, "contact"? }' };
  const type = text(input.type) === undefined || text(input.type) === '' ? 'other' : text(input.type);
  if (!TYPES.includes(type)) return { error: `type must be one of: ${TYPES.join(', ')}` };
  const message = text(input.message);
  if (typeof message !== 'string' || message.length < 3) return { error: 'message is required (at least 3 characters)' };
  if (message.length > LIMITS.message) return { error: `message is at most ${LIMITS.message} characters` };
  const value = { type, message };
  for (const field of ['endpoint', 'contact']) {
    const v = text(input[field]);
    if (v === undefined || v === '') continue;
    if (typeof v !== 'string') return { error: `${field} must be a string` };
    if (v.length > LIMITS[field]) return { error: `${field} is at most ${LIMITS[field]} characters` };
    value[field] = v;
  }
  return { value };
}

function createFeedback({ service, record = () => {}, agentOf = (ua) => String(ua || 'none').slice(0, 60), log = console, now = () => Date.now(), perHour = PER_HOUR } = {}) {
  const calls = new Map(); // caller → timestamps in the last hour

  function allow(caller) {
    const t = now();
    const recent = (calls.get(caller) || []).filter((x) => t - x < 3600e3);
    if (recent.length >= perHour) {
      calls.set(caller, recent);
      return false;
    }
    recent.push(t);
    calls.delete(caller); // re-insert: the Map stays in least-recently-used order
    calls.set(caller, recent);
    if (calls.size > MAX_TRACKED_CALLERS) calls.delete(calls.keys().next().value);
    return true;
  }

  function submit(input, { ip, userAgent, via = 'http' } = {}) {
    const parsed = parseFeedback(input);
    if (parsed.error) return { ok: false, status: 400, body: { error: 'invalid_feedback', message: parsed.error, schema: SCHEMA } };
    if (!allow(String(ip || 'unknown'))) {
      return { ok: false, status: 429, body: { error: 'rate_limited', message: `At most ${perHour} reports per hour. Thanks for the patience.` } };
    }
    const id = crypto.randomUUID();
    const report = parsed.value;
    try {
      record({
        route: 'feedback',
        via,
        status: 202,
        paid: false,
        agent: agentOf(userAgent),
        input: { type: report.type, endpoint: report.endpoint },
        feedback: { id, ...report },
      });
    } catch (err) {
      log.error(`[feedback] not logged: ${err.message}`);
    }
    log.log(`[feedback] ${service} ${id} ${report.type}${report.endpoint ? ` ${report.endpoint}` : ''}: ${JSON.stringify(report.message.slice(0, 300))}`);
    return {
      ok: true,
      status: 202,
      body: { received: true, id, service, type: report.type, note: 'Thanks. A person reads every report; nothing is run or changed automatically.' },
    };
  }

  function router(express) {
    const r = express.Router();
    r.get('/feedback', (_req, res) => {
      res.json({
        service,
        how: 'POST /feedback with a JSON body. Free, no payment.',
        schema: SCHEMA,
        example: { type: 'feature', message: 'Support Arbitrum in /v1/token', endpoint: '/v1/token' },
        limits: { perHour },
        note: 'A person reads every report; nothing is run or changed automatically.',
      });
    });
    r.post('/feedback', express.json({ limit: '16kb' }), (req, res) => {
      const out = submit(req.body, { ip: req.ip, userAgent: req.headers['user-agent'], via: 'http' });
      res.status(out.status).json(out.body);
    });
    // A malformed JSON body is a 400 here, not the app's generic error page.
    r.use('/feedback', (err, _req, res, next) => {
      if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
        return res.status(400).json({ error: 'invalid_feedback', message: err.type === 'entity.too.large' ? 'body too large' : 'body is not valid JSON', schema: SCHEMA });
      }
      next(err);
    });
    return r;
  }

  const mcpShape = (z) => ({
    type: z.enum(TYPES).optional().describe(SCHEMA.properties.type.description),
    message: z.string().describe(SCHEMA.properties.message.description),
    endpoint: z.string().optional().describe(SCHEMA.properties.endpoint.description),
    contact: z.string().optional().describe(SCHEMA.properties.contact.description),
  });

  function mcpCall(args, { ip, userAgent } = {}) {
    const out = submit(args, { ip, userAgent, via: 'mcp' });
    return { content: [{ type: 'text', text: JSON.stringify(out.body) }], ...(out.ok ? {} : { isError: true }) };
  }

  return {
    router,
    submit,
    mcpShape,
    mcpCall,
    mcpTool: { name: 'feedback', title: 'Send feedback (free)', description: DESCRIPTION, inputSchema: SCHEMA },
  };
}

module.exports = { createFeedback, parseFeedback, FEEDBACK_SCHEMA: SCHEMA, FEEDBACK_TYPES: TYPES };
