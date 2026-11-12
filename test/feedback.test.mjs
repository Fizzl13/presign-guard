// POST /feedback and the feedback MCP tool (feedback.js, the same file in every Fizzl service).
import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import feedbackModule from '../src/feedback.cjs';

const { createFeedback, parseFeedback } = feedbackModule;

function setup(opts = {}) {
  const events = [];
  const lines = [];
  const log = { log: (l) => lines.push(l), error: (l) => lines.push(l) };
  const fb = createFeedback({ service: 'test-service', record: (e) => events.push(e), agentOf: () => 'node', log, ...opts });
  const app = express();
  app.use(fb.router(express));
  return { fb, app, events, lines };
}

async function withServer(app, fn) {
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const post = (base, body, raw) => fetch(`${base}/feedback`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw ?? JSON.stringify(body) });

test('feedback: a valid report is accepted (202), logged with the full message, and the contact stays out of the server log', async () => {
  const { app, events, lines } = setup();
  await withServer(app, async (base) => {
    const res = await post(base, { type: 'feature', message: 'Please add Arbitrum', endpoint: '/v1/token', contact: 'agent@example.com' });
    assert.equal(res.status, 202);
    const body = await res.json();
    assert.equal(body.received, true);
    assert.equal(body.type, 'feature');
    assert.match(body.id, /^[0-9a-f-]{36}$/);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].feedback, { id: body.id, type: 'feature', message: 'Please add Arbitrum', endpoint: '/v1/token', contact: 'agent@example.com' });
    assert.equal(events[0].route, 'feedback');
    assert.equal(events[0].via, 'http');
    assert.equal(lines.length, 1);
    assert.ok(!lines[0].includes('agent@example.com'));
  });
});

test('feedback: bad input is a 400 with the schema, and nothing is logged', async () => {
  const { app, events } = setup();
  await withServer(app, async (base) => {
    for (const body of [{}, { message: 'hi' }, { type: 'praise', message: 'hello there' }, { message: 'x'.repeat(2001) }, { message: 'fine', endpoint: 5 }, [1, 2]]) {
      const res = await post(base, body);
      assert.equal(res.status, 400, JSON.stringify(body).slice(0, 60));
      const out = await res.json();
      assert.equal(out.error, 'invalid_feedback');
      assert.ok(out.schema);
    }
    const res = await post(base, null, '{not json');
    assert.equal(res.status, 400);
    assert.equal((await res.json()).message, 'body is not valid JSON');
  });
  assert.equal(events.length, 0);
});

test('feedback: the type defaults to other; at most 10 reports per caller per hour', async () => {
  let t = 0;
  const { app } = setup({ now: () => t });
  await withServer(app, async (base) => {
    const first = await (await post(base, { message: 'works well' })).json();
    assert.equal(first.type, 'other');
    for (let i = 1; i < 10; i++) assert.equal((await post(base, { message: `report ${i}` })).status, 202);
    assert.equal((await post(base, { message: 'one too many' })).status, 429);
    t += 3600e3 + 1;
    assert.equal((await post(base, { message: 'an hour later' })).status, 202);
  });
});

test('feedback: GET /feedback says how to send one', async () => {
  const { app } = setup();
  await withServer(app, async (base) => {
    const res = await fetch(`${base}/feedback`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.service, 'test-service');
    assert.deepEqual(body.schema.required, ['message']);
  });
});

test('feedback: the MCP call records via mcp and marks errors', () => {
  const { fb, events } = setup();
  const ok = fb.mcpCall({ type: 'bug', message: 'tool timed out', endpoint: 'trade_setups' }, { ip: '1.2.3.4' });
  assert.equal(ok.isError, undefined);
  assert.equal(JSON.parse(ok.content[0].text).received, true);
  assert.equal(events[0].via, 'mcp');
  const bad = fb.mcpCall({ message: '' }, { ip: '1.2.3.4' });
  assert.equal(bad.isError, true);
  assert.equal(fb.mcpTool.name, 'feedback');
});

test('feedback: parseFeedback trims and drops empty optional fields', () => {
  assert.deepEqual(parseFeedback({ type: ' bug ', message: '  broken  ', endpoint: '', contact: '  ' }).value, { type: 'bug', message: 'broken' });
});

test('feedback: a report may name the payment it is about (tx with its network, or a receipt id); a malformed one is refused', () => {
  const tx = `0x${'ab'.repeat(32)}`;
  assert.deepEqual(parseFeedback({ message: 'Paid but got a 502', payment: { tx, network: 'eip155:8453' } }).value.payment, { tx, network: 'eip155:8453' });
  assert.deepEqual(parseFeedback({ message: 'By its receipt', payment: { receipt: 'pu_abc-123' } }).value.payment, { receipt: 'pu_abc-123' });
  assert.match(parseFeedback({ message: 'abc', payment: { tx: '<script>' } }).error, /payment\.tx/);
  assert.match(parseFeedback({ message: 'abc', payment: { network: 'eip155:8453' } }).error, /needs tx/);
  assert.match(parseFeedback({ message: 'abc', payment: { tx, amount: 1 } }).error, /no field amount/);
  assert.match(parseFeedback({ message: 'abc', payment: 'yes' }).error, /payment must be an object/);
  const events = [];
  const fb = createFeedback({ service: 'test-service', record: (e) => events.push(e), log: { log() {}, error() {} } });
  const out = fb.submit({ type: 'bug', message: 'Paid but got a 502', payment: { tx, network: 'eip155:8453' } }, { ip: '1.2.3.4' });
  assert.equal(out.status, 202);
  assert.equal(events[0].input.payment, 'eip155:8453', 'the usage line names the network');
  assert.equal(events[0].feedback.payment.tx, tx, 'the report itself keeps the transaction, for the person who reads it');
  assert.ok(fb.mcpTool.inputSchema.properties.payment, 'the MCP tool lists it');
});
