// MPP tempo pull mode: the agent sends a signed Tempo transfer (paying its own fee) and we broadcast it after
// checking its one call. No network: a fake Tempo node holds the receipts.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { keccak256, stringToHex, getAddress, encodeFunctionData, decodeFunctionData, parseSignature } = require('viem');
const { privateKeyToAccount } = require('viem/accounts');
const { Transaction, Abis } = require('viem/tempo');
const { createMppPay, unlessMppPaid, RpcRefused } = require("../src/mpp-pay.cjs");

const REALM = 'svc.test';
const TEMPO_PAY_TO = '0x1111111111111111111111111111111111111111';
const TEMPO_USDC = getAddress('0x20c000000000000000000000b9537d11c60e8b50');
const agent = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const TOPIC = keccak256(stringToHex('TransferWithMemo(address,address,uint256,bytes32)'));
const pad = (a) => `0x${a.slice(2).toLowerCase().padStart(64, '0')}`;
const memoFor = (realm, id) => `0x${keccak256(stringToHex('mpp')).slice(2, 10)}01${keccak256(stringToHex(realm)).slice(2, 22)}${'0'.repeat(20)}${keccak256(stringToHex(id)).slice(2, 16)}`;
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

async function signedTx({ to = TEMPO_PAY_TO, amount = 10000n, memo, token = TEMPO_USDC, chainId = 4217, signer = agent } = {}) {
  const data = encodeFunctionData({ abi: Abis.tip20, functionName: 'transferWithMemo', args: [to, amount, memo] });
  const tx = { chainId, calls: [{ to: token, data }], gas: 100000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, nonce: 0n, nonceKey: 0n, type: 'tempo' };
  const unsigned = await Transaction.serialize(tx);
  return Transaction.serialize(tx, parseSignature(await signer.sign({ hash: keccak256(unsigned) })));
}

function serve(sendRaw) {
  const receipts = new Map();
  const calls = { handler: 0 };
  const mpp = createMppPay({
    secret: 'test-secret', realm: REALM, routes: { 'GET /paid': '$0.01' }, log: { warn() {} },
    tempo: { recipient: TEMPO_PAY_TO, getReceipt: async (h) => receipts.get(h) || null, sendRaw: (raw) => sendRaw(raw, receipts), waitMs: 0 },
  });
  const app = express();
  app.use(mpp.middleware);
  app.use(unlessMppPaid((req, res) => res.status(402).json({ x402Version: 2, accepts: [] })));
  app.get('/paid', (req, res) => { calls.handler++; res.json({ ok: true, paid: res.locals.mppPayment || null }); });
  return new Promise((resolve) => {
    const server = http.createServer(app).listen(0, () => resolve({ base: `http://127.0.0.1:${server.address().port}`, mpp, calls, receipts, close: () => server.close() }));
  });
}
const credential = (c, payload, source = `did:pkh:eip155:4217:${agent.address}`) => {
  const challenge = { id: c.id, realm: c.realm, method: c.method, intent: c.intent, request: Buffer.from(JSON.stringify(c.request)).toString('base64url'), expires: c.expires, opaque: c.opaque };
  return `Payment ${b64u({ challenge, payload, source })}`;
};
const fakeNode = (sent) => async (raw, receipts) => {
  sent.push(raw);
  const tx = Transaction.deserialize(raw);
  const { args } = decodeFunctionData({ abi: Abis.tip20, data: tx.calls[0].data });
  receipts.set(keccak256(raw).toLowerCase(), { status: '0x1', from: tx.from, logs: [{ address: tx.calls[0].to.toLowerCase(), topics: [TOPIC, pad(tx.from), pad(args[0]), args[2]], data: `0x${args[1].toString(16).padStart(64, '0')}` }] });
  return keccak256(raw);
};

test('tempo challenge offers push and pull', async () => {
  const s = await serve(async () => {});
  try { assert.deepEqual(s.mpp.challengeFor('GET /paid', 'tempo').request.methodDetails.supportedModes, ['push', 'pull']); } finally { s.close(); }
});

test('pull: a signed transfer is checked, broadcast once and served with a receipt', async () => {
  const sent = [];
  const s = await serve(fakeNode(sent));
  try {
    const c = s.mpp.challengeFor('GET /paid', 'tempo');
    const raw = await signedTx({ memo: memoFor(REALM, c.id) });
    const auth = credential(c, { type: 'transaction', signature: raw });
    const res = await fetch(`${s.base}/paid`, { headers: { authorization: auth } });
    assert.equal(res.status, 200);
    await res.json();
    assert.deepEqual(sent, [raw]);
    const receipt = JSON.parse(Buffer.from(res.headers.get('payment-receipt'), 'base64url').toString());
    assert.equal(receipt.method, 'tempo');
    assert.equal(receipt.reference, keccak256(raw).toLowerCase());
    assert.equal(s.calls.handler, 1);
    assert.equal((await fetch(`${s.base}/paid`, { headers: { authorization: auth } })).status, 402);
    assert.equal(sent.length, 1);
  } finally { s.close(); }
});

test('pull: wrong recipient, amount, token, challenge or chain is never broadcast', async () => {
  const sent = [];
  const s = await serve(fakeNode(sent));
  try {
    const c = s.mpp.challengeFor('GET /paid', 'tempo');
    const memo = memoFor(REALM, c.id);
    for (const raw of [
      await signedTx({ memo, to: '0x2222222222222222222222222222222222222222' }),
      await signedTx({ memo, amount: 9999n }),
      await signedTx({ memo, token: '0x20c0000000000000000000000000000000000000' }),
      await signedTx({ memo: memoFor(REALM, 'other') }),
      await signedTx({ memo, chainId: 42431 }),
      '0x76deadbeef',
    ]) {
      const res = await fetch(`${s.base}/paid`, { headers: { authorization: credential(c, { type: 'transaction', signature: raw }) } });
      assert.equal(res.status, 402);
    }
    assert.equal(sent.length, 0);
    assert.equal(s.calls.handler, 0);
  } finally { s.close(); }
});

test('pull: a refused broadcast is refused, unless the transaction is already on chain', async () => {
  let onChain = false;
  let cid;
  const s = await serve(async (raw, receipts) => {
    if (onChain) receipts.set(keccak256(raw).toLowerCase(), { status: '0x1', from: agent.address, logs: [{ address: TEMPO_USDC.toLowerCase(), topics: [TOPIC, pad(agent.address), pad(TEMPO_PAY_TO), memoFor(REALM, cid)], data: `0x${(10000).toString(16).padStart(64, '0')}` }] });
    throw new RpcRefused(onChain ? 'already known' : 'insufficient funds for fee');
  });
  try {
    const c = s.mpp.challengeFor('GET /paid', 'tempo');
    cid = c.id;
    const auth = credential(c, { type: 'transaction', signature: await signedTx({ memo: memoFor(REALM, c.id) }) });
    const res = await fetch(`${s.base}/paid`, { headers: { authorization: auth } });
    assert.equal(res.status, 402);
    assert.match((await res.json()).detail, /Tempo refused the transaction/);
    onChain = true;
    assert.equal((await fetch(`${s.base}/paid`, { headers: { authorization: auth } })).status, 200);
  } finally { s.close(); }
});
