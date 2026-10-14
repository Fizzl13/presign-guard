// facilitator-start.js: the supported kinds without x402's start-up exit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { ExactSvmScheme } from '@x402/svm/exact/server';
import facilitatorStartModule from '../src/facilitator-start.cjs';

const { createFacilitatorStart } = facilitatorStartModule;

const BASE = 'eip155:8453';
const SOLANA = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
const quiet = { warn() {} };
const facilitator = (getSupported) => ({ getSupported, verify: async () => ({ isValid: true }), settle: async () => ({ success: true }) });
const supported = (network, extra) => ({ kinds: [{ x402Version: 2, scheme: 'exact', network, ...(extra ? { extra } : {}) }], extensions: [], signers: {} });
const base = { scheme: 'exact', price: '$0.01', network: BASE, payTo: '0x6B0F4651eD42893ab58139938175E4a69f175F25' };
const solana = { scheme: 'exact', price: '$0.01', network: SOLANA, payTo: 'ATWJ82T8nRdQwZnaysB68N5EpaSvLRsQP4h6eWmaJBH9' };

test('a facilitator that hangs is given up after askMs; the others load and its network is left out', async () => {
  const start = createFacilitatorStart([
    facilitator(async () => supported(BASE)),
    facilitator(() => new Promise(() => {})), // never answers
  ], { log: quiet, askMs: 50, retryMs: 60000 });
  const server = new x402ResourceServer(start.clients).register(BASE, new ExactEvmScheme()).register(SOLANA, new ExactSvmScheme());
  const { ready, missing } = start.attach(server, [BASE, SOLANA]);
  await ready;
  assert.deepEqual(missing(), [SOLANA]);
  assert.equal((await server.buildPaymentRequirements(base))[0].network, BASE);
  assert.deepEqual(await server.buildPaymentRequirements(solana), [], 'left out, not an error');
});

test('while a missing network is asked again, the loaded kinds stay usable', async () => {
  let solanaUp = false;
  let slowAnswer = null;
  const start = createFacilitatorStart([
    facilitator(async () => supported(BASE)),
    facilitator(() => (solanaUp ? new Promise((resolve) => { slowAnswer = () => resolve(supported(SOLANA, { feePayer: '2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4' })); }) : Promise.reject(new Error('down')))),
  ], { log: quiet, askMs: 5000, retryMs: 20 });
  const server = new x402ResourceServer(start.clients).register(BASE, new ExactEvmScheme()).register(SOLANA, new ExactSvmScheme());
  const { ready, missing } = start.attach(server, [BASE, SOLANA]);
  await ready;
  assert.deepEqual(missing(), [SOLANA]);
  solanaUp = true;
  await new Promise((r) => setTimeout(r, 60)); // the retry is now waiting on the slow facilitator
  assert.ok(slowAnswer, 'the missing facilitator is being asked again');
  assert.equal((await server.buildPaymentRequirements(base))[0].network, BASE, 'Base still builds during the retry');
  slowAnswer();
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(missing(), []);
  assert.equal((await server.buildPaymentRequirements(solana))[0].network, SOLANA);
});

test('nothing loaded: a paid call asks again, and initialize() (the MCP tools) goes through the same path', async () => {
  let up = false;
  let asked = 0;
  const start = createFacilitatorStart([facilitator(async () => { asked++; if (!up) throw new Error('down'); return supported(BASE); })], { log: quiet, retryMs: 60000 });
  const server = new x402ResourceServer(start.clients).register(BASE, new ExactEvmScheme());
  const { ready } = start.attach(server, [BASE]);
  await ready;
  await assert.rejects(server.buildPaymentRequirements(base));
  up = true;
  assert.equal((await server.buildPaymentRequirements(base))[0].network, BASE);
  const before = asked;
  await server.initialize();
  assert.equal(asked, before + 1);
});
