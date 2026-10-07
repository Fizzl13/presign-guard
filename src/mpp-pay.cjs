// MPP (Machine Payments Protocol, Stripe + Tempo) next to x402 on the paid routes, so
// agents that speak MPP can pay the Doctor too. The `evm` charge method: the agent signs
// the same EIP-3009 USDC transfer on Base as for x402, so the same facilitator (CDP)
// verifies and settles it. Compatible with mppx (wevm/mppx) clients.
//
// - A 402 gets `WWW-Authenticate: Payment id=…, realm=…, method="evm", intent="charge",
//   request=…, expires=…, opaque=…` next to the x402 PAYMENT-REQUIRED header.
// - The agent answers with `Authorization: Payment <base64url credential>`. The challenge
//   id is an HMAC over the challenge (and the route, in opaque), so no state is needed;
//   the authorization nonce must be keccak256(JSON.stringify([id, realm])).
// - Like x402: verified first, settled only after a 2xx answer (a failed diagnosis is
//   never charged), then `Payment-Receipt` on the response.
//
// And, with `tempo`, the `tempo` charge method in "push" mode, the one nearly every MPP agent
// pays with: the agent sends USDC on Tempo itself (a TIP-20 transferWithMemo whose memo binds
// the realm and challenge id) and answers with the transaction hash. We read the receipt from
// a Tempo RPC, so no facilitator. The payment is final before the answer; a failed answer
// frees the hash, so the same credential can be sent again while the challenge lasts.
const crypto = require('crypto');
const { keccak256, stringToHex, getAddress } = require('viem');

const METHOD = 'evm';
const TEMPO = 'tempo';
const INTENT = 'charge';
const BASE_CHAIN_ID = 8453;
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const USDC_EIP712 = { name: 'USD Coin', version: '2' };
const EXPIRES_SECONDS = 300;
// Tempo mainnet pays in USDC.e (the mppx default), the Moderato testnet in pathUSD. Both 6 decimals.
const TEMPO_CHAINS = {
  4217: { name: 'Tempo', currency: getAddress('0x20c000000000000000000000b9537d11c60e8b50'), rpc: 'https://rpc.tempo.xyz' },
  42431: { name: 'Tempo Moderato', currency: getAddress('0x20c0000000000000000000000000000000000000'), rpc: 'https://rpc.moderato.tempo.xyz' },
};
const TRANSFER_WITH_MEMO = keccak256(stringToHex('TransferWithMemo(address,address,uint256,bytes32)'));

// The 32-byte MPP memo (mppx Attribution): keccak256("mpp")[0:4], version 1,
// keccak256(realm)[0:10], client fingerprint [10 bytes], keccak256(challenge id)[0:7].
const MEMO_TAG = keccak256(stringToHex('mpp')).slice(0, 10);
const fingerprint = (value, bytes) => keccak256(stringToHex(String(value))).slice(2, 2 + bytes * 2);
function memoBinds(memo, realm, challengeId) {
  const m = String(memo).toLowerCase();
  return m.length === 66 && m.slice(0, 10) === MEMO_TAG && m.slice(10, 12) === '01'
    && m.slice(12, 32) === fingerprint(realm, 10) && m.slice(52) === fingerprint(challengeId, 7);
}
const topicAddress = (topic) => getAddress(`0x${String(topic).slice(-40)}`);

async function rpcReceipt(rpc, hash) {
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [hash] }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Tempo RPC answered ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`Tempo RPC: ${body.error.message || 'error'}`);
  return body.result;
}

const b64u = (s) => Buffer.from(s).toString('base64url');
const fromB64u = (s) => Buffer.from(String(s), 'base64url').toString('utf8');

// RFC 8785-style canonical JSON (sorted keys), as mppx serializes the request.
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

// "$0.01" -> "10000" (USDC has 6 decimals).
function atomicUsdc(price) {
  const m = /^\$?(\d+)(?:\.(\d{1,6}))?$/.exec(String(price).trim());
  if (!m) throw new Error(`MPP: can't read price ${price}`);
  return String(BigInt(m[1]) * 1000000n + BigInt((m[2] || '').padEnd(6, '0') || '0'));
}

const quote = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

class PaymentError extends Error {}

// facilitator: { verify(paymentPayload, requirements), settle(paymentPayload, requirements) } (x402 v2),
// for the evm method. tempo: { recipient, chainId = 4217, currency, rpc, getReceipt(hash) } turns
// on the tempo method (getReceipt replaces the RPC call, for tests).
function createMppPay({ secret, realm, recipient, routes, facilitator, tempo = null, now = () => Date.now(), log = console }) {
  if (!secret) throw new Error('MPP needs a secret');
  const payTo = recipient ? getAddress(recipient) : null;
  if (facilitator && !payTo) throw new Error('MPP evm needs a recipient');
  let tempoCfg = null;
  if (tempo) {
    const chainId = Number(tempo.chainId || 4217);
    const known = TEMPO_CHAINS[chainId] || {};
    const rpc = tempo.rpc || known.rpc;
    tempoCfg = {
      chainId,
      name: known.name || `Tempo ${chainId}`,
      recipient: getAddress(tempo.recipient),
      currency: getAddress(tempo.currency || known.currency),
      getReceipt: tempo.getReceipt || ((hash) => rpcReceipt(rpc, hash)),
    };
  }
  // "GET /signal/:pair" -> the route key and its price; a request matches by method and path.
  const prices = new Map(Object.entries(routes).map(([route, price]) => [route, atomicUsdc(price)]));
  const patterns = [...prices.keys()].map((route) => {
    const [method, path] = route.split(' ');
    const re = new RegExp(`^${path.split('/').map((part) => (part.startsWith(':') ? '[^/]+' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('/')}/?$`);
    return { route, method, re };
  });
  const routeOf = (req) => {
    const path = `${req.baseUrl || ''}${req.path}`;
    const hit = patterns.find((p) => p.method === req.method && p.re.test(path));
    return hit ? hit.route : null;
  };
  const inFlight = new Set(); // nonces being served, so one signature can't buy two answers at once
  const usedHashes = new Map(); // Tempo tx hash -> until when it stays claimed (its challenge has expired by then)

  const requestFor = {
    [METHOD]: facilitator ? (amount) => ({
      amount,
      currency: BASE_USDC,
      methodDetails: { chainId: BASE_CHAIN_ID, credentialTypes: ['authorization'], decimals: 6 },
      recipient: payTo,
    }) : null,
    // Push only: the agent broadcasts and sends the hash, so nothing is signed for us to submit.
    [TEMPO]: tempoCfg ? (amount) => ({
      amount,
      currency: tempoCfg.currency,
      methodDetails: { chainId: tempoCfg.chainId, supportedModes: ['push'] },
      recipient: tempoCfg.recipient,
    }) : null,
  };
  const methods = Object.keys(requestFor).filter((m) => requestFor[m]);
  if (!methods.length) throw new Error('MPP needs a facilitator (evm) or tempo');
  const idOf = (c) => crypto.createHmac('sha256', secret)
    .update([c.realm, c.method, c.intent, b64u(canonical(c.request)), c.expires || '', c.digest || '', c.opaque || ''].join('|'))
    .digest('base64url');

  function challengeFor(route, method = methods[0]) {
    const c = {
      realm,
      method,
      intent: INTENT,
      request: requestFor[method](prices.get(route)),
      expires: new Date(now() + EXPIRES_SECONDS * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      opaque: b64u(canonical({ route })),
    };
    c.id = idOf(c);
    return c;
  }
  const header = (c) => `Payment ${[
    `id=${quote(c.id)}`, `realm=${quote(c.realm)}`, `method=${quote(c.method)}`, `intent=${quote(c.intent)}`,
    `request=${quote(b64u(canonical(c.request)))}`, `expires=${quote(c.expires)}`, `opaque=${quote(c.opaque)}`,
  ].join(', ')}`;
  // One challenge per method, each its own WWW-Authenticate line.
  const headersFor = (route) => methods.map((m) => header(challengeFor(route, m)));

  const requirementsFor = (request) => ({
    scheme: 'exact',
    network: `eip155:${request.methodDetails.chainId}`,
    amount: request.amount,
    asset: request.currency,
    payTo: request.recipient,
    maxTimeoutSeconds: EXPIRES_SECONDS,
    extra: { ...USDC_EIP712, assetTransferMethod: 'eip3009' },
  });

  // The credential from the Authorization header, checked against what this route asks. Throws PaymentError.
  function readCredential(value, route) {
    const m = /(?:^|,)\s*Payment\s+([A-Za-z0-9_-]+)\s*(?:,|$)/i.exec(value);
    if (!m) throw new PaymentError('No Payment credential in the Authorization header.');
    let cred;
    try { cred = JSON.parse(fromB64u(m[1])); } catch { throw new PaymentError("The Payment credential isn't base64url JSON."); }
    const c = cred && cred.challenge, p = cred && cred.payload;
    if (!c || !p || typeof c !== 'object' || typeof p !== 'object') throw new PaymentError('The credential needs a challenge and a payload.');
    let request;
    try { request = typeof c.request === 'string' ? JSON.parse(fromB64u(c.request)) : c.request; } catch { throw new PaymentError("The challenge request can't be read."); }
    const echoed = { realm: c.realm, method: c.method, intent: c.intent, request, expires: c.expires, digest: c.digest, opaque: c.opaque };
    const want = Buffer.from(idOf(echoed)), got = Buffer.from(String(c.id || ''));
    if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) throw new PaymentError("That challenge wasn't issued here (id doesn't match). Ask again for a fresh 402.");
    // Several services may share one MPP_SECRET: a challenge only pays the service (realm) that issued it.
    if (c.realm !== realm) throw new PaymentError('That challenge is for another service.');
    let bound;
    try { bound = JSON.parse(fromB64u(c.opaque)).route; } catch { bound = null; }
    if (bound !== route) throw new PaymentError('That challenge is for another route.');
    if (!methods.includes(c.method) || c.intent !== INTENT) throw new PaymentError(`Only intent "charge" with method ${methods.map((m) => `"${m}"`).join(' or ')} is accepted here.`);
    if (canonical(request) !== canonical(requestFor[c.method](prices.get(route)))) throw new PaymentError('The price changed. Ask again for a fresh 402.');
    if (!(Date.parse(c.expires) > now())) throw new PaymentError('That challenge has expired. Ask again for a fresh 402.');
    if (c.method === TEMPO) {
      if (p.type !== 'hash') throw new PaymentError('Only a "hash" credential (push mode) is accepted for tempo: send the transfer yourself, then the transaction hash.');
      if (!/^0x[0-9a-fA-F]{64}$/.test(String(p.hash || ''))) throw new PaymentError('The hash must be a 32-byte transaction hash.');
      let source = null;
      if (cred.source !== undefined) {
        const s = /^did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40})$/.exec(String(cred.source));
        if (!s || Number(s[1]) !== tempoCfg.chainId) throw new PaymentError(`source must be did:pkh:eip155:${tempoCfg.chainId}:<your address>.`);
        source = getAddress(s[2]);
      }
      return { method: TEMPO, hash: p.hash.toLowerCase(), source, amount: request.amount, challengeId: c.id, until: Date.parse(c.expires) + 60000 };
    }
    if (p.type !== 'authorization') throw new PaymentError('Only an "authorization" (EIP-3009) credential is accepted.');
    let from, to;
    try { from = getAddress(p.from); to = getAddress(p.to); } catch { throw new PaymentError('from and to must be addresses.'); }
    if (to !== payTo) throw new PaymentError('The authorization pays someone else.');
    if (String(p.value) !== request.amount) throw new PaymentError('The authorization is for another amount.');
    if (p.nonce !== keccak256(stringToHex(JSON.stringify([c.id, c.realm])))) throw new PaymentError('The authorization nonce must be keccak256(JSON.stringify([id, realm])).');
    if (!/^0x[0-9a-fA-F]+$/.test(String(p.signature || ''))) throw new PaymentError('The authorization has no signature.');
    if (!/^\d+$/.test(String(p.validAfter)) || !/^\d+$/.test(String(p.validBefore))) throw new PaymentError('validAfter and validBefore must be integers.');
    const paymentPayload = {
      x402Version: 2,
      accepted: requirementsFor(request),
      payload: { authorization: { from, to, value: String(p.value), validAfter: String(p.validAfter), validBefore: String(p.validBefore), nonce: p.nonce }, signature: p.signature },
    };
    return { method: METHOD, paymentPayload, requirements: paymentPayload.accepted, from, nonce: p.nonce, amount: request.amount };
  }

  // The Tempo transaction must hold a TransferWithMemo of the asked currency and amount, to our
  // recipient, from the payer, with the MPP memo for this realm and challenge. Throws PaymentError.
  async function checkTempo(paid) {
    const receipt = await tempoCfg.getReceipt(paid.hash);
    if (!receipt) throw new PaymentError(`That transaction isn't on ${tempoCfg.name} (yet). Send the same credential again in a moment.`);
    if (receipt.status !== '0x1' && receipt.status !== 'success') throw new PaymentError('That transaction failed on Tempo.');
    const payer = paid.source || getAddress(receipt.from);
    const hit = (receipt.logs || []).find((l) => {
      const t = l.topics || [];
      if (String(t[0]).toLowerCase() !== TRANSFER_WITH_MEMO || t.length !== 4) return false;
      if (String(l.address).toLowerCase() !== tempoCfg.currency.toLowerCase()) return false;
      try {
        return topicAddress(t[1]) === payer && topicAddress(t[2]) === tempoCfg.recipient
          && BigInt(l.data).toString() === paid.amount && memoBinds(t[3], realm, paid.challengeId);
      } catch { return false; }
    });
    if (!hit) throw new PaymentError(`No transfer in that transaction pays ${paid.amount} units of ${tempoCfg.currency} from ${payer} to ${tempoCfg.recipient} with the MPP memo for this challenge.`);
    return payer;
  }

  // Serves a request paid on Tempo: the hash is claimed first, freed again if the answer fails.
  function serveTempo(req, res, next, route, paid) {
    const t = now();
    for (const [hash, until] of usedHashes) if (until < t) usedHashes.delete(hash);
    if (usedHashes.has(paid.hash)) return refuse(req, res, route, 'That transaction has already paid for an answer.');
    usedHashes.set(paid.hash, paid.until);
    const free = () => usedHashes.delete(paid.hash);
    Promise.resolve().then(() => checkTempo(paid)).then((payer) => {
      req.mppPaid = { payer, amount: paid.amount };
      const send = res.send, end = res.end;
      const restore = () => { res.send = send; res.end = end; };
      res.end = function (...args) {
        restore();
        if (res.headersSent) return end.apply(this, args);
        free();
        log.warn(`MPP: ${route} answered without res.send; refused`);
        return refuse(req, res, route, 'This answer could not be served over MPP. Your payment stays valid: send the same credential again.');
      };
      res.send = function (body) {
        restore();
        if (res.statusCode < 200 || res.statusCode >= 300) { free(); return send.call(this, body); }
        res.set('Payment-Receipt', b64u(JSON.stringify({ method: TEMPO, reference: paid.hash, status: 'success', timestamp: new Date(now()).toISOString() })));
        res.locals.mppPayment = { usd: Number(paid.amount) / 1e6, network: tempoCfg.name, payer, tx: paid.hash, protocol: 'mpp' };
        return send.call(this, body);
      };
      next();
    }, (err) => {
      free();
      if (err instanceof PaymentError) return refuse(req, res, route, err.message);
      log.warn(`MPP tempo check failed on ${route}: ${err.message}`);
      refuse(req, res, route, 'The Tempo payment could not be checked right now. Send the same credential again in a moment.');
    });
  }

  function refuse(req, res, route, reason) {
    res.locals.mppRefused = String(reason).slice(0, 160); // for the usage log: why the credential was refused
    res.status(402);
    res.set('WWW-Authenticate', headersFor(route));
    res.set('Cache-Control', 'no-store');
    res.type('application/problem+json').send(JSON.stringify({ type: 'https://paymentauth.org/problems/verification-failed', title: 'Payment failed', status: 402, detail: reason }));
  }

  // Before the x402 paywall: pays the request over MPP (req.mppPaid) or adds the MPP challenge to the 402.
  function middleware(req, res, next) {
    const route = routeOf(req);
    if (!route) return next();
    const auth = req.headers.authorization;
    if (!auth || !/(?:^|,)\s*Payment\s/i.test(auth)) {
      // No MPP credential: let x402 answer, and put the MPP challenge on its 402.
      const writeHead = res.writeHead;
      res.writeHead = function (...args) {
        if (res.statusCode === 402 && !res.getHeader('WWW-Authenticate')) res.setHeader('WWW-Authenticate', headersFor(route));
        return writeHead.apply(this, args);
      };
      return next();
    }
    let paid;
    try { paid = readCredential(auth, route); } catch (err) {
      if (err instanceof PaymentError) return refuse(req, res, route, err.message);
      return next(err);
    }
    if (paid.method === TEMPO) return serveTempo(req, res, next, route, paid);
    if (inFlight.has(paid.nonce)) return refuse(req, res, route, 'This authorization is already being used.');
    inFlight.add(paid.nonce);
    const done = () => inFlight.delete(paid.nonce);
    Promise.resolve(facilitator.verify(paid.paymentPayload, paid.requirements)).then((v) => {
      if (!v || !v.isValid) { done(); return refuse(req, res, route, `Payment not accepted: ${(v && (v.invalidMessage || v.invalidReason)) || 'invalid'}.`); }
      req.mppPaid = { payer: paid.from, amount: paid.amount };
      // Settle only after a 2xx answer, before it is sent. res.json and res.render end in
      // res.send; anything that bypasses it (res.end, streams) is refused, never served unpaid.
      const send = res.send, end = res.end;
      const restore = () => { res.send = send; res.end = end; };
      res.end = function (...args) {
        restore(); done();
        if (res.headersSent) return end.apply(this, args);
        log.warn(`MPP: ${route} answered without res.send; refused`);
        return refuse(req, res, route, 'This answer could not be paid over MPP. Nothing was charged.');
      };
      res.send = function (body) {
        restore();
        if (res.statusCode < 200 || res.statusCode >= 300) { done(); return send.call(this, body); }
        Promise.resolve(facilitator.settle(paid.paymentPayload, paid.requirements)).then((s) => {
          done();
          if (!s || !s.success) return refuse(req, res, route, `Settlement failed: ${(s && (s.errorMessage || s.errorReason)) || 'unknown'}.`);
          const timestamp = new Date(now()).toISOString();
          res.set('Payment-Receipt', b64u(JSON.stringify({ method: METHOD, reference: s.transaction, status: 'success', timestamp })));
          res.locals.mppPayment = { usd: Number(paid.amount) / 1e6, network: 'Base', payer: s.payer || paid.from, tx: s.transaction || null, protocol: 'mpp' };
          send.call(res, body);
        }, (err) => { done(); log.warn(`MPP settle failed on ${route}: ${err.message}`); refuse(req, res, route, 'Settlement failed. Nothing was charged.'); });
        return res;
      };
      next();
    }, (err) => { done(); log.warn(`MPP verify failed on ${route}: ${err.message}`); refuse(req, res, route, 'The payment could not be checked right now. Try again.'); });
  }

  return { middleware, challengeFor, header, readCredential, methods, tempo: tempoCfg && { chainId: tempoCfg.chainId, network: tempoCfg.name, currency: tempoCfg.currency, recipient: tempoCfg.recipient } };
}

// MPP discovery (paymentauth.org draft-payment-discovery, read by MPPScan): adds the evm offer to
// every operation whose x-payment-info has a fixed USD price, next to the x402 fields, and the
// service metadata at the root. Changes and returns spec.
// include(path, method) limits it to the operations MPP really sells. protocols is written as
// objects ([{x402:{}}, {mpp:{…}}]) as @agentcash/discovery (MPPScan, x402scan) reads it: next to a
// price object, plain strings make it drop the payment info.
// tempo: { currency } adds the tempo offer too; evm: false leaves the evm offer out.
function addMppOffers(spec, { categories = [], docs = {}, contact = null, include = () => true, evm = true, tempo = null } = {}) {
  spec['x-service-info'] = { categories, docs };
  if (contact && spec.info && !spec.info.contact) spec.info.contact = contact;
  for (const [path, methods] of Object.entries(spec.paths || {})) {
    for (const [method, op] of Object.entries(methods)) {
      if (!include(path, method.toUpperCase())) continue;
      const info = op && op['x-payment-info'];
      if (!info || !info.price || info.price.mode !== 'fixed' || info.price.amount === undefined) continue;
      const offered = [...(evm ? [[METHOD, BASE_USDC]] : []), ...(tempo ? [[TEMPO, tempo.currency]] : [])];
      info.offers = offered.map(([method, currency]) => ({ amount: atomicUsdc(info.price.amount), currency, description: op.summary || op.description || '', intent: INTENT, method }));
      info.protocols = [{ x402: {} }, ...offered.map(([method, currency]) => ({ mpp: { method, intent: INTENT, currency } }))];
    }
  }
  return spec;
}

// Skips the x402 paywall for a request already paid over MPP.
const unlessMppPaid = (paywall) => (req, res, next) => (req.mppPaid ? next() : paywall(req, res, next));

module.exports = { createMppPay, unlessMppPaid, addMppOffers, atomicUsdc, canonical, memoBinds, BASE_USDC, TEMPO_CHAINS };
