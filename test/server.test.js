'use strict';

const { test, describe, before, after, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { io: ioClient } = require('socket.io-client');
const { createServer, computeSignature } = require('../src/server');

const JWT_SECRET = 'test-jwt-secret';
const DISPATCH_SECRET = 'test-dispatch-secret';
const ALLOWED_ORIGIN = 'https://app.example.com';
const PARTNER_ID = 'a1b2c3d4e5f6a1b2c3d4e5f6';

let server;
let baseUrl;
const clients = [];

function sign(body, { timestamp = String(Date.now()), secret = DISPATCH_SECRET } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const signature = crypto.createHmac('sha256', secret).update(`${timestamp}.${raw}`).digest('hex');
  return { raw, timestamp, signature };
}

async function post(path, body, opts = {}) {
  const { raw, timestamp, signature } = sign(body, opts);
  const headers = { 'content-type': 'application/json' };
  if (opts.timestampHeader !== null) headers['x-fp-timestamp'] = opts.timestampHeader ?? timestamp;
  if (opts.signatureHeader !== null) headers['x-fp-signature'] = opts.signatureHeader ?? signature;
  const res = await fetch(`${baseUrl}${path}`, { method: 'POST', headers, body: raw });
  return { status: res.status, body: await res.json() };
}

const PARTNER_JWT_SECRET = 'p'.repeat(40);
function accessToken(claims = {}, opts = { expiresIn: 900 }) {
  return jwt.sign({ sub: 'u1', partnerId: PARTNER_ID, did: 'dev_abc123', role: 'partner', typ: 'partner_access', ...claims }, PARTNER_JWT_SECRET, opts);
}
function partnerToken(claims = {}) {
  return accessToken(claims);
}
/** A token from before device sign-in: no typ, signed with the old secret. */
function oldToken(claims = {}) {
  return jwt.sign({ sub: PARTNER_ID, partnerId: PARTNER_ID, role: 'partner', ...claims }, JWT_SECRET);
}

function connect(token, extra = {}) {
  const socket = ioClient(baseUrl, {
    auth: { token },
    transports: ['websocket'],
    reconnection: false,
    forceNew: true,
    ...extra,
  });
  clients.push(socket);
  return new Promise((resolve, reject) => {
    socket.once('connect', () => resolve(socket));
    socket.once('connect_error', (err) => reject(err));
  });
}

function waitFor(socket, event, timeoutMs = 1000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for ${event}`)), timeoutMs);
    socket.once(event, (data) => {
      clearTimeout(timer);
      resolve(data);
    });
  });
}

function expectNoEvent(socket, event, ms = 300) {
  return new Promise((resolve, reject) => {
    const handler = () => reject(new Error(`unexpected ${event}`));
    socket.once(event, handler);
    setTimeout(() => {
      socket.off(event, handler);
      resolve();
    }, ms);
  });
}

const validOrder = {
  orderId: 'ORD-123',
  fileURLs: ['https://files.example.com/a.pdf', 'https://files.example.com/b.pdf'],
  originalFileNames: ['a.pdf', 'b.pdf'],
  printingOptions: { copies: 2, color: 'bw' },
};

before(async () => {
  server = createServer({
    partnerJwtSecret: PARTNER_JWT_SECRET,
    dispatchSecret: DISPATCH_SECRET,
    allowedOrigins: [ALLOWED_ORIGIN],
  });
  await new Promise((resolve) => server.httpServer.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.httpServer.address().port}`;
});

afterEach(() => {
  while (clients.length) clients.pop().disconnect();
});

after(async () => {
  server.io.close();
  await new Promise((resolve) => server.httpServer.close(resolve));
});

describe('createServer', () => {
  test('throws without secrets', () => {
    assert.throws(() => createServer({ dispatchSecret: 'x' }));
    assert.throws(() => createServer({ jwtSecret: 'x' }));
  });
});

describe('health', () => {
  test('GET / returns only service/status/uptime/client count', async () => {
    const res = await fetch(`${baseUrl}/`);
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(body).sort(), ['connectedClients', 'service', 'status', 'uptime']);
  });
});

describe('signed requests', () => {
  const body = { partnerId: PARTNER_ID, reason: 'new' };
  test('valid signature -> 200 with delivered 0 when nobody online', async () => {
    const res = await post('/api/notify-jobs', body);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { success: true, delivered: 0 });
  });
  test('computeSignature matches the documented contract', () => {
    const expected = crypto.createHmac('sha256', DISPATCH_SECRET).update('123.{"a":1}').digest('hex');
    assert.equal(computeSignature(DISPATCH_SECRET, '123', '{"a":1}'), expected);
  });
  test('missing signature headers -> 401', async () => {
    assert.equal((await post('/api/notify-jobs', body, { signatureHeader: null })).status, 401);
    assert.equal((await post('/api/notify-jobs', body, { timestampHeader: null })).status, 401);
  });
  test('bad signature (wrong secret) -> 401', async () => {
    assert.equal((await post('/api/notify-jobs', body, { secret: 'other-secret' })).status, 401);
  });
  test('stale timestamp (past and future) -> 401', async () => {
    const past = String(Date.now() - 10 * 60 * 1000);
    const future = String(Date.now() + 10 * 60 * 1000);
    assert.equal((await post('/api/notify-jobs', body, { timestamp: past })).status, 401);
    assert.equal((await post('/api/notify-jobs', body, { timestamp: future })).status, 401);
  });
  test('non-numeric timestamp -> 401', async () => {
    assert.equal((await post('/api/notify-jobs', body, { timestampHeader: 'abc' })).status, 401);
  });
  test('wrong-length signature -> 401, not 500', async () => {
    assert.equal((await post('/api/notify-jobs', body, { signatureHeader: 'abc' })).status, 401);
    assert.equal((await post('/api/notify-jobs', body, { signatureHeader: 'ff'.repeat(64) })).status, 401);
  });
  test('invalid JSON with valid signature -> 400', async () => {
    assert.equal((await post('/api/notify-jobs', '{not json')).status, 400);
  });
  test('replaying the exact signed request -> 409, notified once', async () => {
    const socket = await connect(partnerToken());
    let count = 0;
    socket.on('jobs:available', () => { count += 1; });
    const timestamp = String(Date.now());
    const first = await post('/api/notify-jobs', body, { timestamp });
    const replay = await post('/api/notify-jobs', body, { timestamp });
    assert.equal(first.status, 200);
    assert.equal(replay.status, 409);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(count, 1);
  });
  test('removed endpoints are gone', async () => {
    for (const path of ['/api/dispatch-print-job', '/api/cancel-print-job']) {
      const res = await fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      assert.equal(res.status, 404);
    }
  });
});

describe('POST /api/notify-jobs', () => {
  test('emits jobs:available to the partner room only', async () => {
    const socket = await connect(partnerToken());
    const received = waitFor(socket, 'jobs:available');
    const res = await post('/api/notify-jobs', { partnerId: PARTNER_ID, reason: 'new' });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { success: true, delivered: 1 });
    const msg = await received;
    assert.equal(msg.reason, 'new');
    assert.equal(typeof msg.at, 'number');
  });

  test('unknown reason becomes updated; signature and partnerId are required', async () => {
    const socket = await connect(partnerToken());
    const received = waitFor(socket, 'jobs:available');
    await post('/api/notify-jobs', { partnerId: PARTNER_ID, reason: '<script>' });
    assert.equal((await received).reason, 'updated');
    assert.equal((await post('/api/notify-jobs', { partnerId: PARTNER_ID }, { signatureHeader: 'bad' })).status, 401);
    assert.equal((await post('/api/notify-jobs', { partnerId: 'nope' })).status, 400);
  });
});

describe('device sign-in tokens', () => {
  test('access token with the partner secret connects and joins the partner room', async () => {
    const socket = await connect(accessToken());
    const received = waitFor(socket, 'jobs:available');
    await post('/api/notify-jobs', { partnerId: PARTNER_ID, reason: 'new' });
    assert.equal((await received).reason, 'new');
  });

  test('a token from before device sign-in is told to update', async () => {
    await assert.rejects(connect(oldToken()), /upgrade_required/);
  });
  test('access token signed with the legacy secret, or without a device id, is rejected', async () => {
    const forged = jwt.sign({ sub: 'u1', partnerId: PARTNER_ID, did: 'dev_x', role: 'partner', typ: 'partner_access' }, JWT_SECRET);
    await assert.rejects(connect(forged), /Invalid token/);
    await assert.rejects(connect(accessToken({ did: undefined })), /Invalid token/);
  });

  test('disconnect-device signs out only that device', async () => {
    const target = await connect(accessToken());
    const other = await connect(accessToken({ did: 'dev_other1' }));
    const signedOut = waitFor(target, 'signed_out');
    const res = await post('/api/disconnect-device', { partnerId: PARTNER_ID, deviceId: 'dev_abc123' });
    assert.deepEqual(res.body, { success: true, delivered: 1 });
    assert.equal((await signedOut).reason, 'device_revoked');
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(target.connected, false);
    assert.equal(other.connected, true);
  });

  test('socket closes when the access token expires', async () => {
    const socket = await connect(accessToken({}, { expiresIn: 1 }));
    await new Promise((r) => socket.once('disconnect', r));
    assert.equal(socket.connected, false);
  });
});

describe('socket auth', () => {
  test('rejects missing token', async () => {
    await assert.rejects(connect(undefined), /No token/);
  });

  test('rejects token signed with wrong secret', async () => {
    const bad = jwt.sign({ sub: PARTNER_ID, partnerId: PARTNER_ID, did: 'dev_abc123', role: 'partner', typ: 'partner_access' }, 'other-secret');
    await assert.rejects(connect(bad), /Invalid token/);
  });

  test('rejects garbage token', async () => {
    await assert.rejects(connect('not.a.jwt'), /Invalid token/);
  });

  test('rejects wrong role', async () => {
    await assert.rejects(connect(partnerToken({ role: 'user' })), /Invalid role/);
  });

  test('rejects token without a 24-hex partner id', async () => {
    await assert.rejects(connect(partnerToken({ sub: 'abc', partnerId: undefined })), /Invalid partner id/);
    await assert.rejects(connect(partnerToken({ sub: undefined, partnerId: undefined })), /Invalid partner id/);
  });

  test('admin role with valid id is accepted', async () => {
    const socket = await connect(partnerToken({ role: 'admin' }));
    assert.ok(socket.connected);
  });
});

describe('remote_control', () => {
  test('forwards pause/resume to other sockets in the room', async () => {
    const pc = await connect(partnerToken());
    const mobile = await connect(partnerToken());
    const received = waitFor(pc, 'remote_control_action');
    mobile.emit('remote_control', { action: 'pause', extra: 'dropped' });
    assert.deepEqual(await received, { action: 'pause' });
  });

  test('does not forward invalid actions', async () => {
    const pc = await connect(partnerToken());
    const mobile = await connect(partnerToken());
    const none = expectNoEvent(pc, 'remote_control_action');
    mobile.emit('remote_control', { action: 'shutdown' });
    mobile.emit('remote_control', null);
    mobile.emit('remote_control', 'pause');
    await none;
  });
});

describe('CORS', () => {
  test('allowed origin gets CORS header; disallowed does not', async () => {
    const ok = await fetch(`${baseUrl}/health`, { headers: { origin: ALLOWED_ORIGIN } });
    assert.equal(ok.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN);
    const bad = await fetch(`${baseUrl}/health`, { headers: { origin: 'https://evil.example.com' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });

  test('socket from disallowed origin is rejected; allowed origin connects', async () => {
    await assert.rejects(
      connect(partnerToken(), { extraHeaders: { origin: 'https://evil.example.com' } })
    );
    const socket = await connect(partnerToken(), { extraHeaders: { origin: ALLOWED_ORIGIN } });
    assert.ok(socket.connected);
  });
});
