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

function partnerToken(claims = {}) {
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
    jwtSecret: JWT_SECRET,
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

describe('POST /api/dispatch-print-job', () => {
  test('valid signature -> 200 with delivered 0 when nobody online', async () => {
    const res = await post('/api/dispatch-print-job', { partnerId: PARTNER_ID, order: validOrder });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { success: true, delivered: 0 });
  });

  test('computeSignature matches the documented contract', () => {
    const raw = '{"a":1}';
    const { signature } = sign(raw, { timestamp: '1700000000000' });
    assert.equal(computeSignature(DISPATCH_SECRET, '1700000000000', Buffer.from(raw)), signature);
  });

  test('missing signature headers -> 401', async () => {
    const body = { partnerId: PARTNER_ID, order: validOrder };
    assert.equal((await post('/api/dispatch-print-job', body, { signatureHeader: null })).status, 401);
    assert.equal((await post('/api/dispatch-print-job', body, { timestampHeader: null })).status, 401);
  });

  test('bad signature (wrong secret) -> 401', async () => {
    const res = await post(
      '/api/dispatch-print-job',
      { partnerId: PARTNER_ID, order: validOrder },
      { secret: 'wrong-secret' }
    );
    assert.equal(res.status, 401);
  });

  test('signature over a different body -> 401', async () => {
    const { timestamp, signature } = sign({ partnerId: PARTNER_ID, order: validOrder });
    const res = await post(
      '/api/dispatch-print-job',
      { partnerId: PARTNER_ID, order: { ...validOrder, orderId: 'TAMPERED' } },
      { timestampHeader: timestamp, signatureHeader: signature }
    );
    assert.equal(res.status, 401);
  });

  test('stale timestamp (past and future) -> 401', async () => {
    const body = { partnerId: PARTNER_ID, order: validOrder };
    const past = String(Date.now() - 6 * 60 * 1000);
    const future = String(Date.now() + 6 * 60 * 1000);
    assert.equal((await post('/api/dispatch-print-job', body, { timestamp: past })).status, 401);
    assert.equal((await post('/api/dispatch-print-job', body, { timestamp: future })).status, 401);
  });

  test('non-numeric timestamp -> 401', async () => {
    const res = await post(
      '/api/dispatch-print-job',
      { partnerId: PARTNER_ID, order: validOrder },
      { timestamp: 'abc' }
    );
    assert.equal(res.status, 401);
  });

  test('wrong-length signature -> 401, not 500', async () => {
    const body = { partnerId: PARTNER_ID, order: validOrder };
    assert.equal((await post('/api/dispatch-print-job', body, { signatureHeader: 'abc' })).status, 401);
    assert.equal(
      (await post('/api/dispatch-print-job', body, { signatureHeader: 'ff'.repeat(64) })).status,
      401
    );
  });

  test('invalid partnerId -> 400', async () => {
    for (const partnerId of ['', 'not-an-id', 'z'.repeat(24), 123, null]) {
      const res = await post('/api/dispatch-print-job', { partnerId, order: validOrder });
      assert.equal(res.status, 400, `partnerId=${JSON.stringify(partnerId)}`);
    }
  });

  test('missing order / orderId / file URLs -> 400', async () => {
    const cases = [
      { partnerId: PARTNER_ID },
      { partnerId: PARTNER_ID, order: { ...validOrder, orderId: '' } },
      { partnerId: PARTNER_ID, order: { orderId: 'X' } },
    ];
    for (const body of cases) {
      assert.equal((await post('/api/dispatch-print-job', body)).status, 400);
    }
  });

  test('invalid JSON with valid signature -> 400', async () => {
    const res = await post('/api/dispatch-print-job', '{not json');
    assert.equal(res.status, 400);
  });

  test('connected partner receives new_print_job with all files; delivered = 1', async () => {
    const socket = await connect(partnerToken());
    const received = waitFor(socket, 'new_print_job');
    const res = await post('/api/dispatch-print-job', { partnerId: PARTNER_ID, order: validOrder });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { success: true, delivered: 1 });

    const job = await received;
    assert.equal(job.jobId, 'ORD-123');
    assert.equal(job.orderId, 'ORD-123');
    assert.equal(job.documentUrl, validOrder.fileURLs[0]);
    assert.deepEqual(job.documentUrls, validOrder.fileURLs);
    assert.deepEqual(job.fileNames, validOrder.originalFileNames);
    assert.deepEqual(job.options, validOrder.printingOptions);
    assert.equal(typeof job.timestamp, 'number');
    // Field names the partner apps read
    assert.deepEqual(job.fileURLs, validOrder.fileURLs);
    assert.deepEqual(job.originalFileNames, validOrder.originalFileNames);
  });

  test('forwards fileTypes and originalFileName; ignores non-string arrays', async () => {
    const socket = await connect(partnerToken());
    const received = waitFor(socket, 'new_print_job');
    await post('/api/dispatch-print-job', {
      partnerId: PARTNER_ID,
      order: { ...validOrder, orderId: 'ORD-TYPES', fileTypes: ['pdf', 'docx'], originalFileName: 'a.pdf', originalFileNames: [1, 2] },
    });
    const job = await received;
    assert.deepEqual(job.fileTypes, ['pdf', 'docx']);
    assert.equal(job.originalFileName, 'a.pdf');
    assert.equal(job.originalFileNames, undefined);
  });

  test('replaying the exact signed request -> 409, job not emitted twice', async () => {
    const socket = await connect(partnerToken());
    let count = 0;
    socket.on('new_print_job', () => { count += 1; });
    const body = { partnerId: PARTNER_ID, order: { ...validOrder, orderId: 'ORD-REPLAY' } };
    const timestamp = String(Date.now());
    const first = await post('/api/dispatch-print-job', body, { timestamp });
    const replay = await post('/api/dispatch-print-job', body, { timestamp });
    assert.equal(first.status, 200);
    assert.equal(replay.status, 409);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(count, 1);
  });

  test('single fileURL is wrapped into documentUrls', async () => {
    const socket = await connect(partnerToken());
    const received = waitFor(socket, 'new_print_job');
    const order = { orderId: 'ORD-1', fileURL: 'https://files.example.com/x.pdf' };
    await post('/api/dispatch-print-job', { partnerId: PARTNER_ID, order });
    const job = await received;
    assert.equal(job.documentUrl, order.fileURL);
    assert.deepEqual(job.documentUrls, [order.fileURL]);
  });

  test('other partners do not receive the job', async () => {
    const other = await connect(partnerToken({ sub: 'b'.repeat(24), partnerId: 'b'.repeat(24) }));
    const none = expectNoEvent(other, 'new_print_job');
    const res = await post('/api/dispatch-print-job', { partnerId: PARTNER_ID, order: validOrder });
    assert.equal(res.body.delivered, 0);
    await none;
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

describe('POST /api/cancel-print-job', () => {
  test('emits cancel_print_job with jobId', async () => {
    const socket = await connect(partnerToken());
    const received = waitFor(socket, 'cancel_print_job');
    const res = await post('/api/cancel-print-job', { partnerId: PARTNER_ID, orderId: 'ORD-9' });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { success: true, delivered: 1 });
    assert.deepEqual(await received, { jobId: 'ORD-9' });
  });

  test('requires a valid signature', async () => {
    const res = await post(
      '/api/cancel-print-job',
      { partnerId: PARTNER_ID, orderId: 'ORD-9' },
      { signatureHeader: 'deadbeef' }
    );
    assert.equal(res.status, 401);
  });

  test('validates body', async () => {
    assert.equal((await post('/api/cancel-print-job', { partnerId: 'bad', orderId: 'X' })).status, 400);
    assert.equal((await post('/api/cancel-print-job', { partnerId: PARTNER_ID, orderId: '' })).status, 400);
  });
});

describe('socket auth', () => {
  test('rejects missing token', async () => {
    await assert.rejects(connect(undefined), /No token/);
  });

  test('rejects token signed with wrong secret', async () => {
    const bad = jwt.sign({ sub: PARTNER_ID, role: 'partner' }, 'other-secret');
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
