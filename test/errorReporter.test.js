'use strict';

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { createErrorReporter } = require('../src/errorReporter');

const SECRET = 'dispatch-secret';

function fakeFetch() {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return { ok: true };
  };
  fn.calls = calls;
  return fn;
}

describe('errorReporter', () => {
  test('is disabled without WEB_API_URL', async () => {
    const fetchImpl = fakeFetch();
    const r = createErrorReporter({ webApiUrl: '', secret: SECRET, fetchImpl });
    assert.equal(r.enabled, false);
    assert.equal(await r.report({ message: 'x' }), false);
    assert.equal(fetchImpl.calls.length, 0);
  });

  test('signs the exact body with the shared contract', async () => {
    const fetchImpl = fakeFetch();
    const r = createErrorReporter({ webApiUrl: 'https://web.example.com/', secret: SECRET, fetchImpl, release: 'abc' });
    assert.equal(await r.report({ message: 'socket failed', name: 'TypeError', stack: 'stack' }), true);
    const { url, init } = fetchImpl.calls[0];
    assert.equal(url, 'https://web.example.com/api/errors');
    const ts = init.headers['x-fp-timestamp'];
    const expected = crypto.createHmac('sha256', SECRET).update(`${ts}.${init.body}`).digest('hex');
    assert.equal(init.headers['x-fp-signature'], expected);
    assert.deepEqual(JSON.parse(init.body), { source: 'wss', level: 'error', name: 'TypeError', message: 'socket failed', stack: 'stack', release: 'abc' });
  });

  test('throttles repeats of the same message', async () => {
    let t = 1_000_000;
    const fetchImpl = fakeFetch();
    const r = createErrorReporter({ webApiUrl: 'https://w', secret: SECRET, fetchImpl, now: () => t });
    assert.equal(await r.report({ message: 'same' }), true);
    assert.equal(await r.report({ message: 'same' }), false);
    t += 10_001;
    assert.equal(await r.report({ message: 'same' }), true);
    assert.equal(fetchImpl.calls.length, 2);
  });

  test('never throws when the web app is down', async () => {
    const r = createErrorReporter({ webApiUrl: 'https://w', secret: SECRET, fetchImpl: async () => { throw new Error('ECONNREFUSED'); } });
    assert.equal(await r.report({ message: 'x' }), false);
  });

  test('install forwards console.error and keeps printing it', async () => {
    const fetchImpl = fakeFetch();
    const printed = [];
    const cons = { error: (...a) => printed.push(a), warn: (...a) => printed.push(a) };
    const r = createErrorReporter({ webApiUrl: 'https://w', secret: SECRET, fetchImpl });
    assert.equal(r.install(new EventEmitter(), cons), true);
    cons.error('dispatch failed', new Error('boom'));
    cons.warn('slow client');
    await new Promise((res) => setImmediate(res));
    await new Promise((res) => setImmediate(res));
    assert.equal(printed.length, 2);
    const bodies = fetchImpl.calls.map((c) => JSON.parse(c.init.body));
    assert.deepEqual(bodies.map((b) => [b.level, b.message]), [['error', 'dispatch failed boom'], ['warning', 'slow client']]);
  });

  test('uncaught exceptions are reported, then the process exits', async () => {
    const fetchImpl = fakeFetch();
    const proc = new EventEmitter();
    let exitCode;
    const exited = new Promise((resolve) => { proc.exit = (code) => { exitCode = code; resolve(); }; });
    const r = createErrorReporter({ webApiUrl: 'https://w', secret: SECRET, fetchImpl });
    r.install(proc, { error() {}, warn() {} });
    proc.emit('uncaughtException', new RangeError('bad state'));
    await exited;
    assert.equal(exitCode, 1);
    assert.equal(JSON.parse(fetchImpl.calls[0].init.body).name, 'RangeError');
  });
});
