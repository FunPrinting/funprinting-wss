'use strict';

/**
 * Sends WSS server errors and warnings to the web app's error tracking
 * (POST ${WEB_API_URL}/api/errors), signed with WSS_DISPATCH_SECRET using the
 * same x-fp-timestamp / x-fp-signature contract as web → WSS requests.
 *
 * - console.error / console.warn are forwarded (output is unchanged).
 * - Uncaught exceptions are reported, then the process exits (state may be
 *   corrupt; Render restarts it). Unhandled rejections are reported only.
 * - Bounded: the same message is sent at most once per 10 s, 30 reports/min total.
 * - Disabled when WEB_API_URL is unset. Reporting never throws.
 */
const crypto = require('crypto');

const THROTTLE_MS = 10_000;
const MAX_PER_MINUTE = 30;
const TIMEOUT_MS = 5_000;

function createErrorReporter({ webApiUrl, secret, release, fetchImpl = globalThis.fetch, now = () => Date.now() } = {}) {
  const baseUrl = (webApiUrl || '').replace(/\/+$/, '');
  const enabled = Boolean(baseUrl && secret && fetchImpl);
  const lastSent = new Map();
  let windowStart = 0;
  let sentInWindow = 0;

  function allowed(key) {
    const t = now();
    if (t - windowStart > 60_000) {
      windowStart = t;
      sentInWindow = 0;
    }
    const last = lastSent.get(key);
    if (last !== undefined && t - last < THROTTLE_MS) return false;
    if (sentInWindow >= MAX_PER_MINUTE) return false;
    sentInWindow += 1;
    if (lastSent.size > 500) lastSent.clear();
    lastSent.set(key, t);
    return true;
  }

  /** Returns a promise that resolves when the report was sent (or skipped). */
  function report({ level = 'error', name = 'Error', message, stack, context } = {}) {
    if (!enabled || !message) return Promise.resolve(false);
    const key = `${level}|${name}|${String(message).slice(0, 200)}`;
    if (!allowed(key)) return Promise.resolve(false);

    const body = JSON.stringify({
      source: 'wss',
      level,
      name: String(name).slice(0, 200),
      message: String(message).slice(0, 5000),
      stack: stack ? String(stack).slice(0, 20000) : undefined,
      release,
      context,
    });
    const timestamp = String(now());
    const signature = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    return Promise.resolve()
      .then(() =>
        fetchImpl(`${baseUrl}/api/errors`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-fp-timestamp': timestamp, 'x-fp-signature': signature },
          body,
          signal: controller.signal,
        })
      )
      .then((res) => Boolean(res && res.ok))
      .catch(() => false)
      .finally(() => clearTimeout(timer));
  }

  function formatArgs(args) {
    const err = args.find((a) => a instanceof Error);
    const message = args
      .map((a) => {
        if (typeof a === 'string') return a;
        if (a instanceof Error) return a.message;
        try {
          return JSON.stringify(a);
        } catch {
          return String(a);
        }
      })
      .join(' ')
      .trim();
    return { message, name: err ? err.name : undefined, stack: err ? err.stack : undefined };
  }

  /** Hooks console and process events. Call once at startup. */
  function install(proc = process, cons = console) {
    if (!enabled) return false;
    for (const level of ['error', 'warn']) {
      const original = cons[level].bind(cons);
      cons[level] = (...args) => {
        original(...args);
        try {
          const { message, name, stack } = formatArgs(args);
          void report({ level: level === 'error' ? 'error' : 'warning', name: name || (level === 'error' ? 'ConsoleError' : 'ConsoleWarning'), message, stack });
        } catch {
          // never let reporting break logging
        }
      };
    }
    proc.on('unhandledRejection', (reason) => {
      const err = reason instanceof Error ? reason : new Error(String(reason));
      void report({ name: 'UnhandledRejection', message: err.message, stack: err.stack });
    });
    proc.on('uncaughtException', (err) => {
      // Report, then exit: after an uncaught exception the process state is unknown
      const done = report({ name: err && err.name ? err.name : 'UncaughtException', message: err && err.message ? err.message : String(err), stack: err && err.stack });
      Promise.race([done, new Promise((r) => setTimeout(r, 2000))]).finally(() => proc.exit(1));
    });
    return true;
  }

  return { enabled, report, install };
}

module.exports = { createErrorReporter };
