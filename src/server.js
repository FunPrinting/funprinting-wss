'use strict';

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;
const TIMESTAMP_RE = /^\d{1,16}$/;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const ALLOWED_REMOTE_ACTIONS = new Set(['pause', 'resume']);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Origin check shared by Express CORS and Socket.IO.
 * Requests without an Origin header (Electron, mobile, server-to-server) are allowed.
 */
function makeOriginChecker(allowedOrigins) {
  const allowed = new Set(allowedOrigins);
  return (origin) => !origin || allowed.has(origin);
}

/**
 * Computes the expected signature: lowercase hex HMAC-SHA256(secret, `${timestamp}.${rawBody}`).
 */
function computeSignature(secret, timestamp, rawBody) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest('hex');
}

function safeEqual(a, b) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Express middleware: verifies x-fp-timestamp / x-fp-signature against the raw body,
 * then parses the body as JSON into req.body.
 */
function makeSignatureVerifier(secret, now = () => Date.now()) {
  // Signatures accepted in the last skew window. A captured request replayed within
  // the window is rejected, so one payment can't be printed twice by replaying it.
  const seen = new Map(); // signature -> expiry (ms)
  const remember = (signature) => {
    const t = now();
    for (const [sig, expiry] of seen) {
      if (expiry > t) break; // insertion order = expiry order
      seen.delete(sig);
    }
    seen.set(signature, t + 2 * MAX_CLOCK_SKEW_MS);
  };

  return (req, res, next) => {
    const timestamp = req.get('x-fp-timestamp');
    const signature = req.get('x-fp-signature');

    if (!timestamp || !signature) {
      return res.status(401).json({ error: 'Missing signature headers' });
    }
    if (!TIMESTAMP_RE.test(timestamp)) {
      return res.status(401).json({ error: 'Invalid timestamp' });
    }
    if (Math.abs(now() - Number(timestamp)) > MAX_CLOCK_SKEW_MS) {
      return res.status(401).json({ error: 'Stale timestamp' });
    }

    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const expected = computeSignature(secret, timestamp, rawBody);
    if (!safeEqual(signature, expected)) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    if (seen.has(signature)) {
      return res.status(409).json({ error: 'Replayed request' });
    }
    remember(signature);

    req.rawBody = rawBody;
    try {
      req.body = rawBody.length ? JSON.parse(rawBody.toString('utf8')) : {};
    } catch {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Body must be a JSON object' });
    }
    next();
  };
}

function createServer({ dispatchSecret, partnerJwtSecret, allowedOrigins = [] } = {}) {
  if (!partnerJwtSecret) throw new Error('createServer: partnerJwtSecret is required');
  if (!dispatchSecret) throw new Error('createServer: dispatchSecret is required');

  const isOriginAllowed = makeOriginChecker(allowedOrigins);
  const startedAt = Date.now();

  const app = express();
  app.disable('x-powered-by');
  app.use(
    cors({
      origin: (origin, cb) => cb(null, isOriginAllowed(origin)),
      methods: ['GET', 'POST'],
    })
  );

  const httpServer = http.createServer(app);

  const io = new Server(httpServer, {
    cors: {
      origin: (origin, cb) => cb(null, isOriginAllowed(origin)),
      methods: ['GET', 'POST'],
    },
    // Reject disallowed browser origins at the handshake (CORS alone doesn't stop WebSocket upgrades).
    allowRequest: (req, cb) => cb(null, isOriginAllowed(req.headers.origin)),
    pingTimeout: 60000,
    pingInterval: 25000,
    maxHttpBufferSize: 1e6,
  });

  app.get('/', (req, res) => {
    res.json({
      service: 'FunPrinting WebSocket Cloud Engine',
      status: 'running',
      connectedClients: io.engine.clientsCount,
      uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
    });
  });

  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // WebSocket auth
  io.use((socket, next) => {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token || typeof token !== 'string') {
      return next(new Error('Authentication error: No token provided'));
    }

    // Only device sign-in access tokens (typ partner_access, 15 min, PARTNER_JWT_SECRET)
    // connect. Apps from before device sign-in must update and sign in again.
    let claims;
    try {
      claims = jwt.decode(token);
    } catch {
      claims = null;
    }
    if (!claims || typeof claims !== 'object') return next(new Error('Authentication error: Invalid token'));
    // A readable token without the access type is from an app that predates device sign-in
    if (claims.typ !== 'partner_access') return next(new Error('Authentication error: upgrade_required'));

    let decoded;
    try {
      decoded = jwt.verify(token, partnerJwtSecret, { algorithms: ['HS256'] });
    } catch {
      return next(new Error('Authentication error: Invalid token'));
    }
    if ((typeof decoded.did !== 'string' || !decoded.did)) {
      return next(new Error('Authentication error: Invalid token'));
    }

    if (!decoded || (decoded.role !== 'partner' && decoded.role !== 'admin')) {
      return next(new Error('Authentication error: Invalid role'));
    }

    const partnerId = decoded.partnerId || decoded.sub;
    if (typeof partnerId !== 'string' || !OBJECT_ID_RE.test(partnerId)) {
      return next(new Error('Authentication error: Invalid partner id'));
    }

    socket.partnerId = partnerId;
    socket.deviceId = decoded.did;
    // socket.data survives fetchSockets() with any adapter (plain properties only
    // survive with the in-memory adapter)
    socket.data.partnerId = partnerId;
    socket.data.deviceId = socket.deviceId;
    // An access token expires after 15 minutes; drop the socket then, so a revoked
    // device can't stay connected. The app reconnects with a refreshed token.
    if (typeof decoded.exp === 'number') {
      socket.tokenExpiresAt = decoded.exp * 1000;
    }
    next();
  });

  io.on('connection', (socket) => {
    const room = `partner_${socket.partnerId}`;
    console.log(`🟢 Partner connected: ${socket.partnerId} (Socket ID: ${socket.id})`);
    socket.join(room);
    if (socket.deviceId) socket.join(`device_${socket.deviceId}`);
    if (socket.tokenExpiresAt) {
      const ms = Math.max(0, socket.tokenExpiresAt - Date.now());
      const timer = setTimeout(() => socket.disconnect(true), Math.min(ms, 2 ** 31 - 1));
      socket.on('disconnect', () => clearTimeout(timer));
    }

    socket.on('hardware_status_update', () => {
      console.log(`🖨️ Hardware update from ${socket.partnerId}`);
    });

    socket.on('print_job_ack', (data) => {
      const jobId = data && typeof data.jobId === 'string' ? data.jobId : '(unknown)';
      console.log(`✅ Job ${jobId} ACKed by ${socket.partnerId}`);
    });

    // Remote control forwarding (mobile app -> PC app). Only pause/resume are allowed.
    socket.on('remote_control', (data) => {
      const action = data && data.action;
      if (!ALLOWED_REMOTE_ACTIONS.has(action)) {
        console.warn(`⚠️ Ignored remote_control with invalid action from ${socket.partnerId}`);
        return;
      }
      console.log(`📱 Remote control action '${action}' from ${socket.partnerId}`);
      socket.to(room).emit('remote_control_action', { action });
    });

    socket.on('disconnect', () => {
      console.log(`🔴 Partner disconnected: ${socket.partnerId}`);
    });
  });

  const signedJson = [
    express.raw({ type: () => true, limit: '1mb' }),
    makeSignatureVerifier(dispatchSecret),
  ];

  // Job list changed for a partner: devices re-fetch /api/partner/v1/jobs.
  // Carries no job data; the API is the source of truth.
  app.post('/api/notify-jobs', signedJson, async (req, res, next) => {
    try {
      const { partnerId, reason } = req.body;
      if (!isNonEmptyString(partnerId) || !OBJECT_ID_RE.test(partnerId)) {
        return res.status(400).json({ error: 'Invalid partnerId' });
      }
      const safeReason = ['new', 'updated', 'cancelled'].includes(reason) ? reason : 'updated';
      const room = `partner_${partnerId}`;
      const sockets = await io.in(room).fetchSockets();
      io.to(room).emit('jobs:available', { reason: safeReason, at: Date.now() });
      res.status(200).json({ success: true, delivered: sockets.length });
    } catch (err) {
      next(err);
    }
  });

  // New chat message for a partner: connected mobile/desktop apps update unread/chat view.
  app.post('/api/notify-chat', signedJson, async (req, res, next) => {
    try {
      const { partnerId, conversationId, orderId, senderName, preview } = req.body;
      if (!isNonEmptyString(partnerId) || !OBJECT_ID_RE.test(partnerId) || !isNonEmptyString(conversationId)) {
        return res.status(400).json({ error: 'Invalid body' });
      }
      const room = `partner_${partnerId}`;
      const sockets = await io.in(room).fetchSockets();
      io.to(room).emit('chat:message', {
        conversationId,
        orderId: typeof orderId === 'string' ? orderId : undefined,
        senderName: typeof senderName === 'string' ? senderName.slice(0, 80) : 'Customer',
        preview: typeof preview === 'string' ? preview.slice(0, 140) : '',
        at: Date.now(),
      });
      res.status(200).json({ success: true, delivered: sockets.length });
    } catch (err) {
      next(err);
    }
  });

  // A partner device was signed out: close its sockets now
  app.post('/api/disconnect-device', signedJson, async (req, res, next) => {
    try {
      const { partnerId, deviceId } = req.body;
      if (!isNonEmptyString(partnerId) || !OBJECT_ID_RE.test(partnerId) || !isNonEmptyString(deviceId) || deviceId.length > 64) {
        return res.status(400).json({ error: 'Invalid body' });
      }
      const sockets = await io.in(`device_${deviceId}`).fetchSockets();
      const own = sockets.filter((sk) => sk.data.partnerId === partnerId);
      for (const sk of own) {
        sk.emit('signed_out', { reason: 'device_revoked' });
        sk.disconnect(true);
      }
      res.status(200).json({ success: true, delivered: own.length });
    } catch (err) {
      next(err);
    }
  });

  // JSON error handler (e.g. body too large); never leak stack traces.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status || err.statusCode || 500;
    if (status >= 500) console.error('Unhandled error:', err);
    res.status(status).json({ error: status >= 500 ? 'Internal server error' : 'Bad request' });
  });

  return { app, io, httpServer };
}

module.exports = { createServer, computeSignature };
