'use strict';

const { createServer } = require('./src/server');

const REQUIRED_ENV = ['NEXTAUTH_SECRET', 'WSS_DISPATCH_SECRET'];
const missing = REQUIRED_ENV.filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.error(
    `❌ FATAL: missing required environment variable(s): ${missing.join(', ')}. ` +
      'See .env.example. Refusing to start.'
  );
  process.exit(1);
}

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

if (allowedOrigins.length === 0) {
  console.warn('⚠️ ALLOWED_ORIGINS is empty: only requests without an Origin header will be accepted.');
}

const { httpServer } = createServer({
  jwtSecret: process.env.NEXTAUTH_SECRET,
  dispatchSecret: process.env.WSS_DISPATCH_SECRET,
  allowedOrigins,
});

const PORT = Number(process.env.PORT) || 3001;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 FunPrinting WebSocket Cloud Engine running on port ${PORT}`);
});
