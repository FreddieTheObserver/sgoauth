// config/env.ts validates at import time and exits the process when anything is
// missing, so tests need a complete environment before any module is imported.
// Real environment values win over .env (verified: process.loadEnvFile fills
// gaps, it never overrides), so these placeholders apply without the developer's
// own .env interfering — and without needing real Google credentials to run the
// suite. DATABASE_URL is deliberately left to .env: these tests hit real Postgres.
process.env.NODE_ENV ||= 'test';
process.env.APP_ORIGIN ||= 'http://localhost:3000';
process.env.GOOGLE_CLIENT_ID ||= 'test-client-id.apps.googleusercontent.com';
process.env.GOOGLE_CLIENT_SECRET ||= 'test-client-secret';
process.env.GOOGLE_REDIRECT_URI ||= `${process.env.APP_ORIGIN}/api/auth/google/callback`;
process.env.OAUTH_TX_SECRET ||= Buffer.alloc(32, 1).toString('base64');
process.env.IP_HASH_SALT ||= Buffer.alloc(32, 2).toString('base64');
