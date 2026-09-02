import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { z } from 'zod';

/**
 * Boot-time environment contract.
 *
 * Everything the app needs is parsed once, here, and the process exits if any of
 * it is wrong. A missing secret must crash the app — never silently degrade to an
 * insecure default, which is how apps end up in production with no session
 * encryption and no one noticing.
 */

// The .env lives at the monorepo root, and this module is two directories deep in
// both src/ and dist/. Walk up rather than hard-coding a depth that a build layout
// change would silently break.
function loadDotEnv(): void {
  let dir = import.meta.dirname;
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, '.env');
    if (existsSync(candidate)) {
      process.loadEnvFile(candidate);
      return;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // No file: CI and production supply variables through the real environment.
}

const generateHint = (bytes: number) =>
  `node -e "console.log(require('crypto').randomBytes(${bytes}).toString('base64'))"`;

const base64Secret = (bytes: number) =>
  z.string().refine(
    (v) => {
      try {
        return Buffer.from(v, 'base64').length === bytes;
      } catch {
        return false;
      }
    },
    { message: `must be ${bytes} random bytes, base64-encoded — generate with: ${generateHint(bytes)}` },
  );

// Treat an empty value as absent, so `ALLOWED_HD=` in .env means "not configured"
// rather than "lock logins to the empty domain".
const optionalString = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === '' ? undefined : v.trim()));

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    APP_ORIGIN: z.url(),
    API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),

    DATABASE_URL: z.string().min(1),

    GOOGLE_CLIENT_ID: z.string().min(1),
    GOOGLE_CLIENT_SECRET: z.string().min(1),
    GOOGLE_REDIRECT_URI: z.url(),

    OAUTH_TX_SECRET: base64Secret(32),
    IP_HASH_SALT: base64Secret(32),

    SESSION_TTL_DAYS: z.coerce.number().int().positive().default(7),
    SESSION_ABSOLUTE_TTL_DAYS: z.coerce.number().int().positive().default(30),

    COOKIE_PREFIX: z.string().default('__Host-'),
    ALLOWED_HD: optionalString,
  })
  .superRefine((v, ctx) => {
    // The redirect URI Google is given must be the URL the *browser* sees, which is
    // the Next origin — not the port this API listens on. Getting this wrong is the
    // single most common way this flow fails, and Google's error is unhelpful.
    const expected = `${v.APP_ORIGIN}/api/auth/google/callback`;
    if (v.GOOGLE_REDIRECT_URI !== expected) {
      ctx.addIssue({
        code: 'custom',
        path: ['GOOGLE_REDIRECT_URI'],
        message: `must be ${expected} — the browser-visible URL, matching the value registered in Google Cloud Console exactly`,
      });
    }

    // A sliding window that outlives its own hard cap is not a hard cap.
    if (v.SESSION_ABSOLUTE_TTL_DAYS < v.SESSION_TTL_DAYS) {
      ctx.addIssue({
        code: 'custom',
        path: ['SESSION_ABSOLUTE_TTL_DAYS'],
        message: `must be >= SESSION_TTL_DAYS (${v.SESSION_TTL_DAYS})`,
      });
    }

    if (v.NODE_ENV === 'production') {
      // __Host- requires Secure, which requires https. The dev escape hatch must not
      // survive into production, so both halves are asserted here.
      if (!v.APP_ORIGIN.startsWith('https://')) {
        ctx.addIssue({
          code: 'custom',
          path: ['APP_ORIGIN'],
          message: 'must be https:// in production',
        });
      }
      if (v.COOKIE_PREFIX !== '__Host-') {
        ctx.addIssue({
          code: 'custom',
          path: ['COOKIE_PREFIX'],
          message: 'must be "__Host-" in production',
        });
      }
    }
  });

// Exported so the rules above can be unit-tested directly, without a process that exits.
export const envSchema = schema;

export type Env = z.infer<typeof schema>;

function parseEnv(): Env {
  loadDotEnv();
  const result = schema.safeParse(process.env);

  if (!result.success) {
    const lines = result.error.issues.map(
      (issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`,
    );
    // Written straight to stderr: this runs before the logger exists, and the
    // process is about to die anyway.
    process.stderr.write(
      `\nInvalid environment configuration:\n${lines.join('\n')}\n\n` +
        `Check your .env against .env.example.\n\n`,
    );
    process.exit(1);
  }

  return Object.freeze(result.data);
}

export const env: Env = parseEnv();

export const isProduction = env.NODE_ENV === 'production';
