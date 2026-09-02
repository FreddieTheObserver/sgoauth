import { defineConfig, env } from 'prisma/config';

// Prisma 7 no longer reads .env by itself once a config file exists, and our .env lives at the
// monorepo root rather than next to this file. Load it here so `prisma migrate` / `generate` work
// from any cwd. Missing file is not fatal: in CI and production the vars come from the environment.
const envPath = new URL('../../.env', import.meta.url);
try {
  process.loadEnvFile(envPath);
} catch {
  // no .env on disk — rely on the ambient environment
}

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    // Throws at CLI start if unset, rather than silently connecting somewhere unintended.
    url: env('DATABASE_URL'),
  },
});
