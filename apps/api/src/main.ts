import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module.js';
import { env, isProduction } from './config/env.js';

async function bootstrap(): Promise<void> {
  // Buffered so the lines Nest writes while wiring modules are held until the
  // real logger exists, and then replayed through it. Without this the boot logs
  // are the one part of the output that is neither structured nor redacted.
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
  app.useLogger(app.get(Logger));

  // The API only ever sees traffic through Next's /api/* rewrite, so the real
  // client address arrives in X-Forwarded-For. Without this every session row,
  // log line and rate-limit bucket would key on the proxy instead of the user —
  // which for the throttler means one shared bucket for every visitor at once.
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          // Nothing here should ever be framed — this origin issues redirects
          // that carry session cookies.
          'frame-ancestors': ["'none'"],
        },
      },
      // Legacy equivalent of frame-ancestors 'none'. Helmet defaults this to
      // SAMEORIGIN, which contradicts the CSP above in browsers that predate it.
      xFrameOptions: { action: 'deny' },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      // HSTS on http://localhost would pin every localhost project on the
      // machine to https. Production only.
      hsts: isProduction ? { maxAge: 15_552_000, includeSubDomains: true } : false,
    }),
  );

  app.use(cookieParser());

  // Lets PrismaService.onModuleDestroy run on SIGTERM so the pool closes cleanly.
  app.enableShutdownHooks();

  await app.listen(env.API_PORT);
}

await bootstrap();
