import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module.js';
import { env, isProduction } from './config/env.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // The API only ever sees traffic through Next's /api/* rewrite, so the real
  // client address arrives in X-Forwarded-For. Without this every session row
  // and rate-limit bucket would key on the proxy instead of the user.
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
