import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { LoggerModule } from 'nestjs-pino';
import { AuthModule } from './auth/auth.module.js';
import { SessionModule } from './auth/session.module.js';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter.js';
import { CsrfOriginGuard } from './common/guards/csrf-origin.guard.js';
import { loggerOptions } from './common/logger.js';
import { env } from './config/env.js';
import { HealthModule } from './health/health.module.js';
import { PrismaModule } from './prisma/prisma.module.js';

// One minute, the window every limit below is expressed in.
const THROTTLE_TTL_MS = 60_000;

// Generous, because it is a floor rather than a policy: it exists so a single
// address cannot hammer any endpoint, and the routes that need a real limit say
// so themselves with @Throttle.
const GLOBAL_LIMIT = 100;

@Module({
  imports: [
    LoggerModule.forRoot(loggerOptions),
    ThrottlerModule.forRoot({
      throttlers: [{ name: 'default', ttl: THROTTLE_TTL_MS, limit: GLOBAL_LIMIT }],
      // Storage is in-memory, which is correct for one instance and wrong for
      // several: each would enforce the limit against its own share of the
      // traffic. A shared store is the answer at that point, not a bigger number.
      //
      // Off under test. The e2e suites drive several hundred requests from one
      // address in a few seconds, which is exactly the shape this limit exists
      // to stop — leaving it on would decide test outcomes by request ordering.
      // An APP_GUARD registered by class cannot be swapped per suite, so the
      // switch lives here; the limit is verified against the running server
      // instead, which is better evidence than a mock anyway.
      skipIf: () => env.NODE_ENV === 'test',
    }),
    ScheduleModule.forRoot(),
    PrismaModule,
    SessionModule,
    AuthModule,
    HealthModule,
  ],
  providers: [
    // Order matters: Nest runs global guards in the order they are registered.
    // Rate limiting is the cheapest possible rejection, so it goes first — and a
    // flood of cross-origin requests should be spending someone's budget rather
    // than getting free 403s.
    //
    // Both are global on purpose. Protection that a new controller has to opt
    // into is protection that the next controller will forget.
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: CsrfOriginGuard },

    // Registered here rather than through app.useGlobalFilters() so it resolves
    // through DI and gets a real logger.
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule {}
