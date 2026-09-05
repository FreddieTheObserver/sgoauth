import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { SessionModule } from './auth/session.module.js';
import { CsrfOriginGuard } from './common/guards/csrf-origin.guard.js';
import { HealthModule } from './health/health.module.js';
import { PrismaModule } from './prisma/prisma.module.js';

@Module({
  imports: [PrismaModule, SessionModule, HealthModule],
  providers: [
    // Global on purpose. CSRF protection that a new controller has to opt into
    // is CSRF protection that the next controller will forget.
    { provide: APP_GUARD, useClass: CsrfOriginGuard },
  ],
})
export class AppModule {}
