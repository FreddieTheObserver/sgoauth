import { Injectable } from '@nestjs/common';
import { HealthIndicatorService, type HealthCheckAttempt } from '@nestjs/terminus';
import { PrismaService } from '../prisma/prisma.service.js';

/**
 * Our own database probe rather than terminus's PrismaHealthIndicator.
 *
 * That one issues a MongoDB `$runCommandRaw({ ping: 1 })` first and only falls
 * back to SQL when the resulting error message happens to contain the string
 * "Use the mongodb provider" — so every probe costs a failed command plus an
 * exception, and a reworded Prisma error would silently turn this endpoint red.
 * A plain `SELECT 1` says the same thing in one round trip and depends on no
 * error text.
 */
@Injectable()
export class DatabaseHealthIndicator {
  constructor(
    private readonly healthIndicatorService: HealthIndicatorService,
    private readonly prisma: PrismaService,
  ) {}

  check(): HealthCheckAttempt<'database'> {
    return this.healthIndicatorService
      .check('database')
      .attempt(async () => {
        await this.prisma.$queryRaw`SELECT 1`;
      })
      // A wedged connection must fail the probe, not hang the endpoint.
      .withTimeout(2000);
  }
}
