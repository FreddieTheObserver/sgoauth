import { Controller, Get } from '@nestjs/common';
import { HealthCheck, HealthCheckService, type HealthCheckResult } from '@nestjs/terminus';
import { SkipThrottle } from '@nestjs/throttler';
import { DatabaseHealthIndicator } from './database.health.js';

@Controller('health')
// A load balancer polling this every few seconds would eventually throttle
// itself, and an orchestrator reading 429 as unhealthy would then take a
// perfectly healthy instance out of rotation.
@SkipThrottle()
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly database: DatabaseHealthIndicator,
  ) {}

  // Readiness, not just liveness: a process that is up but cannot reach Postgres
  // can serve no authenticated request, and should not be sent traffic.
  @Get()
  @HealthCheck()
  check(): Promise<HealthCheckResult> {
    return this.health.check([() => this.database.check()]);
  }
}
