import { Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';
import { env } from '../config/env.js';
import { PrismaClient } from '../generated/prisma/client.js';

/**
 * Prisma 7 runs the query compiler, so a driver adapter is required rather than
 * optional — there is no built-in connection path any more.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  constructor() {
    super({ adapter: new PrismaPg({ connectionString: env.DATABASE_URL }) });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
    this.logger.log('Database connected');
  }

  // Paired with app.enableShutdownHooks() so in-flight queries finish and the
  // pool closes cleanly instead of the process dropping sockets on exit.
  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
