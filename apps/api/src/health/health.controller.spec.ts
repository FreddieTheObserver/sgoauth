import { Test, type TestingModule } from '@nestjs/testing';
import { TerminusModule } from '@nestjs/terminus';
import { PrismaService } from '../prisma/prisma.service.js';
import { DatabaseHealthIndicator } from './database.health.js';
import { HealthController } from './health.controller.js';

describe('HealthController', () => {
  // Stubbed so the unit suite stays fast and needs no database; the e2e suite
  // exercises the real connection.
  const build = async (queryRaw: () => Promise<unknown>): Promise<HealthController> => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [TerminusModule],
      controllers: [HealthController],
      providers: [
        DatabaseHealthIndicator,
        { provide: PrismaService, useValue: { $queryRaw: queryRaw } },
      ],
    }).compile();
    return module.get(HealthController);
  };

  it('reports ok when the database answers', async () => {
    const controller = await build(async () => [{ '?column?': 1 }]);
    await expect(controller.check()).resolves.toMatchObject({
      status: 'ok',
      info: { database: { status: 'up' } },
    });
  });

  it('reports 503 when the database is unreachable', async () => {
    const controller = await build(async () => {
      throw new Error('connection refused');
    });
    // Terminus signals a failed check by throwing a 503, not by resolving.
    await expect(controller.check()).rejects.toMatchObject({ status: 503 });
  });
});
