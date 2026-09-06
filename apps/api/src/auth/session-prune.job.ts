import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { SessionService } from './session.service.js';

/**
 * The one scheduled thing in the app, kept in its own class so it is visible in
 * the module's provider list. A @Cron hanging off SessionService would make the
 * schedule a side effect of importing a module every request already depends on.
 *
 * Two instances running this at once is harmless: the delete is a single
 * statement over a set that only shrinks, so the second one finds nothing and
 * does nothing. That is the reason not to reach for a distributed lock here.
 */
@Injectable()
export class SessionPruneJob {
  private readonly logger = new Logger(SessionPruneJob.name);

  constructor(private readonly sessions: SessionService) {}

  // Daily, off-peak. The rows are already unusable — validate() rejected them
  // long before the job runs — so this is housekeeping, never a control.
  @Cron(CronExpression.EVERY_DAY_AT_3AM)
  async prune(): Promise<void> {
    const deleted = await this.sessions.pruneDead();
    if (deleted > 0) this.logger.log(`Pruned ${deleted} dead session rows`);
  }
}
