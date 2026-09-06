import { Global, Module } from '@nestjs/common';
import { SessionPruneJob } from './session-prune.job.js';
import { SessionService } from './session.service.js';

// Global for the same reason PrismaModule is: SessionGuard is used across every
// feature module, and a guard's dependencies resolve in the module that declares
// the controller — so without this each one would have to import this module
// just to be able to say @UseGuards(SessionGuard).
@Global()
@Module({
  // The prune job is a provider and not an export: the module that owns the
  // Session table owns cleaning it up, and nothing else needs to reach it.
  providers: [SessionService, SessionPruneJob],
  exports: [SessionService],
})
export class SessionModule {}
