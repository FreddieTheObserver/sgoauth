import { Global, Module } from '@nestjs/common';
import { SessionService } from './session.service.js';

// Global for the same reason PrismaModule is: SessionGuard is used across every
// feature module, and a guard's dependencies resolve in the module that declares
// the controller — so without this each one would have to import this module
// just to be able to say @UseGuards(SessionGuard).
@Global()
@Module({
  providers: [SessionService],
  exports: [SessionService],
})
export class SessionModule {}
