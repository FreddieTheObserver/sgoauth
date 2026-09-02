import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service.js';

// Global: every feature module needs database access, and threading an import
// through each one buys nothing.
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
