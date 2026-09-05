import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module.js';
import { AccountService } from './account.service.js';
import { AuthController } from './auth.controller.js';
import { GoogleService, googleJwksProvider } from './google.service.js';
import { OAuthTxService } from './oauth-tx.service.js';

@Module({
  imports: [AuditModule],
  controllers: [AuthController],
  providers: [GoogleService, googleJwksProvider, OAuthTxService, AccountService],
})
export class AuthModule {}
