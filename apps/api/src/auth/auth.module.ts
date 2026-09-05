import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { GoogleService } from './google.service.js';
import { OAuthTxService } from './oauth-tx.service.js';

@Module({
  controllers: [AuthController],
  providers: [GoogleService, OAuthTxService],
})
export class AuthModule {}
