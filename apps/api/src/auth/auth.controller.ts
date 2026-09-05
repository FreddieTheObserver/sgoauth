import { Controller, Get, Query, Res } from '@nestjs/common';
import type { Response } from 'express';
import { setOAuthTxCookie } from './cookies.js';
import { GoogleService, randomToken } from './google.service.js';
import { OAuthTxService } from './oauth-tx.service.js';
import { safeReturnTo } from './return-to.js';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly google: GoogleService,
    private readonly oauthTx: OAuthTxService,
  ) {}

  /**
   * Start the handshake.
   *
   * Reached by a real top-level navigation - a link or a form, never fetch().
   * A cross-origin redirect to accounts.google.com cannot be followed by XHR,
   * and building this button as a fetch() is the single most common way this
   * flow is first got wrong.
   */
  @Get('google')
  async start(@Query('returnTo') returnTo: unknown, @Res() res: Response): Promise<void> {
    const state = randomToken();
    const codeVerifier = randomToken();
    const nonce = randomToken();

    // returnTo is filtered on the way in, not on the way out. By the time the
    // callback reads it back it is already known-safe, and it has spent the
    // round trip inside an encrypted cookie where nobody could edit it.
    const tx = await this.oauthTx.issue({
      state,
      codeVerifier,
      nonce,
      returnTo: safeReturnTo(returnTo),
    });
    setOAuthTxCookie(res, tx);

    res.redirect(this.google.createAuthorizationUrl({ state, codeVerifier, nonce }).toString());
  }
}
