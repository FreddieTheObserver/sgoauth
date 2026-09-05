import { Controller, ForbiddenException, Get, Logger, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuditService, AuthEventType } from '../audit/audit.service.js';
import { hashIp } from '../common/ip-hash.js';
import { AccountService } from './account.service.js';
import {
  OAUTH_TX_COOKIE,
  clearOAuthTxCookie,
  setOAuthTxCookie,
  setSessionCookie,
} from './cookies.js';
import { GoogleService, randomToken } from './google.service.js';
import { LoginDeniedError } from './login-denied.error.js';
import { OAuthTxService } from './oauth-tx.service.js';
import { SessionService } from './session.service.js';
import { safeReturnTo } from './return-to.js';
import { timingSafeEqualString } from './timing.js';

const LOGIN_PATH = '/login';

/** Express gives back an array for a repeated query parameter; only a single
 * string is ever a legitimate value here. */
function single(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly google: GoogleService,
    private readonly oauthTx: OAuthTxService,
    private readonly accounts: AccountService,
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
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

  /**
   * Finish the handshake. The security-critical path, and the steps below run in
   * this order for a reason - each one is cheap and each one makes the next one
   * safe to attempt.
   */
  @Get('google/callback')
  async callback(
    @Query() query: Record<string, unknown>,
    @Req() request: Request,
    @Res() res: Response,
  ): Promise<void> {
    const context = {
      ipHash: hashIp(request.ip),
      userAgent: request.get('user-agent') ?? null,
    };

    // 1. The user pressed Cancel on Google's consent screen. Not an attack, and
    // not something to answer with a 403 they cannot act on.
    if (single(query.error)) {
      await this.audit.record({
        type: AuthEventType.LoginDenied,
        ...context,
        detail: { reason: 'provider.denied' },
      });
      res.redirect(`${LOGIN_PATH}?error=access_denied`);
      return;
    }

    // 2. Read the handshake cookie and clear it before validating anything. It
    // is strictly single-use: replaying the same code a second time finds no
    // cookie to check itself against, so the replay dies here rather than at the
    // token endpoint.
    const rawTx = request.cookies?.[OAUTH_TX_COOKIE] as unknown;
    clearOAuthTxCookie(res);

    const tx = await this.oauthTx.consume(single(rawTx) ?? undefined);
    if (!tx) return this.deny('tx.missing_or_invalid', context);

    // 3. The state check. This is what stops login CSRF: without it an attacker
    // can hand you their own authorization code and quietly sign you into their
    // account, where everything you then do is visible to them.
    const state = single(query.state);
    if (!state || !timingSafeEqualString(state, tx.state)) {
      return this.deny('state.mismatch', context);
    }

    const code = single(query.code);
    if (!code) return this.deny('code.missing', context);

    // 4. Redeem the code with the PKCE verifier that never left this server.
    const idToken = await this.google.exchangeCode(code, tx.codeVerifier);
    if (!idToken) return this.deny('code.exchange_failed', context);

    // 5. Verify the ID token. Signature, issuer, audience, algorithm, nonce,
    // email_verified and the workspace domain all happen inside this call.
    const identity = await this.google.verifyIdToken(idToken, tx.nonce);
    if (!identity) return this.deny('id_token.invalid', context);

    // 6. Map the verified identity onto a local user.
    let user: { id: string };
    try {
      user = await this.accounts.resolveUser(identity, context);
    } catch (error) {
      if (error instanceof LoginDeniedError) return this.deny(error.reason, context);
      throw error;
    }

    // 7. Mint the session and write the trail.
    const session = await this.sessions.mint(user.id, context);
    setSessionCookie(res, session.token, session.expiresAt);
    await this.audit.record({ type: AuthEventType.LoginSuccess, userId: user.id, ...context });

    // 8. Redirect away from the callback URL, so the authorization code stops
    // sitting in the address bar, browser history, and any Referer sent from the
    // page that renders next.
    res.redirect(safeReturnTo(tx.returnTo));
  }

  /**
   * One exit for every failure. The client gets a bare 403 with no body worth
   * reading: which check failed is recorded for us and told to nobody, because
   * "state was wrong" and "that account is disabled" are different answers only
   * an attacker benefits from telling apart.
   */
  private async deny(
    reason: string,
    context: { ipHash: string | null; userAgent: string | null },
  ): Promise<never> {
    this.logger.warn(`Login denied: ${reason}`);
    await this.audit.record({
      type: AuthEventType.LoginDenied,
      ...context,
      detail: { reason },
    });
    throw new ForbiddenException();
  }
}
