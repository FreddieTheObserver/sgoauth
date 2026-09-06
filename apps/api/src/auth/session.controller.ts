import {
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  NotFoundException,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuditService, AuthEventType } from '../audit/audit.service.js';
import { CurrentSession } from '../common/decorators/current-session.js';
import { CurrentUser } from '../common/decorators/current-user.js';
import { SessionGuard } from '../common/guards/session.guard.js';
import { requestContext } from '../common/request-context.js';
import type { SessionUser } from '../common/types/session-user.js';
import { clearSessionCookie } from './cookies.js';
import { LOGIN_PATH } from './return-to.js';
import { SessionService, type DeviceSession } from './session.service.js';

/**
 * Everything that operates on a session that already exists — who it belongs to,
 * ending it, and the device list.
 *
 * Split from AuthController because the two halves have opposite entry
 * conditions: the handshake routes are unauthenticated by definition, while
 * every route here requires a caller. That lets SessionGuard sit on the class
 * rather than on each handler, so a route added below is protected by default
 * instead of protected if someone remembered the decorator.
 */
@Controller('auth')
@UseGuards(SessionGuard)
// Deliberately left on the global rate limit rather than the handshake's tight
// one. /auth/me is what the web app's DAL calls on every render, so a bucket
// sized for login attempts would log out anyone navigating quickly. There is
// nothing to brute-force here anyway: every route is already behind a session
// and scoped to rows the caller owns.
export class SessionController {
  constructor(
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Who is calling. The web app's DAL hangs every page's auth check off this,
   * which is why it answers with the narrow SessionUser and nothing else.
   */
  @Get('me')
  // An authenticated body held by any intermediary is one user's identity served
  // to the next one. Nothing behind this guard is ever cacheable.
  @Header('Cache-Control', 'no-store')
  me(@CurrentUser() user: SessionUser): SessionUser {
    return user;
  }

  /** The device list: where this account is currently signed in. */
  @Get('sessions')
  @Header('Cache-Control', 'no-store')
  list(
    @CurrentUser('id') userId: string,
    @CurrentSession('id') sessionId: string,
  ): Promise<DeviceSession[]> {
    return this.sessions.listActive(userId, sessionId);
  }

  /**
   * End this session.
   *
   * Reached by a plain form POST, so it answers with a redirect: Nest clears the
   * cookie and sends the browser to the login page, and the web app never has to
   * touch an auth cookie itself.
   */
  @Post('logout')
  async logout(
    @CurrentUser('id') userId: string,
    @CurrentSession('id') sessionId: string,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const revoked = await this.sessions.revoke(sessionId, userId);

    // Unconditional, and before the audit write: whatever the database did, this
    // browser must stop presenting the credential.
    clearSessionCookie(response);

    // Only when a row actually changed. Two logouts racing each other are one
    // event, and an audit trail padded with no-ops is harder to read after an
    // incident, not easier.
    if (revoked) {
      await this.audit.record({
        type: AuthEventType.SessionRevoked,
        userId,
        ...requestContext(request),
        detail: { scope: 'self', sessionId },
      });
    }

    this.redirectToLogin(response);
  }

  /**
   * Log out everywhere, this device included.
   *
   * The one someone presses after losing a laptop, so it deliberately does not
   * spare the caller: "everywhere" that quietly means "except here" is the wrong
   * answer to the only question being asked.
   */
  @Post('logout-all')
  async logoutAll(
    @CurrentUser('id') userId: string,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const count = await this.sessions.revokeAll(userId);

    clearSessionCookie(response);

    if (count > 0) {
      await this.audit.record({
        type: AuthEventType.SessionRevoked,
        userId,
        ...requestContext(request),
        detail: { scope: 'all', count },
      });
    }

    this.redirectToLogin(response);
  }

  /**
   * Revoke one session from the device list.
   *
   * Ownership is enforced inside the update rather than here — see
   * SessionService.revoke. A session that is not yours, never existed, or is
   * already revoked all answer 404: a 403 that appeared only for ids that really
   * exist would be an oracle for enumerating other people's sessions.
   */
  @Delete('sessions/:id')
  @HttpCode(204)
  async revokeOne(
    @Param('id') id: string,
    @CurrentUser('id') userId: string,
    @CurrentSession('id') sessionId: string,
    @Req() request: Request,
    // passthrough: Nest still writes the 204 and ends the response; this handler
    // only needs to add a Set-Cookie header on the way out.
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    const revoked = await this.sessions.revoke(id, userId);
    if (!revoked) throw new NotFoundException();

    // Revoking the session you are holding is allowed - it is just logout by
    // another name - so the cookie goes with it rather than being resent until
    // the next request bounces.
    if (id === sessionId) clearSessionCookie(response);

    await this.audit.record({
      type: AuthEventType.SessionRevoked,
      userId,
      ...requestContext(request),
      detail: { scope: 'one', sessionId: id },
    });
  }

  /**
   * 303 rather than 302: the browser must follow this with a GET. A 302 answering
   * a POST leaves that to browser convention, and the one place it is not
   * followed is the one place the user lands on a blank page mid-logout.
   */
  private redirectToLogin(response: Response): void {
    response.redirect(303, LOGIN_PATH);
  }
}
