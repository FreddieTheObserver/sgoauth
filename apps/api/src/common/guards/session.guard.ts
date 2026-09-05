import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response } from 'express';
import { SESSION_COOKIE, clearSessionCookie, setSessionCookie } from '../../auth/cookies.js';
import { SessionService } from '../../auth/session.service.js';
import type { AuthenticatedRequest } from '../types/session-user.js';

/**
 * Turns the session cookie into `request.user`, or a 401.
 *
 * Applied per route rather than globally: the OAuth handshake endpoints are
 * reached by definition without a session, and a global guard with a `@Public()`
 * escape hatch inverts the safe default — a route is then protected only if
 * someone remembered to leave the decorator off.
 */
@Injectable()
export class SessionGuard implements CanActivate {
  constructor(private readonly sessions: SessionService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const request = http.getRequest<AuthenticatedRequest>();

    const token: unknown = request.cookies?.[SESSION_COOKIE];
    if (typeof token !== 'string' || token.length === 0) {
      throw new UnauthorizedException();
    }

    const validated = await this.sessions.validate(token);
    if (!validated) {
      // The cookie is dead — revoked, expired, or never ours. Clearing it stops
      // the browser resending it forever, and stops the web app's optimistic
      // "cookie present, assume signed in" redirect from looping.
      clearSessionCookie(http.getResponse<Response>());
      throw new UnauthorizedException();
    }

    if (validated.renewed) {
      // Same token, later expiry. Rotating the value here instead would race
      // with concurrent requests from the same browser and log the user out.
      setSessionCookie(http.getResponse<Response>(), token, validated.session.expiresAt);
    }

    request.user = validated.user;
    request.session = validated.session;
    return true;
  }
}
