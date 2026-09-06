import { type ExecutionContext, createParamDecorator } from '@nestjs/common';
import type { AuthenticatedRequest, RequestSession } from '../types/session-user.js';

/**
 * `@CurrentSession() session: RequestSession` — or `@CurrentSession('id') id: string`.
 *
 * The caller's own session as SessionGuard resolved it: enough to revoke this
 * one, deliberately not enough to replay it. The row's id is here, the token
 * that maps to it never is — that value exists only in the browser's cookie and
 * as a SHA-256 in the database.
 *
 * Like @CurrentUser, this reads what the guard put there. A handler using it
 * without SessionGuard gets `undefined`, not an anonymous stand-in.
 */
export const CurrentSession = createParamDecorator(
  <K extends keyof RequestSession>(field: K | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<Partial<AuthenticatedRequest>>();
    return field ? request.session?.[field] : request.session;
  },
);
