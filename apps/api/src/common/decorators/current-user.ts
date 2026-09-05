import { type ExecutionContext, createParamDecorator } from '@nestjs/common';
import type { AuthenticatedRequest, SessionUser } from '../types/session-user.js';

/**
 * `@CurrentUser() user: SessionUser` — or `@CurrentUser('id') id: string`.
 *
 * Only ever populated by SessionGuard, so a handler using this decorator without
 * that guard receives `undefined` rather than an unauthenticated stand-in. Guard
 * the route; the decorator is a reader, not a check.
 */
export const CurrentUser = createParamDecorator(
  <K extends keyof SessionUser>(field: K | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<Partial<AuthenticatedRequest>>();
    return field ? request.user?.[field] : request.user;
  },
);
