import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Role } from '../../generated/prisma/enums.js';
import { ROLES_KEY } from '../decorators/roles.decorator.js';
import type { AuthenticatedRequest } from '../types/session-user.js';

/**
 * Authorization, and only authorization. It runs after SessionGuard has
 * established *who* is calling and answers whether they may.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Handler first, then class: a controller-wide @Roles(ADMIN) can be relaxed
    // on one route by a handler-level @Roles(USER, ADMIN).
    const required = this.reflector.getAllAndOverride<Role[] | undefined>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) return true;

    const request = context.switchToHttp().getRequest<Partial<AuthenticatedRequest>>();
    const user = request.user;

    // No user means SessionGuard did not run ahead of this one. Fail closed: a
    // misordered guard chain must never turn a role-restricted route into an
    // open one.
    if (!user) throw new ForbiddenException();
    if (!required.includes(user.role)) throw new ForbiddenException();

    return true;
  }
}
