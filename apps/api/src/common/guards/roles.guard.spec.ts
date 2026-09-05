import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Roles } from '../decorators/roles.decorator.js';
import type { SessionUser } from '../types/session-user.js';
import { RolesGuard } from './roles.guard.js';

describe('RolesGuard', () => {
  const guard = new RolesGuard(new Reflector());

  // Exercised through the real decorator and a real Reflector, so the metadata
  // key stays a private detail of the pair rather than something the test asserts.
  @Roles('ADMIN')
  class AdminController {
    @Roles('ADMIN')
    restricted(): void {}

    @Roles('USER', 'ADMIN')
    relaxed(): void {}

    unmarked(): void {}
  }

  class OpenController {
    anything(): void {}
  }

  const user = (role: SessionUser['role']): SessionUser => ({
    id: 'u1',
    email: 'a@example.com',
    name: null,
    avatarUrl: null,
    role,
  });

  const contextFor = (
    target: object,
    handler: (...args: never[]) => unknown,
    request: object,
  ): ExecutionContext =>
    ({
      getHandler: () => handler,
      getClass: () => target,
      switchToHttp: () => ({ getRequest: () => request }),
    }) as unknown as ExecutionContext;

  it('allows a route with no @Roles metadata', () => {
    const context = contextFor(OpenController, OpenController.prototype.anything, {});
    expect(guard.canActivate(context)).toBe(true);
  });

  it('allows a user holding the required role', () => {
    const context = contextFor(AdminController, AdminController.prototype.restricted, {
      user: user('ADMIN'),
    });
    expect(guard.canActivate(context)).toBe(true);
  });

  it('refuses a user without the required role', () => {
    const context = contextFor(AdminController, AdminController.prototype.restricted, {
      user: user('USER'),
    });
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('lets a handler widen what the controller restricts', () => {
    const context = contextFor(AdminController, AdminController.prototype.relaxed, {
      user: user('USER'),
    });
    expect(guard.canActivate(context)).toBe(true);
  });

  it('inherits controller-level roles for an unmarked handler', () => {
    const asUser = contextFor(AdminController, AdminController.prototype.unmarked, {
      user: user('USER'),
    });
    expect(() => guard.canActivate(asUser)).toThrow(ForbiddenException);

    const asAdmin = contextFor(AdminController, AdminController.prototype.unmarked, {
      user: user('ADMIN'),
    });
    expect(guard.canActivate(asAdmin)).toBe(true);
  });

  it('fails closed when no session guard ran ahead of it', () => {
    const context = contextFor(AdminController, AdminController.prototype.restricted, {});
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });
});
