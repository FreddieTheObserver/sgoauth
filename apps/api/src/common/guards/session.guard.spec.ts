import { UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { SESSION_COOKIE } from '../../auth/cookies.js';
import type { SessionService, ValidatedSession } from '../../auth/session.service.js';
import { SessionGuard } from './session.guard.js';

describe('SessionGuard', () => {
  const user = {
    id: 'u1',
    email: 'a@example.com',
    name: null,
    avatarUrl: null,
    role: 'USER' as const,
  };

  const build = (validated: ValidatedSession | null) => {
    const validate = vi.fn(async () => validated);
    const guard = new SessionGuard({ validate } as unknown as SessionService);
    const response = { cookie: vi.fn(), clearCookie: vi.fn() };
    return { guard, validate, response };
  };

  const contextFor = (cookies: Record<string, unknown>, response: object) => {
    const request: Record<string, unknown> = { cookies };
    const context = {
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => response }),
    } as unknown as ExecutionContext;
    return { context, request };
  };

  it('rejects a request with no session cookie', async () => {
    const { guard, validate, response } = build(null);
    const { context } = contextFor({}, response);

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    // No cookie means no lookup: an unauthenticated request must not cost a query.
    expect(validate).not.toHaveBeenCalled();
  });

  it('rejects an empty cookie value without hitting the database', async () => {
    const { guard, validate, response } = build(null);
    const { context } = contextFor({ [SESSION_COOKIE]: '' }, response);

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    expect(validate).not.toHaveBeenCalled();
  });

  it('rejects a token the service refuses, and clears the dead cookie', async () => {
    const { guard, response } = build(null);
    const { context } = contextFor({ [SESSION_COOKIE]: 'revoked-token' }, response);

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    expect(response.clearCookie).toHaveBeenCalledWith(
      SESSION_COOKIE,
      expect.objectContaining({ httpOnly: true, secure: true, sameSite: 'lax', path: '/' }),
    );
  });

  it('attaches the user and session on success', async () => {
    const expiresAt = new Date('2026-01-08T00:00:00Z');
    const { guard, validate, response } = build({ user, session: { id: 's1', expiresAt } });
    const { context, request } = contextFor({ [SESSION_COOKIE]: 'good-token' }, response);

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(validate).toHaveBeenCalledWith('good-token');
    expect(request.user).toEqual(user);
    expect(request.session).toEqual({ id: 's1', expiresAt });
  });

  it('never writes a cookie back on success, however far the window slid', async () => {
    // The cookie carries the absolute cap and never changes, so an authenticated
    // request costs no Set-Cookie header. It is also what makes sliding work at
    // all for a server-rendered page: a renewal header would be swallowed by the
    // Next-side fetch that asked for it, leaving the row extended and the
    // browser's copy still expiring on the original date.
    const { guard, response } = build({
      user,
      session: { id: 's1', expiresAt: new Date('2026-02-01T00:00:00Z') },
    });
    const { context } = contextFor({ [SESSION_COOKIE]: 'good-token' }, response);

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(response.cookie).not.toHaveBeenCalled();
  });
});
