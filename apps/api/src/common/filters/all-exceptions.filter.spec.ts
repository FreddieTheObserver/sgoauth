import {
  type ArgumentsHost,
  ForbiddenException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { AllExceptionsFilter } from './all-exceptions.filter.js';

describe('AllExceptionsFilter', () => {
  const filter = new AllExceptionsFilter();

  const build = (headersSent = false, url = '/auth/logout') => {
    const json = vi.fn();
    const end = vi.fn();
    const status = vi.fn(() => ({ json }));
    const response = { status, json, end, headersSent };
    const request = { method: 'POST', url, originalUrl: url, id: 'req-1' };

    const host = {
      getType: () => 'http',
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => response }),
    } as unknown as ArgumentsHost;

    return { host, status, json, end };
  };

  const bodyOf = (json: ReturnType<typeof vi.fn>) => json.mock.calls[0][0];

  it('answers an HttpException with its own status', () => {
    const { host, status } = build();
    filter.catch(new ForbiddenException(), host);
    expect(status).toHaveBeenCalledWith(403);
  });

  it('answers anything else with 500', () => {
    const { host, status } = build();
    filter.catch(new Error('connect ECONNREFUSED 127.0.0.1:5432'), host);
    expect(status).toHaveBeenCalledWith(500);
  });

  it('sends the registered reason phrase and never the exception message', () => {
    const { host, json } = build();
    // The shape a well-meaning refactor produces, and the reason this filter
    // exists: a message written for a developer that answers "does this account
    // exist" for anyone who asks.
    filter.catch(new NotFoundException('No session s_123 for user ada@example.com'), host);

    expect(bodyOf(json)).toEqual({
      statusCode: 404,
      error: 'Not Found',
      requestId: 'req-1',
    });
  });

  it.each([
    ['a database error', new Error('relation "Session" does not exist')],
    ['a thrown string', 'something went wrong in the token exchange'],
    ['an unauthorized', new UnauthorizedException('token hash 9f2a… not found')],
  ])('leaks nothing from %s', (_label, thrown) => {
    const { host, json } = build();
    filter.catch(thrown, host);

    const serialised = JSON.stringify(bodyOf(json));
    for (const leak of ['Session', 'ada@example.com', 'token hash', 'relation', 'exchange']) {
      expect(serialised).not.toContain(leak);
    }
  });

  it('carries the request id, so the detail is findable in the logs', () => {
    const { host, json } = build();
    filter.catch(new ForbiddenException(), host);
    expect(bodyOf(json).requestId).toBe('req-1');
  });

  it('redacts the URL it logs, not just the one it answers', () => {
    // Caught against a running server: the log line explaining a 403 was being
    // built from request.url directly, which put a live authorization code into
    // the log the moment a callback failed — the exact leak the rest of this
    // layer exists to prevent, written by the thing reporting the refusal.
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    const { host } = build(false, '/auth/google/callback?code=4/0AY-live-code&state=abc');

    filter.catch(new ForbiddenException(), host);

    const logged = String(warn.mock.calls[0][0]);
    expect(logged).not.toContain('4/0AY-live-code');
    expect(logged).not.toContain('abc');
    expect(logged).toContain('/auth/google/callback');
    warn.mockRestore();
  });

  it('only ends the response once the handler has started writing one', () => {
    // A redirect is already on the wire; there is no envelope left to replace,
    // and calling status() on it would throw over the top of the real error.
    const { host, status, end } = build(true);
    filter.catch(new Error('boom'), host);

    expect(status).not.toHaveBeenCalled();
    expect(end).toHaveBeenCalled();
  });
});
