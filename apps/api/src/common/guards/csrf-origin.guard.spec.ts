import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { CsrfOriginGuard } from './csrf-origin.guard.js';

describe('CsrfOriginGuard', () => {
  const guard = new CsrfOriginGuard();

  const contextFor = (method: string, headers: Record<string, string>): ExecutionContext =>
    ({
      getType: () => 'http',
      switchToHttp: () => ({ getRequest: () => ({ method, headers }) }),
    }) as unknown as ExecutionContext;

  const allows = (method: string, headers: Record<string, string>) =>
    guard.canActivate(contextFor(method, headers));

  const refuses = (method: string, headers: Record<string, string>) =>
    expect(() => guard.canActivate(contextFor(method, headers))).toThrow(ForbiddenException);

  it('lets safe methods through regardless of origin', () => {
    // Reads are not what CSRF exploits, and the OAuth callback is a cross-site GET.
    expect(allows('GET', { origin: 'https://evil.com' })).toBe(true);
    expect(allows('HEAD', {})).toBe(true);
    expect(allows('OPTIONS', { origin: 'https://evil.com' })).toBe(true);
  });

  it('allows a state-changing request from our own origin', () => {
    expect(allows('POST', { origin: 'http://localhost:3000' })).toBe(true);
  });

  it('refuses a foreign origin', () => {
    refuses('POST', { origin: 'https://evil.com' });
    refuses('DELETE', { origin: 'https://evil.com' });
  });

  it('refuses a lookalike origin rather than prefix-matching it', () => {
    refuses('POST', { origin: 'http://localhost:3000.evil.com' });
    refuses('POST', { origin: 'http://localhost:30000' });
  });

  it('refuses the literal "null" origin a sandboxed frame sends', () => {
    refuses('POST', { origin: 'null' });
  });

  it('falls back to Sec-Fetch-Site when no Origin header is present', () => {
    expect(allows('POST', { 'sec-fetch-site': 'same-origin' })).toBe(true);
    refuses('POST', { 'sec-fetch-site': 'cross-site' });
    refuses('POST', { 'sec-fetch-site': 'same-site' });
    // A top-level user-initiated POST is not a thing a browser produces.
    refuses('POST', { 'sec-fetch-site': 'none' });
  });

  it('refuses a state-changing request with neither header', () => {
    refuses('POST', {});
  });

  it('ignores non-http contexts', () => {
    const rpc = { getType: () => 'rpc' } as unknown as ExecutionContext;
    expect(guard.canActivate(rpc)).toBe(true);
  });
});
