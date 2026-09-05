import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import { env } from '../../config/env.js';

// Normalised once: `new URL(...).origin` drops a trailing slash and lowercases
// the host, so a harmless APP_ORIGIN typo cannot lock out every write request.
const APP_ORIGIN = new URL(env.APP_ORIGIN).origin;

// The methods that are supposed to be side-effect free. HEAD and OPTIONS are
// included because blocking a preflight would break nothing and help no one —
// we configure no CORS, so no cross-origin preflight can succeed anyway.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * CSRF defense, applied globally to every state-changing request.
 *
 * `SameSite=Lax` already stops the classic cross-site form POST, but it treats
 * every subdomain of the site as the same site — a single compromised sibling
 * host is enough to bypass it. Checking `Origin` against our exact origin closes
 * that gap, and it does so without a token to mint, store, rotate or leak.
 */
@Injectable()
export class CsrfOriginGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    if (context.getType() !== 'http') return true;

    const request = context.switchToHttp().getRequest<Request>();
    if (SAFE_METHODS.has(request.method)) return true;

    const origin = request.headers.origin;
    if (typeof origin === 'string') {
      // Note the strict equality: an `Origin` of "null" (sandboxed iframe, some
      // redirect chains) and a lookalike host both land here and are refused.
      if (origin === APP_ORIGIN) return true;
      throw new ForbiddenException();
    }

    // No Origin at all. Every current browser sends it on non-GET, so this is a
    // non-browser client or an old one. Sec-Fetch-Site is the only other signal
    // we accept, and only when the browser itself says the request came from us.
    if (request.headers['sec-fetch-site'] === 'same-origin') return true;

    throw new ForbiddenException();
  }
}
