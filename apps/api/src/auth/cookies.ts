import type { CookieOptions, Response } from 'express';
import { env } from '../config/env.js';

/**
 * The one place that builds cookie options.
 *
 * Every attribute below is load-bearing, and a single call site that forgets one
 * of them is a real vulnerability rather than an inconsistency — so no other
 * module is allowed to call `res.cookie` for an auth cookie.
 */

export const SESSION_COOKIE = `${env.COOKIE_PREFIX}sid`;

const baseOptions: CookieOptions = {
  // XSS cannot read it. This is why the session is a cookie and never a value
  // handed to JavaScript.
  httpOnly: true,
  // Required by the `__Host-` prefix. Chrome and Firefox treat http://localhost
  // as a secure context and accept it, so this stays true in dev too.
  secure: true,
  // Google's callback is a top-level GET navigation, which carries Lax cookies.
  // `strict` would drop the session on the way back from any external link.
  sameSite: 'lax',
  // `__Host-` requires exactly Path=/ and no Domain attribute — that pairing is
  // what stops a sibling subdomain from writing a cookie we would then trust.
  path: '/',
};

export function setSessionCookie(res: Response, token: string, expiresAt: Date): void {
  // The browser expires the cookie at the same moment the row expires, so a
  // dead session stops being sent rather than being sent and rejected.
  res.cookie(SESSION_COOKIE, token, { ...baseOptions, expires: expiresAt });
}

export function clearSessionCookie(res: Response): void {
  // Attributes must match the ones the cookie was set with, or the browser
  // treats this as a different cookie and leaves the original in place.
  res.clearCookie(SESSION_COOKIE, baseOptions);
}
