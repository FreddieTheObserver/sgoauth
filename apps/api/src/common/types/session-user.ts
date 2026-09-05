import type { Request } from 'express';
import type { Role } from '../../generated/prisma/enums.js';

/**
 * The only shape of "who is calling" the rest of the app ever sees.
 *
 * Deliberately narrow: no `disabledAt`, no session token, no OAuth fields. A
 * guard that hands the full Prisma row down the stack is how internal columns
 * end up serialised into an API response by a later, well-meaning `return user`.
 */
export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
  role: Role;
}

/** The caller's own session — enough to revoke it, not enough to replay it. */
export interface RequestSession {
  id: string;
  expiresAt: Date;
}

/**
 * A request that has passed SessionGuard. Both fields are non-optional here on
 * purpose: anything typed as an AuthenticatedRequest is downstream of the guard,
 * so treating `user` as possibly-absent there would be noise. Code that runs
 * before the guard should type the request as plain `Request`.
 */
export interface AuthenticatedRequest extends Request {
  user: SessionUser;
  session: RequestSession;
}
