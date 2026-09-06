import type { Request } from 'express';
import { hashIp } from './ip-hash.js';

/**
 * The "who and from where" every audit row carries.
 *
 * Both fields are derived rather than stored raw: the address is salted and
 * hashed on the way in, and the user agent is truncated by AuditService. Pulled
 * into one function because a second copy of it is how one call site ends up
 * writing the plain IP.
 */
export interface RequestContext {
  ipHash: string | null;
  userAgent: string | null;
}

export function requestContext(request: Request): RequestContext {
  return {
    // request.ip is only the real client because main.ts sets `trust proxy` —
    // everything reaches this API through Next's /api/* rewrite.
    ipHash: hashIp(request.ip),
    userAgent: request.get('user-agent') ?? null,
  };
}
