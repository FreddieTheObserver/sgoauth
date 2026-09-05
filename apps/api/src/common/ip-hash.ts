import { createHash } from 'node:crypto';
import { env } from '../config/env.js';

/**
 * We store a salted hash of the client address, never the address itself.
 *
 * It still answers the question the device list and the audit trail actually
 * ask - "is this the same origin as last time?" - while holding no PII to leak
 * or subpoena. The salt matters: IPv4 is a 32-bit space, so an unsalted hash of
 * it is reversible by brute force in seconds.
 */
export function hashIp(ip: string | undefined | null): string | null {
  if (!ip) return null;
  return createHash('sha256')
    .update(Buffer.from(env.IP_HASH_SALT, 'base64'))
    .update(ip, 'utf8')
    .digest('base64url');
}
