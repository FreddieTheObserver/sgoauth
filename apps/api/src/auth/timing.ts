import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time string comparison.
 *
 * Used for the `state` check, where the two values are a secret we issued and a
 * value an attacker supplies. A plain `===` short-circuits on the first
 * differing byte, which leaks how much of a guess was right and turns forgery
 * into a per-character search rather than a 256-bit one.
 *
 * Length is compared first and in variable time on purpose: timingSafeEqual
 * throws on mismatched lengths, and the length of a random token is not a
 * secret.
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
