import { createHash, randomBytes } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import type { SessionUser } from '../common/types/session-user.js';
import { env } from '../config/env.js';
import { PrismaService } from '../prisma/prisma.service.js';

const DAY_MS = 86_400_000;

/**
 * Plain SHA-256 is the right choice here, and only because of what the input is:
 * a 256-bit CSPRNG value. There is no dictionary to run against it, so bcrypt or
 * argon2 would buy nothing but latency on every authenticated request. The same
 * function must never be used on anything a human chose.
 */
export function hashSessionToken(token: string): Uint8Array<ArrayBuffer> {
  // Copied into a plain Uint8Array: Prisma types its Bytes columns that way, and
  // Buffer's ArrayBufferLike backing store does not satisfy it.
  return Uint8Array.from(createHash('sha256').update(token, 'utf8').digest());
}

// 256 bits from the CSPRNG. The entropy is what makes a plain hash at rest
// safe, and what makes guessing a live session id not worth attempting.
const TOKEN_BYTES = 32;

export interface MintedSession {
  /** The raw cookie value. Held only long enough to be written to a header. */
  token: string;
  expiresAt: Date;
}

export interface ValidatedSession {
  user: SessionUser;
  session: { id: string; expiresAt: Date };
  /** The sliding window moved — the caller must re-set the cookie with this expiry. */
  renewed: boolean;
}

@Injectable()
export class SessionService {
  private readonly ttlMs = env.SESSION_TTL_DAYS * DAY_MS;
  private readonly absoluteTtlMs = env.SESSION_ABSOLUTE_TTL_DAYS * DAY_MS;

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Issue a session. The token is returned to the caller and never stored - what
   * goes in the database is its SHA-256, so a dump of the Session table yields
   * nothing replayable.
   */
  async mint(
    userId: string,
    context: { userAgent?: string | null; ipHash?: string | null },
  ): Promise<MintedSession> {
    const token = randomBytes(TOKEN_BYTES).toString('base64url');
    const now = Date.now();
    const expiresAt = new Date(now + this.ttlMs);

    await this.prisma.session.create({
      data: {
        userId,
        tokenHash: hashSessionToken(token),
        // Truncated because it is attacker-controlled and only ever displayed:
        // an unbounded header should not become an unbounded column.
        userAgent: context.userAgent?.slice(0, 512) ?? null,
        ipHash: context.ipHash ?? null,
        expiresAt,
        // Fixed at creation and never extended. This is the ceiling that makes
        // the sliding window safe.
        absoluteExpiresAt: new Date(now + this.absoluteTtlMs),
      },
    });

    return { token, expiresAt };
  }

  /**
   * Turn a raw cookie value into a caller, or into nothing.
   *
   * Returns `null` for every failure without distinguishing them: unknown token,
   * revoked, idle-expired, past the absolute cap and disabled user are one
   * outcome to the client. Which one it was goes to the audit log, not the wire.
   */
  async validate(token: string): Promise<ValidatedSession | null> {
    if (!token) return null;

    // One indexed lookup on the unique hash. The raw token is never a query
    // argument and never touches the database.
    const session = await this.prisma.session.findUnique({
      where: { tokenHash: hashSessionToken(token) },
      select: {
        id: true,
        expiresAt: true,
        absoluteExpiresAt: true,
        revokedAt: true,
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            avatarUrl: true,
            role: true,
            disabledAt: true,
          },
        },
      },
    });

    if (!session) return null;

    const now = new Date();
    if (session.revokedAt !== null) return null;
    if (session.expiresAt <= now) return null;
    // Checked separately from `expiresAt` because sliding only ever moves that
    // one; the absolute cap is what guarantees no session lives forever.
    if (session.absoluteExpiresAt <= now) return null;
    // A ban takes effect on the next request rather than at the next login.
    if (session.user.disabledAt !== null) return null;

    const { expiresAt, renewed } = this.slide(session.expiresAt, session.absoluteExpiresAt, now);

    // One write covers both: `lastUsedAt` feeds the device list, and the new
    // expiry only when the window actually moved.
    await this.prisma.session.update({
      where: { id: session.id },
      data: renewed ? { lastUsedAt: now, expiresAt } : { lastUsedAt: now },
    });

    return {
      // Rebuilt field by field rather than spread, so adding a column to User
      // cannot quietly widen what every authenticated request carries.
      user: {
        id: session.user.id,
        email: session.user.email,
        name: session.user.name,
        avatarUrl: session.user.avatarUrl,
        role: session.user.role,
      },
      session: { id: session.id, expiresAt },
      renewed,
    };
  }

  /**
   * Extend only in the back half of the window: renewing on every request costs
   * a write and a `Set-Cookie` header to buy a few seconds of lifetime. Idle
   * sessions still die, active ones never expire under the user, and the
   * absolute cap is a ceiling the extension cannot cross.
   */
  private slide(
    expiresAt: Date,
    absoluteExpiresAt: Date,
    now: Date,
  ): { expiresAt: Date; renewed: boolean } {
    if (expiresAt.getTime() - now.getTime() >= this.ttlMs / 2) {
      return { expiresAt, renewed: false };
    }

    const extended = Math.min(now.getTime() + this.ttlMs, absoluteExpiresAt.getTime());
    // Inside the last half-TTL before the hard cap the extension is clamped to a
    // value we already have, and re-setting the cookie would be pure noise.
    if (extended <= expiresAt.getTime()) {
      return { expiresAt, renewed: false };
    }

    return { expiresAt: new Date(extended), renewed: true };
  }
}
