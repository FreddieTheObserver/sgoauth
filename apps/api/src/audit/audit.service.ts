import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';

/**
 * Append-only. Nothing in this service updates or deletes, and nothing else in
 * the app writes to AuthEvent - an audit trail the application can rewrite is
 * not an audit trail.
 */

export const AuthEventType = {
  LoginSuccess: 'login.success',
  LoginDenied: 'login.denied',
  AccountCreated: 'account.created',
  AccountLinked: 'account.linked',
  SessionRevoked: 'session.revoked',
} as const;

export type AuthEventType = (typeof AuthEventType)[keyof typeof AuthEventType];

export interface AuthEventInput {
  type: AuthEventType;
  userId?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
  /** Why, never what: a reason code, never a token, code or raw address. */
  detail?: Record<string, string | number | boolean | null>;
}

// Structural, so a caller inside $transaction can pass the transaction client
// and have the event committed or rolled back with the rest of its work.
type AuthEventWriter = Pick<PrismaService, 'authEvent'>;

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async record(event: AuthEventInput, client: AuthEventWriter = this.prisma): Promise<void> {
    await client.authEvent.create({
      data: {
        type: event.type,
        userId: event.userId ?? null,
        ipHash: event.ipHash ?? null,
        userAgent: event.userAgent?.slice(0, 512) ?? null,
        detail: event.detail ?? undefined,
      },
    });
  }
}
