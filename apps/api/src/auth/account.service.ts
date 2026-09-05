import { Injectable, Logger } from '@nestjs/common';
import { AuditService, AuthEventType } from '../audit/audit.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { GoogleIdentity } from './google.service.js';
import { LoginDeniedError } from './login-denied.error.js';

// Generic on purpose. GitHub or Microsoft later is a new value here plus a
// client, not a schema change.
const PROVIDER = 'google';

export interface ResolvedUser {
  id: string;
}

export interface AccountContext {
  ipHash: string | null;
  userAgent: string | null;
}

@Injectable()
export class AccountService {
  private readonly logger = new Logger(AccountService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Map a verified Google identity onto a local user, creating or linking as
   * needed. Runs in one transaction so a half-linked account cannot survive a
   * crash between the two writes.
   *
   * The caller must have verified the ID token first. Nothing here re-checks the
   * signature, so calling it with an unverified identity would be a takeover.
   */
  async resolveUser(identity: GoogleIdentity, context: AccountContext): Promise<ResolvedUser> {
    return this.prisma.$transaction(async (tx) => {
      // 1. Known account. The lookup is on (provider, sub) - the immutable
      // identity key - so a user who changed their Google email still lands on
      // their own account rather than on someone else's.
      const account = await tx.oAuthAccount.findUnique({
        where: {
          provider_providerAccountId: { provider: PROVIDER, providerAccountId: identity.sub },
        },
        include: { user: true },
      });

      if (account) {
        if (account.user.disabledAt !== null) {
          throw new LoginDeniedError('user.disabled');
        }

        await tx.user.update({
          where: { id: account.user.id },
          // Profile fields only. User.email is deliberately not refreshed: a
          // changed Google address could collide with another row's unique
          // email and fail the login, and moving a local identity to a new
          // address is an email-change flow, not a side effect of signing in.
          data: { name: identity.name, avatarUrl: identity.avatarUrl },
        });

        // The snapshot on the account row does track the current address, so the
        // audit trail can show what Google asserted at each login.
        if (account.email !== identity.email) {
          await tx.oAuthAccount.update({
            where: { id: account.id },
            data: { email: identity.email },
          });
        }

        return { id: account.user.id };
      }

      // 2. No account for this `sub`, but the address is already known here.
      const existing = await tx.user.findUnique({ where: { email: identity.email } });

      if (existing) {
        if (existing.disabledAt !== null) {
          throw new LoginDeniedError('user.disabled');
        }

        // Pre-hijacking defense. An attacker who seeded an account at your
        // address before you ever signed in must not have your Google login
        // handed to them. Linking is allowed only when the address was already
        // proven on this side; the incoming half was proven by the
        // `email_verified` claim before we got here.
        //
        // The plan called for creating a separate account in this case, which
        // User.email being @unique makes impossible. Failing closed is the safer
        // half of that choice anyway: a denied login is recoverable, a wrongly
        // linked identity is not.
        if (existing.emailVerifiedAt === null) {
          throw new LoginDeniedError('link.unverified_local_account');
        }

        await tx.oAuthAccount.create({
          data: {
            userId: existing.id,
            provider: PROVIDER,
            providerAccountId: identity.sub,
            email: identity.email,
          },
        });

        await this.audit.record(
          {
            type: AuthEventType.AccountLinked,
            userId: existing.id,
            ipHash: context.ipHash,
            userAgent: context.userAgent,
            detail: { provider: PROVIDER },
          },
          tx,
        );

        this.logger.log(`Linked ${PROVIDER} account to existing user ${existing.id}`);
        return { id: existing.id };
      }

      // 3. Brand new. emailVerifiedAt is set from the verified claim, which is
      // what makes a later link to this row safe.
      const created = await tx.user.create({
        data: {
          email: identity.email,
          emailVerifiedAt: new Date(),
          name: identity.name,
          avatarUrl: identity.avatarUrl,
          accounts: {
            create: {
              provider: PROVIDER,
              providerAccountId: identity.sub,
              email: identity.email,
            },
          },
        },
      });

      await this.audit.record(
        {
          type: AuthEventType.AccountCreated,
          userId: created.id,
          ipHash: context.ipHash,
          userAgent: context.userAgent,
          detail: { provider: PROVIDER },
        },
        tx,
      );

      return { id: created.id };
    });
  }
}
