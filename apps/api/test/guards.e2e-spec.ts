import { randomBytes } from 'node:crypto';
import { Controller, Get, UseGuards, type INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { SESSION_COOKIE } from '../src/auth/cookies.js';
import { hashSessionToken } from '../src/auth/session.service.js';
import { Roles } from '../src/common/decorators/roles.decorator.js';
import { RolesGuard } from '../src/common/guards/roles.guard.js';
import { SessionGuard } from '../src/common/guards/session.guard.js';
import { PrismaService } from '../src/prisma/prisma.service.js';

/**
 * The last of the throwaway routes.
 *
 * SessionGuard and CsrfOriginGuard are driven through the real /auth routes
 * below now. RolesGuard has no real @Roles route to sit on yet, and the thing
 * only an HTTP test can show is the pairing: that a missing session answers 401
 * before RolesGuard ever gets the chance to answer 403. This goes when the
 * first admin route lands.
 */
@Controller('probe')
class ProbeController {
  @Get('admin')
  @UseGuards(SessionGuard, RolesGuard)
  @Roles('ADMIN')
  admin(): { ok: boolean } {
    return { ok: true };
  }
}

const DAY = 86_400_000;

describe('guards (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const userIds: string[] = [];

  beforeAll(async () => {
    const fixture = await Test.createTestingModule({
      imports: [AppModule],
      controllers: [ProbeController],
    }).compile();

    app = fixture.createNestApplication<NestExpressApplication>();
    // Mirrors main.ts: without cookie-parser the guard sees no cookies at all.
    app.use(cookieParser());
    await app.init();
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    if (userIds.length > 0) {
      // Events first: AuthEvent.userId is SetNull on delete, so removing the
      // users would orphan the rows the logout tests here write.
      await prisma.authEvent.deleteMany({ where: { userId: { in: userIds } } });
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
    }
    await app.close();
  });

  const makeUser = async (role: 'USER' | 'ADMIN' = 'USER', disabled = false) => {
    const user = await prisma.user.create({
      data: {
        email: `${randomBytes(8).toString('hex')}@example.test`,
        emailVerifiedAt: new Date(),
        name: 'Probe User',
        role,
        disabledAt: disabled ? new Date() : null,
      },
    });
    userIds.push(user.id);
    return user;
  };

  const makeSession = async (
    userId: string,
    overrides: { expiresAt?: Date; absoluteExpiresAt?: Date; revokedAt?: Date } = {},
  ) => {
    const token = randomBytes(32).toString('base64url');
    const session = await prisma.session.create({
      data: {
        userId,
        tokenHash: hashSessionToken(token),
        expiresAt: overrides.expiresAt ?? new Date(Date.now() + 7 * DAY),
        absoluteExpiresAt: overrides.absoluteExpiresAt ?? new Date(Date.now() + 30 * DAY),
        revokedAt: overrides.revokedAt ?? null,
      },
    });
    return { token, session };
  };

  const cookie = (token: string) => `${SESSION_COOKIE}=${token}`;

  describe('SessionGuard', () => {
    it('401s with no cookie', async () => {
      await request(app.getHttpServer()).get('/auth/me').expect(401);
    });

    it('401s on a garbage token', async () => {
      await request(app.getHttpServer())
        .get('/auth/me')
        .set('Cookie', cookie('not-a-real-token'))
        .expect(401);
    });

    it('resolves the user on a live session', async () => {
      const user = await makeUser();
      const { token } = await makeSession(user.id);

      const res = await request(app.getHttpServer())
        .get('/auth/me')
        .set('Cookie', cookie(token))
        .expect(200);

      expect(res.body).toEqual({
        id: user.id,
        email: user.email,
        name: 'Probe User',
        avatarUrl: null,
        role: 'USER',
      });
      // Well inside the window: nothing to re-set.
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('updates lastUsedAt', async () => {
      const user = await makeUser();
      const { token, session } = await makeSession(user.id);

      await request(app.getHttpServer()).get('/auth/me').set('Cookie', cookie(token)).expect(200);

      const after = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
      expect(after.lastUsedAt.getTime()).toBeGreaterThan(session.lastUsedAt.getTime());
    });

    it.each([
      ['revoked', { revokedAt: new Date() }],
      ['idle-expired', { expiresAt: new Date(Date.now() - DAY) }],
      ['past the absolute cap', { absoluteExpiresAt: new Date(Date.now() - DAY) }],
    ])('401s on a %s session and clears the cookie', async (_label, overrides) => {
      const user = await makeUser();
      const { token } = await makeSession(user.id, overrides);

      const res = await request(app.getHttpServer())
        .get('/auth/me')
        .set('Cookie', cookie(token))
        .expect(401);

      expect(String(res.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);
    });

    it('401s once the user is disabled', async () => {
      const user = await makeUser('USER', true);
      const { token } = await makeSession(user.id);
      await request(app.getHttpServer()).get('/auth/me').set('Cookie', cookie(token)).expect(401);
    });

    it('slides the window in the row without writing a cookie back', async () => {
      const user = await makeUser();
      const { token, session } = await makeSession(user.id, {
        expiresAt: new Date(Date.now() + 2 * DAY),
      });

      const res = await request(app.getHttpServer())
        .get('/auth/me')
        .set('Cookie', cookie(token))
        .expect(200);

      const after = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
      expect(after.expiresAt.getTime()).toBeGreaterThan(session.expiresAt.getTime());
      // The row moved and the response carries nothing. The cookie was pinned to
      // the absolute cap when it was minted, which is why a renewal header is
      // not needed here - and why sliding survives a page rendered on the Next
      // server, where a Set-Cookie from this API would be swallowed.
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('never slides past the absolute cap', async () => {
      const user = await makeUser();
      const cap = new Date(Date.now() + 2 * DAY);
      const { token, session } = await makeSession(user.id, {
        expiresAt: new Date(Date.now() + DAY),
        absoluteExpiresAt: cap,
      });

      await request(app.getHttpServer()).get('/auth/me').set('Cookie', cookie(token)).expect(200);

      const after = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
      expect(after.expiresAt.getTime()).toBe(cap.getTime());
    });
  });

  describe('CsrfOriginGuard', () => {
    it('allows a POST from our own origin', async () => {
      const user = await makeUser();
      const { token } = await makeSession(user.id);

      await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', cookie(token))
        .set('Origin', 'http://localhost:3000')
        .expect(303);
    });

    it('403s a POST from a foreign origin', async () => {
      const user = await makeUser();
      const { token } = await makeSession(user.id);

      await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', cookie(token))
        .set('Origin', 'https://evil.com')
        .expect(403);
    });

    it('403s a POST carrying neither Origin nor Sec-Fetch-Site', async () => {
      const user = await makeUser();
      const { token } = await makeSession(user.id);

      await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', cookie(token))
        .expect(403);
    });

    it('accepts Sec-Fetch-Site same-origin when Origin is absent', async () => {
      const user = await makeUser();
      const { token } = await makeSession(user.id);

      await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', cookie(token))
        .set('Sec-Fetch-Site', 'same-origin')
        .expect(303);
    });

    it('answers before the session is even looked at', async () => {
      // No cookie at all, and still 403 rather than 401: the global guard runs
      // ahead of the controller's. A CSRF check that ran after authentication
      // would be one an unauthenticated attacker has already walked past.
      await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Origin', 'https://evil.com')
        .expect(403);
    });

    it('leaves GETs alone', async () => {
      const user = await makeUser();
      const { token } = await makeSession(user.id);

      await request(app.getHttpServer())
        .get('/auth/me')
        .set('Cookie', cookie(token))
        .set('Origin', 'https://evil.com')
        .expect(200);
    });
  });

  describe('RolesGuard', () => {
    it('403s a USER on an ADMIN route', async () => {
      const user = await makeUser('USER');
      const { token } = await makeSession(user.id);
      await request(app.getHttpServer())
        .get('/probe/admin')
        .set('Cookie', cookie(token))
        .expect(403);
    });

    it('allows an ADMIN', async () => {
      const user = await makeUser('ADMIN');
      const { token } = await makeSession(user.id);
      await request(app.getHttpServer())
        .get('/probe/admin')
        .set('Cookie', cookie(token))
        .expect(200);
    });

    it('401s rather than 403s when there is no session at all', async () => {
      await request(app.getHttpServer()).get('/probe/admin').expect(401);
    });
  });
});
