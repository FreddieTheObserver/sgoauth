import { randomBytes } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { SESSION_COOKIE } from '../src/auth/cookies.js';
import { hashSessionToken } from '../src/auth/session.service.js';
import { PrismaService } from '../src/prisma/prisma.service.js';

const DAY = 86_400_000;
const ORIGIN = 'http://localhost:3000';

describe('session routes (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const userIds: string[] = [];

  beforeAll(async () => {
    const fixture = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = fixture.createNestApplication<NestExpressApplication>();
    // Mirrors main.ts: without cookie-parser nothing here sees a session at all.
    app.use(cookieParser());
    await app.init();
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    if (userIds.length > 0) {
      // Events first: AuthEvent.userId is SetNull on delete, so removing the
      // users would orphan this suite's rows instead of taking them with it.
      await prisma.authEvent.deleteMany({ where: { userId: { in: userIds } } });
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
    }
    await app.close();
  });

  const server = () => app.getHttpServer();

  const makeUser = async () => {
    const user = await prisma.user.create({
      data: {
        // Distinct from every other suite's fixtures, so cleanup here can never
        // reach a row another suite is relying on.
        email: `${randomBytes(8).toString('hex')}@sessions.example.test`,
        emailVerifiedAt: new Date(),
        name: 'Grace Hopper',
      },
    });
    userIds.push(user.id);
    return user;
  };

  const makeSession = async (
    userId: string,
    overrides: {
      expiresAt?: Date;
      absoluteExpiresAt?: Date;
      revokedAt?: Date;
      userAgent?: string;
      lastUsedAt?: Date;
    } = {},
  ) => {
    const token = randomBytes(32).toString('base64url');
    const session = await prisma.session.create({
      data: {
        userId,
        tokenHash: hashSessionToken(token),
        userAgent: overrides.userAgent ?? 'Mozilla/5.0 (fixture)',
        expiresAt: overrides.expiresAt ?? new Date(Date.now() + 7 * DAY),
        absoluteExpiresAt: overrides.absoluteExpiresAt ?? new Date(Date.now() + 30 * DAY),
        revokedAt: overrides.revokedAt ?? null,
        ...(overrides.lastUsedAt ? { lastUsedAt: overrides.lastUsedAt } : {}),
      },
    });
    return { token, session };
  };

  /** A signed-in caller: a user, a live session, and the cookie for it. */
  const signIn = async () => {
    const user = await makeUser();
    const { token, session } = await makeSession(user.id);
    return { user, session, cookie: `${SESSION_COOKIE}=${token}`, token };
  };

  const rowFor = (id: string) => prisma.session.findUniqueOrThrow({ where: { id } });

  const setCookies = (res: request.Response): string[] =>
    (res.headers['set-cookie'] as unknown as string[]) ?? [];

  /**
   * The last Set-Cookie for a name is the one the browser keeps. Since the guard
   * stopped writing the session cookie back there should only ever be one, which
   * a test below asserts outright.
   */
  const finalSessionCookie = (res: request.Response): string | undefined =>
    setCookies(res)
      .filter((c) => c.startsWith(`${SESSION_COOKIE}=`))
      .at(-1);

  const revocations = (userId: string) =>
    prisma.authEvent.findMany({ where: { userId, type: 'session.revoked' } });

  const ids = (body: { id: string }[]) => body.map((row) => row.id);

  describe('GET /auth/me', () => {
    it('answers with the session user and nothing else', async () => {
      const { user, cookie } = await signIn();

      const res = await request(server()).get('/auth/me').set('Cookie', cookie).expect(200);

      expect(res.body).toEqual({
        id: user.id,
        email: user.email,
        name: 'Grace Hopper',
        avatarUrl: null,
        role: 'USER',
      });
      // The internal columns stay internal, even though the guard read them.
      for (const internal of ['disabledAt', 'emailVerifiedAt', 'createdAt', 'updatedAt']) {
        expect(res.body).not.toHaveProperty(internal);
      }
    });

    it('forbids any intermediary from holding on to the answer', async () => {
      const { cookie } = await signIn();
      const res = await request(server()).get('/auth/me').set('Cookie', cookie).expect(200);
      expect(res.headers['cache-control']).toContain('no-store');
    });

    it('401s without a session', async () => {
      await request(server()).get('/auth/me').expect(401);
    });
  });

  describe('GET /auth/sessions', () => {
    it('lists the live sessions, most recently used first, and marks this one', async () => {
      const { user, session, cookie } = await signIn();
      const older = await makeSession(user.id, {
        userAgent: 'Firefox',
        lastUsedAt: new Date(Date.now() - DAY),
      });

      const res = await request(server()).get('/auth/sessions').set('Cookie', cookie).expect(200);

      expect(ids(res.body)).toEqual([session.id, older.session.id]);
      expect(res.body[0]).toMatchObject({ id: session.id, current: true });
      expect(res.body[1]).toMatchObject({
        id: older.session.id,
        current: false,
        userAgent: 'Firefox',
      });
    });

    it('hides revoked, idle-expired and absolutely-expired rows', async () => {
      const { user, session, cookie } = await signIn();
      await makeSession(user.id, { revokedAt: new Date() });
      await makeSession(user.id, { expiresAt: new Date(Date.now() - DAY) });
      await makeSession(user.id, { absoluteExpiresAt: new Date(Date.now() - DAY) });

      const res = await request(server()).get('/auth/sessions').set('Cookie', cookie).expect(200);
      expect(ids(res.body)).toEqual([session.id]);
    });

    it('shows only the devices belonging to the caller', async () => {
      const mine = await signIn();
      const theirs = await signIn();

      const res = await request(server())
        .get('/auth/sessions')
        .set('Cookie', mine.cookie)
        .expect(200);

      expect(ids(res.body)).toContain(mine.session.id);
      expect(ids(res.body)).not.toContain(theirs.session.id);
    });

    it('sends nothing that would help anyone use a session', async () => {
      const { cookie } = await signIn();
      const res = await request(server()).get('/auth/sessions').set('Cookie', cookie).expect(200);

      expect(Object.keys(res.body[0]).sort()).toEqual([
        'createdAt',
        'current',
        'expiresAt',
        'id',
        'lastUsedAt',
        'userAgent',
      ]);
      // The IP digest is salted and unreadable to its own owner; sending it would
      // only hand a scraped page a stable value for correlating sessions.
      expect(JSON.stringify(res.body)).not.toContain('ipHash');
    });

    it('401s without a session', async () => {
      await request(server()).get('/auth/sessions').expect(401);
    });
  });

  describe('POST /auth/logout', () => {
    it('revokes this session, clears the cookie and sends the browser to /login', async () => {
      const { user, session, cookie } = await signIn();

      const res = await request(server())
        .post('/auth/logout')
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(303);

      expect(res.headers.location).toBe('/login');
      expect(finalSessionCookie(res)).toContain(`${SESSION_COOKIE}=;`);

      const after = await rowFor(session.id);
      expect(after.revokedAt).not.toBeNull();
      expect(await revocations(user.id)).toHaveLength(1);
    });

    it('sends exactly one cookie header when the window slid on the way in', async () => {
      // The guard slides the row here and writes nothing back, so the clear is
      // the only Set-Cookie on the response rather than the last of two.
      const user = await makeUser();
      const { token } = await makeSession(user.id, { expiresAt: new Date(Date.now() + 2 * DAY) });

      const res = await request(server())
        .post('/auth/logout')
        .set('Cookie', `${SESSION_COOKIE}=${token}`)
        .set('Origin', ORIGIN)
        .expect(303);

      const sessionCookies = setCookies(res).filter((c) =>
        c.startsWith(`${SESSION_COOKIE}=`),
      );
      expect(sessionCookies).toHaveLength(1);
      expect(sessionCookies[0]).toContain(`${SESSION_COOKIE}=;`);
    });

    it('makes the cookie useless on the very next request', async () => {
      const { cookie } = await signIn();

      await request(server())
        .post('/auth/logout')
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(303);

      await request(server()).get('/auth/me').set('Cookie', cookie).expect(401);
    });

    it('leaves the other devices on the account signed in', async () => {
      const { user, cookie } = await signIn();
      const other = await makeSession(user.id);

      await request(server())
        .post('/auth/logout')
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(303);

      expect((await rowFor(other.session.id)).revokedAt).toBeNull();
    });

    it('403s a logout driven from another origin, and the session survives', async () => {
      const { session, cookie } = await signIn();

      await request(server())
        .post('/auth/logout')
        .set('Cookie', cookie)
        .set('Origin', 'https://evil.com')
        .expect(403);

      expect((await rowFor(session.id)).revokedAt).toBeNull();
    });

    it('401s without a session', async () => {
      await request(server()).post('/auth/logout').set('Origin', ORIGIN).expect(401);
    });
  });

  describe('POST /auth/logout-all', () => {
    it('closes every device including the one asking', async () => {
      const { user, session, cookie } = await signIn();
      const phone = await makeSession(user.id);
      const laptop = await makeSession(user.id);

      const res = await request(server())
        .post('/auth/logout-all')
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(303);

      expect(res.headers.location).toBe('/login');
      expect(finalSessionCookie(res)).toContain(`${SESSION_COOKIE}=;`);

      for (const id of [session.id, phone.session.id, laptop.session.id]) {
        expect((await rowFor(id)).revokedAt).not.toBeNull();
      }

      // One event for the whole sweep, carrying what it actually closed.
      const [event] = await revocations(user.id);
      expect(event.detail).toMatchObject({ scope: 'all', count: 3 });
    });

    it('touches no other account', async () => {
      const mine = await signIn();
      const theirs = await signIn();

      await request(server())
        .post('/auth/logout-all')
        .set('Cookie', mine.cookie)
        .set('Origin', ORIGIN)
        .expect(303);

      expect((await rowFor(theirs.session.id)).revokedAt).toBeNull();
    });
  });

  describe('DELETE /auth/sessions/:id', () => {
    it('revokes the named device and leaves the caller signed in', async () => {
      const { user, session, cookie } = await signIn();
      const phone = await makeSession(user.id);

      const res = await request(server())
        .delete(`/auth/sessions/${phone.session.id}`)
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(204);

      // Killing another device must not log the caller out of this one.
      expect(finalSessionCookie(res)).toBeUndefined();
      expect((await rowFor(phone.session.id)).revokedAt).not.toBeNull();
      expect((await rowFor(session.id)).revokedAt).toBeNull();

      const [event] = await revocations(user.id);
      expect(event.detail).toMatchObject({ scope: 'one', sessionId: phone.session.id });
    });

    it('clears the cookie when the caller revokes the device they are on', async () => {
      const { session, cookie } = await signIn();

      const res = await request(server())
        .delete(`/auth/sessions/${session.id}`)
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(204);

      expect(finalSessionCookie(res)).toContain(`${SESSION_COOKIE}=;`);
      await request(server()).get('/auth/me').set('Cookie', cookie).expect(401);
    });

    it('404s on a session id belonging to someone else, and does not touch it', async () => {
      const mine = await signIn();
      const theirs = await signIn();

      await request(server())
        .delete(`/auth/sessions/${theirs.session.id}`)
        .set('Cookie', mine.cookie)
        .set('Origin', ORIGIN)
        .expect(404);

      expect((await rowFor(theirs.session.id)).revokedAt).toBeNull();
      expect(await revocations(mine.user.id)).toHaveLength(0);
    });

    it('answers an id that never existed exactly the same way', async () => {
      // Identical to the case above on purpose: a 403 that showed up only for
      // ids that really exist would enumerate other people's sessions.
      const { cookie } = await signIn();

      await request(server())
        .delete('/auth/sessions/not-a-real-session-id')
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(404);
    });

    it('refuses to re-stamp a session that is already revoked', async () => {
      const { user, cookie } = await signIn();
      const revokedAt = new Date(Date.now() - DAY);
      const stale = await makeSession(user.id, { revokedAt });

      await request(server())
        .delete(`/auth/sessions/${stale.session.id}`)
        .set('Cookie', cookie)
        .set('Origin', ORIGIN)
        .expect(404);

      // When the session died is what the retained row is kept to answer.
      expect((await rowFor(stale.session.id)).revokedAt).toEqual(revokedAt);
    });

    it('403s a delete driven from another origin', async () => {
      const { user, cookie } = await signIn();
      const phone = await makeSession(user.id);

      await request(server())
        .delete(`/auth/sessions/${phone.session.id}`)
        .set('Cookie', cookie)
        .set('Origin', 'https://evil.com')
        .expect(403);

      expect((await rowFor(phone.session.id)).revokedAt).toBeNull();
    });

    it('401s without a session', async () => {
      await request(server()).delete('/auth/sessions/anything').set('Origin', ORIGIN).expect(401);
    });
  });
});
