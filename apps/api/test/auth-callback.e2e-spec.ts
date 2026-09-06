import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { OAUTH_TX_COOKIE, SESSION_COOKIE } from '../src/auth/cookies.js';
import { GOOGLE_JWKS } from '../src/auth/google.service.js';
import { hashSessionToken } from '../src/auth/session.service.js';
import { env } from '../src/config/env.js';
import { PrismaService } from '../src/prisma/prisma.service.js';

// Google, under our control: a keypair we own, served as a local JWKS, so every
// test below can forge an ID token on purpose and assert the forgery is refused.
const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...((await exportJWK(publicKey)) as JWK), alg: 'RS256' };
const jwks = createLocalJWKSet({ keys: [jwk] });
const { privateKey: foreignKey } = await generateKeyPair('RS256', { extractable: true });

const SUB = 'google-sub-e2e';
// Distinct from every other suite's fixtures, so cleanup here can never reach
// rows another suite is relying on.
const EMAIL = 'ada.callback@example.test';

interface TokenOptions {
  key?: CryptoKey;
  issuer?: string;
  audience?: string;
  claims?: Record<string, unknown>;
}

const signIdToken = (nonce: string, options: TokenOptions = {}) =>
  new SignJWT({
    email: EMAIL,
    email_verified: true,
    name: 'Ada Lovelace',
    picture: 'https://example.com/ada.png',
    nonce,
    ...options.claims,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject((options.claims?.sub as string) ?? SUB)
    .setIssuer(options.issuer ?? 'https://accounts.google.com')
    .setAudience(options.audience ?? env.GOOGLE_CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(options.key ?? privateKey);

describe('GET /auth/google/callback (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    const fixture = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(GOOGLE_JWKS)
      .useValue(jwks)
      .compile();

    app = fixture.createNestApplication<NestExpressApplication>();
    app.use(cookieParser());
    await app.init();
    prisma = app.get(PrismaService);
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    await prisma.user.deleteMany({ where: { email: EMAIL } });
    await prisma.authEvent.deleteMany({ where: { userId: null } });
  });

  afterAll(async () => {
    await app.close();
  });

  const server = () => app.getHttpServer();

  /** Run the real first leg, and keep what the browser would have kept. */
  const startHandshake = async (query = '') => {
    const res = await request(server()).get(`/auth/google${query}`).expect(302);
    const setCookie = res.headers['set-cookie'] as unknown as string[];
    const cookie = setCookie.find((c) => c.startsWith(`${OAUTH_TX_COOKIE}=`));
    if (!cookie) throw new Error('handshake set no cookie');

    const location = new URL(res.headers.location as string);
    return {
      cookie: cookie.split(';')[0],
      state: location.searchParams.get('state') as string,
      nonce: location.searchParams.get('nonce') as string,
    };
  };

  /** Google's token endpoint answers with whatever this test wants it to. */
  const stubTokenEndpoint = (idToken: string | null) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        idToken === null
          ? Response.json({ error: 'invalid_grant' }, { status: 400 })
          : Response.json({ id_token: idToken }),
      ),
    );
  };

  const callback = (params: { cookie?: string; code?: string; state?: string }) => {
    const query = new URLSearchParams({
      code: params.code ?? 'the-code',
      ...(params.state === undefined ? {} : { state: params.state }),
    });
    const req = request(server()).get(`/auth/google/callback?${query.toString()}`);
    return params.cookie ? req.set('Cookie', params.cookie) : req;
  };

  /** The whole happy path, parameterised for the attack cases. */
  type LoginOptions = TokenOptions & { query?: string; state?: string };

  const login = async (options: LoginOptions = {}): Promise<request.Response> => {
    const handshake = await startHandshake(options.query);
    stubTokenEndpoint(await signIdToken(handshake.nonce, options));
    return callback({
      cookie: handshake.cookie,
      state: options.state ?? handshake.state,
    });
  };

  const loginExpect = async (status: number, options: LoginOptions = {}) => {
    const res = await login(options);
    expect(res.status).toBe(status);
    return res;
  };

  /** Scoped to this suite's own user: a global count would see other suites. */
  const sessionCount = () => prisma.session.count({ where: { user: { email: EMAIL } } });

  const sessionCookieFrom = (res: request.Response) => {
    const setCookie = (res.headers['set-cookie'] as unknown as string[]) ?? [];
    return setCookie.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  };

  describe('the happy path', () => {
    it('creates the user, the account, the session and the audit row', async () => {
      const res = await loginExpect(302);

      expect(res.headers.location).toBe('/dashboard');

      const user = await prisma.user.findUniqueOrThrow({
        where: { email: EMAIL },
        include: { accounts: true, sessions: true, events: true },
      });

      // Verified on the way in, which is what makes a later link to this row safe.
      expect(user.emailVerifiedAt).not.toBeNull();
      expect(user.name).toBe('Ada Lovelace');
      expect(user.accounts).toHaveLength(1);
      expect(user.accounts[0]).toMatchObject({ provider: 'google', providerAccountId: SUB });
      expect(user.sessions).toHaveLength(1);
      expect(user.events.map((e) => e.type)).toEqual(
        expect.arrayContaining(['account.created', 'login.success']),
      );
    });

    it('sets a hardened session cookie holding a token that is not in the database', async () => {
      const res = await loginExpect(302);
      const cookie = sessionCookieFrom(res);

      expect(cookie).toBeDefined();
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('Secure');
      expect(cookie).toContain('SameSite=Lax');
      expect(cookie).toContain('Path=/');

      const token = decodeURIComponent(
        (cookie as string).slice(`${SESSION_COOKIE}=`.length).split(';')[0],
      );
      const session = await prisma.session.findUniqueOrThrow({
        where: { tokenHash: hashSessionToken(token) },
      });
      // What is stored is the hash; the raw token appears nowhere in the row.
      expect(Buffer.from(session.tokenHash).equals(hashSessionToken(token))).toBe(true);
      expect(JSON.stringify(session)).not.toContain(token);
      expect(session.ipHash).not.toBeNull();

      // The cookie's own expiry is the absolute cap, not the sliding one. The
      // sliding window lives in the row and is enforced on every request; the
      // cookie only carries the outer bound past which no session can be alive.
      const expires = /Expires=([^;]+)/.exec(cookie as string)?.[1];
      expect(new Date(expires as string).getTime()).toBe(
        // Set-Cookie dates have no sub-second precision.
        Math.floor(session.absoluteExpiresAt.getTime() / 1000) * 1000,
      );
      expect(session.absoluteExpiresAt.getTime()).toBeGreaterThan(session.expiresAt.getTime());
    });

    it('clears the handshake cookie so it is strictly single-use', async () => {
      const res = await loginExpect(302);
      const setCookie = res.headers['set-cookie'] as unknown as string[];
      expect(setCookie.some((c) => c.startsWith(`${OAUTH_TX_COOKIE}=;`))).toBe(true);
    });

    it('recognises a returning user by sub rather than creating a second one', async () => {
      await loginExpect(302);
      await loginExpect(302, { claims: { name: 'Ada L.' } });

      const users = await prisma.user.findMany({
        where: { email: EMAIL },
        include: { accounts: true, sessions: true },
      });

      expect(users).toHaveLength(1);
      expect(users[0].accounts).toHaveLength(1);
      // Profile refreshed on each login; two logins, two sessions.
      expect(users[0].name).toBe('Ada L.');
      expect(users[0].sessions).toHaveLength(2);
    });

    it('honours a site-relative returnTo and refuses an off-site one', async () => {
      const good = await loginExpect(302, { query: '?returnTo=/settings/sessions' });
      expect(good.headers.location).toBe('/settings/sessions');

      const evil = await loginExpect(302, { query: '?returnTo=//evil.com' });
      expect(evil.headers.location).toBe('/dashboard');
    });
  });

  describe('the attacks', () => {
    const expectNoLogin = async (res: request.Response) => {
      expect(sessionCookieFrom(res)).toBeUndefined();
      expect(await sessionCount()).toBe(0);
      const denials = await prisma.authEvent.findMany({ where: { type: 'login.denied' } });
      expect(denials.length).toBeGreaterThan(0);
    };

    it('refuses a forged state', async () => {
      const res = await loginExpect(403, { state: 'forged-state' });
      await expectNoLogin(res);
    });

    it('refuses a missing state', async () => {
      const handshake = await startHandshake();
      stubTokenEndpoint(await signIdToken(handshake.nonce));
      const res = await callback({ cookie: handshake.cookie }).expect(403);
      await expectNoLogin(res);
    });

    it('refuses a missing handshake cookie', async () => {
      const handshake = await startHandshake();
      stubTokenEndpoint(await signIdToken(handshake.nonce));
      const res = await callback({ state: handshake.state }).expect(403);
      await expectNoLogin(res);
    });

    it('refuses a tampered handshake cookie', async () => {
      const handshake = await startHandshake();
      stubTokenEndpoint(await signIdToken(handshake.nonce));

      const [name, value] = handshake.cookie.split('=');
      const flipped = value.startsWith('A') ? `B${value.slice(1)}` : `A${value.slice(1)}`;

      const res = await callback({
        cookie: `${name}=${flipped}`,
        state: handshake.state,
      }).expect(403);
      await expectNoLogin(res);
    });

    it('refuses a replay once the handshake cookie is gone', async () => {
      // The browser cleared it on the first callback. A captured code alone is
      // not enough to finish a login. (A genuinely reused code is also rejected
      // by Google at the token endpoint, which this mock cannot express.)
      const handshake = await startHandshake();
      stubTokenEndpoint(await signIdToken(handshake.nonce));

      await callback({ cookie: handshake.cookie, state: handshake.state }).expect(302);
      const replay = await callback({ state: handshake.state }).expect(403);
      expect(sessionCookieFrom(replay)).toBeUndefined();
    });

    it('refuses an ID token signed by the wrong key', async () => {
      const res = await loginExpect(403, { key: foreignKey });
      await expectNoLogin(res);
    });

    it('refuses an ID token minted for another client', async () => {
      const res = await loginExpect(403, { audience: 'attacker.apps.googleusercontent.com' });
      await expectNoLogin(res);
    });

    it('refuses an ID token from the wrong issuer', async () => {
      const res = await loginExpect(403, { issuer: 'https://accounts.evil.com' });
      await expectNoLogin(res);
    });

    it('refuses a replayed ID token whose nonce is from another handshake', async () => {
      const handshake = await startHandshake();
      stubTokenEndpoint(await signIdToken('a-nonce-from-somewhere-else'));
      const res = await callback({ cookie: handshake.cookie, state: handshake.state }).expect(403);
      await expectNoLogin(res);
    });

    it('refuses an unverified email and creates nothing', async () => {
      const res = await loginExpect(403, { claims: { email_verified: false } });
      await expectNoLogin(res);
      expect(await prisma.user.count({ where: { email: EMAIL } })).toBe(0);
    });

    it('refuses when Google rejects the code', async () => {
      const handshake = await startHandshake();
      stubTokenEndpoint(null);
      const res = await callback({ cookie: handshake.cookie, state: handshake.state }).expect(403);
      await expectNoLogin(res);
    });

    it('refuses a disabled user without touching their session count', async () => {
      await loginExpect(302);
      await prisma.user.update({ where: { email: EMAIL }, data: { disabledAt: new Date() } });
      await prisma.session.deleteMany({ where: { user: { email: EMAIL } } });

      const res = await loginExpect(403);
      await expectNoLogin(res);
    });

    it('clears the handshake cookie even when the login is refused', async () => {
      const res = await loginExpect(403, { state: 'forged-state' });
      const setCookie = (res.headers['set-cookie'] as unknown as string[]) ?? [];
      expect(setCookie.some((c) => c.startsWith(`${OAUTH_TX_COOKIE}=;`))).toBe(true);
    });

    it('says nothing about which check failed', async () => {
      const res = await loginExpect(403, { state: 'forged-state' });
      const body = JSON.stringify(res.body);
      for (const leak of ['state', 'nonce', 'email_verified', 'disabled', 'reason']) {
        expect(body).not.toContain(leak);
      }
    });
  });

  describe('account linking', () => {
    it('links a first Google login onto an already-verified local account', async () => {
      const existing = await prisma.user.create({
        data: { email: EMAIL, emailVerifiedAt: new Date(), name: 'Existing' },
      });

      await loginExpect(302);

      const user = await prisma.user.findUniqueOrThrow({
        where: { email: EMAIL },
        include: { accounts: true, events: true },
      });

      expect(user.id).toBe(existing.id);
      expect(user.accounts).toHaveLength(1);
      expect(user.accounts[0].providerAccountId).toBe(SUB);
      expect(user.events.map((e) => e.type)).toContain('account.linked');
    });

    it('refuses to link onto a local account whose address was never verified', async () => {
      // Pre-hijacking: someone seeded an account at this address before the real
      // owner ever signed in with Google. Linking would hand it straight to them.
      await prisma.user.create({ data: { email: EMAIL, emailVerifiedAt: null } });

      const res = await loginExpect(403);

      expect(sessionCookieFrom(res)).toBeUndefined();
      const user = await prisma.user.findUniqueOrThrow({
        where: { email: EMAIL },
        include: { accounts: true },
      });
      expect(user.accounts).toHaveLength(0);
      expect(await sessionCount()).toBe(0);
    });
  });

  describe('the user pressing cancel', () => {
    it('redirects to the login page rather than answering 403', async () => {
      const res = await request(server())
        .get('/auth/google/callback?error=access_denied')
        .expect(302);

      expect(res.headers.location).toBe('/login?error=access_denied');
      expect(sessionCookieFrom(res)).toBeUndefined();

      const denials = await prisma.authEvent.findMany({ where: { type: 'login.denied' } });
      expect(denials).toHaveLength(1);
    });
  });
});
