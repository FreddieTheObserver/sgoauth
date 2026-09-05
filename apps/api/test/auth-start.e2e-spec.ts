import { createHash } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { OAUTH_TX_COOKIE } from '../src/auth/cookies.js';
import { OAuthTxService } from '../src/auth/oauth-tx.service.js';
import { env } from '../src/config/env.js';

describe('GET /auth/google (e2e)', () => {
  let app: INestApplication;
  let oauthTx: OAuthTxService;

  beforeAll(async () => {
    const fixture = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = fixture.createNestApplication<NestExpressApplication>();
    app.use(cookieParser());
    await app.init();
    oauthTx = app.get(OAuthTxService);
  });

  afterAll(async () => {
    await app.close();
  });

  const start = async (query = '') => {
    const res = await request(app.getHttpServer()).get(`/auth/google${query}`).expect(302);

    const setCookie = res.headers['set-cookie'] as unknown as string[];
    const txCookie = setCookie.find((c) => c.startsWith(`${OAUTH_TX_COOKIE}=`));
    if (!txCookie) throw new Error('no oauth_tx cookie was set');

    const value = txCookie.slice(`${OAUTH_TX_COOKIE}=`.length).split(';')[0];
    return {
      location: new URL(res.headers.location as string),
      txCookie,
      tx: await oauthTx.consume(decodeURIComponent(value)),
    };
  };

  it('redirects to Google with every handshake parameter', async () => {
    const { location } = await start();

    expect(location.origin).toBe('https://accounts.google.com');
    expect(location.searchParams.get('client_id')).toBe(env.GOOGLE_CLIENT_ID);
    expect(location.searchParams.get('redirect_uri')).toBe(env.GOOGLE_REDIRECT_URI);
    expect(location.searchParams.get('response_type')).toBe('code');
    expect(location.searchParams.get('scope')).toBe('openid email profile');
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
    expect(location.searchParams.get('prompt')).toBe('select_account');
    expect(location.searchParams.get('access_type')).toBeNull();
  });

  it('sets one encrypted, single-use handshake cookie', async () => {
    const { txCookie } = await start();

    expect(txCookie).toContain('HttpOnly');
    expect(txCookie).toContain('Secure');
    expect(txCookie).toContain('SameSite=Lax');
    expect(txCookie).toContain('Path=/');
    expect(txCookie).toContain('Max-Age=600');
  });

  it('binds the cookie to the redirect: same state, same nonce, matching challenge', async () => {
    const { location, tx } = await start();

    expect(tx).not.toBeNull();
    expect(location.searchParams.get('state')).toBe(tx?.state);
    expect(location.searchParams.get('nonce')).toBe(tx?.nonce);
    expect(location.searchParams.get('code_challenge')).toBe(
      createHash('sha256')
        .update(tx?.codeVerifier ?? '')
        .digest('base64url'),
    );
  });

  it('never puts the code verifier on the wire', async () => {
    const { location, txCookie, tx } = await start();

    expect(location.toString()).not.toContain(tx?.codeVerifier);
    expect(txCookie).not.toContain(tx?.codeVerifier);
  });

  it('issues fresh values on every attempt', async () => {
    const [first, second] = [await start(), await start()];

    expect(first.tx?.state).not.toBe(second.tx?.state);
    expect(first.tx?.nonce).not.toBe(second.tx?.nonce);
    expect(first.tx?.codeVerifier).not.toBe(second.tx?.codeVerifier);
  });

  it('keeps a site-relative returnTo', async () => {
    const { tx } = await start('?returnTo=/settings/sessions');
    expect(tx?.returnTo).toBe('/settings/sessions');
  });

  it.each([
    ['//evil.com', '?returnTo=//evil.com'],
    ['https://evil.com', '?returnTo=https%3A%2F%2Fevil.com'],
    ['a repeated parameter', '?returnTo=/ok&returnTo=//evil.com'],
  ])('refuses %s and falls back to the dashboard', async (_label, query) => {
    const { tx } = await start(query);
    expect(tx?.returnTo).toBe('/dashboard');
  });
});
