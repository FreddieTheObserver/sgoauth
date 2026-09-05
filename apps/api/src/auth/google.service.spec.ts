import { createHash } from 'node:crypto';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWTVerifyGetKey,
  type JWK,
} from 'jose';
import { env } from '../config/env.js';
import { GoogleService, randomToken } from './google.service.js';

// A Google we control: our own RSA keypair, served as a local JWKS, so the suite
// can sign ID tokens on purpose and prove the forgeries are refused.
const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...((await exportJWK(publicKey)) as JWK), alg: 'RS256' };
const jwks = createLocalJWKSet({ keys: [jwk] });

const { privateKey: foreignKey } = await generateKeyPair('RS256', { extractable: true });

const NONCE = 'the-nonce';

const signIdToken = async (
  claims: Record<string, unknown> = {},
  options: { key?: CryptoKey; issuer?: string; audience?: string; expired?: boolean } = {},
) => {
  const token = new SignJWT({
    email: 'ada@example.com',
    email_verified: true,
    name: 'Ada Lovelace',
    picture: 'https://example.com/ada.png',
    nonce: NONCE,
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject((claims.sub as string) ?? 'google-sub-123')
    .setIssuer(options.issuer ?? 'https://accounts.google.com')
    .setAudience(options.audience ?? env.GOOGLE_CLIENT_ID)
    .setIssuedAt(options.expired ? Math.floor(Date.now() / 1000) - 7200 : undefined)
    .setExpirationTime(options.expired ? Math.floor(Date.now() / 1000) - 3600 : '5m');

  return token.sign(options.key ?? privateKey);
};

describe('GoogleService.createAuthorizationUrl', () => {
  const service = new GoogleService(jwks);
  const url = service.createAuthorizationUrl({
    state: 'the-state',
    codeVerifier: 'the-verifier',
    nonce: 'the-nonce',
  });
  const query = url.searchParams;

  it('points at Google', () => {
    expect(url.origin).toBe('https://accounts.google.com');
    expect(url.pathname).toBe('/o/oauth2/v2/auth');
  });

  it('carries the client and the browser-visible redirect uri', () => {
    expect(query.get('client_id')).toBe(env.GOOGLE_CLIENT_ID);
    expect(query.get('redirect_uri')).toBe(env.GOOGLE_REDIRECT_URI);
    expect(query.get('response_type')).toBe('code');
  });

  it('requests only openid, email and profile', () => {
    expect(query.get('scope')).toBe('openid email profile');
  });

  it('carries state and nonce verbatim', () => {
    expect(query.get('state')).toBe('the-state');
    expect(query.get('nonce')).toBe('the-nonce');
  });

  it('sends the S256 challenge and never the verifier itself', () => {
    expect(query.get('code_challenge_method')).toBe('S256');
    expect(query.get('code_challenge')).toBe(
      createHash('sha256').update('the-verifier').digest('base64url'),
    );
    expect(url.toString()).not.toContain('the-verifier');
  });

  it('forces the account chooser', () => {
    expect(query.get('prompt')).toBe('select_account');
  });

  it('never asks for offline access', () => {
    // A refresh token we never requested is a credential we can never leak.
    expect(query.get('access_type')).toBeNull();
    expect(query.has('approval_prompt')).toBe(false);
  });

  it('omits hd when no workspace domain is configured', () => {
    expect(query.get('hd')).toBe(env.ALLOWED_HD ?? null);
  });
});

describe('GoogleService.verifyIdToken', () => {
  const service = new GoogleService(jwks);

  it('accepts a properly signed token and returns the identity', async () => {
    const identity = await service.verifyIdToken(await signIdToken(), NONCE);

    expect(identity).toEqual({
      sub: 'google-sub-123',
      email: 'ada@example.com',
      name: 'Ada Lovelace',
      avatarUrl: 'https://example.com/ada.png',
    });
  });

  it('refuses a token signed by the wrong key', async () => {
    // The whole trust anchor: a token that is well-formed and has every correct
    // claim is still worthless without Google's signature.
    const forged = await signIdToken({}, { key: foreignKey });
    await expect(service.verifyIdToken(forged, NONCE)).resolves.toBeNull();
  });

  it('refuses a token minted for a different client', async () => {
    const other = await signIdToken({}, { audience: 'someone-else.apps.googleusercontent.com' });
    await expect(service.verifyIdToken(other, NONCE)).resolves.toBeNull();
  });

  it('refuses a token from the wrong issuer', async () => {
    const other = await signIdToken({}, { issuer: 'https://accounts.evil.com' });
    await expect(service.verifyIdToken(other, NONCE)).resolves.toBeNull();
  });

  it('accepts both spellings of the Google issuer', async () => {
    const bare = await signIdToken({}, { issuer: 'accounts.google.com' });
    await expect(service.verifyIdToken(bare, NONCE)).resolves.not.toBeNull();
  });

  it('refuses an expired token', async () => {
    const stale = await signIdToken({}, { expired: true });
    await expect(service.verifyIdToken(stale, NONCE)).resolves.toBeNull();
  });

  it('refuses a nonce that does not match the handshake', async () => {
    const replayed = await signIdToken({ nonce: 'a-different-handshake' });
    await expect(service.verifyIdToken(replayed, NONCE)).resolves.toBeNull();
  });

  it('refuses a token with no nonce at all', async () => {
    const noNonce = await signIdToken({ nonce: undefined });
    await expect(service.verifyIdToken(noNonce, NONCE)).resolves.toBeNull();
  });

  it.each([
    ['false', false],
    ['the string "true"', 'true'],
    ['missing', undefined],
  ])('refuses an email_verified of %s', async (_label, value) => {
    // Strictly boolean true. Google sends a boolean in ID tokens; anything else
    // is a different document than the one we decided to trust.
    const token = await signIdToken({ email_verified: value });
    await expect(service.verifyIdToken(token, NONCE)).resolves.toBeNull();
  });

  it('refuses a token with no subject', async () => {
    const token = await new SignJWT({ email: 'ada@example.com', email_verified: true, nonce: NONCE })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('https://accounts.google.com')
      .setAudience(env.GOOGLE_CLIENT_ID)
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(service.verifyIdToken(token, NONCE)).resolves.toBeNull();
  });

  it('refuses garbage', async () => {
    await expect(service.verifyIdToken('not-a-jwt', NONCE)).resolves.toBeNull();
    await expect(service.verifyIdToken('', NONCE)).resolves.toBeNull();
  });

  it('tolerates a missing name and picture', async () => {
    const sparse = await signIdToken({ name: undefined, picture: undefined });
    await expect(service.verifyIdToken(sparse, NONCE)).resolves.toEqual({
      sub: 'google-sub-123',
      email: 'ada@example.com',
      name: null,
      avatarUrl: null,
    });
  });
});

describe('GoogleService.exchangeCode', () => {
  const service = new GoogleService({} as JWTVerifyGetKey);

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const stubFetch = (impl: (url: string, init: RequestInit) => Promise<Response> | Response) => {
    const spy = vi.fn(impl);
    vi.stubGlobal('fetch', spy);
    return spy;
  };

  it('posts the code and the PKCE verifier, and returns the id_token', async () => {
    const spy = stubFetch(() => Response.json({ id_token: 'the-id-token' }));

    await expect(service.exchangeCode('the-code', 'the-verifier')).resolves.toBe('the-id-token');

    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://oauth2.googleapis.com/token');
    expect(init.method).toBe('POST');

    const body = new URLSearchParams(String(init.body));
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('the-code');
    expect(body.get('code_verifier')).toBe('the-verifier');
    expect(body.get('redirect_uri')).toBe(env.GOOGLE_REDIRECT_URI);
    expect(body.get('client_secret')).toBe(env.GOOGLE_CLIENT_SECRET);
  });

  it('returns null when Google rejects the code', async () => {
    stubFetch(() => Response.json({ error: 'invalid_grant' }, { status: 400 }));
    await expect(service.exchangeCode('used-code', 'verifier')).resolves.toBeNull();
  });

  it('returns null when the response carries no id_token', async () => {
    stubFetch(() => Response.json({ access_token: 'only-this' }));
    await expect(service.exchangeCode('code', 'verifier')).resolves.toBeNull();
  });

  it('returns null when Google cannot be reached', async () => {
    stubFetch(() => Promise.reject(new Error('ECONNREFUSED')));
    await expect(service.exchangeCode('code', 'verifier')).resolves.toBeNull();
  });

  it('returns null on an unparseable body', async () => {
    stubFetch(() => new Response('<html>502</html>', { status: 200 }));
    await expect(service.exchangeCode('code', 'verifier')).resolves.toBeNull();
  });
});

describe('randomToken', () => {
  it('is 256 bits, base64url, and never repeats', () => {
    const token = randomToken();
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(new Set(Array.from({ length: 100 }, randomToken)).size).toBe(100);
  });
});
