import { EncryptJWT } from 'jose';
import { env } from '../config/env.js';
import { OAuthTxService, type OAuthTx } from './oauth-tx.service.js';

describe('OAuthTxService', () => {
  const service = new OAuthTxService();
  const key = new Uint8Array(Buffer.from(env.OAUTH_TX_SECRET, 'base64'));

  const tx: OAuthTx = {
    state: 'state-value',
    codeVerifier: 'verifier-value',
    nonce: 'nonce-value',
    returnTo: '/dashboard',
  };

  it('round-trips the handshake state', async () => {
    const cookie = await service.issue(tx);
    await expect(service.consume(cookie)).resolves.toEqual(tx);
  });

  it('produces a compact JWE, not a readable cookie', async () => {
    const cookie = await service.issue(tx);
    // Five dot-separated segments is the JWE compact serialisation.
    expect(cookie.split('.')).toHaveLength(5);
    // The PKCE verifier is the value that must never be legible in a cookie jar.
    expect(cookie).not.toContain('verifier-value');
    expect(cookie).not.toContain('state-value');
  });

  it.each([
    ['nothing', undefined],
    ['an empty string', ''],
    ['garbage', 'not-a-jwe'],
    ['a session token by mistake', 'GkTv9r0Xk3Qw'],
  ])('refuses %s', async (_label, raw) => {
    await expect(service.consume(raw)).resolves.toBeNull();
  });

  it('refuses a tampered ciphertext', async () => {
    const cookie = await service.issue(tx);
    const parts = cookie.split('.');
    // Flip a character in the ciphertext segment. A256GCM is authenticated, so
    // this fails to decrypt rather than yielding different claims.
    parts[3] = parts[3].startsWith('A') ? `B${parts[3].slice(1)}` : `A${parts[3].slice(1)}`;
    await expect(service.consume(parts.join('.'))).resolves.toBeNull();
  });

  it('refuses a cookie encrypted with a different key', async () => {
    const foreign = await new EncryptJWT(tx)
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setExpirationTime('10m')
      .encrypt(new Uint8Array(32).fill(9));

    await expect(service.consume(foreign)).resolves.toBeNull();
  });

  it('refuses an expired cookie even though the browser still sent it', async () => {
    const stale = await new EncryptJWT(tx)
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .encrypt(key);

    await expect(service.consume(stale)).resolves.toBeNull();
  });

  it('refuses a payload that decrypts but is the wrong shape', async () => {
    const wrong = await new EncryptJWT({ state: 'only-state' })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setExpirationTime('10m')
      .encrypt(key);

    await expect(service.consume(wrong)).resolves.toBeNull();
  });

  it('refuses a returnTo that was not a site-relative path', async () => {
    const evil = await new EncryptJWT({ ...tx, returnTo: 'https://evil.com' })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setExpirationTime('10m')
      .encrypt(key);

    await expect(service.consume(evil)).resolves.toBeNull();
  });
});
