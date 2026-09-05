import { createHash } from 'node:crypto';
import { env } from '../config/env.js';
import { GoogleService, randomToken } from './google.service.js';

describe('GoogleService.createAuthorizationUrl', () => {
  const service = new GoogleService();
  const params = { state: 'the-state', codeVerifier: 'the-verifier', nonce: 'the-nonce' };
  const url = service.createAuthorizationUrl(params);
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

describe('randomToken', () => {
  it('is 256 bits, base64url, and never repeats', () => {
    const token = randomToken();
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(new Set(Array.from({ length: 100 }, randomToken)).size).toBe(100);
  });
});
