import { createHash, randomBytes } from 'node:crypto';
import { Inject, Injectable, Logger, type Provider } from '@nestjs/common';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { z } from 'zod';
import { env } from '../config/env.js';
import { timingSafeEqualString } from './timing.js';

const AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs';

// Google mints tokens under both spellings and has for years. Accepting exactly
// these two is not laxness; accepting anything else would be.
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

// `openid` gets us an ID token, `email` and `profile` fill it out. Nothing else:
// a scope we do not request is a permission we cannot leak.
const SCOPES = ['openid', 'email', 'profile'];

// A remote key set created once and reused: it caches Google's keys, refetches
// on an unknown `kid` so rotation is handled, and rate-limits itself. Building
// it per request would mean an outbound fetch on every login.
export const GOOGLE_JWKS = Symbol('GOOGLE_JWKS');

export const googleJwksProvider: Provider = {
  provide: GOOGLE_JWKS,
  useFactory: (): JWTVerifyGetKey => createRemoteJWKSet(new URL(JWKS_URI)),
};

/**
 * 256 bits of CSPRNG, base64url. The shape shared by `state`, the PKCE verifier
 * and `nonce` - all three are unguessable one-shot values whose only job is to
 * be compared against themselves later.
 */
export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

/** S256, the only challenge method worth using: `plain` protects nothing. */
function codeChallenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier).digest('base64url');
}

const tokenResponseSchema = z.object({
  id_token: z.string().min(1),
});

// Only the claims we actually act on. Anything else Google sends is ignored
// rather than trusted by accident.
const idTokenClaimsSchema = z.object({
  sub: z.string().min(1),
  email: z.string().min(1),
  email_verified: z.boolean(),
  name: z.string().optional(),
  picture: z.string().optional(),
  hd: z.string().optional(),
  nonce: z.string().optional(),
});

export interface GoogleIdentity {
  /** The stable, immutable identity key. Never the email. */
  sub: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
}

@Injectable()
export class GoogleService {
  private readonly logger = new Logger(GoogleService.name);

  constructor(@Inject(GOOGLE_JWKS) private readonly jwks: JWTVerifyGetKey) {}

  /**
   * Every security-relevant parameter is set here, in the open, rather than
   * inside a library - this URL is the first half of the trust chain and it
   * should be readable in a diff.
   */
  createAuthorizationUrl(params: { state: string; codeVerifier: string; nonce: string }): URL {
    const url = new URL(AUTHORIZATION_ENDPOINT);
    const query = url.searchParams;

    query.set('client_id', env.GOOGLE_CLIENT_ID);
    // Must match the Console entry byte for byte, and it is the browser-visible
    // Next origin, not the port this API listens on.
    query.set('redirect_uri', env.GOOGLE_REDIRECT_URI);
    query.set('response_type', 'code');
    query.set('scope', SCOPES.join(' '));

    // Comes back in the query string; compared against the copy in the encrypted
    // cookie. This is what stops an attacker completing a login into their own
    // Google account in your browser.
    query.set('state', params.state);

    // Comes back inside the signed ID token, not the query string - which is
    // exactly why it defeats replay of a captured token.
    query.set('nonce', params.nonce);

    // PKCE. The verifier never leaves this server; only its hash goes to Google,
    // so a code intercepted in transit cannot be redeemed without us.
    query.set('code_challenge', codeChallenge(params.codeVerifier));
    query.set('code_challenge_method', 'S256');

    // Without this, a browser already signed into one Google account silently
    // reuses it, and "log in as someone else" becomes impossible to explain.
    query.set('prompt', 'select_account');

    // A hint to Google's account chooser only. The binding check is the verified
    // `hd` claim in the callback - a parameter the attacker also controls proves
    // nothing.
    if (env.ALLOWED_HD) query.set('hd', env.ALLOWED_HD);

    // Deliberately absent: access_type=offline. This app never calls a Google
    // API on the user's behalf, so we never want a refresh token. Nothing to
    // store means nothing to leak.

    return url;
  }

  /**
   * Redeem the authorization code. The `code_verifier` is the half of PKCE that
   * never left this server, so a code stolen in transit cannot be redeemed
   * without also stealing our handshake cookie and our client secret.
   *
   * Returns the raw ID token, or null. It is not trusted yet - it is not even
   * decoded here.
   */
  async exchangeCode(code: string, codeVerifier: string): Promise<string | null> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: env.GOOGLE_REDIRECT_URI,
    });

    let response: Response;
    try {
      response = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body,
        // A hung Google endpoint must fail the login, not hold a request open.
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      this.logger.warn(`Token exchange could not reach Google: ${(error as Error).message}`);
      return null;
    }

    if (!response.ok) {
      // Google answers with an { error, error_description } body. Only the short
      // code is logged: the full body echoes request parameters, and this is the
      // one place an authorization code could end up in a log file.
      const detail = await response
        .json()
        .then((parsed) => (parsed as { error?: string }).error ?? 'unknown')
        .catch(() => 'unparseable');
      this.logger.warn(`Token exchange rejected: ${response.status} ${detail}`);
      return null;
    }

    const parsed = tokenResponseSchema.safeParse(await response.json().catch(() => null));
    if (!parsed.success) {
      this.logger.warn('Token exchange returned no id_token');
      return null;
    }

    return parsed.data.id_token;
  }

  /**
   * The trust anchor of the entire application.
   *
   * Everything downstream - which user you are, whether an account gets linked -
   * rests on this signature check. Decoding the token instead of verifying it,
   * which is what the tutorial this project is based on effectively does, means
   * anyone who can reach the callback can claim to be anyone.
   */
  async verifyIdToken(idToken: string, expectedNonce: string): Promise<GoogleIdentity | null> {
    let payload: unknown;
    try {
      const verified = await jwtVerify(idToken, this.jwks, {
        issuer: ISSUERS,
        // Binds the token to *our* client. A token minted for another app is a
        // perfectly valid Google token and still must not log anyone in here.
        audience: env.GOOGLE_CLIENT_ID,
        // Pinned, so `alg: none` and HMAC-with-the-public-key confusion are not
        // even reachable.
        algorithms: ['RS256'],
        clockTolerance: 5,
      });
      payload = verified.payload;
    } catch (error) {
      this.logger.warn(`ID token failed verification: ${(error as Error).message}`);
      return null;
    }

    const claims = idTokenClaimsSchema.safeParse(payload);
    if (!claims.success) {
      this.logger.warn('ID token verified but is missing required claims');
      return null;
    }

    // Replay protection: this token was minted for the handshake we started, in
    // this browser, moments ago. A token captured from any other flow fails here
    // even though its signature is perfectly valid.
    if (!claims.data.nonce || !timingSafeEqualString(claims.data.nonce, expectedNonce)) {
      this.logger.warn('ID token nonce did not match the handshake');
      return null;
    }

    // Without this check, anyone able to create an unverified Google account
    // claiming your address can take over your account here. One line, and it is
    // the whole difference between an identity and a claim.
    if (claims.data.email_verified !== true) {
      this.logger.warn('ID token presented an unverified email');
      return null;
    }

    // Read from the signed claim, never from a query parameter the caller could
    // set themselves.
    if (env.ALLOWED_HD && claims.data.hd !== env.ALLOWED_HD) {
      this.logger.warn('ID token is outside the allowed workspace domain');
      return null;
    }

    return {
      sub: claims.data.sub,
      email: claims.data.email,
      name: claims.data.name ?? null,
      avatarUrl: claims.data.picture ?? null,
    };
  }
}
