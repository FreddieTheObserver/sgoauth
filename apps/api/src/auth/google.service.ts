import { createHash, randomBytes } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { env } from '../config/env.js';

const AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';

// `openid` gets us an ID token, `email` and `profile` fill it out. Nothing else:
// a scope we do not request is a permission we cannot leak.
const SCOPES = ['openid', 'email', 'profile'];

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

@Injectable()
export class GoogleService {
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
}
