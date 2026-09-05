import { Injectable, Logger } from '@nestjs/common';
import { EncryptJWT, jwtDecrypt } from 'jose';
import { z } from 'zod';
import { env } from '../config/env.js';

/**
 * The handshake state, carried in one encrypted cookie.
 *
 * One encrypted cookie beats three plaintext ones. It is atomic to set and to
 * clear, it is tamper-evident, and it does not leak the PKCE verifier to
 * anything that can read raw cookie values - a browser extension, a shared
 * machine, a screenshot of DevTools. The tutorial this project is based on
 * keeps the same data in an Express session, which needs a session store before
 * the user has even logged in, and gives an attacker something to fixate.
 */

const txSchema = z.object({
  state: z.string().min(1),
  codeVerifier: z.string().min(1),
  nonce: z.string().min(1),
  returnTo: z.string().startsWith('/'),
});

export type OAuthTx = z.infer<typeof txSchema>;

// `dir` means the secret IS the content-encryption key - no key wrapping, no
// asymmetric step. A256GCM is authenticated, so a flipped bit fails decryption
// rather than silently producing different claims.
const HEADER = { alg: 'dir', enc: 'A256GCM' } as const;
const LIFETIME = '10m';

@Injectable()
export class OAuthTxService {
  private readonly logger = new Logger(OAuthTxService.name);
  private readonly key = new Uint8Array(Buffer.from(env.OAUTH_TX_SECRET, 'base64'));

  issue(tx: OAuthTx): Promise<string> {
    return new EncryptJWT(tx).setProtectedHeader(HEADER).setIssuedAt().setExpirationTime(LIFETIME).encrypt(this.key);
  }

  /**
   * Decrypt and validate, or nothing. The expiry is enforced here rather than
   * trusted to the cookie's Max-Age, because Max-Age is a hint the client is
   * free to ignore - a saved cookie can be replayed a week later.
   */
  async consume(raw: string | undefined): Promise<OAuthTx | null> {
    if (!raw) return null;

    try {
      const { payload } = await jwtDecrypt(raw, this.key, {
        contentEncryptionAlgorithms: [HEADER.enc],
        keyManagementAlgorithms: [HEADER.alg],
      });
      return txSchema.parse(payload);
    } catch (error) {
      // Expected whenever someone tampers with the cookie, so this is a debug
      // line and not a warning - and the reason never reaches the response.
      this.logger.debug(`Rejected oauth_tx cookie: ${(error as Error).message}`);
      return null;
    }
  }
}
