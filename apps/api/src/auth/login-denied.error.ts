/**
 * A login that must fail closed.
 *
 * Carries a short reason code for the audit trail and the logs. The reason
 * never reaches the client: telling an attacker whether they got the state
 * wrong, the nonce wrong or the account disabled is free reconnaissance, and
 * "which of these failed" is exactly what they are probing for.
 */
export class LoginDeniedError extends Error {
  constructor(readonly reason: string) {
    super(`Login denied: ${reason}`);
    this.name = 'LoginDeniedError';
  }
}
