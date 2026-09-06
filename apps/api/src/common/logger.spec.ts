import { redactUrl } from './logger.js';

describe('redactUrl', () => {
  it('leaves a plain path alone', () => {
    expect(redactUrl('/auth/me')).toBe('/auth/me');
  });

  it('strips the authorization code and the state out of the callback URL', () => {
    // The one line in this file that matters. Every successful login passes
    // through /auth/google/callback carrying a live code, and a default HTTP
    // logger writes that URL out verbatim.
    const redacted = redactUrl('/auth/google/callback?code=4%2F0AY-real-code&state=abc123');

    expect(redacted).not.toContain('4/0AY-real-code');
    expect(redacted).not.toContain('abc123');
    expect(redacted).toContain('code=%5Bredacted%5D');
    expect(redacted).toContain('state=%5Bredacted%5D');
  });

  it('keeps the parameter names, so a log still shows a code arrived', () => {
    expect(redactUrl('/auth/google/callback?code=x')).toMatch(/^\/auth\/google\/callback\?code=/);
  });

  it.each(['id_token', 'access_token', 'token'])('redacts %s as well', (param) => {
    expect(redactUrl(`/whatever?${param}=secret-value`)).not.toContain('secret-value');
  });

  it('leaves harmless parameters readable', () => {
    // returnTo has already been through safeReturnTo, and knowing where a login
    // was headed is exactly the sort of thing a log is for.
    expect(redactUrl('/auth/google?returnTo=%2Fsettings%2Fsessions')).toBe(
      '/auth/google?returnTo=%2Fsettings%2Fsessions',
    );
  });

  it('redacts a secret parameter without dropping its neighbours', () => {
    const redacted = redactUrl('/auth/google/callback?state=s&code=c&returnTo=%2Fx');
    expect(redacted).toContain('returnTo=%2Fx');
    expect(redacted).not.toMatch(/code=c(&|$)/);
  });

  it('survives an empty query and a repeated parameter', () => {
    // A bare trailing ? carries nothing, so it goes with the empty query.
    expect(redactUrl('/auth/me?')).toBe('/auth/me');
    // Express hands back an array for a repeated parameter; both values have to
    // go, not just the first.
    expect(redactUrl('/cb?code=a&code=b')).not.toMatch(/code=a|code=b/);
  });
});
