/**
 * Open redirect is a classic and easy vulnerability to ship: a login flow that
 * honours `?returnTo=https://evil.com` hands an attacker a phishing page served
 * with *our* domain's authority, one click after a real Google consent screen.
 *
 * The rule is allow-list shaped rather than block-list shaped - a value is
 * rejected unless it is unambiguously a path on this site.
 */

export const DEFAULT_RETURN_TO = '/dashboard';

// Long enough for any real in-app path, short enough that nothing interesting
// fits in the Location header we echo it into.
const MAX_LENGTH = 512;

// C0 controls and DEL. CR and LF are the header-injection pair, but a bare TAB
// or NUL has its own history of making two URL parsers disagree. Written as a
// codepoint scan rather than a character class, because a regex holding literal
// control characters is invisible in a diff and unreviewable.
function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

export function safeReturnTo(raw: unknown, fallback = DEFAULT_RETURN_TO): string {
  // `unknown` rather than `string | undefined` because this reads a query
  // parameter: Express hands back an array for `?returnTo=a&returnTo=b`, and an
  // array reaching .startsWith() here would be a 500 on a hostile input.
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_LENGTH) return fallback;

  // Must be site-relative. This alone rejects "https://evil.com" and "javascript:...".
  if (!raw.startsWith('/')) return fallback;

  // "//evil.com" is protocol-relative: the browser reads it as an absolute URL
  // on evil.com. "/\evil.com" is the same trick, because browsers normalise a
  // backslash to a forward slash before parsing.
  if (raw.startsWith('//') || raw.startsWith('/\\')) return fallback;

  if (hasControlCharacter(raw)) return fallback;

  return raw;
}
