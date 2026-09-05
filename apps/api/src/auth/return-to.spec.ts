import { DEFAULT_RETURN_TO, safeReturnTo } from './return-to.js';

describe('safeReturnTo', () => {
  it.each([
    ['/dashboard', '/dashboard'],
    ['/settings/sessions', '/settings/sessions'],
    ['/dashboard?tab=devices', '/dashboard?tab=devices'],
    ['/dashboard#top', '/dashboard#top'],
    ['/', '/'],
  ])('keeps the site-relative path %s', (raw, expected) => {
    expect(safeReturnTo(raw)).toBe(expected);
  });

  it.each([
    ['nothing at all', undefined],
    ['an empty string', ''],
    ['an absolute url', 'https://evil.com'],
    ['a scheme-relative url', '//evil.com'],
    ['a backslash protocol-relative url', '/\\evil.com'],
    ['a mixed slash url', '/\\/evil.com'],
    ['a javascript url', 'javascript:alert(1)'],
    ['a data url', 'data:text/html,<script>alert(1)</script>'],
    ['a bare path', 'dashboard'],
    ['a windows path', 'C:\\Windows'],
  ])('falls back on %s', (_label, raw) => {
    expect(safeReturnTo(raw)).toBe(DEFAULT_RETURN_TO);
  });

  it('rejects control characters that would split the Location header', () => {
    expect(safeReturnTo('/dashboard\r\nSet-Cookie: x=1')).toBe(DEFAULT_RETURN_TO);
    expect(safeReturnTo('/dash\nboard')).toBe(DEFAULT_RETURN_TO);
    expect(safeReturnTo('/dash\tboard')).toBe(DEFAULT_RETURN_TO);
    expect(safeReturnTo('/dash\u0000board')).toBe(DEFAULT_RETURN_TO);
    expect(safeReturnTo('/dash\u007fboard')).toBe(DEFAULT_RETURN_TO);
  });

  it('rejects anything oversized', () => {
    expect(safeReturnTo(`/${'a'.repeat(512)}`)).toBe(DEFAULT_RETURN_TO);
  });

  it('honours a caller-supplied fallback', () => {
    expect(safeReturnTo('https://evil.com', '/login')).toBe('/login');
  });
});
