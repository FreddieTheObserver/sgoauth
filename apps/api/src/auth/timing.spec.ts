import { timingSafeEqualString } from './timing.js';

describe('timingSafeEqualString', () => {
  it('accepts identical strings', () => {
    expect(timingSafeEqualString('abc123', 'abc123')).toBe(true);
    expect(timingSafeEqualString('', '')).toBe(true);
  });

  it('rejects different strings of the same length', () => {
    expect(timingSafeEqualString('abc123', 'abc124')).toBe(false);
    expect(timingSafeEqualString('abc123', 'zbc123')).toBe(false);
  });

  it('rejects different lengths instead of throwing', () => {
    // timingSafeEqual itself throws on a length mismatch; a 500 on a forged
    // state would be an oracle of its own.
    expect(timingSafeEqualString('abc', 'abcd')).toBe(false);
    expect(timingSafeEqualString('', 'a')).toBe(false);
  });

  it('handles multi-byte characters by byte length', () => {
    expect(timingSafeEqualString('café', 'café')).toBe(true);
    expect(timingSafeEqualString('café', 'cafe')).toBe(false);
  });
});
