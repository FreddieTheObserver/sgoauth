import { createHash } from 'node:crypto';
import type { PrismaService } from '../prisma/prisma.service.js';
import { SessionService, hashSessionToken } from './session.service.js';

describe('SessionService.validate', () => {
  const HOUR = 3_600_000;
  const DAY = 24 * HOUR;
  const now = Date.now();
  const at = (offsetMs: number) => new Date(now + offsetMs);

  type Row = ReturnType<typeof row>;

  const row = (overrides: Record<string, unknown> = {}) => ({
    id: 's1',
    expiresAt: at(6 * DAY),
    absoluteExpiresAt: at(29 * DAY),
    revokedAt: null as Date | null,
    ...overrides,
    user: {
      id: 'u1',
      email: 'a@example.com',
      name: 'Ada',
      avatarUrl: null,
      role: 'USER' as const,
      disabledAt: null as Date | null,
      ...(overrides.user as object | undefined),
    },
  });

  const build = (found: Row | null) => {
    const findUnique = vi.fn(async (_args: { where: { tokenHash: Uint8Array } }) => found);
    const update = vi.fn(async (_args: { data: Record<string, unknown> }) => ({}));
    const service = new SessionService({
      session: { findUnique, update },
    } as unknown as PrismaService);
    return { service, findUnique, update };
  };

  it('looks the session up by the hash, never by the token', async () => {
    const { service, findUnique } = build(row());
    await service.validate('raw-token');

    const [args] = findUnique.mock.calls[0];
    expect(Buffer.from(args.where.tokenHash)).toEqual(
      createHash('sha256').update('raw-token').digest(),
    );
    expect(JSON.stringify(args)).not.toContain('raw-token');
  });

  it('produces a 32-byte digest', () => {
    expect(hashSessionToken('x')).toHaveLength(32);
  });

  it('returns the narrowed user for a live session', async () => {
    const { service, update } = build(row());
    const result = await service.validate('raw-token');

    expect(result?.user).toEqual({
      id: 'u1',
      email: 'a@example.com',
      name: 'Ada',
      avatarUrl: null,
      role: 'USER',
    });
    // disabledAt is an internal column and must not ride along on every request.
    expect(result?.user).not.toHaveProperty('disabledAt');
    expect(result?.session.id).toBe('s1');
    expect(result?.renewed).toBe(false);
    // Well inside the window: lastUsedAt moves, the expiry does not.
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.not.objectContaining({ expiresAt: expect.anything() }),
      }),
    );
  });

  it.each([
    ['an unknown token', null],
    ['a revoked session', row({ revokedAt: at(-HOUR) })],
    ['an idle-expired session', row({ expiresAt: at(-HOUR) })],
    ['a session past its absolute cap', row({ expiresAt: at(DAY), absoluteExpiresAt: at(-HOUR) })],
    ['a disabled user', row({ user: { disabledAt: at(-HOUR) } })],
  ])('refuses %s', async (_label, found) => {
    const { service, update } = build(found as Row | null);
    await expect(service.validate('raw-token')).resolves.toBeNull();
    // A rejected session must not have its lifetime touched on the way out.
    expect(update).not.toHaveBeenCalled();
  });

  it('refuses an empty token without querying', async () => {
    const { service, findUnique } = build(row());
    await expect(service.validate('')).resolves.toBeNull();
    expect(findUnique).not.toHaveBeenCalled();
  });

  it('slides the window once less than half the TTL remains', async () => {
    const { service, update } = build(row({ expiresAt: at(2 * DAY) }));
    const result = await service.validate('raw-token');

    expect(result?.renewed).toBe(true);
    // A fresh full TTL from now, not an increment on the old expiry.
    expect(result?.session.expiresAt.getTime()).toBeGreaterThan(now + 6.9 * DAY);
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ expiresAt: result?.session.expiresAt }),
      }),
    );
  });

  it('never slides past the absolute cap', async () => {
    const cap = at(2 * DAY);
    const { service } = build(row({ expiresAt: at(DAY), absoluteExpiresAt: cap }));
    const result = await service.validate('raw-token');

    expect(result?.renewed).toBe(true);
    expect(result?.session.expiresAt).toEqual(cap);
  });

  it('does not re-set the cookie when the cap leaves nothing to extend', async () => {
    const cap = at(DAY);
    const { service, update } = build(row({ expiresAt: cap, absoluteExpiresAt: cap }));
    const result = await service.validate('raw-token');

    expect(result?.renewed).toBe(false);
    expect(result?.session.expiresAt).toEqual(cap);
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.not.objectContaining({ expiresAt: expect.anything() }),
      }),
    );
  });
});
