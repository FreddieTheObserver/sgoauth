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

    expect(result?.session.expiresAt).toEqual(cap);
  });

  it('does not write the expiry again when the cap leaves nothing to extend', async () => {
    const cap = at(DAY);
    const { service, update } = build(row({ expiresAt: cap, absoluteExpiresAt: cap }));
    const result = await service.validate('raw-token');

    expect(result?.session.expiresAt).toEqual(cap);
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.not.objectContaining({ expiresAt: expect.anything() }),
      }),
    );
  });
});

describe('SessionService revocation and the device list', () => {
  const at = (offsetMs: number) => new Date(Date.now() + offsetMs);

  type Where = Record<string, any>;
  type FindManyArgs = { where: Where; select: Record<string, boolean>; orderBy: Where };
  type UpdateManyArgs = { where: Where; data: Record<string, unknown> };

  const listRow = (id: string) => ({
    id,
    userAgent: 'Mozilla/5.0',
    createdAt: at(-86_400_000),
    lastUsedAt: new Date(),
    expiresAt: at(86_400_000),
  });

  const build = (rows: ReturnType<typeof listRow>[] = [], count = 1) => {
    const findMany = vi.fn(async (_args: FindManyArgs) => rows);
    const updateMany = vi.fn(async (_args: UpdateManyArgs) => ({ count }));
    const service = new SessionService({
      session: { findMany, updateMany },
    } as unknown as PrismaService);
    return { service, findMany, updateMany };
  };

  describe('listActive', () => {
    it('asks only for sessions that could still authenticate', async () => {
      const { service, findMany } = build();
      await service.listActive('u1', 's-current');

      const [args] = findMany.mock.calls[0];
      expect(args.where).toMatchObject({
        userId: 'u1',
        revokedAt: null,
        expiresAt: { gt: expect.any(Date) },
        absoluteExpiresAt: { gt: expect.any(Date) },
      });
      // Most recently used first: the row the reader is looking for is the one
      // they are least likely to recognise.
      expect(args.orderBy).toEqual({ lastUsedAt: 'desc' });
    });

    it('never reads the token hash or the IP hash', async () => {
      const { service, findMany } = build();
      await service.listActive('u1', 's-current');

      // Asserted as an exact set rather than a pair of absences, so widening
      // what the device list returns has to be a deliberate edit here too.
      const [args] = findMany.mock.calls[0];
      expect(Object.keys(args.select).sort()).toEqual([
        'createdAt',
        'expiresAt',
        'id',
        'lastUsedAt',
        'userAgent',
      ]);
    });

    it('flags the row the caller is holding as the current device', async () => {
      const { service } = build([listRow('s-current'), listRow('s-phone')]);
      const list = await service.listActive('u1', 's-current');

      expect(list.map((session) => [session.id, session.current])).toEqual([
        ['s-current', true],
        ['s-phone', false],
      ]);
    });
  });

  describe('revoke', () => {
    it('scopes the update to the owner and to a session not already revoked', async () => {
      const { service, updateMany } = build();
      await expect(service.revoke('s1', 'u1')).resolves.toBe(true);

      const [args] = updateMany.mock.calls[0];
      // userId in the WHERE is the whole ownership check: another user's id
      // matches nothing, so there is no row to act on and no read to leak one.
      expect(args.where).toEqual({ id: 's1', userId: 'u1', revokedAt: null });
      expect(args.data).toEqual({ revokedAt: expect.any(Date) });
    });

    it('reports nothing revoked when the id is not the caller’s', async () => {
      const { service } = build([], 0);
      await expect(service.revoke('someone-elses-session', 'u1')).resolves.toBe(false);
    });
  });

  describe('revokeAll', () => {
    it('closes every live session and says how many', async () => {
      const { service, updateMany } = build([], 3);
      await expect(service.revokeAll('u1')).resolves.toBe(3);

      const [args] = updateMany.mock.calls[0];
      expect(args.where).toMatchObject({
        userId: 'u1',
        revokedAt: null,
        // Already-expired rows are left alone: they cannot authenticate, and
        // stamping them would record a revocation that never happened.
        expiresAt: { gt: expect.any(Date) },
        absoluteExpiresAt: { gt: expect.any(Date) },
      });
    });

    it('selects and stamps with one reading of the clock', async () => {
      // Two readings would leave a window in which a session expires between
      // being selected and being written, and the count would then overstate
      // what was closed.
      const { service, updateMany } = build([], 1);
      await service.revokeAll('u1');

      const [args] = updateMany.mock.calls[0];
      expect(args.data.revokedAt).toEqual(args.where.expiresAt.gt);
    });
  });
});

describe('SessionService.pruneDead', () => {
  const DAY = 86_400_000;

  const build = (count = 0) => {
    const deleteMany = vi.fn(async (_args: { where: Record<string, any> }) => ({ count }));
    const service = new SessionService({ session: { deleteMany } } as unknown as PrismaService);
    return { service, deleteMany };
  };

  it('keeps a dead row for one more absolute lifetime before deleting it', () => {
    // Revoked rows are retained so the device list can tell "you revoked this"
    // from "this never existed", and so a session.revoked event still points at
    // something. Both stop mattering; SESSION_ABSOLUTE_TTL_DAYS is how long the
    // deployment already said a session can matter, reused as that window.
    const { service, deleteMany } = build();
    const now = new Date();
    void service.pruneDead(now);

    const [args] = deleteMany.mock.calls[0];
    const cutoff = new Date(now.getTime() - 30 * DAY);
    expect(args.where.OR).toEqual([{ expiresAt: { lt: cutoff } }, { revokedAt: { lt: cutoff } }]);
  });

  it('spares a session that only died today', async () => {
    // Asserted through the cutoff rather than a fixture, since the query is the
    // whole behaviour: yesterday is nowhere near 30 days ago.
    const { service, deleteMany } = build();
    await service.pruneDead(new Date());

    const [args] = deleteMany.mock.calls[0];
    const cutoff: Date = args.where.OR[0].expiresAt.lt;
    expect(cutoff.getTime()).toBeLessThan(Date.now() - 29 * DAY);
  });

  it('reports how many rows went', async () => {
    const { service } = build(7);
    await expect(service.pruneDead()).resolves.toBe(7);
  });
});
