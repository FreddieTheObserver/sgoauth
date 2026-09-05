import { SetMetadata } from '@nestjs/common';
import type { Role } from '../../generated/prisma/enums.js';

export const ROLES_KEY = 'roles';

/**
 * Marks a handler (or a whole controller) as requiring one of these roles.
 *
 * Typed against the Prisma enum rather than `string`, so renaming a role in the
 * schema breaks the build instead of silently making a route unreachable.
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
