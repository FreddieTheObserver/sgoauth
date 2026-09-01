# sgoauth

A secure "Sign in with Google" reference implementation — **Next.js 16 + NestJS 12 + PostgreSQL**.

Built as a hardened rebuild of the usual Express/MongoDB OAuth tutorial: same user-visible feature, but with
PKCE, real ID-token verification, revocable sessions, and a test suite that proves the attacks fail.

> **Status:** planned, not yet implemented. See [`PLAN.md`](./PLAN.md) for the full design.

## Stack

| Layer | Choice |
|---|---|
| Frontend | Next.js 16 (App Router, TypeScript, Tailwind) |
| Backend | NestJS 12 (Express platform) |
| Database | PostgreSQL 18 + Prisma 7 (`PrismaPg` adapter) |
| OAuth | [`arctic`](https://arcticjs.dev) for the code exchange, [`jose`](https://github.com/panva/jose) for ID-token verification |
| Sessions | Opaque 256-bit token in an `HttpOnly __Host-` cookie; SHA-256 hash stored in Postgres |

## How it fits together

The browser only ever talks to one origin. Next.js rewrites `/api/*` to NestJS, so cookies are first-party
and there is no CORS anywhere in the project.

```
browser ──► http://localhost:3000            (Next.js)
              │ next.config.ts rewrites
              └─ /api/:path*  ──►  :4000     (NestJS → PostgreSQL)
```

## Layout

```
apps/api/        NestJS — owns the OAuth flow, sessions and database
apps/web/        Next.js — never sees a token, only cookies
packages/contracts/   shared zod schemas + types
docker-compose.yml    postgres:18
```

## Getting started

```bash
cp .env.example .env      # then fill in the Google credentials
docker compose up -d
pnpm install
pnpm --filter api prisma migrate dev
pnpm dev                  # web :3000, api :4000
```

Google Cloud Console needs an OAuth **Web application** client with:

- Authorized JavaScript origin — `http://localhost:3000`
- Authorized redirect URI — `http://localhost:3000/api/auth/google/callback`

Note the redirect URI is port **3000**, not 4000: it must be the URL the *browser* sees, and it has to match
exactly. Scopes are `openid`, `email`, `profile` — nothing more.

## Security

The design notes in [`PLAN.md`](./PLAN.md) list every control and the specific attack it stops. The short
version:

- **Authorization code + PKCE (S256)**, `state` compared in constant time, `nonce` checked against the token.
- **The ID token is verified**, not decoded — `jose.jwtVerify` against Google's JWKS, checking `iss`, `aud`,
  `exp` and the signature. Decoding without verifying means accepting forged identities.
- **`email_verified` is enforced**, and accounts are keyed on the Google `sub`, never the email address —
  emails change and can be reassigned to a different person.
- **Sessions are opaque and revocable.** Only a SHA-256 hash is stored, so a database leak yields nothing
  replayable. Logout, "log out everywhere" and bans take effect on the next request.
- **No token ever reaches JavaScript** — no `localStorage`, no client props. `HttpOnly` cookies only.
- CSRF is handled by `SameSite=Lax` plus an `Origin` check on every state-changing request.

## Licence

Not yet specified.
