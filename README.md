# sgoauth

A secure "Sign in with Google" reference implementation — **Next.js 16 + NestJS 12 + PostgreSQL**.

Built as a hardened rebuild of the usual Express/MongoDB OAuth tutorial: same user-visible feature, but with
PKCE, real ID-token verification, revocable sessions, and a test suite that proves the attacks fail.

> **Status:** the login flow works end to end. Layers 0–3 of [`PLAN.md`](./PLAN.md) — schema, backend,
> frontend — are built and verified against a running stack. Layer 4 is outstanding: the shared
> `packages/contracts` schema, security headers on the Next side, and `SECURITY.md`.

## Stack

| Layer | Choice |
|---|---|
| Frontend | Next.js 16 (App Router, TypeScript, Tailwind) |
| Backend | NestJS 12 (Express platform) |
| Database | PostgreSQL 18 + Prisma 7 (`PrismaPg` adapter) |
| OAuth | PKCE, the authorization URL and the code exchange written out here rather than taken from a library; [`jose`](https://github.com/panva/jose) for ID-token verification |
| Sessions | Opaque 256-bit token in an `HttpOnly __Host-` cookie; SHA-256 hash stored in Postgres |

The code exchange is about sixty lines and has no dependency behind it. That is deliberate: this project
exists to keep the security-critical steps visible in a diff, and the library that would otherwise cover
them is unmaintained. [`PLAN.md`](./PLAN.md) has the full reasoning.

## How it fits together

The browser only ever talks to one origin. Next.js rewrites `/api/*` to NestJS, so cookies are first-party
and there is no CORS anywhere in the project.

```
browser ──► http://localhost:3000            (Next.js)
              │ next.config.ts rewrites
              └─ /api/:path*  ──►  :4000     (NestJS → PostgreSQL)
```

## What works today

Sign in at `/login`, land on `/dashboard`, review your devices and sign any of them out at
`/settings/sessions`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/google` | Start the handshake → 302 to Google |
| GET | `/auth/google/callback` | Verify, upsert, mint the session → 302 into the app |
| GET | `/auth/me` | The session user, or 401 |
| GET | `/auth/sessions` | Device list |
| POST | `/auth/logout` | Revoke this session, clear the cookie |
| POST | `/auth/logout-all` | Revoke every session for the user |
| DELETE | `/auth/sessions/:id` | Revoke one, ownership-checked |
| GET | `/health` | Readiness, including the database |

Paths are as NestJS mounts them. The browser reaches each one under `/api`, and never learns the API
exists.

## Layout

```
apps/api/        NestJS — owns the OAuth flow, sessions and database
apps/web/        Next.js — never sees a token, only cookies
packages/contracts/   shared zod schemas + types (Layer 4, not yet populated)
docker-compose.yml    postgres:18
```

## Getting started

```bash
cp .env.example .env      # then fill in the Google credentials
pnpm db:up                # docker compose up -d
pnpm install
pnpm --filter api db:migrate
pnpm dev                  # web :3000, api :4000
```

`pnpm dev` runs the two apps. Postgres is separate — `pnpm db:up` and `pnpm db:down`.

Google Cloud Console needs an OAuth **Web application** client with:

- Authorized JavaScript origin — `http://localhost:3000`
- Authorized redirect URI — `http://localhost:3000/api/auth/google/callback`

Note the redirect URI is port **3000**, not 4000: it must be the URL the *browser* sees, and it has to match
exactly. Scopes are `openid`, `email`, `profile` — nothing more.

## Tests

```bash
pnpm --filter api test        # unit
pnpm --filter api test:e2e    # end to end — needs Postgres up
```

The e2e suite mocks Google with a keypair it owns, so it can forge ID tokens on purpose and assert that each
attack is refused: a forged or missing `state`, a tampered handshake cookie, a replayed code, a token signed
with the wrong key, a wrong `aud` or `iss`, a mismatched `nonce`, `email_verified: false`, an off-site
`returnTo`, a revoked or expired session, a state-changing request from a foreign origin, and one user
reaching for another's session id.

## Security

The design notes in [`PLAN.md`](./PLAN.md) list every control and the specific attack it stops. The short
version:

- **Authorization code + PKCE (S256)**, `state` compared in constant time, `nonce` checked against the token.
- **The ID token is verified**, not decoded — `jose.jwtVerify` against Google's JWKS, checking `iss`, `aud`,
  `exp`, the signature and a pinned algorithm. Decoding without verifying means accepting forged identities.
- **`email_verified` is enforced**, and accounts are keyed on the Google `sub`, never the email address —
  emails change and can be reassigned to a different person.
- **Sessions are opaque and revocable.** Only a SHA-256 hash is stored, so a database leak yields nothing
  replayable. Logout, "log out everywhere" and bans take effect on the next request. Every session carries
  both a sliding expiry and an absolute cap it can never be extended past.
- **No token ever reaches JavaScript** — no `localStorage`, no client props. `HttpOnly` cookies only.
- CSRF is handled by `SameSite=Lax` plus an `Origin` check on every state-changing request.
- **Errors say only their status code.** Which check failed goes to the logs; the client is told nothing it
  could use to tell one failure from another.
- **Logs hold no credentials.** Cookies and the callback's `code` and `state` are redacted, and client
  addresses are stored as a salted hash rather than kept.
- **A global rate limit** covers the API, with a much tighter one on the handshake, where login attempts
  and callback flooding arrive.
- **`AuthEvent` is append-only** — logins, denials, account links and revocations, with hashed IPs and a
  reason code, and never a token.

## Licence

Not yet specified.
