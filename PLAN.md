# Secure Google OAuth 2.0 login — Next.js 16 + NestJS 12 + PostgreSQL

## Context

`sgoauth` starts empty. The goal is a production-shaped "Sign in with Google" that follows the
structure of the Express/MongoDB tutorial this project is based on, but rebuilt on NestJS + PostgreSQL
and hardened well past what that tutorial does.

The tutorial's flow is functional but has real gaps: no PKCE, no ID-token signature verification, no
`email_verified` check, accounts keyed on email, `state` kept in an Express session, tokens minted as
long-lived JWTs in cookies, and no revocation path. Each of those is a concrete vulnerability, not a
style preference. This plan builds the same user-visible feature — click button, land on a dashboard as
yourself — on top of controls that hold up, and keeps the security-critical steps *visible in our code*
rather than buried in a Passport strategy, so the reasoning is learnable and auditable.

Outcome: a monorepo you can `pnpm dev` into a working login, with a test suite that proves the attacks
fail, and a schema that makes GitHub/Microsoft login or passkeys an additive change later.

## Decisions locked in

| Decision | Choice |
|---|---|
| Session credential | Opaque 256-bit token in cookie; SHA-256 hash stored in Postgres |
| Topology | Single origin — Next rewrites `/api/*` → NestJS. No CORS. `__Host-` cookies, `SameSite=Lax` |
| OAuth mechanics | Our own PKCE + code exchange (~60 lines) + `jose` for explicit ID-token verification |
| Scope | Core login + session/device management + security test suite + hardening layer + RBAC & audit log |

Version notes worth knowing up front, all verified against the registry/docs at time of writing:

- **`npm i prisma` currently installs `8.0.0-rc`** — the `latest` dist-tag points at a release candidate.
  Pin `prisma@7.10.0` and `@prisma/client@7.10.0` explicitly.
- **Next.js 16 renamed `middleware.ts` → `proxy.ts`** (`export function proxy(request)`), and it now runs on
  the **Node.js runtime**. `middleware.ts` is deprecated.
- **`arctic` is deprecated** — npm reports "Package no longer supported" on 3.7.0, which is itself the
  `latest` tag, so there is no patched version to move to. An unmaintained dependency on the code-exchange
  path gets no security fixes, and what it was doing for us is PKCE generation, one URL builder and one
  `POST` to Google's token endpoint. We write those ourselves: ~60 lines, no dependency, and it suits the
  project's own goal of keeping the security-critical steps visible rather than buried in a library.
  `openid-client` is the maintained alternative and the better call for a team that does not want to own
  this code — it just hides exactly the steps this project exists to make legible.
- **The ID token must be verified, not decoded.** `jose.jwtVerify` against Google's JWKS is the trust
  anchor and the single most important line of code in the project. `jose` stays: actively maintained,
  and the piece we would never hand-roll.
- Prisma 7: `datasource db { provider = "postgresql" }` carries **no `url`** — the connection string lives in
  `prisma.config.ts` and the `PrismaPg` adapter.

---

## Repo layout

```
sgoauth/
├─ apps/
│  ├─ api/          NestJS 12  (owns the OAuth flow, sessions, Postgres)
│  └─ web/          Next.js 16 App Router (never sees a token; only cookies)
├─ packages/
│  └─ contracts/    shared zod schemas + inferred TS types (SessionUser, etc.)
├─ docker-compose.yml    postgres:18
├─ pnpm-workspace.yaml
├─ .env.example
└─ SECURITY.md      threat model + why each control exists
```

Single origin is the backbone of the whole design:

```
browser ──► http://localhost:3000            (Next 16)
              │ next.config.ts rewrites
              └─ /api/:path*  ──►  http://localhost:4000  (NestJS)
```

The browser never learns the API exists. Cookies are first-party, no CORS is configured anywhere, and
Google's registered `redirect_uri` is the **browser-visible** `http://localhost:3000/api/auth/google/callback`
while Nest's route is `/auth/google/callback`. Nest therefore needs `APP_ORIGIN` and `GOOGLE_REDIRECT_URI`
in config — it cannot infer them from the incoming request.

---

## Layer 0 — Scaffold & infra

- `pnpm-workspace.yaml`; root scripts `dev` / `build` / `test` fanning out to both apps.
- `docker-compose.yml`: `postgres:18`, named volume, healthcheck, non-default password from `.env`.
- `.env.example` committed, `.env` gitignored. `.gitignore` covers `.env*`, `dist`, `.next`, `generated`.
- `apps/api`: `nest new` (Nest 12, Express platform). `apps/web`: `create-next-app` (App Router, TS, Tailwind).

Env contract (`.env.example`) — every one of these is validated at boot in Layer 2:

```
NODE_ENV=development
APP_ORIGIN=http://localhost:3000
API_PORT=4000
DATABASE_URL=postgresql://app:...@localhost:5432/sgoauth?schema=public
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/google/callback
OAUTH_TX_SECRET=              # 32 bytes base64 — encrypts the handshake cookie
IP_HASH_SALT=                 # 32 bytes base64 — we store hashed IPs, not raw
SESSION_TTL_DAYS=7            # sliding
SESSION_ABSOLUTE_TTL_DAYS=30  # hard cap, never extended
COOKIE_PREFIX=__Host-         # see localhost note below
ALLOWED_HD=                   # optional: lock to one Google Workspace domain
```

> **`__Host-` on localhost:** the prefix requires the `Secure` attribute. Chrome and Firefox treat
> `http://localhost` as a secure context and accept it; Safari historically does not. `COOKIE_PREFIX` exists
> so dev can fall back to an unprefixed name — and production **must** be `__Host-`, enforced by the env
> validator. If you want parity, `mkcert` for local HTTPS is the cleaner fix.

---

## Layer 1 — Schema (`apps/api/prisma/schema.prisma`)

Generator `provider = "prisma-client"` with an explicit `output = "../src/generated/prisma"`,
`prisma.config.ts` holding `datasource.url`, `datasource db { provider = "postgresql" }`.

```prisma
enum Role { USER ADMIN }

model User {
  id              String    @id @default(cuid(2))
  email           String    @unique
  emailVerifiedAt DateTime?
  name            String?
  avatarUrl       String?
  role            Role      @default(USER)
  disabledAt      DateTime?
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt
  accounts        OAuthAccount[]
  sessions        Session[]
  events          AuthEvent[]
}

model OAuthAccount {
  id                String   @id @default(cuid(2))
  userId            String
  provider          String              // "google" — generic on purpose
  providerAccountId String              // Google `sub`. THE identity key. Never the email.
  email             String?             // snapshot for display/audit only
  refreshTokenEnc   Bytes?              // AES-256-GCM, only if offline access is ever enabled
  createdAt         DateTime @default(now())
  user              User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  @@unique([provider, providerAccountId])
  @@index([userId])
}

model Session {
  id                String    @id @default(cuid(2))
  userId            String
  tokenHash         Bytes     @unique   // sha256(cookie value) — the raw token is never stored
  userAgent         String?
  ipHash            String?
  createdAt         DateTime  @default(now())
  lastUsedAt        DateTime  @default(now())
  expiresAt         DateTime              // sliding
  absoluteExpiresAt DateTime              // hard cap
  revokedAt         DateTime?
  user              User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  @@index([userId])
  @@index([expiresAt])
}

model AuthEvent {                          // append-only; never updated or deleted by app code
  id        String   @id @default(cuid(2))
  userId    String?
  type      String   // login.success | login.denied | session.revoked | account.linked | ...
  ipHash    String?
  userAgent String?
  detail    Json?
  createdAt DateTime @default(now())
  user      User?    @relation(fields: [userId], references: [id], onDelete: SetNull)
  @@index([userId, createdAt])
}
```

Two schema choices carry most of the security weight:

- **`@@unique([provider, providerAccountId])` is the identity key, not `email`.** Google emails can change,
  and a Workspace domain that lapses can have addresses reassigned to a new owner — keying on email is a
  documented account-takeover path. `sub` is stable and immutable.
- **`tokenHash` is `Bytes`, not the token.** A database leak yields hashes of high-entropy random values,
  which are not reversible and not replayable. Plain SHA-256 is correct here precisely *because* the input
  has 256 bits of entropy — bcrypt/argon2 would only add latency to every request.

Then: `prisma migrate dev --name init`.

---

## Layer 2 — Backend (`apps/api/src`)

```
main.ts                     helmet, cookie-parser, trust proxy, enableShutdownHooks()
config/env.ts               zod schema → fail fast at boot
prisma/prisma.service.ts    PrismaPg adapter, onModuleInit/onModuleDestroy
common/
  guards/csrf-origin.guard.ts   global; Origin / Sec-Fetch-Site check on every non-GET
  guards/session.guard.ts       hash cookie → one indexed lookup → req.user
  guards/roles.guard.ts         + @Roles(Role.ADMIN)
  decorators/current-user.ts
  filters/all-exceptions.filter.ts   generic messages out, detail to logs only
  logger.ts                     pino, redacting cookie / set-cookie / authorization / code
auth/
  auth.controller.ts
  google.service.ts           PKCE + code exchange + jose ID-token verification
  oauth-tx.service.ts         the encrypted handshake cookie
  session.service.ts          mint / validate / slide / revoke
  account.service.ts          upsert + linking rules
  cookies.ts                  ONE place that builds cookie options
  return-to.ts                open-redirect-safe returnTo
users/  health/  audit/
```

### Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/google` | Start handshake → 302 to Google |
| GET | `/auth/google/callback` | Verify, upsert, mint session → 302 to app |
| GET | `/auth/me` | Session user DTO, or 401 |
| POST | `/auth/logout` | Revoke this session, clear cookie |
| POST | `/auth/logout-all` | Revoke every session for the user |
| GET | `/auth/sessions` | Device list |
| DELETE | `/auth/sessions/:id` | Revoke one (ownership-checked) |

### `GET /auth/google`

1. `state`, `codeVerifier` and `nonce`, each `base64url(randomBytes(32))` from `crypto`.
2. Build the authorization URL: `client_id`, `redirect_uri`, `response_type=code`,
   `scope=openid email profile`, `state`, `nonce`, `prompt=select_account`, `hd` if `ALLOWED_HD` is
   configured, and PKCE — `code_challenge = base64url(sha256(codeVerifier))`, `code_challenge_method=S256`.
3. **Do not send `access_type=offline`.** For a login-only app we never want a Google refresh token —
   nothing to store means nothing to leak. Gate it behind a future flag if Google API access is ever added.
4. Set **one** `__Host-oauth_tx` cookie: a `jose` `EncryptJWT` (`dir` + `A256GCM`, key from `OAUTH_TX_SECRET`)
   holding `{ state, codeVerifier, nonce, returnTo }`, `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`.
   One encrypted cookie beats three plaintext ones: it is atomic to clear, tamper-evident, and doesn't leak
   the PKCE verifier to anything that can read raw cookie values.
5. 302 to Google.

`SameSite=Lax` is required and sufficient here — Google's callback is a top-level GET navigation, which
carries Lax cookies; `Strict` would drop them and break the flow.

### `GET /auth/google/callback` — the security-critical path, in order

1. If Google returned `?error=` (user hit Cancel) → log `login.denied`, 302 to `/login?error=access_denied`.
2. Read and decrypt `__Host-oauth_tx`; **clear the cookie immediately** — it is strictly single-use.
   Missing or undecryptable → 403.
3. `crypto.timingSafeEqual(state_from_cookie, state_from_query)` → mismatch is 403. This is the CSRF /
   login-fixation defense: an attacker cannot make you log into *their* Google account.
4. `POST https://oauth2.googleapis.com/token` with the code, `code_verifier`, client credentials and
   `grant_type=authorization_code` — PKCE binds the code to the browser that started the flow, so an
   intercepted code is useless on its own.
5. **Verify the ID token.** Not optional, not `decodeIdToken`:
   ```ts
   // module-level: caches keys and handles rotation
   const JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

   const { payload } = await jwtVerify(tokens.idToken(), JWKS, {
     issuer: ['https://accounts.google.com', 'accounts.google.com'],
     audience: env.GOOGLE_CLIENT_ID,
     algorithms: ['RS256'],
     clockTolerance: 5,
   });
   ```
   Then assert, in code: `payload.nonce === tx.nonce` (replay protection),
   `payload.email_verified === true` (**without this, anyone who can create an unverified Google account
   claiming your email can take over your account**), and `payload.hd === ALLOWED_HD` when configured —
   from the *claim*, never from a query parameter.
6. `account.service` upsert, in a transaction:
   - `OAuthAccount` on `(provider:'google', providerAccountId: sub)` exists → use its user.
   - Else if a `User` with that email exists → link **only if** the incoming `email_verified` is true *and*
     the existing user's `emailVerifiedAt` is set. Otherwise create a separate account. This blocks
     pre-hijacking, where an attacker seeds an account at your address before you ever sign up.
   - Else create user + account. Refresh `name`/`avatarUrl` on each login.
   - Reject if `user.disabledAt` is set.
7. Mint the session (below), set `__Host-sid`, write `login.success` to `AuthEvent`.
8. **302 to `safeReturnTo(tx.returnTo)`** so the authorization code leaves the address bar and browser
   history rather than sitting there.

### Session service

- `token = base64url(randomBytes(32))` from `crypto` — 256 bits, CSPRNG.
- Persist `sha256(token)`, `userAgent`, `ipHash = sha256(IP + IP_HASH_SALT)`, `expiresAt = now + TTL`,
  `absoluteExpiresAt = now + ABSOLUTE_TTL`.
- Cookie `__Host-sid`: `HttpOnly; Secure; SameSite=Lax; Path=/`.
- **Validate:** hash the cookie → one indexed lookup → reject if `revokedAt`, past `expiresAt`, past
  `absoluteExpiresAt`, or the user is disabled. Update `lastUsedAt`.
- **Slide:** when less than half the TTL remains, extend `expiresAt` (never past `absoluteExpiresAt`) and
  re-set the cookie. Idle sessions die; active ones don't nag; nothing lives forever.
- **Revoke:** set `revokedAt`; never delete. `validate` already rejects on it, so the effect lands on the
  very next request either way — but the device list needs to tell "you revoked this" apart from "this row
  never existed", an `AuthEvent` of `session.revoked` is only correlatable while its session survives, and
  "log out everywhere" becomes one `updateMany` rather than a delete racing the cascade. The leftover
  `tokenHash` is a SHA-256 of a token the browser no longer holds, so retention costs nothing.
- `@nestjs/schedule` job prunes expired and revoked rows together.

### `return-to.ts` — open redirect

A classic and easy vuln to ship. Reject anything that isn't a site-relative path:

```ts
export function safeReturnTo(raw: string | undefined, fallback = '/dashboard') {
  if (!raw || !raw.startsWith('/')) return fallback;
  if (raw.startsWith('//') || raw.startsWith('/\\')) return fallback; // protocol-relative → evil.com
  if (/[\r\n]/.test(raw)) return fallback;                            // header injection
  return raw;
}
```

### Hardening layer

- **`config/env.ts`** — zod-parsed at boot, process exits on failure. Asserts minimum secret lengths and
  that `NODE_ENV=production` implies `https://` origin and `COOKIE_PREFIX=__Host-`. A missing secret should
  crash the app, never silently degrade to an insecure default.
- **CSRF** — a global `CsrfOriginGuard` on all non-GET/HEAD: require `Origin` (or `Sec-Fetch-Site`) and
  match it against `APP_ORIGIN`. Paired with `SameSite=Lax` this is stronger and simpler than double-submit
  tokens, and it closes the gap `SameSite` alone leaves against a compromised sibling subdomain.
- **`helmet()`** on Nest; `frame-ancestors 'none'`, `Referrer-Policy: strict-origin-when-cross-origin`, HSTS in prod.
- **`@nestjs/throttler`** — global default plus a much tighter limit on `/auth/*`.
- **pino** with redaction of `cookie`, `set-cookie`, `authorization`, and any `code`/`token` field, plus a
  request id. Auth logs that contain the credential are their own breach.
- **Errors** — `AllExceptionsFilter` returns generic messages; details go to logs. Never leak whether an
  account exists.
- `app.enableShutdownHooks()`, `@nestjs/terminus` health check, `trust proxy` set for correct client IPs.

---

## Layer 3 — Frontend (`apps/web`)

```
next.config.ts    rewrites /api/:path* → http://localhost:4000/:path* ; security headers
proxy.ts          optimistic cookie-presence redirect ONLY (Next 16 name)
src/app/
  login/page.tsx                <a href="/api/auth/google"> — a real navigation
  dashboard/page.tsx            await verifySession()
  settings/sessions/page.tsx    device list + revoke + "log out everywhere"
src/lib/dal.ts                  getSession() / verifySession(), React cache()
src/lib/dto.ts                  narrow what reaches the client
```

Three things that matter more than they look:

1. **The login button must be a link or form navigation, never `fetch()`.** A cross-origin redirect to
   `accounts.google.com` cannot be followed by XHR — this is the most common way this flow is first built wrong.

2. **`proxy.ts` is optimistic only.** It checks for cookie *presence* to redirect early; it must not be
   trusted for authorization. Next's own docs are explicit: verify inside every Server Component, Route
   Handler and Server Action, because a matcher change or a Server Action moving routes silently removes
   proxy coverage. Our real check is `verifySession()` in the DAL, called close to the data.

3. **No token ever touches JavaScript.** No `localStorage`, no `sessionStorage`, no token in a client prop.
   The session is an `HttpOnly` cookie; XSS cannot read it.

`dal.ts` wraps `getSession()` in React's `cache()` so a render pass hits `/auth/me` once, forwarding
`cookies()` with `cache: 'no-store'`. Logout is a plain form `POST` to `/api/auth/logout` — Nest clears the
cookie and redirects, so Next never juggles auth cookies itself.

Auth checks go in pages and leaf components, **not layouts** — layouts don't re-render on navigation and
don't gate the segments beneath them.

---

## Layer 4 — Wiring

- `next.config.ts` rewrite + matching `GOOGLE_REDIRECT_URI`, so one origin serves both apps.
- `packages/contracts` exports the `SessionUser` zod schema consumed by both sides — one source of truth for
  the DTO shape.
- Root `pnpm dev` runs Postgres, api and web together.

### Google Cloud Console (manual, do once)

1. New project → **APIs & Services → OAuth consent screen** → External → scopes `openid`, `email`, `profile`
   only. Add yourself as a test user.
2. **Credentials → OAuth client ID → Web application**.
3. Authorized JavaScript origin: `http://localhost:3000`.
4. Authorized redirect URI: `http://localhost:3000/api/auth/google/callback` — **exact match, no wildcards**,
   and note it is port 3000 (what the browser sees), not 4000.
5. Copy the client ID/secret into `.env`. The secret is server-only and must never reach `apps/web`.

---

## Layer 5 — Security test suite (`apps/api/test`)

Vitest e2e against a **mocked Google**: generate an RSA keypair in the test setup, serve a local JWKS, and
sign ID tokens with it so we can forge tokens on purpose. Each test asserts an attack *fails*:

| Test | Expected |
|---|---|
| `state` in query ≠ state in cookie | 403 |
| Missing / tampered `__Host-oauth_tx` | 403 |
| Same `code` replayed (tx cookie already cleared) | 403 |
| ID token signed by the wrong key | 403 |
| ID token with wrong `aud` or wrong `iss` | 403 |
| `nonce` mismatch | 403 |
| `email_verified: false` | 403, no user created |
| `returnTo=//evil.com` and `returnTo=/\evil.com` | redirects to `/dashboard` |
| Expired / revoked / absolute-capped session | 401 |
| `POST /auth/logout` then reuse cookie | 401 |
| Non-GET with foreign/absent `Origin` | 403 |
| Second user revoking another's session id | 404/403 |
| `@Roles(ADMIN)` route as a `USER` | 403 |

Plus a unit test table for `safeReturnTo` and a check that `AuthEvent` rows are written on login, denial and revoke.

---

## Why each control exists

Compact reference; the long form goes in `SECURITY.md`.

| Control | Attack it stops |
|---|---|
| PKCE (S256) | Authorization code interception / injection |
| `state` + timing-safe compare | Login CSRF — being signed into an attacker's account |
| `nonce` + verified claim | ID token replay |
| `jwtVerify` against Google JWKS | Forged identity — the whole trust anchor |
| Key on `sub`, never email | Takeover via email change / reassigned Workspace address |
| `email_verified === true` | Takeover via unverified account claiming your address |
| Conditional account linking | Pre-hijacking (attacker seeds an account at your address first) |
| `HttpOnly` cookie, no localStorage | XSS token theft |
| `__Host-` prefix | Cookie tossing / fixation from a sibling subdomain |
| `SameSite=Lax` + Origin guard | CSRF on state-changing requests |
| Opaque token, SHA-256 at rest | DB leak → no replayable credentials |
| Sliding + absolute expiry | Unbounded session lifetime |
| Revocation via `revokedAt` | Stale access after logout, ban, or role change |
| No `access_type=offline` | Nothing to store means nothing to leak |
| `safeReturnTo` | Open redirect → phishing / token leakage |
| 302 off the callback URL | Code sitting in history, Referer, and logs |
| Rate limiting on `/auth/*` | Brute force, callback flooding |
| Fail-fast env validation | Silently shipping with a missing secret |
| Log redaction, hashed IPs | Credentials in logs; unnecessary PII retention |
| Append-only `AuthEvent` | No forensic trail after an incident |

## Where this diverges from the tutorial

| Tutorial | Here | Why |
|---|---|---|
| `express-session` holds `state` | Encrypted single-use `__Host-oauth_tx` cookie | No session store needed before login; nothing to fixate |
| Userinfo endpoint / unverified decode | `jose.jwtVerify` against JWKS | The tutorial trusts an unauthenticated claim |
| Access + refresh JWTs in cookies | Opaque session, hashed in Postgres | Instant revocation; no key-rotation or alg-confusion risk |
| User keyed on email | Keyed on `(provider, sub)` | Emails move between people |
| MongoDB | PostgreSQL + Prisma 7 | Relational fit |
| No PKCE / nonce | Both, enforced | Current OAuth 2.1 baseline |
| CORS + separate origins | One origin, zero CORS | Avoids third-party cookies blocked by Safari/Firefox |

---

## Verification

```bash
docker compose up -d
pnpm --filter api prisma migrate dev
pnpm dev                                  # web :3000, api :4000
```

**Happy path** — visit `http://localhost:3000/login`, click *Continue with Google*, consent. You should land
on `/dashboard` showing your name and email, with a clean URL (no `code=`). In DevTools → Application →
Cookies there is exactly one `__Host-sid`, `HttpOnly` ✓ `Secure` ✓ `SameSite=Lax`, and the `__Host-oauth_tx`
cookie is gone. `document.cookie` in the console returns nothing useful.

**Then confirm the defenses actually hold** — these are the checks worth doing by hand once:

```bash
# forged state → 403, no session issued
curl -i "http://localhost:3000/api/auth/google/callback?code=x&state=forged"

# CSRF: state-changing request with a foreign Origin → 403
curl -i -X POST http://localhost:3000/api/auth/logout \
     -H "Origin: https://evil.com" -H "Cookie: __Host-sid=<yours>"

# open redirect → lands on /dashboard, not evil.com
curl -i "http://localhost:3000/api/auth/google?returnTo=//evil.com"

# session survives nothing after logout
curl -i http://localhost:3000/api/auth/me -H "Cookie: __Host-sid=<revoked>"   # 401
```

In the UI: open `/settings/sessions` in two different browsers, revoke one from the other, and confirm the
revoked browser is bounced to `/login` on its next request. Then `select * from "AuthEvent"` and check the
login, revoke and logout rows are there.

**Automated:** `pnpm --filter api test` — the whole table in Layer 5 must be green.

## Beyond v1

The schema is already shaped for these: additional providers (`OAuthAccount` is generic — GitHub/Microsoft
is one more provider config and client), email + password with argon2id, TOTP MFA, WebAuthn passkeys,
step-up re-auth for sensitive actions, encrypted-at-rest Google refresh tokens if you ever call Google APIs,
anomaly detection off `AuthEvent`, and a separate migrator-vs-runtime Postgres role with `sslmode=require`
for deployment.

## Working notes

- Layered build order: **all schema → all backend → all frontend → all wiring**, parallelizing within each layer.
