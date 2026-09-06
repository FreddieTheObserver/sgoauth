import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

/**
 * The data access layer — the only place this app asks who is signed in.
 *
 * `import "server-only"` is the first line for a reason: it makes the build fail
 * if a Client Component ever imports this file. Nothing here may be bundled for
 * the browser, and a compile error is a better guard than a convention.
 *
 * This is also where the real authorization check lives. `proxy.ts` redirects on
 * cookie *presence* and is an optimisation, not a control: a matcher change or a
 * Server Action moving between routes silently removes its coverage. Pages call
 * verifySession() close to the data instead, which cannot be routed around.
 */

// Server-side calls go straight to the API. The /api/* rewrite in next.config.ts
// exists for the browser — routing our own server-side fetch back through our own
// server would be a pointless extra hop. Same default as that file: both read
// API_ORIGIN, which is the actual source of truth.
const API_ORIGIN = process.env.API_ORIGIN ?? "http://localhost:4000";

export const LOGIN_PATH = "/login";

/**
 * What /auth/me answers with.
 *
 * Declared here for now; Layer 4 replaces it with the zod schema in
 * packages/contracts so both sides share one definition of the shape.
 */
export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
  role: "USER" | "ADMIN";
}

function isSessionUser(value: unknown): value is SessionUser {
  // Not a security check — the API is ours and the response arrived over
  // loopback. It turns a shape change into a loud failure rather than a page
  // that renders "undefined" at whoever is signed in.
  const user = value as Partial<SessionUser> | null;
  return typeof user?.id === "string" && typeof user.email === "string";
}

/**
 * Who is signed in, or null.
 *
 * Wrapped in React's cache() so a render pass that checks the session in three
 * different components still makes one request. The cache is per request, so
 * nothing leaks between users.
 */
export const getSession = cache(async (): Promise<SessionUser | null> => {
  const cookieHeader = (await cookies()).toString();
  // No cookies at all cannot be a session. Skipping the round trip keeps a
  // logged-out page render from touching the API at all.
  if (!cookieHeader) return null;

  const response = await fetch(`${API_ORIGIN}/auth/me`, {
    // Forwarded verbatim: this request is made on the browser's behalf, and in a
    // single-origin app every cookie the browser holds is already the API's.
    headers: { cookie: cookieHeader },
    // Next 16 defaults to this, said out loud because it is load-bearing. A
    // cached answer here would be one visitor's identity served to the next.
    cache: "no-store",
  });

  // 401 is an answer: not signed in. Anything else is the API being broken or
  // unreachable, which is a different thing and must not be quietly rendered as
  // "logged out" — that turns an outage into an endless redirect to /login.
  if (response.status === 401) return null;
  if (!response.ok) {
    throw new Error(`/auth/me answered ${response.status}`);
  }

  const body: unknown = await response.json();
  if (!isSessionUser(body)) {
    throw new Error("/auth/me answered with an unexpected shape");
  }

  return body;
});

/**
 * Who is signed in, or off to the login page.
 *
 * Never returns null, so a page that calls it cannot forget to handle the
 * logged-out case — redirect() throws, and nothing after it runs.
 */
export async function verifySession(): Promise<SessionUser> {
  const user = await getSession();
  if (!user) redirect(LOGIN_PATH);
  return user;
}
