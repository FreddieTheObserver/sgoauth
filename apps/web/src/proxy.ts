import { NextResponse, type NextRequest } from "next/server";

/**
 * An optimisation, and never a control.
 *
 * All this does is notice that a request for a signed-in page arrived carrying
 * no session cookie at all, and send it to /login without paying for a render
 * and an API round trip first. It reads cookie *presence* and nothing else: it
 * does not know whether the value is valid, revoked, expired, or invented.
 *
 * The real check is verifySession() in the DAL, called inside each page. Next's
 * own docs are blunt about why, and the reason is structural rather than
 * cautious: coverage here is a matcher, and a matcher is a list someone has to
 * remember to update. A new route, a renamed segment, or a Server Action moving
 * between files silently drops out of it, and nothing fails until it matters.
 */

// Must match the API's cookie name, which is COOKIE_PREFIX + "sid". A mismatch
// costs a wasted round trip and never an authorization mistake — the page still
// asks the API who is signed in — which is exactly the property that makes this
// file safe to be approximate about.
const SESSION_COOKIE = `${process.env.COOKIE_PREFIX ?? "__Host-"}sid`;

const LOGIN_PATH = "/login";

export function proxy(request: NextRequest): NextResponse {
  if (request.cookies.has(SESSION_COOKIE)) {
    // Deliberately no redirect in the other direction.
    //
    // Sending a request that *has* a cookie away from /login would loop for
    // anyone holding a dead one: /login sends them to /dashboard, verifySession
    // finds no session and sends them back, and the cookie is still there. The
    // API clears a dead cookie on the 401 that rejects it, but that Set-Cookie
    // arrives on a fetch the Next server made, which swallows it — so the
    // browser never drops the cookie and the loop has nothing to break it.
    //
    // Redirecting only in the direction that adds friction is what keeps this
    // safe: the worst a wrong guess can do here is cost one render.
    return NextResponse.next();
  }

  const url = request.nextUrl.clone();
  const returnTo = `${url.pathname}${url.search}`;

  url.pathname = LOGIN_PATH;
  url.search = "";
  // Carried through the login page into the handshake, where the API filters it
  // with safeReturnTo before it is ever echoed into a redirect. A deep link
  // therefore survives the whole Google round trip.
  url.searchParams.set("returnTo", returnTo);

  return NextResponse.redirect(url);
}

// Only the signed-in pages. "/" decides for itself, since it has to ask who is
// signed in either way to know where to send them.
export const config = {
  matcher: ["/dashboard/:path*", "/settings/:path*"],
};
