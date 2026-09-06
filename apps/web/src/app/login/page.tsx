import { redirect } from "next/navigation";
import { getSession } from "@/lib/dal";

// Google's consent screen is on another origin, so starting the handshake has to
// be a real top-level navigation. Turning this into a fetch() is the single most
// common way this flow is first built wrong: a cross-origin redirect cannot be
// followed by XHR, and the request dies at the browser with a CORS error that
// says nothing useful.
//
// It is a plain <a> rather than next/link for a second reason: Link prefetches,
// and a prefetch here would start a real handshake — minting state and setting
// the handshake cookie — for a button nobody clicked.
const START_HANDSHAKE = "/api/auth/google";

const MESSAGES: Record<string, string> = {
  access_denied: "You cancelled the sign-in before it finished.",
};

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  // Nothing to do here if the cookie is already good.
  if (await getSession()) redirect("/dashboard");

  const params = await searchParams;
  const error = typeof params.error === "string" ? params.error : null;
  const returnTo = typeof params.returnTo === "string" ? params.returnTo : null;

  // Passed through to the API, which is where it gets filtered: safeReturnTo
  // runs on the way into the handshake cookie, so by the time the callback reads
  // it back it is already known to be a path on this site.
  const href = returnTo
    ? `${START_HANDSHAKE}?returnTo=${encodeURIComponent(returnTo)}`
    : START_HANDSHAKE;

  return (
    <main className="flex flex-1 items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-8">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="text-sm text-black/60 dark:text-white/60">
            Continue with your Google account.
          </p>
        </div>

        {error ? (
          <p
            role="alert"
            className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
          >
            {MESSAGES[error] ?? "Sign-in did not complete. Please try again."}
          </p>
        ) : null}

        <a
          href={href}
          className="flex w-full items-center justify-center rounded-md bg-foreground px-4 py-2.5 text-sm font-medium text-background transition-opacity hover:opacity-90"
        >
          Continue with Google
        </a>
      </div>
    </main>
  );
}
