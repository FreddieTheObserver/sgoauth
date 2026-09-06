import Image from "next/image";
import { verifySession } from "@/lib/dal";

export default async function DashboardPage() {
  // The real check, in the page rather than the layout. Layouts do not re-render
  // on navigation between the segments beneath them, so an auth check placed in
  // one can be skipped by a client-side navigation into a child route.
  const user = await verifySession();

  return (
    <main className="flex flex-1 items-center justify-center p-6">
      <div className="w-full max-w-md space-y-8">
        <div className="flex items-center gap-4">
          {user.avatarUrl ? (
            <Image
              src={user.avatarUrl}
              // Decorative: it sits beside the name it belongs to, and repeating
              // that name to a screen reader adds nothing.
              alt=""
              width={48}
              height={48}
              className="rounded-full"
            />
          ) : null}
          <div className="min-w-0">
            <h1 className="truncate text-xl font-semibold tracking-tight">
              {user.name ?? user.email}
            </h1>
            <p className="truncate text-sm text-black/60 dark:text-white/60">{user.email}</p>
          </div>
        </div>

        <dl className="rounded-lg border border-black/10 p-4 text-sm dark:border-white/15">
          <div className="flex items-center justify-between gap-4">
            <dt className="text-black/60 dark:text-white/60">Role</dt>
            <dd className="font-medium">{user.role}</dd>
          </div>
        </dl>

        {/*
          A plain form POST, not a fetch(). The browser stamps it with an Origin
          the API checks, Nest clears the cookie and answers 303 to /login, and
          this app never has to touch an auth cookie itself.
        */}
        <form action="/api/auth/logout" method="post">
          <button
            type="submit"
            className="w-full rounded-md border border-black/15 px-4 py-2.5 text-sm font-medium transition-colors hover:bg-black/5 dark:border-white/20 dark:hover:bg-white/10"
          >
            Sign out
          </button>
        </form>
      </div>
    </main>
  );
}
