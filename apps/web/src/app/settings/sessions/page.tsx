import Link from "next/link";
import { getDevices, verifySession } from "@/lib/dal";
import { DeviceList } from "./device-list";

export default async function SessionsPage() {
  // In the page, not the layout: a layout does not re-render on navigation
  // between the segments beneath it, so an auth check placed in one can be
  // skipped by a client-side navigation into a child route.
  await verifySession();
  const devices = await getDevices();

  return (
    <main className="flex flex-1 justify-center p-6">
      <div className="w-full max-w-lg space-y-8 py-8">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Where you are signed in</h1>
          <p className="text-sm text-black/60 dark:text-white/60">
            Signing a device out takes effect on its very next request.
          </p>
        </div>

        <DeviceList devices={devices} />

        {/*
          A plain form POST, like sign-out on the dashboard: the browser stamps it
          with the Origin the API checks, and Nest clears the cookie and redirects.
          "Everywhere" includes this device — the button exists for someone who
          thinks they are compromised, and sparing the browser they happen to be
          holding would be the wrong answer to that.
        */}
        <form
          action="/api/auth/logout-all"
          method="post"
          className="border-t border-black/10 pt-6 dark:border-white/15"
        >
          <button
            type="submit"
            className="w-full rounded-md border border-black/15 px-4 py-2.5 text-sm font-medium transition-colors hover:bg-black/5 dark:border-white/20 dark:hover:bg-white/10"
          >
            Sign out everywhere, including this device
          </button>
        </form>

        <Link
          href="/dashboard"
          className="inline-block text-sm text-black/60 underline-offset-4 hover:underline dark:text-white/60"
        >
          Back to dashboard
        </Link>
      </div>
    </main>
  );
}
