"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { DeviceView } from "@/lib/dto";

/**
 * The one Client Component in the app, and it exists for one reason: revoking a
 * device is a DELETE, and the API refuses a state-changing request that does not
 * carry an Origin it recognises.
 *
 * A Server Action would run on the Next server, where there is no browser to
 * stamp one on — the API answers 403 to exactly that shape. Driving the request
 * from the browser is what makes the CSRF check meaningful rather than something
 * our own server asserts on the browser's behalf. Cookies ride along because a
 * same-origin fetch sends them by default.
 */
export function DeviceList({ devices }: { devices: DeviceView[] }) {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function revoke(device: DeviceView) {
    setPending(device.id);
    setError(null);

    try {
      const response = await fetch(`/api/auth/sessions/${device.id}`, { method: "DELETE" });

      if (!response.ok) {
        // 404 covers "already revoked" as well as "not yours", so the honest
        // message is that the list is stale rather than that something broke.
        setError(
          response.status === 404
            ? "That device was already signed out. Refreshing the list."
            : "Could not sign that device out. Please try again.",
        );
        router.refresh();
        return;
      }

      // One answer for both cases, including revoking the device you are on.
      // That is just logout by another name, and the API cleared the cookie on
      // the way out — a client fetch, so unlike the DAL's server-side calls that
      // Set-Cookie does reach the browser. The refresh then arrives with no
      // cookie at all and proxy.ts sends it to /login before this page renders.
      router.refresh();
    } catch {
      setError("Could not reach the server. Please try again.");
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="space-y-3">
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
        >
          {error}
        </p>
      ) : null}

      <ul className="divide-y divide-black/10 rounded-lg border border-black/10 dark:divide-white/10 dark:border-white/15">
        {devices.map((device) => (
          <li key={device.id} className="flex items-center justify-between gap-4 p-4">
            <div className="min-w-0 space-y-1">
              <p className="flex items-center gap-2 text-sm font-medium">
                <span className="truncate">{device.label}</span>
                {device.current ? (
                  <span className="shrink-0 rounded-full bg-black/10 px-2 py-0.5 text-xs font-normal dark:bg-white/15">
                    This device
                  </span>
                ) : null}
              </p>
              <p className="text-xs text-black/60 dark:text-white/60">
                Last used {device.lastUsed} · first seen {device.firstSeen}
              </p>
            </div>

            <button
              type="button"
              onClick={() => void revoke(device)}
              disabled={pending !== null}
              className="shrink-0 rounded-md border border-black/15 px-3 py-1.5 text-sm transition-colors hover:bg-black/5 disabled:opacity-50 dark:border-white/20 dark:hover:bg-white/10"
            >
              {pending === device.id ? "Signing out…" : "Sign out"}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
