/**
 * The boundary between what the server knows and what the browser is handed.
 *
 * Everything passed into a Client Component is serialized into the HTML payload,
 * so it is readable by anyone who views source — "passed as a prop" is not a
 * hiding place. This module is the one place that decides what crosses, and it
 * ships what the page renders and nothing else.
 *
 * Deliberately not marked `server-only`, unlike dal.ts: this is the module that
 * exists to be imported from both sides of the boundary.
 */

/** A device-list row exactly as GET /auth/sessions answers it. */
export interface ApiDeviceSession {
  id: string;
  current: boolean;
  userAgent: string | null;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
}

/** The same row, narrowed to what the page actually shows. */
export interface DeviceView {
  id: string;
  current: boolean;
  label: string;
  firstSeen: string;
  lastUsed: string;
}

// Order matters: Edge and Opera both put "Chrome" in their user agent, and an
// iPhone claims "like Mac OS X". First match wins, so the more specific
// signatures are listed first.
const BROWSERS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\bEdgi?A?\w*\//, "Edge"],
  [/\bOPR\/|\bOpera\b/, "Opera"],
  [/\bFirefox\//, "Firefox"],
  [/\bChrome\//, "Chrome"],
  [/\bSafari\//, "Safari"],
];

const PLATFORMS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\bWindows\b/, "Windows"],
  [/\bAndroid\b/, "Android"],
  [/\biPhone\b|\biPad\b/, "iOS"],
  [/\bMac OS X\b/, "macOS"],
  [/\bLinux\b/, "Linux"],
];

const match = (patterns: typeof BROWSERS, value: string): string | null =>
  patterns.find(([pattern]) => pattern.test(value))?.[1] ?? null;

/**
 * A label someone can recognise their own device by.
 *
 * A display heuristic and nothing more — the user agent is a string the client
 * chose, so this answers "is this the laptop I remember?" and never "who is
 * this". The raw string does not cross: the page has no use for it, and shipping
 * a full fingerprint into the HTML to render eight characters of it would be a
 * poor trade.
 */
export function deviceLabel(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";

  const browser = match(BROWSERS, userAgent);
  const platform = match(PLATFORMS, userAgent);

  if (browser && platform) return `${browser} on ${platform}`;
  return browser ?? platform ?? "Unknown device";
}

// Formatted on the server, in UTC, with the zone said out loud. Rendering a date
// on the client instead would format it against the visitor's locale and clock,
// which is the classic source of a hydration mismatch — and a session list that
// flickers between two timestamps is a session list nobody trusts.
const WHEN = new Intl.DateTimeFormat("en-GB", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
});

const formatWhen = (value: string): string => `${WHEN.format(new Date(value))} UTC`;

export function toDeviceView(row: ApiDeviceSession): DeviceView {
  return {
    // The id is the one field the browser genuinely needs: it is what a revoke
    // request names. It is not a credential — DELETE /auth/sessions/:id checks
    // ownership inside the update, so knowing an id grants nothing.
    id: row.id,
    current: row.current,
    label: deviceLabel(row.userAgent),
    firstSeen: formatWhen(row.createdAt),
    lastUsed: formatWhen(row.lastUsedAt),
  };
}
