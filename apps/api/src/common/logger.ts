import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Params } from 'nestjs-pino';
import { env } from '../config/env.js';
import { hashIp } from './ip-hash.js';

/**
 * Structured logging, configured around one rule: an auth log that contains the
 * credential is its own breach.
 *
 * Three things leak by default in every HTTP logger, and all three sit on the
 * paths this app exists to protect:
 *
 *   - the `cookie` and `set-cookie` headers, which carry the session token
 *     verbatim on every single request;
 *   - the callback's query string, where `code` is a live authorization code and
 *     `state` is the value the whole login-CSRF defense rests on;
 *   - `remoteAddress`, the raw client IP that the rest of this app goes out of
 *     its way never to store.
 *
 * Redaction handles the first. The serializers below handle the other two.
 */

// Header paths pino drops before anything is written. `authorization` is listed
// even though nothing reads it today: listing it costs nothing, and adding a
// bearer token later and forgetting costs a log full of them.
const REDACTED_HEADERS = [
  'req.headers.cookie',
  'req.headers.authorization',
  'res.headers["set-cookie"]',
];

// Query parameters worth knowing arrived and never worth recording the value of.
// Everything else keeps its value: `?returnTo=/settings` is useful in a log, and
// it has already been through safeReturnTo by the time anyone reads it.
const SECRET_PARAMS = new Set(['code', 'state', 'id_token', 'access_token', 'token']);

/**
 * A URL that is safe to write down: same path, same parameter names, dangerous
 * values replaced. Keeping the names means a log line still shows that a
 * callback carried a code, which is exactly what someone reading it after an
 * incident needs to know.
 */
export function redactUrl(rawUrl: string): string {
  const [path, query] = rawUrl.split('?', 2);
  if (!query) return path;

  const params = new URLSearchParams(query);
  for (const key of params.keys()) {
    if (SECRET_PARAMS.has(key)) params.set(key, '[redacted]');
  }

  return `${path}?${params.toString()}`;
}

/**
 * What pino-http actually hands a serializer: a wrapper carrying the id and a
 * normalised url, with the original Express request on `raw`. `ip` lives there
 * and not on the wrapper — reading it off the wrapper silently yields undefined,
 * which looks exactly like a request that had no address.
 */
type LoggedRequest = IncomingMessage & {
  id?: string;
  url?: string;
  ip?: string;
  raw?: { ip?: string };
};

const isDevelopment = env.NODE_ENV === 'development';

export const loggerOptions: Params = {
  pinoHttp: {
    // Generated here rather than taken from an inbound X-Request-Id: a header the
    // client controls lets anyone write chosen text into our logs, and lets them
    // collide their id with someone else's on purpose.
    genReqId: (): string => randomUUID(),

    // Warnings and errors still surface under test; the per-request info lines
    // would bury the assertion output and say nothing a failing test does not.
    level: env.NODE_ENV === 'test' ? 'warn' : 'info',

    redact: { paths: REDACTED_HEADERS, remove: true },

    serializers: {
      req: (req: LoggedRequest) => ({
        id: req.id,
        method: req.method,
        url: redactUrl(req.url ?? ''),
        // The same salted digest the Session and AuthEvent rows carry, so a log
        // line correlates with them without either one holding an address.
        // Express resolves X-Forwarded-For here because main.ts trusts the proxy.
        ipHash: hashIp(req.raw?.ip ?? req.ip),
      }),
      res: (res: ServerResponse) => ({ statusCode: res.statusCode }),
    },

    // A readiness probe answering every few seconds is not information.
    autoLogging: { ignore: (req: IncomingMessage) => req.url === '/health' },

    // Development only. Production wants raw NDJSON for a log pipeline to parse,
    // and pino-pretty runs in a worker thread that has no business being spawned
    // by every test file.
    transport: isDevelopment
      ? { target: 'pino-pretty', options: { singleLine: true, translateTime: 'SYS:HH:MM:ss.l' } }
      : undefined,
  },
};
