import { STATUS_CODES } from 'node:http';
import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { redactUrl } from '../logger.js';

/**
 * One exit for every unhandled error, and the same shape every time.
 *
 * The body is built from the status code alone. The exception's own message is
 * logged and never sent, because messages are written for developers and drift
 * toward being useful: "no user with that email", "session s_123 is already
 * revoked", a Prisma error naming a column and a constraint. Each of those tells
 * an attacker whether an account exists or what the schema looks like, and none
 * of them helps the person who actually hit the error.
 *
 * That leaves the status code as the whole public answer, which is what the rest
 * of the app already assumes: the OAuth callback answers a bare 403 to eleven
 * different failures, and session revocation answers 404 to three.
 */

interface ErrorBody {
  statusCode: number;
  /** The canonical reason phrase for the status, and nothing more specific. */
  error: string;
  /** Matches the id on the log line that holds the detail. */
  requestId?: string;
}

// pino-http stamps every request with an id; the filter only reads it.
type LoggedRequest = Request & { id?: string };

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const status =
      exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

    // This app serves HTTP and nothing else. If that ever changes, an unhandled
    // error in the new transport should be loud here rather than swallowed.
    if (host.getType() !== 'http') {
      this.logger.error('Unhandled non-HTTP exception', this.stackOf(exception));
      return;
    }

    const http = host.switchToHttp();
    const request = http.getRequest<LoggedRequest>();
    const response = http.getResponse<Response>();

    // Through redactUrl, not straight off the request. The single most likely
    // request to end up in here is a failed /auth/google/callback, whose query
    // string holds a live authorization code and the state it is bound to —
    // writing that into a log to explain a 403 would leak the credential the
    // 403 exists to protect.
    const where = `${request.method} ${redactUrl(request.originalUrl || request.url)}`;

    // A 4xx is a refusal the app made on purpose; anything else is a bug or an
    // outage, and only that second kind is worth a stack trace.
    if (status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      this.logger.error(`${where} failed`, this.stackOf(exception));
    } else {
      this.logger.warn(`${where} -> ${status}: ${this.messageOf(exception)}`);
    }

    // The handler already began writing — a redirect, a stream — so there is no
    // envelope left to replace and ending the response is all that remains.
    if (response.headersSent) {
      response.end();
      return;
    }

    const body: ErrorBody = {
      statusCode: status,
      // Node's own table, so the phrase is the registered one rather than
      // something derived from an enum name that happens to have an alias.
      error: STATUS_CODES[status] ?? 'Error',
    };
    if (request.id) body.requestId = request.id;

    response.status(status).json(body);
  }

  private stackOf(exception: unknown): string {
    return exception instanceof Error ? (exception.stack ?? exception.message) : String(exception);
  }

  private messageOf(exception: unknown): string {
    return exception instanceof Error ? exception.message : String(exception);
  }
}
