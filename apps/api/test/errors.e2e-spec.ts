import { Controller, Get, NotFoundException, type INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';

/**
 * Throwaway routes, and unavoidably so: no production route is supposed to 500,
 * which is exactly the case the filter exists for.
 */
@Controller('boom')
class BoomController {
  @Get('crash')
  crash(): never {
    // The shape a real outage takes: a driver error naming the host and port.
    throw new Error('connect ECONNREFUSED 127.0.0.1:5432');
  }

  @Get('leaky')
  leaky(): never {
    // The shape a well-meaning refactor takes: an accurate message that answers
    // "does this account exist" for anyone who asks.
    throw new NotFoundException('No user with email ada@example.test');
  }
}

describe('error responses (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const fixture = await Test.createTestingModule({
      imports: [AppModule],
      controllers: [BoomController],
    }).compile();

    app = fixture.createNestApplication<NestExpressApplication>();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  const server = () => app.getHttpServer();

  it('answers an unhandled error with 500 and nothing about it', async () => {
    const res = await request(server()).get('/boom/crash').expect(500);

    expect(res.body).toMatchObject({ statusCode: 500, error: 'Internal Server Error' });
    const serialised = JSON.stringify(res.body);
    expect(serialised).not.toContain('ECONNREFUSED');
    expect(serialised).not.toContain('5432');
    expect(serialised).not.toContain('stack');
  });

  it('drops the message off an HttpException that carries one', async () => {
    const res = await request(server()).get('/boom/leaky').expect(404);

    expect(res.body).toMatchObject({ statusCode: 404, error: 'Not Found' });
    expect(JSON.stringify(res.body)).not.toContain('ada@example.test');
  });

  it('carries a request id that matches the log line holding the detail', async () => {
    const res = await request(server()).get('/boom/crash').expect(500);
    expect(res.body.requestId).toMatch(/^[0-9a-f-]{36}$/);

    // A fresh id per request, not a counter and not something the caller set.
    const second = await request(server()).get('/boom/crash').expect(500);
    expect(second.body.requestId).not.toBe(res.body.requestId);
  });

  it('does not let a client choose its own request id', async () => {
    const res = await request(server())
      .get('/boom/crash')
      .set('X-Request-Id', 'chosen-by-the-caller')
      .expect(500);

    expect(res.body.requestId).not.toBe('chosen-by-the-caller');
  });

  it('gives an unknown route the same generic envelope', async () => {
    const res = await request(server()).get('/no-such-route').expect(404);
    expect(res.body).toMatchObject({ statusCode: 404, error: 'Not Found' });
  });

  it.each([
    ['the CSRF guard', 403, () => request(server()).post('/auth/logout').set('Origin', 'https://evil.com')],
    ['the session guard', 401, () => request(server()).get('/auth/me')],
  ])('wraps the refusal from %s in the same envelope', async (_label, status, send) => {
    const res = await send().expect(status);

    expect(Object.keys(res.body).sort()).toEqual(['error', 'requestId', 'statusCode']);
    expect(res.body.statusCode).toBe(status);
  });
});
