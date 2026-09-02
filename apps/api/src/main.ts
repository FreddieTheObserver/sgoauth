import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // 3000 belongs to Next; the API sits behind its /api/* rewrite on 4000.
  // This reads process.env directly only until config/env.ts lands.
  await app.listen(Number(process.env.API_PORT) || 4000);
}
await bootstrap();
