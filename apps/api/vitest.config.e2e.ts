import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    globals: true,
    root: './',
    setupFiles: ['./test/setup-env.ts'],
    include: ['**/*.e2e-spec.ts'],
    // These suites share one database. Run the files one at a time, or a
    // cleanup in one lands in the middle of a test in another.
    fileParallelism: false,
  },
});
