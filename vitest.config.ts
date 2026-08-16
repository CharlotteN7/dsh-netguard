/**
 * Unit tests: no subprocess, no network beyond loopback servers the suite
 * starts itself, no harness checkout required.
 *
 * The thresholds are 100% per file. This is a security control, so an arm
 * nothing exercises is an arm nobody has checked; the handful of genuinely
 * unreachable lines carry a `v8 ignore` with a stated reason instead, and each
 * of those has its decision function unit-tested on its own.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      thresholds: { lines: 100, functions: 100, branches: 100, statements: 100, perFile: true },
    },
  },
})
