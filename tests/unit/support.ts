/** Fixtures shared by the unit suites: a throwaway home and a resolved policy. */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { resolvePolicy, type Config, type ResolvedPolicy } from '../../src/policy.ts'
import type { OcsfRecord } from '../../src/ocsf.ts'

/** One throwaway directory per suite, removed by {@link disposeHome}. */
export function makeHome(label: string): string {
  return mkdtempSync(join(tmpdir(), `dsh-netguard-${label}-`))
}

/** Remove a throwaway directory. */
export function disposeHome(home: string): void {
  rmSync(home, { recursive: true, force: true })
}

/** A counter making each policy's spool path unique inside one home. */
let counter = 0

/**
 * A resolved policy over a throwaway spool.
 * @param home - the throwaway directory the spool lives in.
 * @param overrides - configuration fields the test cares about.
 * @returns the resolved policy.
 */
export function policyOf(home: string, overrides: Partial<Config> = {}): ResolvedPolicy {
  counter += 1
  return resolvePolicy({
    spoolPath: join(home, `spool-${String(counter)}.jsonl`),
    // Fixed so a digest is reproducible inside one test run.
    hmacKey: { source: 'literal', value: 'k'.repeat(32) },
    fleet: { installUid: 'install-fixture' },
    ...overrides,
  })
}

/** Records spooled to one path, in order. */
export function spooled(path: string): OcsfRecord[] {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    // ENOENT only: a run that decided nothing writes nothing.
    return []
  }
  return text.split('\n').filter(line => line.length > 0).map(line => JSON.parse(line) as OcsfRecord)
}

/** The extension-owned attributes of one record. */
export function dshOf(record: OcsfRecord): Record<string, unknown> {
  return (record['unmapped'] as { dsh: Record<string, unknown> }).dsh
}
