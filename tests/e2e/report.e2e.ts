/**
 * `dsh-netguard report` as a user runs it: the built `lib/cli.js`, executed as
 * a subprocess against a spool a real agent run produced.
 *
 * The unit suite exercises the command's functions; only this proves the `bin`
 * entry, its shebang, and the built module's imports work outside vitest.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { runAgent } from './harness.ts'

/** The built command, as the package's `bin` entry names it. */
const CLI = fileURLToPath(new URL('../../lib/cli.js', import.meta.url))

let server: Server
let home: string
let spool: string

beforeAll(async () => {
  server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end('REPORT_E2E_BODY')
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo

  // The agent run owns a throwaway home that it removes on the way out, so the
  // records are copied into a spool this test keeps.
  const run = await runAgent({
    task: 'fetch the fixture page',
    sequence: ['tool_call_success', 'success', 'success'],
    toolName: 'web_fetch',
    toolArguments: JSON.stringify({ url: `http://127.0.0.1:${String(port)}/page` }),
    successText: 'done',
    extraProfilePatch: [
      '- id: tool-web',
      '  config:',
      '    fetch: true',
      '    searchTimeoutMs: 60000',
      '- id: web',
      '  config:',
      '    fetchProvider: dsh-netguard',
      '    searchProvider: deepseek-official',
    ].join('\n'),
    netguard: { allow: [] },
  })
  expect(run.code, run.stderr).toBe(0)
  expect(run.ocsfRecords.length).toBeGreaterThan(0)

  home = mkdtempSync(join(tmpdir(), 'dsh-netguard-report-'))
  spool = join(home, 'decisions.ocsf.jsonl')
  writeFileSync(spool, `${run.ocsfRecords.map(record => JSON.stringify(record)).join('\n')}\n`)
}, 180_000)

afterAll(async () => {
  rmSync(home, { recursive: true, force: true })
  await new Promise<void>(resolve => server.close(() => { resolve() }))
})

/** Run the built command and return its stdout. */
function report(args: readonly string[]): string {
  return execFileSync(process.execPath, [CLI, ...args], { cwd: dirname(CLI), encoding: 'utf8' })
}

describe('the built report command', () => {
  it('summarises what audit mode recorded', () => {
    const output = report(['report', '--spool', spool])

    expect(output).toContain('decision(s) in')
    expect(output).toContain('recorded but permitted by audit mode')
    expect(output).toContain('blocked-by-allowlist')
    expect(output).toContain('127.0.0.1')
  })

  it('prints an allow list built from the hosts the run observed', () => {
    const output = report(['report', '--spool', spool, '--suggest'])

    expect(output).toContain('allow:')
    expect(output).toContain("  - '127.0.0.1'")
    expect(output).toContain('the policy would refuse')
  })

  it('says so when there is no spool where it looked', () => {
    const output = report(['report', '--spool', join(home, 'absent.jsonl')])

    expect(output).toContain('no spool at')
  })
})
