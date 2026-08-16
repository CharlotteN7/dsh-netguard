/** `dsh-netguard report`: argument parsing, the summary, and the suggested allow list. */

import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { formatSuggestion, main, parseArgv, parseRecord, parseSince, readSpool } from '../../src/cli.ts'
import { buildDecisionRecord, createEnvironment, type DecisionInput } from '../../src/ocsf.ts'
import { disposeHome, makeHome, policyOf } from './support.ts'

const home = makeHome('cli')
afterAll(() => { disposeHome(home) })

/** A spool file holding the given decisions. */
let counter = 0
function spoolOf(decisions: readonly Partial<DecisionInput>[], time = 1_700_000_000_000): string {
  counter += 1
  const path = join(home, `spool-${String(counter)}.jsonl`)
  const env = createEnvironment(policyOf(home, { allow: ['*'] }), '0.1.0', () => time)
  writeFileSync(path, `${decisions.map((decision, index) => JSON.stringify(buildDecisionRecord(env, {
    kind: 'fetch',
    verdict: 'allowed',
    enforced: true,
    host: 'example.com',
    port: 443,
    firstSeen: false,
    decisionId: `netguard-${String(index)}`,
    seq: index + 1,
    ...decision,
  }))).join('\n')}\n`)
  return path
}

/** Run the command and collect what it wrote. */
function run(argv: readonly string[], env: NodeJS.ProcessEnv = {}, now = 1_700_000_000_000) {
  const out: string[] = []
  const err: string[] = []
  const code = main(argv, line => out.push(line), line => err.push(line), env, now)
  return { code, out: out.join('\n'), err: err.join('\n') }
}

describe('parsing the command line', () => {
  it('reports usage with no arguments and with --help', () => {
    expect(parseArgv([], {}, 0)).toEqual({ kind: 'usage' })
    expect(parseArgv(['--help'], {}, 0)).toEqual({ kind: 'usage' })
  })

  it('rejects an unknown command and an unknown option', () => {
    expect(parseArgv(['explode'], {}, 0)).toMatchObject({ kind: 'error' })
    expect(parseArgv(['report', '--nope', 'x'], {}, 0)).toMatchObject({ kind: 'error' })
  })

  it('rejects an option with no value', () => {
    expect(parseArgv(['report', '--spool'], {}, 0)).toMatchObject({ kind: 'error', message: /needs a value/ })
  })

  it('defaults the spool to the harness home', () => {
    expect(parseArgv(['report'], { DSH_HOME: '/srv/dsh' }, 0)).toMatchObject({
      options: { spool: '/srv/dsh/netguard/decisions.ocsf.jsonl' },
    })
  })

  it('accepts a spool, a session, a suggestion flag, and a since bound', () => {
    expect(parseArgv(['report', '--spool', '/tmp/s', '--session', 'abc', '--suggest', '--since', '1h'], {}, 3_600_000))
      .toMatchObject({ options: { spool: '/tmp/s', session: 'abc', suggest: true, since: 0 } })
  })

  it('rejects a --since it cannot read', () => {
    expect(parseArgv(['report', '--since', 'yesterday'], {}, 0)).toMatchObject({ kind: 'error' })
  })
})

describe('parsing a --since bound', () => {
  it.each([
    ['30s', 30_000],
    ['5m', 300_000],
    ['2h', 7_200_000],
    ['1d', 86_400_000],
  ])('reads the relative bound %s', (text, back) => {
    expect(parseSince(text, 1_000_000_000)).toBe(1_000_000_000 - back)
  })

  it('reads an ISO timestamp', () => {
    expect(parseSince('2026-08-15T00:00:00Z', 0)).toBe(Date.parse('2026-08-15T00:00:00Z'))
  })

  it('reports text it cannot read', () => {
    expect(parseSince('soon', 0)).toBeUndefined()
  })
})

describe('reading the spool', () => {
  it('reports an absent file as absence', () => {
    expect(readSpool(join(home, 'no-such-spool.jsonl'))).toEqual({ kind: 'absent' })
  })

  it('reports an unreadable path as a problem', () => {
    expect(readSpool(home)).toMatchObject({ kind: 'unreadable' })
  })

  it('counts a torn line rather than trusting it', () => {
    const path = spoolOf([{}])
    writeFileSync(path, `${'{"class_uid":4001,"unmapped"'}\n`, { flag: 'a' })

    expect(readSpool(path)).toMatchObject({ unreadable: 1, records: [{ host: 'example.com' }] })
  })

  it.each([
    ['text that is not JSON', 'not json'],
    ['a JSON array', '[]'],
    ['a record with no attributes of ours', '{"class_uid":4001}'],
    ['a record with attributes but no host', '{"unmapped":{"dsh":{"verdict":"allowed","kind":"fetch"}}}'],
  ])('skips %s', (_label, line) => {
    expect(parseRecord(line)).toBeUndefined()
  })

  it('fills in what a sparse record does not carry', () => {
    const line = JSON.stringify({ unmapped: { dsh: { verdict: 'denied', kind: 'fetch', host: 'evil.test' } } })

    expect(parseRecord(line)).toEqual({
      time: 0,
      host: 'evil.test',
      port: 0,
      verdict: 'denied',
      enforced: false,
      mode: 'unknown',
      kind: 'fetch',
    })
  })

  it('reads attributes a deployment placed at the top level', () => {
    const line = JSON.stringify({
      time: 5,
      dst_endpoint: { hostname: 'example.com', port: 443 },
      acme: { verdict: 'allowed', kind: 'fetch', enforced: true, mode: 'audit' },
    })

    expect(parseRecord(line)).toMatchObject({ host: 'example.com', verdict: 'allowed', mode: 'audit' })
  })
})

describe('the report', () => {
  it('prints usage with no arguments', () => {
    expect(run([])).toMatchObject({ code: 0, out: expect.stringContaining('Usage: dsh-netguard report') })
  })

  it('says the file is empty when nothing has been recorded', () => {
    expect(run(['report', '--spool', join(home, 'absent.jsonl')]).out).toContain('no spool at')
  })

  it('fails when the spool cannot be read', () => {
    expect(run(['report', '--spool', home])).toMatchObject({ code: 1, err: expect.stringContaining('cannot read') })
  })

  it('reports usage on stderr and exits 2 for a bad invocation', () => {
    expect(run(['report', '--since', 'soon'])).toMatchObject({ code: 2, err: expect.stringContaining('Usage:') })
  })

  it('counts allowed, denied, and the denials audit mode let through', () => {
    const path = spoolOf([
      {},
      { verdict: 'denied', enforced: true, reason: 'blocked-by-allowlist', host: 'evil.test' },
      { verdict: 'denied', enforced: false, reason: 'blocked-by-denylist', rule: 'deny:evil.test', host: 'evil.test' },
    ])

    const { out } = run(['report', '--spool', path])

    expect(out).toContain('allowed: 1   denied: 2   of those, recorded but permitted by audit mode: 1')
    expect(out).toContain('blocked-by-allowlist')
    expect(out).toContain('deny:evil.test')
    expect(out).toContain('(audit: permitted)')
  })

  it('names a denial with no reason and shows the address a request reached', () => {
    const path = spoolOf([
      { verdict: 'denied', enforced: true },
      { resolvedIp: '93.184.216.34' },
    ])

    const { out } = run(['report', '--spool', path])

    expect(out).toContain('unknown')
    expect(out).toContain('[93.184.216.34]')
  })

  it('groups by tool and by host', () => {
    const path = spoolOf([{ toolName: 'web_fetch' }, { toolName: 'web_search', host: 'other.test' }])

    const { out } = run(['report', '--spool', path])

    expect(out).toContain('web_fetch')
    expect(out).toContain('other.test')
  })

  it('honours --session and --since', () => {
    const path = spoolOf([
      { sessionId: 'a' },
      { sessionId: 'b', host: 'other.test' },
    ])

    expect(run(['report', '--spool', path, '--session', 'a']).out).toContain('1 decision')
    expect(run(['report', '--spool', path, '--since', '2100-01-01T00:00:00Z']).out).toContain('0 decision')
  })

  it('says how many lines it could not parse', () => {
    const path = spoolOf([{}])
    writeFileSync(path, 'torn\n', { flag: 'a' })

    expect(run(['report', '--spool', path]).out).toContain('1 line(s) did not parse')
  })
})

describe('the suggested allow list', () => {
  it('turns the observed hosts into a ready block, with what each one did', () => {
    const path = spoolOf([
      {},
      { host: 'evil.test', verdict: 'denied', enforced: false, reason: 'blocked-by-allowlist' },
    ])

    const { out } = run(['report', '--spool', path, '--suggest'])

    expect(out).toContain('allow:')
    expect(out).toContain("  - 'evil.test'   # 1 request(s), 1 the policy would refuse")
    expect(out).toContain("  - 'example.com'   # 1 request(s), 0 the policy would refuse")
    expect(out).toContain('may be the request you mounted this plugin to stop')
  })

  it('says so when there is nothing to suggest', () => {
    expect(formatSuggestion([])).toEqual(['# dsh-netguard observed no hosts in the selected records.'])
  })

  it('leaves the query placeholder out of the list', () => {
    expect(formatSuggestion([{
      time: 0,
      host: '(query)',
      port: 0,
      verdict: 'allowed',
      enforced: true,
      mode: 'audit',
      kind: 'search',
    }])).toEqual(['# dsh-netguard observed no hosts in the selected records.'])
  })
})
