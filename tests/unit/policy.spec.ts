/** Configuration defaults, the repo-local tier, and the tighten-only merge. */

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { identifyHost, type HostIdentity } from '../../src/address.ts'
import {
  Config,
  loadRepoPolicy,
  parseRepoPolicy,
  readOrCreateInstallUid,
  resolvePolicy,
} from '../../src/policy.ts'
import { disposeHome, makeHome } from './support.ts'

const home = makeHome('policy')
afterAll(() => { disposeHome(home) })

/** Identify a host the tests know is well formed. */
function host(text: string): HostIdentity {
  const identity = identifyHost(text)
  if (identity === undefined) throw new Error(`test fixture "${text}" is not a host`)
  return identity
}

/** A minimal valid configuration with a throwaway spool. */
function base(overrides: Partial<Parameters<typeof resolvePolicy>[0]> = {}) {
  return { spoolPath: join(home, 'spool.jsonl'), ...overrides }
}

describe('the configuration schema', () => {
  it('requires a spool path', () => {
    expect(() => Config({} as never)).toThrow()
  })

  it('defaults the mode to audit, and the allow list to empty', () => {
    const validated = Config({ spoolPath: join(home, 'spool.jsonl') })

    expect(validated.mode).toBe('audit')
    expect(validated.allow).toEqual([])
  })
})

describe('resolving the deployment configuration', () => {
  it('denies everything by default, because the shipped allow list is empty', () => {
    const policy = resolvePolicy(base())

    expect(policy.mode).toBe('audit')
    expect(policy.hosts.evaluate(host('example.com'), 443)).toMatchObject({ reason: 'blocked-by-allowlist' })
  })

  it('puts the host memory beside the spool unless the deployment names one', () => {
    expect(resolvePolicy(base()).hostMemoryPath).toBe(`${join(home, 'spool.jsonl')}.hosts`)
    expect(resolvePolicy(base({ hostMemoryPath: '/tmp/elsewhere' })).hostMemoryPath).toBe('/tmp/elsewhere')
  })

  it('refuses a pattern it cannot compile, at load rather than at the first request', () => {
    expect(() => resolvePolicy(base({ allow: ['prod*.example.com'] }))).toThrow(/wildcard inside a label/)
  })

  it('opens a private range a deployment names', () => {
    expect(resolvePolicy(base({ allowPrivateAddresses: ['127.0.0.0/8'] })).openedAddresses).toHaveLength(1)
  })

  it.each([
    ['the instance metadata address', '169.254.169.254/32'],
    ['a range containing it', '169.254.0.0/16'],
    ['the Azure wire server', '168.63.129.16'],
  ])('refuses to open %s', (_label, entry) => {
    expect(() => resolvePolicy(base({ allowPrivateAddresses: [entry] }))).toThrow(/cloud instance metadata/)
  })

  it('refuses an allowPrivateAddresses entry that is not a CIDR block', () => {
    expect(() => resolvePolicy(base({ allowPrivateAddresses: ['example.com'] }))).toThrow(/not a CIDR block/)
  })

  it.each([
    ['maxUrlLength', { maxUrlLength: 0 }],
    ['maxResponseBytes', { maxResponseBytes: -1 }],
    ['maxBodyChars', { maxBodyChars: Number.NaN }],
    ['timeoutMs', { timeoutMs: 0 }],
  ])('refuses a non-positive fetch.%s', (name, fetch) => {
    expect(() => resolvePolicy(base({ fetch }))).toThrow(new RegExp(`fetch.${name} must be a positive`))
  })

  it('refuses a fractional or negative redirect budget', () => {
    expect(() => resolvePolicy(base({ fetch: { maxRedirects: 1.5 } }))).toThrow(/non-negative integer/)
    expect(() => resolvePolicy(base({ fetch: { maxRedirects: -1 } }))).toThrow(/non-negative integer/)
    expect(resolvePolicy(base({ fetch: { maxRedirects: 0 } })).fetch.maxRedirects).toBe(0)
  })

  it.each([
    ['spoolPath', { spoolPath: 'netguard.ocsf.jsonl' }],
    ['hostMemoryPath', { hostMemoryPath: 'netguard.hosts' }],
    ['fleet.installUidPath', { fleet: { installUidPath: 'netguard.install-uid' } }],
  ])('refuses a relative %s, which would resolve inside the workspace', (name, overrides) => {
    expect(() => resolvePolicy(base(overrides))).toThrow(new RegExp(`${name.replace('.', '\\.')} must be an absolute path`))
  })

  it('refuses a non-positive search.maxQueryLength', () => {
    expect(() => resolvePolicy(base({ search: { maxQueryLength: 0 } }))).toThrow(/search.maxQueryLength must be a positive/)
    expect(resolvePolicy(base()).searchMaxQueryLength).toBe(2048)
  })

  it('needs both halves of a search delegate, or neither', () => {
    expect(() => resolvePolicy(base({ search: { delegate: { module: 'x' } } }))).toThrow(/naming the provider class/)
    expect(() => resolvePolicy(base({ search: { delegate: { export: 'X' } } }))).toThrow(/needs search.delegate.module/)
    expect(resolvePolicy(base()).searchDelegate).toBeUndefined()
    expect(resolvePolicy(base({ search: { delegate: { module: 'x', export: 'X' } } })).searchDelegate)
      .toEqual({ module: 'x', export: 'X', options: {} })
  })
})

describe('the digest key', () => {
  it('is ephemeral by default, so two mounts do not share one', () => {
    expect(resolvePolicy(base()).hmacKey).not.toEqual(resolvePolicy(base()).hmacKey)
  })

  it('is taken verbatim from a literal of sufficient length', () => {
    expect(resolvePolicy(base({ hmacKey: { source: 'literal', value: 'k'.repeat(32) } })).hmacKey)
      .toEqual(Buffer.from('k'.repeat(32)))
  })

  it('refuses a literal that is too short to be a key', () => {
    expect(() => resolvePolicy(base({ hmacKey: { source: 'literal', value: 'short' } }))).toThrow(/at least 32 bytes/)
  })

  it('reads an environment variable when one is named', () => {
    const policy = resolvePolicy(base({ hmacKey: { source: 'env', variable: 'NETGUARD_KEY' } }), undefined, {
      NETGUARD_KEY: 'e'.repeat(40),
    })

    expect(policy.hmacKey).toEqual(Buffer.from('e'.repeat(40)))
  })

  it('fails loud when the named variable is absent or too short', () => {
    expect(() => resolvePolicy(base({ hmacKey: { source: 'env' } }))).toThrow(/hmacKey.variable is required/)
    expect(() => resolvePolicy(base({ hmacKey: { source: 'env', variable: 'NETGUARD_KEY' } }), undefined, {}))
      .toThrow(/must hold an HMAC key/)
  })
})

describe('the install uid', () => {
  it('is minted once and reused', () => {
    const path = join(home, 'uid', 'install-uid')

    const first = readOrCreateInstallUid(path)

    expect(first).toMatch(/^[0-9a-f-]{36}$/)
    expect(readOrCreateInstallUid(path)).toBe(first)
    expect(readFileSync(path, 'utf8').trim()).toBe(first)
  })

  it('is minted afresh when the file is empty', () => {
    const path = join(home, 'empty-uid')
    writeFileSync(path, '\n')

    expect(readOrCreateInstallUid(path)).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('is minted in memory rather than failing the mount when it cannot be persisted', () => {
    // The spool directory is not always writable, and refusing to mount over it
    // is the outage `SpoolSink.write` deliberately refuses to cause.
    const unwritable = join(home, 'blocked')
    writeFileSync(unwritable, 'a file where a directory would have to be\n')
    const failures: unknown[] = []

    const uid = readOrCreateInstallUid(join(unwritable, 'install-uid'), error => failures.push(error))

    expect(uid).toMatch(/^[0-9a-f-]{36}$/)
    expect(failures).toHaveLength(1)
  })

  it('reports a spool this process cannot write to, and still resolves a policy', () => {
    const unwritable = join(home, 'blocked-2')
    writeFileSync(unwritable, 'a file where a directory would have to be\n')
    const failures: unknown[] = []

    const policy = resolvePolicy(
      { spoolPath: join(unwritable, 'spool.jsonl') },
      undefined,
      process.env,
      error => failures.push(error),
    )

    expect(policy.fleet.installUid).toMatch(/^[0-9a-f-]{36}$/)
    expect(failures).toHaveLength(1)
  })

  it('drops the failure when no caller asked to hear about it', () => {
    const unwritable = join(home, 'blocked-3')
    writeFileSync(unwritable, 'a file where a directory would have to be\n')

    expect(readOrCreateInstallUid(join(unwritable, 'install-uid'))).toMatch(/^[0-9a-f-]{36}$/)
    expect(resolvePolicy({ spoolPath: join(unwritable, 'spool.jsonl') }).fleet.installUid).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('is taken from the configuration when a deployment supplies one', () => {
    expect(resolvePolicy(base({ fleet: { installUid: 'fleet-7' } })).fleet.installUid).toBe('fleet-7')
  })

  it('drops empty fleet labels and tags rather than emitting empty ones', () => {
    expect(resolvePolicy(base({ fleet: { installUid: 'x' } })).fleet).toMatchObject({
      labels: undefined,
      tags: undefined,
    })
    expect(resolvePolicy(base({ fleet: { installUid: 'x', labels: ['ci'], tags: { team: 'sec' } } })).fleet)
      .toMatchObject({ labels: ['ci'], tags: [{ name: 'team', value: 'sec' }] })
  })
})

describe('the repo-local policy tier', () => {
  it('adds deny patterns', () => {
    expect(parseRepoPolicy('v: 1\naddDeny: [\'*.evil.test\']\n')).toEqual({ addDeny: ['*.evil.test'], enforce: false })
  })

  it('may raise audit to enforce', () => {
    const policy = resolvePolicy(base({ mode: 'audit' }), parseRepoPolicy('v: 1\nenforce: true\n'))

    expect(policy.mode).toBe('enforce')
  })

  it('may not lower enforce to audit', () => {
    expect(() => parseRepoPolicy('v: 1\nenforce: false\n')).toThrow(/may only tighten/)
  })

  it.each([
    ['an allow list', 'v: 1\nallow: [\'*\']\n', /unknown keys: allow/],
    ['a new spool path', 'v: 1\nspoolPath: /tmp/mine\n', /unknown keys: spoolPath/],
    ['an opened private range', 'v: 1\nallowPrivateAddresses: [\'10.0.0.0/8\']\n', /unknown keys/],
    ['a wrong version', 'v: 2\n', /v must be 1/],
    ['a list instead of a mapping', '- one\n', /must be a mapping/],
    ['a non-string deny entry', 'v: 1\naddDeny: [3]\n', /list of strings/],
    ['a deny pattern that cannot compile', 'v: 1\naddDeny: [\'*.com\']\n', /top-level domain/],
    ['a non-boolean enforce', 'v: 1\nenforce: yes please\n', /must be true or false/],
  ])('refuses %s', (_label, text, expected) => {
    expect(() => parseRepoPolicy(text)).toThrow(expected)
  })

  it('refuses a `!!js` tag as a parse error rather than executing it', () => {
    expect(() => parseRepoPolicy('v: 1\naddDeny: !!js/function "function(){return 1}"\n'))
      .toThrow(/not safe-schema YAML/)
  })

  it('merges its deny patterns after the deployment\'s own', () => {
    const policy = resolvePolicy(base({ allow: ['*'] }), parseRepoPolicy('v: 1\naddDeny: [\'evil.test\']\n'))

    expect(policy.hosts.evaluate(host('evil.test'), 443)).toMatchObject({ rule: 'deny:evil.test' })
    expect(policy.hosts.evaluate(host('good.test'), 443).kind).toBe('allow')
  })
})

describe('reading a repo-local policy file', () => {
  it('reports an absent file as absence, not as a fault', () => {
    expect(loadRepoPolicy(join(home, 'no-such-file.yml'))).toEqual({ kind: 'absent' })
  })

  it('reports an unreadable path as a problem', () => {
    expect(loadRepoPolicy(home)).toMatchObject({ kind: 'invalid', problem: expect.stringContaining('cannot read') })
  })

  it('reports a malformed file as a problem rather than obeying part of it', () => {
    const path = join(home, 'bad-policy.yml')
    writeFileSync(path, 'v: 1\nallow: [\'*\']\n')

    expect(loadRepoPolicy(path)).toMatchObject({ kind: 'invalid', problem: expect.stringContaining('unknown keys') })
  })

  it('loads a valid file', () => {
    const path = join(home, 'good-policy.yml')
    writeFileSync(path, 'v: 1\naddDeny: [\'evil.test\']\n')

    expect(loadRepoPolicy(path)).toEqual({ kind: 'loaded', policy: { addDeny: ['evil.test'], enforce: false } })
  })
})
