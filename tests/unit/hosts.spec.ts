/** The pattern grammar, the patterns it refuses, and deny-wins evaluation. */

import { describe, expect, it } from 'vitest'
import { identifyHost, type HostIdentity } from '../../src/address.ts'
import { HostPolicy, parseHostPattern, patternMatches } from '../../src/hosts.ts'

/** Identify a host the tests know is well formed. */
function host(text: string): HostIdentity {
  const identity = identifyHost(text)
  if (identity === undefined) throw new Error(`test fixture "${text}" is not a host`)
  return identity
}

/** Whether one pattern selects one host at one port. */
function matches(pattern: string, target: string, port = 443): boolean {
  return patternMatches(parseHostPattern(pattern, { allowAny: true }), host(target), port)
}

describe('the pattern grammar', () => {
  it('matches an exact host and nothing else', () => {
    expect(matches('example.com', 'example.com')).toBe(true)
    expect(matches('example.com', 'api.example.com')).toBe(false)
    expect(matches('example.com', 'notexample.com')).toBe(false)
  })

  it('matches subdomains only under a single star, never the apex', () => {
    expect(matches('*.example.com', 'api.example.com')).toBe(true)
    expect(matches('*.example.com', 'a.b.example.com')).toBe(true)
    expect(matches('*.example.com', 'example.com')).toBe(false)
  })

  it('matches the apex as well under a double star', () => {
    expect(matches('**.example.com', 'example.com')).toBe(true)
    expect(matches('**.example.com', 'example.com.evil.test')).toBe(false)
    expect(matches('**.example.com', 'api.example.com')).toBe(true)
  })

  it('matches everything under a bare star', () => {
    expect(matches('*', 'anything.example')).toBe(true)
    expect(matches('*', '93.184.216.34')).toBe(true)
  })

  it('never lets a wildcard match an IP address', () => {
    expect(matches('*.example.com', '127.0.0.1')).toBe(false)
    expect(matches('**.example.com', '[::1]')).toBe(false)
  })

  it('is case- and trailing-dot-insensitive on both sides', () => {
    expect(matches('EXAMPLE.com', 'example.com.')).toBe(true)
  })

  it('matches an IPv4 literal however either side spells it', () => {
    expect(matches('127.0.0.1', '2130706433')).toBe(true)
    expect(matches('2130706433', '127.0.0.1')).toBe(true)
  })

  it('matches a bracketed IPv6 literal, including its IPv4-mapped spelling', () => {
    expect(matches('[::1]', '[0:0:0:0:0:0:0:1]')).toBe(true)
    expect(matches('127.0.0.1', '[::ffff:127.0.0.1]')).toBe(true)
  })
})

describe('ports in a pattern', () => {
  it('matches every port when the pattern names none', () => {
    expect(matches('example.com', 'example.com', 8443)).toBe(true)
  })

  it('matches only the named port when the pattern names one', () => {
    expect(matches('example.com:8443', 'example.com', 8443)).toBe(true)
    expect(matches('example.com:8443', 'example.com', 443)).toBe(false)
  })

  it('accepts a port after a bracketed IPv6 literal', () => {
    expect(matches('[::1]:443', '[::1]', 443)).toBe(true)
    expect(matches('[::1]:443', '[::1]', 80)).toBe(false)
    expect(matches('[::1]', '[::1]', 80)).toBe(true)
  })
})

describe('patterns the compiler refuses', () => {
  it.each([
    ['an empty string', '', /not a host pattern|empty string/],
    ['a URL', 'https://example.com', /not a host pattern/],
    ['a path', 'example.com/api', /not a host pattern/],
    ['credentials', 'user@example.com', /not a host pattern/],
    ['a prefix wildcard', 'prod*.blob.core.windows.net', /wildcard inside a label/],
    ['a suffix wildcard', 'example.*', /wildcard inside a label/],
    ['a mid-label wildcard', 'a*b.example.com', /wildcard inside a label/],
    ['a wildcard over a top-level domain', '*.com', /top-level domain/],
    ['a double-star over a top-level domain', '**.com', /top-level domain/],
    ['a wildcard over a public suffix', '*.co.uk', /public suffix/],
    ['a wildcard over an IP address', '*.127.0.0.1', /wildcard to an IP|top-level domain/],
    ['an unbracketed IPv6 literal', '::1', /without brackets/],
    ['an unclosed IPv6 literal', '[::1', /never closed/],
    ['trailing text after an IPv6 literal', '[::1]x', /trailing text/],
    ['a port that is not a number', 'example.com:https', /port that is not a number/],
    ['a port of zero', 'example.com:0', /outside 1-65535/],
    ['a port past the range', 'example.com:70000', /port that is not a number|outside 1-65535/],
    ['a wildcard over nothing', '*.', /does not name a host/],
    ['empty brackets', '[]', /does not name a host/],
  ])('refuses %s', (_label, pattern, expected) => {
    expect(() => parseHostPattern(pattern, { allowAny: true })).toThrow(expected)
  })

  it('refuses a bare star in the deny list, where an empty allow list is the way to deny everything', () => {
    expect(() => parseHostPattern('*', { allowAny: false })).toThrow(/only appear in the allow list/)
  })

  it('refuses a bare TLD as an exact pattern only when it is not a resolvable host', () => {
    // `localhost` is a single label and legitimate: an exact pattern matches
    // itself only, so it widens nothing.
    expect(parseHostPattern('localhost', { allowAny: false })).toMatchObject({ kind: 'exact', base: 'localhost' })
  })
})

describe('evaluating a policy', () => {
  it('denies everything when the allow list is empty', () => {
    const policy = HostPolicy.compile([], [])

    expect(policy.evaluate(host('example.com'), 443)).toEqual({ kind: 'deny', reason: 'blocked-by-allowlist' })
  })

  it('lets a deny pattern win over an allow pattern that also matches', () => {
    const policy = HostPolicy.compile(['**.example.com'], ['secrets.example.com'])

    expect(policy.evaluate(host('api.example.com'), 443)).toEqual({ kind: 'allow', rule: 'allow:**.example.com' })
    expect(policy.evaluate(host('secrets.example.com'), 443)).toEqual({
      kind: 'deny',
      reason: 'blocked-by-denylist',
      rule: 'deny:secrets.example.com',
    })
  })

  it('lets a deny pattern win over the bare star', () => {
    const policy = HostPolicy.compile(['*'], ['*.internal.example'])

    expect(policy.evaluate(host('api.internal.example'), 443).kind).toBe('deny')
    expect(policy.evaluate(host('example.com'), 443).kind).toBe('allow')
  })

  it('reports the patterns it compiled, for the report command', () => {
    expect(HostPolicy.compile(['a.example.com'], ['b.example.com']).describe()).toEqual({
      allow: ['a.example.com'],
      deny: ['b.example.com'],
    })
  })
})
