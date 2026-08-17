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
  return patternMatches(parseHostPattern(pattern, { list: 'allow' }), host(target), port, '/')
}

/** Whether one pattern selects one host at one path. */
function matchesPath(pattern: string, target: string, path: string | undefined): boolean {
  return patternMatches(parseHostPattern(pattern, { list: 'allow' }), host(target), 443, path)
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
    expect(matches('*', '198.51.100.34')).toBe(true)
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
    ['a scheme with a path behind it', 'https://example.com/api', /not a host pattern/],
    ['credentials', 'user@example.com', /not a host pattern/],
    ['a prefix wildcard', 'prod*.blob.core.windows.net', /wildcard inside a label/],
    ['a suffix wildcard', 'example.*', /wildcard inside a label/],
    ['a mid-label wildcard', 'a*b.example.com', /wildcard inside a label/],
    // A second wildcard used to compile to a base no host can end with, so the
    // pattern matched nothing at all — silent in an allow list, a hole in a deny list.
    ['an interior wildcard behind *.', '*.*.internal.example', /wildcard inside a label/],
    ['an interior wildcard behind **.', '**.*.internal.example', /wildcard inside a label/],
    ['a trailing wildcard label', '*.internal.*', /wildcard inside a label/],
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
    expect(() => parseHostPattern(pattern, { list: 'allow' })).toThrow(expected)
  })

  it('refuses a bare star in the deny list, where an empty allow list is the way to deny everything', () => {
    expect(() => parseHostPattern('*', { list: 'deny' })).toThrow(/only appear in the allow list/)
  })

  it('refuses a bare TLD as an exact pattern only when it is not a resolvable host', () => {
    // `localhost` is a single label and legitimate: an exact pattern matches
    // itself only, so it widens nothing.
    expect(parseHostPattern('localhost', { list: 'deny' })).toMatchObject({ kind: 'exact', base: 'localhost' })
  })
})

describe('a path-scoped allow entry', () => {
  it('grants the path itself and everything under it', () => {
    expect(matchesPath('example.com/org/repo', 'example.com', '/org/repo')).toBe(true)
    expect(matchesPath('example.com/org/repo', 'example.com', '/org/repo/blob/main')).toBe(true)
  })

  it('grants nothing else on the host', () => {
    expect(matchesPath('example.com/org/repo', 'example.com', '/')).toBe(false)
    expect(matchesPath('example.com/org/repo', 'example.com', '/other/repo')).toBe(false)
    expect(matchesPath('example.com/org/repo', 'example.com', '/org')).toBe(false)
  })

  it('ends the prefix on a segment boundary, so a longer name is not a longer path', () => {
    expect(matchesPath('example.com/api', 'example.com', '/apiv2')).toBe(false)
    expect(matchesPath('example.com/api', 'example.com', '/api/v2')).toBe(true)
  })

  it('matches the path case-sensitively, because only the host half is case-insensitive', () => {
    expect(matchesPath('EXAMPLE.com/Org/Repo', 'example.com', '/Org/Repo')).toBe(true)
    expect(matchesPath('example.com/Org/Repo', 'example.com', '/org/repo')).toBe(false)
  })

  it('matches no path at all when the request percent-encodes a slash', () => {
    // This package and the origin server would disagree about where the
    // segment ends, and the origin is the one that serves the response.
    expect(matchesPath('example.com/org/repo', 'example.com', '/org/repo/..%2f..%2fadmin')).toBe(false)
    expect(matchesPath('example.com/org/repo', 'example.com', '/org/repo/%2Fadmin')).toBe(false)
  })

  it('scopes a wildcard host and a pinned port the same way', () => {
    expect(patternMatches(parseHostPattern('*.example.com/api', { list: 'allow' }), host('a.example.com'), 443, '/api/v2'))
      .toBe(true)
    expect(patternMatches(parseHostPattern('example.com:8443/api', { list: 'allow' }), host('example.com'), 8443, '/api'))
      .toBe(true)
    expect(patternMatches(parseHostPattern('example.com:8443/api', { list: 'allow' }), host('example.com'), 443, '/api'))
      .toBe(false)
  })

  it('matches on the host alone for a caller that has no path, which is the query filter', () => {
    expect(matchesPath('example.com/org/repo', 'example.com', undefined)).toBe(true)
  })

  it.each([
    ['a path in a deny list', 'example.com/api', 'deny', /deny match is host-wide/],
    ['a trailing slash', 'example.com/api/', 'allow', /without the trailing slash/],
    ['a path that is only a slash', 'example.com/', 'allow', /without the trailing slash/],
    ['a wildcard in the path', 'example.com/org/*', 'allow', /wildcard in the path/],
    ['a prefix wildcard in a segment', 'example.com/org/repo*', 'allow', /wildcard in the path/],
    ['a query string', 'example.com/search?q=1', 'allow', /query string or a fragment/],
    ['a fragment', 'example.com/page#top', 'allow', /query string or a fragment/],
    ['a percent-encoded slash', 'example.com/org%2Frepo', 'allow', /percent-encodes a slash/],
    ['a dot segment', 'example.com/org/./repo', 'allow', /"\." or "\.\." segment/],
    ['a percent-encoded dot-dot segment', 'example.com/org/%2e%2e/repo', 'allow', /"\." or "\.\." segment/],
    ['an empty segment', 'example.com//repo', 'allow', /path this grammar does not accept/],
    ['a quote in the path', "example.com/org/'repo", 'allow', /path this grammar does not accept/],
    ['a path on the bare star', '*/api', 'allow', /scopes every host to one path/],
    // A CIDR block is what an operator writes in `allowPrivateAddresses`, one
    // field above; reading `10.0.0.0/8` as a path would be a different policy
    // from the one they wrote.
    ['a path on an IPv4 address', '10.0.0.0/8', 'allow', /reads as a CIDR block/],
    ['a path on an IPv6 literal', '[::1]/64', 'allow', /reads as a CIDR block/],
  ] as const)('refuses %s', (_label, pattern, list, expected) => {
    expect(() => parseHostPattern(pattern, { list })).toThrow(expected)
  })
})

describe('evaluating a policy', () => {
  it('denies everything when the allow list is empty', () => {
    const policy = HostPolicy.compile([], [])

    expect(policy.evaluate(host('example.com'), 443, '/')).toEqual({ kind: 'deny', reason: 'blocked-by-allowlist' })
  })

  it('lets a deny pattern win over an allow pattern that also matches', () => {
    const policy = HostPolicy.compile(['**.example.com'], ['secrets.example.com'])

    expect(policy.evaluate(host('api.example.com'), 443, '/')).toEqual({ kind: 'allow', rule: 'allow:**.example.com' })
    expect(policy.evaluate(host('secrets.example.com'), 443, '/')).toEqual({
      kind: 'deny',
      reason: 'blocked-by-denylist',
      rule: 'deny:secrets.example.com',
    })
  })

  it('refuses an interior wildcard in a deny list instead of compiling a rule that matches nothing', () => {
    expect(() => HostPolicy.compile(['*'], ['*.*.internal.example'])).toThrow(/wildcard inside a label/)
  })

  it('lets a deny pattern win over the bare star', () => {
    const policy = HostPolicy.compile(['*'], ['*.internal.example'])

    expect(policy.evaluate(host('api.internal.example'), 443, '/').kind).toBe('deny')
    expect(policy.evaluate(host('example.com'), 443, '/').kind).toBe('allow')
  })

  it('reports the patterns it compiled, for the report command', () => {
    expect(HostPolicy.compile(['a.example.com'], ['b.example.com']).describe()).toEqual({
      allow: ['a.example.com'],
      deny: ['b.example.com'],
    })
  })

  it('reports a path outside the grant as an allowlist denial, naming no rule', () => {
    const policy = HostPolicy.compile(['example.com/org/repo'], [])

    expect(policy.evaluate(host('example.com'), 443, '/org/repo/tree')).toEqual({
      kind: 'allow',
      rule: 'allow:example.com/org/repo',
    })
    expect(policy.evaluate(host('example.com'), 443, '/other')).toEqual({ kind: 'deny', reason: 'blocked-by-allowlist' })
  })

  it('lets a host-wide deny win over a path-scoped allow', () => {
    const policy = HostPolicy.compile(['example.com/org/repo'], ['example.com'])

    expect(policy.evaluate(host('example.com'), 443, '/org/repo')).toEqual({
      kind: 'deny',
      reason: 'blocked-by-denylist',
      rule: 'deny:example.com',
    })
  })
})
