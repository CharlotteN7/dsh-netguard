/** What a URL and a resolver answer have to survive before a socket is opened. */

import { afterAll, describe, expect, it } from 'vitest'
import { identifyHost, type HostIdentity } from '../../src/address.ts'
import { checkAddresses, checkUrl, effectivePort, isSameOrigin } from '../../src/decide.ts'
import { disposeHome, makeHome, policyOf } from './support.ts'

const home = makeHome('decide')
afterAll(() => { disposeHome(home) })

/** Identify a host the tests know is well formed. */
function host(text: string): HostIdentity {
  const identity = identifyHost(text)
  if (identity === undefined) throw new Error(`test fixture "${text}" is not a host`)
  return identity
}

/** One resolver answer, as `checkAddresses` receives it. */
function answer(address: string): { identity: HostIdentity; family: 4 | 6 } {
  const identity = host(address)
  return { identity, family: identity.kind === 'ipv4' ? 4 : 6 }
}

describe('the effective port', () => {
  it('is the explicit one when the URL names it, and the scheme default otherwise', () => {
    expect(effectivePort(new URL('https://example.com'))).toBe(443)
    expect(effectivePort(new URL('http://example.com'))).toBe(80)
    expect(effectivePort(new URL('https://example.com:8443/a'))).toBe(8443)
  })
})

describe('checking a URL', () => {
  const policy = policyOf(home, { allow: ['**.example.com'], deny: ['secret.example.com'] })

  it('allows an allowlisted host and names the rule', () => {
    const checked = checkUrl('https://api.example.com/things?q=1', policy)

    expect(checked).toMatchObject({
      kind: 'checked',
      decision: { kind: 'allow', rule: 'allow:**.example.com' },
      target: { display: 'api.example.com', port: 443 },
    })
  })

  it('denies a host the allow list does not cover', () => {
    expect(checkUrl('https://elsewhere.test/', policy)).toMatchObject({
      kind: 'checked',
      decision: { kind: 'deny', reason: 'blocked-by-allowlist' },
    })
  })

  it('denies a host the deny list covers, even though the allow list also matches it', () => {
    expect(checkUrl('https://secret.example.com/', policy)).toMatchObject({
      decision: { kind: 'deny', reason: 'blocked-by-denylist', rule: 'deny:secret.example.com' },
    })
  })

  it.each([
    ['gopher:', 'gopher://api.example.com/'],
    ['ftp:', 'ftp://api.example.com/x'],
    ['ws:', 'ws://api.example.com/socket'],
  ])('denies the %s scheme, which still names a host to record', (_label, raw) => {
    expect(checkUrl(raw, policy)).toMatchObject({ decision: { kind: 'deny', reason: 'blocked-by-scheme' } })
  })

  it.each([
    ['file:', 'file:///etc/passwd'],
    ['data:', 'data:text/plain,hello'],
  ])('reports the hostless %s scheme as hostless, naming the scheme', (_label, raw) => {
    // There is no endpoint to put in a record, so the caller records it against
    // a marker; the message still tells the model what to change.
    expect(checkUrl(raw, policy)).toMatchObject({
      kind: 'invalid',
      reason: 'blocked-by-scheme',
      detail: expect.stringContaining('only http and https are allowed'),
    })
  })

  it('denies embedded credentials before it looks at the host', () => {
    expect(checkUrl('https://user:pass@api.example.com/', policy)).toMatchObject({
      decision: { kind: 'deny', reason: 'blocked-by-credentials' },
    })
  })

  it('reads the canonical host, so an obfuscated literal is decided as what it is', () => {
    const loopback = policyOf(home, { allow: ['127.0.0.1'] })

    expect(checkUrl('http://2130706433/', loopback)).toMatchObject({
      target: { identity: { key: '127.0.0.1' } },
      decision: { kind: 'allow' },
    })
    expect(checkUrl('http://[::ffff:7f00:1]/', loopback)).toMatchObject({
      target: { identity: { key: '127.0.0.1' } },
      decision: { kind: 'allow' },
    })
  })

  it('shows the port in the display host only when the URL named one', () => {
    const ported = policyOf(home, { allow: ['*'] })

    expect(checkUrl('https://example.com:8443/', ported)).toMatchObject({ target: { display: 'example.com:8443' } })
    expect(checkUrl('https://example.com/', ported)).toMatchObject({ target: { display: 'example.com' } })
  })

  it('reports text that is not a URL as hostless, and never echoes it back', () => {
    const checked = checkUrl('not a url', policy)

    expect(checked).toMatchObject({ kind: 'invalid', reason: 'blocked-by-invalid-url' })
    expect(JSON.stringify(checked)).not.toContain('not a url')
  })

  it('denies a URL past the configured length against the host it names', () => {
    const short = policyOf(home, { allow: ['*'], fetch: { maxUrlLength: 30 } })

    expect(checkUrl(`https://api.example.com/${'a'.repeat(50)}`, short)).toMatchObject({
      kind: 'checked',
      target: { identity: { key: 'api.example.com' } },
      decision: { kind: 'deny', reason: 'blocked-by-url-length', detail: expect.stringContaining('maximum of 30') },
    })
  })

  it('reports the host verdict on an over-length URL, so padding cannot hide the target', () => {
    const short = policyOf(home, { allow: ['good.test'], fetch: { maxUrlLength: 30 } })

    expect(checkUrl(`https://evil.test/?${'a'.repeat(50)}`, short)).toMatchObject({
      kind: 'checked',
      target: { identity: { key: 'evil.test' } },
      decision: { kind: 'deny', reason: 'blocked-by-allowlist' },
    })
  })
})

describe('checking a resolver answer', () => {
  const policy = policyOf(home, { allow: ['*'] })

  it('allows an answer of public addresses only', () => {
    expect(checkAddresses([answer('198.51.100.34')], policy)).toEqual({ kind: 'allow', rule: 'address:public' })
  })

  it('denies an empty answer rather than connecting to nothing', () => {
    expect(checkAddresses([], policy)).toMatchObject({ kind: 'deny', reason: 'blocked-by-private-address' })
  })

  it.each([
    ['loopback', '127.0.0.1'],
    ['cloud metadata', '169.254.169.254'],
    ['the Azure wire server', '168.63.129.16'],
    ['an RFC1918 address', '10.1.2.3'],
    ['a unique-local IPv6 address', '[fc00::1]'],
  ])('denies an answer containing %s', (_label, address) => {
    expect(checkAddresses([answer(address)], policy)).toMatchObject({
      kind: 'deny',
      reason: 'blocked-by-private-address',
    })
  })

  it('denies a mixed answer, so the outcome does not depend on address selection order', () => {
    expect(checkAddresses([answer('198.51.100.34'), answer('169.254.169.254')], policy)).toMatchObject({
      kind: 'deny',
      rule: 'address:cloud-metadata',
    })
  })

  it('allows a private address the deployment opened', () => {
    const opened = policyOf(home, { allow: ['*'], allowPrivateAddresses: ['127.0.0.1/32'] })

    expect(checkAddresses([answer('127.0.0.1')], opened).kind).toBe('allow')
    expect(checkAddresses([answer('127.0.0.2')], opened).kind).toBe('deny')
  })
})

describe('the same-origin rule for a redirect', () => {
  it.each([
    ['a path change', 'https://a.example.com/one', 'https://a.example.com/two', true],
    ['a host change', 'https://a.example.com/', 'https://b.example.com/', false],
    ['a scheme change', 'https://a.example.com/', 'http://a.example.com/', false],
    ['a port change', 'https://a.example.com/', 'https://a.example.com:8443/', false],
  ])('%s', (_label, from, to, expected) => {
    expect(isSameOrigin(new URL(from), new URL(to))).toBe(expected)
  })
})
