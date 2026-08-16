/** Host canonicalisation, IPv4-mapped IPv6 decompression, and the refused-address table. */

import { describe, expect, it } from 'vitest'
import {
  cidrContains,
  embeddedIpv4,
  identifyHost,
  ipv6Bytes,
  overlapsUnopenable,
  parseCidr,
  refusedAddressClass,
  UNOPENABLE_ADDRESSES,
} from '../../src/address.ts'

/** Parse a CIDR the tests know is well formed. */
function cidr(text: string) {
  const parsed = parseCidr(text)
  if (parsed === undefined) throw new Error(`test fixture "${text}" is not a CIDR`)
  return parsed
}

/** Identify a host the tests know is well formed. */
function host(text: string) {
  const identity = identifyHost(text)
  if (identity === undefined) throw new Error(`test fixture "${text}" is not a host`)
  return identity
}

describe('canonicalising a host', () => {
  it.each([
    ['2130706433', '127.0.0.1'],
    ['0x7f000001', '127.0.0.1'],
    ['127.1', '127.0.0.1'],
    ['017700000001', '127.0.0.1'],
    ['127.0.0.1', '127.0.0.1'],
  ])('reads every spelling of an IPv4 literal (%s)', (written, expected) => {
    expect(identifyHost(written)).toEqual({ key: expected, kind: 'ipv4' })
  })

  it.each([
    ['[::ffff:127.0.0.1]', '127.0.0.1'],
    ['::ffff:127.0.0.1', '127.0.0.1'],
    // The spelling WHATWG URL leaves behind after canonicalising the one above.
    ['[::ffff:7f00:1]', '127.0.0.1'],
    ['[::ffff:a9fe:a9fe]', '169.254.169.254'],
    // The deprecated IPv4-compatible form.
    ['[::127.0.0.1]', '127.0.0.1'],
    // The NAT64 well-known prefix, which a DNS64 resolver answers with.
    ['[64:ff9b::7f00:1]', '127.0.0.1'],
  ])('decompresses an IPv4-bearing IPv6 literal (%s)', (written, expected) => {
    expect(identifyHost(written)).toEqual({ key: expected, kind: 'ipv4' })
  })

  it.each([
    ['[::1]', '::1'],
    ['::1', '::1'],
    ['[0:0:0:0:0:0:0:1]', '::1'],
    ['[fe80::1]', 'fe80::1'],
  ])('keeps a genuine IPv6 literal as one (%s)', (written, expected) => {
    expect(identifyHost(written)).toEqual({ key: expected, kind: 'ipv6' })
  })

  it.each([
    ['::ffff:127.0.0.1', '127.0.0.1'],
    ['::13.1.68.3', '13.1.68.3'],
    ['64:ff9b::192.0.2.33', '192.0.2.33'],
  ])('expands the trailing dotted quad of %s, which URL canonicalisation hides', (literal, expected) => {
    // `identifyHost` never sees this spelling — WHATWG URL rewrites it to hex
    // groups — so the expansion is exercised directly.
    expect(embeddedIpv4(ipv6Bytes(literal))).toBe(expected)
  })

  it('expands a literal written out in full and one with a trailing ::', () => {
    expect(ipv6Bytes('2001:db8:0:0:0:0:0:1')).toEqual(ipv6Bytes('2001:db8::1'))
    expect(ipv6Bytes('2001:db8::')).toEqual(ipv6Bytes('2001:0db8:0:0:0:0:0:0'))
  })

  it('does not mistake ::1 for the IPv4 address 0.0.0.1', () => {
    expect(embeddedIpv4(ipv6Bytes('::1'))).toBeUndefined()
    expect(embeddedIpv4(ipv6Bytes('::'))).toBeUndefined()
  })

  it('lower-cases a name, applies IDNA, and drops a trailing dot', () => {
    expect(identifyHost('EXAMPLE.com.')).toEqual({ key: 'example.com', kind: 'name' })
    expect(identifyHost('bücher.de')).toEqual({ key: 'xn--bcher-kva.de', kind: 'name' })
  })

  it.each([
    ['an empty string', ''],
    ['a name with a port, which would silently lose the port', 'example.com:443'],
    ['a URL', 'http://example.com'],
    ['a space', 'not a host'],
  ])('refuses %s', (_label, written) => {
    expect(identifyHost(written)).toBeUndefined()
  })
})

describe('CIDR blocks', () => {
  it('treats a bare address as a single-host block', () => {
    expect(cidr('169.254.169.254')).toMatchObject({ family: 4, length: 32 })
    expect(cidr('::1')).toMatchObject({ family: 6, length: 128 })
  })

  it('masks the block value, so a sloppy base address still contains its range', () => {
    expect(cidrContains(cidr('10.1.2.3/8'), host('10.255.255.255'))).toBe(true)
  })

  it('never matches across families or against a name', () => {
    expect(cidrContains(cidr('10.0.0.0/8'), host('[fc00::1]'))).toBe(false)
    expect(cidrContains(cidr('10.0.0.0/8'), host('example.com'))).toBe(false)
  })

  it.each([
    ['a name', 'example.com/24'],
    ['a prefix past the family width', '10.0.0.0/33'],
    ['a prefix that is not a number', '10.0.0.0/eight'],
    ['a negative prefix', '10.0.0.0/-1'],
  ])('refuses %s', (_label, text) => {
    expect(parseCidr(text)).toBeUndefined()
  })
})

describe('the refused-address table', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'cloud-metadata'],
    ['169.254.170.2', 'cloud-metadata'],
    ['168.63.129.16', 'cloud-metadata'],
    ['169.254.1.1', 'link-local'],
    ['100.64.0.1', 'carrier-nat'],
    ['192.0.0.1', 'reserved'],
    ['198.18.0.1', 'benchmark'],
    ['224.0.0.1', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['0.0.0.0', 'unspecified'],
    ['[::1]', 'loopback'],
    ['[::]', 'unspecified'],
    ['[fc00::1]', 'private'],
    ['[fe80::1]', 'link-local'],
    ['[ff02::1]', 'multicast'],
    ['[fd00:ec2::254]', 'cloud-metadata'],
  ])('refuses %s as %s', (address, expected) => {
    expect(refusedAddressClass(host(address))).toBe(expected)
  })

  it('permits an ordinary public address', () => {
    expect(refusedAddressClass(host('93.184.216.34'))).toBeUndefined()
    expect(refusedAddressClass(host('[2606:2800:220:1:248:1893:25c8:1946]'))).toBeUndefined()
  })

  it('lets a deployment open a private range it names', () => {
    expect(refusedAddressClass(host('127.0.0.1'), [cidr('127.0.0.0/8')])).toBeUndefined()
    expect(refusedAddressClass(host('10.1.2.3'), [cidr('10.0.0.0/8')])).toBeUndefined()
  })

  it('keeps cloud metadata refused even when a deployment opened the range around it', () => {
    // The table is consulted before the opened list, and the metadata entries
    // are absolute, so a wide opening cannot reach them.
    expect(refusedAddressClass(host('169.254.169.254'), [cidr('169.254.0.0/16')])).toBe('cloud-metadata')
  })
})

describe('ranges a deployment may never open', () => {
  it('names the block a request overlaps', () => {
    expect(overlapsUnopenable(cidr('169.254.169.254/32'))?.source).toBe('169.254.169.254/32')
    expect(overlapsUnopenable(cidr('169.254.0.0/16'))?.source).toBe('169.254.169.254/32')
    expect(overlapsUnopenable(cidr('168.63.129.16'))?.source).toBe('168.63.129.16/32')
    expect(overlapsUnopenable(cidr('[fe80::]/10'))?.source).toBe('fe80::/10')
  })

  it('permits a private range that touches none of them', () => {
    expect(overlapsUnopenable(cidr('10.0.0.0/8'))).toBeUndefined()
    expect(overlapsUnopenable(cidr('127.0.0.0/8'))).toBeUndefined()
  })

  it('lists every absolute entry', () => {
    expect(UNOPENABLE_ADDRESSES.map(entry => entry.source)).toEqual([
      '169.254.169.254/32',
      '169.254.170.2/32',
      '168.63.129.16/32',
      'fd00:ec2::254/128',
      '169.254.0.0/16',
      'fe80::/10',
    ])
  })
})
