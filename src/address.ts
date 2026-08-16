/**
 * Host and address literals: one canonical spelling per host, explicit
 * decompression of IPv4-mapped IPv6, and the table of addresses this package
 * refuses to dial.
 *
 * Two rules make the canonicalisation trustworthy. The first is that every
 * hostname is read through WHATWG `URL`, which already turns `2130706433`,
 * `0x7f000001`, `127.1` and `017700000001` into `127.0.0.1` and applies IDNA to
 * names — so no decimal, octal, hexadecimal or unicode spelling reaches the
 * matcher unnormalised. The second is that `URL` does *not* unwrap an
 * IPv4-mapped IPv6 address: it serialises `[::ffff:127.0.0.1]` as
 * `[::ffff:7f00:1]`, which no IPv4 rule would match. This module unwraps that
 * form, the deprecated IPv4-compatible form, and the NAT64 well-known prefix
 * itself.
 *
 * The address table is a security invariant and is not configurable. A
 * deployment may open named private ranges through `allowPrivateAddresses`
 * (see `policy.ts`); the cloud metadata endpoints and the whole link-local
 * range are excluded from even that, because an agent that can reach
 * `169.254.169.254` holds the host's cloud role.
 * @module dsh-netguard/address
 */

import { isIP } from 'node:net'

/** How a host was written, after canonicalisation. */
export type HostKind = 'ipv4' | 'ipv6' | 'name'

/** One host in the single spelling every comparison in this package uses. */
export interface HostIdentity {
  /** The comparison key: a dotted quad, a bracket-free compressed IPv6, or a lower-case DNS name. */
  readonly key: string
  readonly kind: HostKind
}

/** Strip one layer of IPv6 literal brackets. */
function unbracket(raw: string): string {
  return raw.startsWith('[') && raw.endsWith(']') ? raw.slice(1, -1) : raw
}

/**
 * Expand an IPv6 literal to its sixteen bytes.
 * @param text - the literal, without brackets; `net.isIP` must already accept it.
 * @returns the address bytes.
 */
export function ipv6Bytes(text: string): Uint8Array {
  const [head, tail] = text.split('::', 2) as [string, string | undefined]
  const parseGroups = (part: string): string[] => (part.length === 0 ? [] : part.split(':'))
  const headGroups = parseGroups(head)
  const tailGroups = tail === undefined ? [] : parseGroups(tail)
  const groups = [...headGroups, ...tailGroups]
  // A trailing dotted quad occupies the last two groups; `net.isIP` has already
  // accepted the literal, so a `.` can only appear in that position.
  const embedded = groups.at(-1)?.includes('.') === true ? groups.pop() : undefined
  const filled = 8 - (embedded === undefined ? 0 : 2)
  const bytes = new Uint8Array(16)
  const expanded: number[] = []
  for (const group of headGroups.filter(entry => !entry.includes('.'))) expanded.push(Number.parseInt(group, 16))
  const trailing = tailGroups.filter(entry => !entry.includes('.')).map(group => Number.parseInt(group, 16))
  while (expanded.length + trailing.length < filled) expanded.push(0)
  expanded.push(...trailing)
  for (const [index, value] of expanded.entries()) {
    bytes[index * 2] = (value >> 8) & 0xff
    bytes[index * 2 + 1] = value & 0xff
  }
  if (embedded !== undefined) {
    const quad = embedded.split('.').map(part => Number.parseInt(part, 10))
    for (const [index, value] of quad.entries()) bytes[12 + index] = value
  }
  return bytes
}

/** The four bytes of a dotted quad. */
function ipv4Bytes(text: string): Uint8Array {
  return Uint8Array.from(text.split('.').map(part => Number.parseInt(part, 10)))
}

/** Render four bytes as a dotted quad. */
function dottedQuad(bytes: Uint8Array, offset: number): string {
  return [0, 1, 2, 3].map(index => String(bytes[offset + index])).join('.')
}

/**
 * IPv6 prefixes whose low 32 bits are an IPv4 address, so a rule written about
 * IPv4 has to see them. `::ffff:0:0/96` is the mapped form the WHATWG URL
 * parser leaves compressed, `::/96` is the deprecated compatible form, and
 * `64:ff9b::/96` is the NAT64 well-known prefix, which a resolver on a
 * DNS64 network hands back for an IPv4-only name.
 */
const IPV4_BEARING_PREFIXES: readonly {
  readonly prefix: readonly number[]
  /**
   * True for the compatible prefix, whose block also contains `::` and `::1` —
   * the unspecified and loopback addresses, which name themselves rather than
   * `0.0.0.0` and `0.0.0.1`.
   */
  readonly excludesLowValues: boolean
}[] = [
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], excludesLowValues: false },
  { prefix: [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0], excludesLowValues: false },
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], excludesLowValues: true },
]

/** Whether `bytes` begins with `prefix`. */
function startsWith(bytes: Uint8Array, prefix: readonly number[]): boolean {
  return prefix.every((value, index) => bytes[index] === value)
}

/**
 * The IPv4 address an IPv6 literal carries, when it carries one.
 *
 * `::` and `::1` are excluded: their low 32 bits are `0.0.0.0` and `0.0.0.1`,
 * which are not the addresses they name.
 * @param bytes - the sixteen bytes of the IPv6 address.
 * @returns the embedded dotted quad, or `undefined` when there is none.
 */
export function embeddedIpv4(bytes: Uint8Array): string | undefined {
  for (const { prefix, excludesLowValues } of IPV4_BEARING_PREFIXES) {
    if (!startsWith(bytes, prefix)) continue
    if (excludesLowValues && bytes[12] === 0 && bytes[13] === 0) return undefined
    return dottedQuad(bytes, 12)
  }
  return undefined
}

/**
 * Canonicalise one hostname as written in a URL, a policy pattern, or a
 * resolver answer.
 *
 * @param raw - the hostname; IPv6 may be bracketed or bare.
 * @returns the canonical identity, or `undefined` when the text is not a
 *   hostname at all.
 */
export function identifyHost(raw: string): HostIdentity | undefined {
  const inner = unbracket(raw.trim())
  if (inner.length === 0) return undefined
  const literal = isIP(inner)
  // A colon in anything but an IPv6 literal is a port, a scheme, or credentials.
  // Parsing it here would silently discard that half of the text.
  if (literal !== 6 && inner.includes(':')) return undefined
  const wrapped = literal === 6 ? `[${inner}]` : inner
  let hostname: string
  try {
    hostname = new URL(`http://${wrapped}`).hostname
  } catch {
    // URL parse failure only: the text is not a host, which every caller
    // reports as an invalid target rather than guessing at an intent.
    return undefined
  }
  if (hostname.startsWith('[')) {
    const literal = unbracket(hostname)
    const mapped = embeddedIpv4(ipv6Bytes(literal))
    return mapped === undefined ? { key: literal, kind: 'ipv6' } : { key: mapped, kind: 'ipv4' }
  }
  if (isIP(hostname) === 4) return { key: hostname, kind: 'ipv4' }
  // A trailing dot is the same name; keeping it would let `example.com.` slip
  // past a rule written for `example.com`.
  return { key: hostname.replace(/\.$/, ''), kind: 'name' }
}

/** One CIDR block, in the form the containment test uses. */
export interface Cidr {
  /** The block as written, for messages. */
  readonly source: string
  readonly family: 4 | 6
  readonly value: bigint
  readonly length: number
}

/** The numeric value of an address's bytes. */
function toBigInt(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

/** The bytes of a canonical address identity. */
function addressBytes(identity: HostIdentity): Uint8Array {
  return identity.kind === 'ipv4' ? ipv4Bytes(identity.key) : ipv6Bytes(identity.key)
}

/**
 * Parse one CIDR block.
 * @param text - `address/length`, or a bare address meaning a single host.
 * @returns the parsed block, or `undefined` when the text is not one.
 */
export function parseCidr(text: string): Cidr | undefined {
  const [address, length] = text.trim().split('/', 2) as [string, string | undefined]
  const identity = identifyHost(address)
  if (identity === undefined || identity.kind === 'name') return undefined
  const family = identity.kind === 'ipv4' ? 4 : 6
  const bits = family === 4 ? 32 : 128
  const prefix = length === undefined ? bits : Number(length)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return undefined
  const value = toBigInt(addressBytes(identity))
  return { source: text.trim(), family, value: value >> BigInt(bits - prefix) << BigInt(bits - prefix), length: prefix }
}

/**
 * Whether one address falls inside one block.
 * @param cidr - the block.
 * @param identity - a canonical address identity.
 * @returns true when the address is inside the block.
 */
export function cidrContains(cidr: Cidr, identity: HostIdentity): boolean {
  if (identity.kind === 'name') return false
  if ((identity.kind === 'ipv4' ? 4 : 6) !== cidr.family) return false
  const bits = cidr.family === 4 ? 32 : 128
  const shift = BigInt(bits - cidr.length)
  return (toBigInt(addressBytes(identity)) >> shift) === (cidr.value >> shift)
}

/** Whether two blocks share any address. */
function cidrsOverlap(a: Cidr, b: Cidr): boolean {
  if (a.family !== b.family) return false
  const shift = BigInt((a.family === 4 ? 32 : 128) - Math.min(a.length, b.length))
  return (a.value >> shift) === (b.value >> shift)
}

/** Why one resolved address is refused. */
export type AddressClass =
  | 'loopback'
  | 'private'
  | 'link-local'
  | 'cloud-metadata'
  | 'unspecified'
  | 'multicast'
  | 'reserved'
  | 'carrier-nat'
  | 'benchmark'

/** One entry of the refused-address table. */
interface AddressRule {
  readonly cidr: Cidr
  readonly label: AddressClass
  /** True when no configuration may re-open the block. */
  readonly absolute: boolean
}

/** Build one table entry; the literals here are constants, so a parse failure is a build error. */
function rule(text: string, label: AddressClass, absolute = false): AddressRule {
  const cidr = parseCidr(text)
  /* v8 ignore next -- the table below holds literals only, so this never fires; the throw keeps a typo from becoming a silently absent rule. */
  if (cidr === undefined) throw new Error(`dsh-netguard: "${text}" is not a CIDR block`)
  return { cidr, label, absolute }
}

/**
 * Addresses no allowlist entry makes reachable.
 *
 * `169.254.169.254` and `fd00:ec2::254` are AWS/GCP/OpenStack instance
 * metadata, `169.254.170.2` is the ECS task role endpoint, and
 * `168.63.129.16` is Azure's wire server: each hands out the host's own cloud
 * credentials to anything that can make an HTTP request. harden-runner
 * allowlists RFC1918 by default; for an agent running on a developer's own
 * machine or a build host that is the wrong call, so nothing here is reachable
 * unless a deployment names it, and these entries are not nameable at all.
 */
export const REFUSED_ADDRESSES: readonly AddressRule[] = Object.freeze([
  rule('169.254.169.254/32', 'cloud-metadata', true),
  rule('169.254.170.2/32', 'cloud-metadata', true),
  rule('168.63.129.16/32', 'cloud-metadata', true),
  rule('fd00:ec2::254/128', 'cloud-metadata', true),
  rule('169.254.0.0/16', 'link-local', true),
  rule('fe80::/10', 'link-local', true),
  rule('0.0.0.0/8', 'unspecified'),
  rule('::/128', 'unspecified'),
  rule('127.0.0.0/8', 'loopback'),
  rule('::1/128', 'loopback'),
  rule('10.0.0.0/8', 'private'),
  rule('172.16.0.0/12', 'private'),
  rule('192.168.0.0/16', 'private'),
  rule('fc00::/7', 'private'),
  rule('100.64.0.0/10', 'carrier-nat'),
  rule('192.0.0.0/24', 'reserved'),
  rule('198.18.0.0/15', 'benchmark'),
  rule('224.0.0.0/4', 'multicast'),
  rule('ff00::/8', 'multicast'),
  rule('240.0.0.0/4', 'reserved'),
])

/** Blocks a deployment may never open, named for the error message. */
export const UNOPENABLE_ADDRESSES: readonly Cidr[] = Object.freeze(
  REFUSED_ADDRESSES.filter(entry => entry.absolute).map(entry => entry.cidr),
)

/**
 * Whether a deployment-supplied block would re-open an address that must stay
 * unreachable.
 * @param cidr - the block a deployment asked to allow.
 * @returns the unopenable block it overlaps, or `undefined`.
 */
export function overlapsUnopenable(cidr: Cidr): Cidr | undefined {
  return UNOPENABLE_ADDRESSES.find(entry => cidrsOverlap(entry, cidr))
}

/**
 * Classify one resolved address against the refused table.
 * @param identity - a canonical address identity.
 * @param opened - blocks the deployment opened; a match there clears a
 *   non-absolute rule and never an absolute one.
 * @returns the class that refuses the address, or `undefined` when it may be dialled.
 */
export function refusedAddressClass(
  identity: HostIdentity,
  opened: readonly Cidr[] = [],
): AddressClass | undefined {
  const hit = REFUSED_ADDRESSES.find(entry => cidrContains(entry.cidr, identity))
  if (hit === undefined) return undefined
  if (hit.absolute) return hit.label
  return opened.some(entry => cidrContains(entry, identity)) ? undefined : hit.label
}
