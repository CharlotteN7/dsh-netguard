/**
 * The host matcher: the pattern grammar, the patterns it refuses to compile,
 * and the deny-wins evaluation.
 *
 * The semantics are Codex's, which are the only unambiguous ones in the prior
 * art:
 *
 * - `example.com` matches that host and nothing else;
 * - `*.example.com` matches subdomains only, never the apex;
 * - `**.example.com` matches the apex and every subdomain;
 * - `*` matches anything and may appear only in an allow list;
 * - a deny match wins over every allow match, across every configuration source;
 * - an empty allow list denies everything;
 * - an IPv6 literal is bracketed (`[::1]`, `[::1]:443`).
 *
 * A pattern that could be read two ways is refused rather than widened.
 * @module dsh-netguard/hosts
 */

import { identifyHost, type HostIdentity } from './address.ts'
import { PolicyError } from './errors.ts'

/** How one pattern selects hosts. */
export type PatternKind =
  /** `*`: every host. */
  | 'any'
  /** `example.com`: that host only. */
  | 'exact'
  /** `*.example.com`: subdomains, never the apex. */
  | 'subdomains'
  /** `**.example.com`: the apex and every subdomain. */
  | 'apex-and-subdomains'

/** One compiled pattern. */
export interface HostPattern {
  /** The pattern exactly as configured; this is what a record reports as the rule. */
  readonly source: string
  readonly kind: PatternKind
  /** The canonical host or wildcard base; empty for `*`. */
  readonly base: string
  /** The port the pattern pins, or `undefined` when it matches every port. */
  readonly port?: number
}

/**
 * Second-level public suffixes a wildcard may not be written over.
 *
 * This is an approximation and is documented as one: shipping a public suffix
 * list would make the package's trusted computing base a 15,000-line data file
 * that goes stale. It rejects the spellings that are both easy to write and
 * catastrophic (`*.co.uk` allows every British company), and the README says
 * that a wildcard over a self-service namespace such as `*.github.io` is
 * accepted and is the operator's own risk.
 */
const MULTI_LABEL_PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.in', 'net.in', 'org.in',
  'co.za', 'org.za',
  'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.ua',
  'com.pl', 'com.ru', 'com.my', 'com.ph', 'com.vn',
  'co.kr', 'or.kr', 'co.il', 'co.id', 'co.th',
])

/** Characters that mean the text is a URL or an authority, not a host pattern. */
const NOT_A_HOST = /[\s/?#@\\]/

/** Split `host[:port]`, refusing a spelling that could be read two ways. */
function splitPort(text: string, source: string): { host: string; port?: number } {
  if (text.startsWith('[')) {
    const close = text.indexOf(']')
    if (close < 0) throw new PolicyError(`"${source}" opens an IPv6 literal that is never closed`)
    const rest = text.slice(close + 1)
    const host = text.slice(0, close + 1)
    if (rest.length === 0) return { host }
    if (!rest.startsWith(':')) throw new PolicyError(`"${source}" has trailing text after the IPv6 literal`)
    return { host, port: parsePort(rest.slice(1), source) }
  }
  const colons = text.split(':').length - 1
  if (colons === 0) return { host: text }
  if (colons > 1) {
    throw new PolicyError(
      `"${source}" looks like an IPv6 address without brackets; write [${text}] for the host, or [${text}]:443 for a port`,
    )
  }
  const [host, port] = text.split(':') as [string, string]
  return { host, port: parsePort(port, source) }
}

/** Parse the port half of a pattern. */
function parsePort(text: string, source: string): number {
  if (!/^\d{1,5}$/.test(text)) throw new PolicyError(`"${source}" has a port that is not a number: "${text}"`)
  const port = Number(text)
  if (port < 1 || port > 65_535) throw new PolicyError(`"${source}" has a port outside 1-65535`)
  return port
}

/** The refusal every wildcard inside a label produces, wherever it is written. */
function interiorWildcard(source: string): PolicyError {
  return new PolicyError(
    `"${source}" puts a wildcard inside a label; only a leading *. or **. is accepted, because a prefix`
    + ' wildcard over a self-service namespace matches names an attacker can register',
  )
}

/** Validate the base of a wildcard pattern, which must be a name of at least two labels. */
function wildcardBase(raw: string, source: string): string {
  // A second wildcard in the remainder compiles to a base no host can ever end
  // with, so the pattern matches nothing: silent in an allow list, a hole in a
  // deny list.
  if (raw.includes('*')) throw interiorWildcard(source)
  const identity = identifyHost(raw)
  if (identity === undefined) throw new PolicyError(`"${source}" does not name a host`)
  if (identity.kind !== 'name') {
    throw new PolicyError(`"${source}" applies a wildcard to an IP address; an address matches itself only`)
  }
  const labels = identity.key.split('.')
  if (labels.length < 2) {
    throw new PolicyError(`"${source}" is a wildcard over a top-level domain, which would allow every host under it`)
  }
  if (MULTI_LABEL_PUBLIC_SUFFIXES.has(identity.key)) {
    throw new PolicyError(`"${source}" is a wildcard over the public suffix "${identity.key}", which anyone can register under`)
  }
  return identity.key
}

/**
 * Compile one pattern.
 * @param raw - the pattern as configured.
 * @param options - whether the bare `*` wildcard is accepted in this list.
 * @returns the compiled pattern.
 * @throws PolicyError when the pattern is malformed, ambiguous, or too wide to be meant.
 */
export function parseHostPattern(raw: string, options: { readonly allowAny: boolean }): HostPattern {
  const source = raw.trim()
  if (source.length === 0) throw new PolicyError('an empty string is not a host pattern')
  if (NOT_A_HOST.test(source)) {
    throw new PolicyError(`"${source}" is not a host pattern; write a host, optionally with a port, and no scheme or path`)
  }
  const lowered = source.toLowerCase()
  if (lowered === '*') {
    if (!options.allowAny) {
      throw new PolicyError('"*" may only appear in the allow list; an empty allow list is how you deny everything')
    }
    return { source, kind: 'any', base: '' }
  }
  const { host, port } = splitPort(lowered, source)
  const withPort = <T extends HostPattern>(pattern: T): T => (port === undefined ? pattern : { ...pattern, port })

  if (host.startsWith('**.')) {
    return withPort({ source, kind: 'apex-and-subdomains', base: wildcardBase(host.slice(3), source) })
  }
  if (host.startsWith('*.')) {
    return withPort({ source, kind: 'subdomains', base: wildcardBase(host.slice(2), source) })
  }
  if (host.includes('*')) throw interiorWildcard(source)
  const identity = identifyHost(host)
  if (identity === undefined) throw new PolicyError(`"${source}" does not name a host`)
  return withPort({ source, kind: 'exact', base: identity.key })
}

/**
 * Whether one pattern selects one host and port.
 * @param pattern - the compiled pattern.
 * @param identity - the canonical host identity.
 * @param port - the request's effective port.
 * @returns true when the pattern matches.
 */
export function patternMatches(pattern: HostPattern, identity: HostIdentity, port: number): boolean {
  if (pattern.port !== undefined && pattern.port !== port) return false
  switch (pattern.kind) {
    case 'any':
      return true
    case 'exact':
      return identity.key === pattern.base
    case 'subdomains':
      return identity.kind === 'name' && identity.key.endsWith(`.${pattern.base}`)
    case 'apex-and-subdomains':
      return identity.kind === 'name'
        && (identity.key === pattern.base || identity.key.endsWith(`.${pattern.base}`))
    /* v8 ignore next 4 -- PatternKind is closed; the arm exists so adding a kind fails the build. */
    default: {
      const unhandled: never = pattern.kind
      throw new TypeError(`dsh-netguard: unhandled pattern kind ${JSON.stringify(unhandled)}`)
    }
  }
}

/** What the matcher decided about one host. */
export type HostVerdict =
  | { readonly kind: 'allow'; readonly rule: string }
  | { readonly kind: 'deny'; readonly reason: 'blocked-by-allowlist' | 'blocked-by-denylist'; readonly rule?: string }

/** The compiled allow and deny lists, evaluated deny-first. */
export class HostPolicy {
  /**
   * @param allow - compiled allow patterns; an empty list denies everything.
   * @param deny - compiled deny patterns, which win over every allow pattern.
   */
  constructor(
    private readonly allow: readonly HostPattern[],
    private readonly deny: readonly HostPattern[],
  ) {}

  /**
   * Compile both lists.
   * @param allow - allow patterns as configured; the bare `*` is accepted here only.
   * @param deny - deny patterns as configured.
   * @returns the compiled policy.
   * @throws PolicyError on any pattern that cannot be compiled.
   */
  static compile(allow: readonly string[], deny: readonly string[]): HostPolicy {
    return new HostPolicy(
      allow.map(pattern => parseHostPattern(pattern, { allowAny: true })),
      deny.map(pattern => parseHostPattern(pattern, { allowAny: false })),
    )
  }

  /**
   * Decide one host and port.
   * @param identity - the canonical host identity.
   * @param port - the request's effective port.
   * @returns the verdict and the rule that produced it.
   */
  evaluate(identity: HostIdentity, port: number): HostVerdict {
    const denied = this.deny.find(pattern => patternMatches(pattern, identity, port))
    if (denied !== undefined) return { kind: 'deny', reason: 'blocked-by-denylist', rule: `deny:${denied.source}` }
    const allowed = this.allow.find(pattern => patternMatches(pattern, identity, port))
    if (allowed !== undefined) return { kind: 'allow', rule: `allow:${allowed.source}` }
    return { kind: 'deny', reason: 'blocked-by-allowlist' }
  }

  /** Every pattern, for the report command and for diagnostics. */
  describe(): { readonly allow: readonly string[]; readonly deny: readonly string[] } {
    return { allow: this.allow.map(pattern => pattern.source), deny: this.deny.map(pattern => pattern.source) }
  }
}
