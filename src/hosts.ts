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
 * One addition of this package's own: an allow entry may carry a path, as in
 * `example.com/org/repo`, which grants that path and everything under it and
 * nothing else on the host. `example.com/org/repo` is a meaningfully narrower
 * grant than all of `example.com`, and a host allowlist has no other way to
 * express it. The path half is deliberately the smallest grammar that is still
 * useful: a segment-boundary prefix, matched case-sensitively, with no wildcard
 * inside it, no query string, and no trailing slash. A deny entry stays
 * host-wide — see {@link patternPath} for why each of those is a refusal rather
 * than a reading.
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
  /**
   * The path prefix the pattern scopes to, with no trailing slash, or
   * `undefined` when the pattern covers every path on the host.
   */
  readonly path?: string
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

/** A scheme in front of the host, which no pattern carries. */
const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i

/**
 * The path half of a pattern: one or more non-empty segments of the characters
 * a path may carry, with no trailing slash.
 *
 * Everything outside this — a space, a quote, a backslash, a bracket — is
 * refused rather than escaped, because the pattern text is what a record
 * reports as `firewall_rule.uid`.
 */
const PATTERN_PATH = /^(?:\/[A-Za-z0-9._~%+@:,-]+)+$/

/** A percent-encoded slash, which hides a segment boundary from one of the two readers. */
const ENCODED_SLASH = /%2f/i

/** A path segment that WHATWG `URL` resolves away, in any spelling it accepts. */
const DOT_SEGMENT = /^(?:\.|%2e)(?:\.|%2e)?$/i

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
 * Validate the path half of a pattern.
 *
 * Every rule here is a refusal rather than a reading, because the alternative
 * to each one is a pattern an operator and this package would read differently:
 *
 * - a deny entry carrying a path would refuse *less* than the same line without
 *   one, which is the one direction a deny must never be misread in;
 * - a trailing slash is a second spelling of the same grant;
 * - a wildcard inside a path invites `example.com/*`, which is the host with
 *   extra characters, and `example.com/a*b`, which is the prefix-wildcard shape
 *   §13 of ADR.md refuses for hosts;
 * - a query string is not part of the grant at all: this matches on the path,
 *   and a pattern that appeared to constrain `?token=` would be a claim this
 *   package cannot keep;
 * - a `.` or `..` segment cannot appear in a request path, because WHATWG `URL`
 *   has already resolved it away, so such a pattern would match nothing;
 * - a percent-encoded slash hides a segment boundary from one of the two
 *   readers of the path, and origin servers disagree about which.
 * @param text - the path half, including its leading slash.
 * @param source - the whole pattern, for the message.
 * @param list - which list the pattern is being compiled for.
 * @returns the path prefix, case preserved.
 * @throws PolicyError on a path that could be read two ways.
 */
function patternPath(text: string, source: string, list: 'allow' | 'deny'): string {
  if (list === 'deny') {
    throw new PolicyError(
      `"${source}" puts a path on a deny entry; a deny match is host-wide, and a path would refuse less than the`
      + ' same line without one',
    )
  }
  if (text.endsWith('/')) {
    throw new PolicyError(`"${source}" ends in a slash; a path grant covers everything under it, so write it without the trailing slash`)
  }
  if (text.includes('*')) {
    throw new PolicyError(
      `"${source}" puts a wildcard in the path; a path grant already covers every path under it, and no other`
      + ' wildcard is accepted there',
    )
  }
  if (text.includes('?') || text.includes('#')) {
    throw new PolicyError(
      `"${source}" carries a query string or a fragment; a path grant is matched on the path alone, and pinning a`
      + ' query is not something this package can enforce',
    )
  }
  if (ENCODED_SLASH.test(text)) {
    throw new PolicyError(`"${source}" percent-encodes a slash, which hides where one path segment ends; write the segments out`)
  }
  if (text.slice(1).split('/').some(segment => DOT_SEGMENT.test(segment))) {
    throw new PolicyError(`"${source}" has a "." or ".." segment, which a request path never carries, so the pattern would match nothing`)
  }
  if (!PATTERN_PATH.test(text)) {
    throw new PolicyError(`"${source}" has a path this grammar does not accept; write non-empty segments of [A-Za-z0-9._~%+@:,-]`)
  }
  return text
}

/**
 * Compile one pattern.
 * @param raw - the pattern as configured.
 * @param options - which list the pattern belongs to; the bare `*` and a path
 *   suffix are accepted in the allow list only.
 * @returns the compiled pattern.
 * @throws PolicyError when the pattern is malformed, ambiguous, or too wide to be meant.
 */
export function parseHostPattern(raw: string, options: { readonly list: 'allow' | 'deny' }): HostPattern {
  const source = raw.trim()
  if (source.length === 0) throw new PolicyError('an empty string is not a host pattern')
  if (SCHEME.test(source)) {
    throw new PolicyError(`"${source}" is not a host pattern; write a host, optionally with a port and a path, and no scheme`)
  }
  const slash = source.indexOf('/')
  const authority = slash < 0 ? source : source.slice(0, slash)
  if (NOT_A_HOST.test(authority)) {
    throw new PolicyError(`"${source}" is not a host pattern; write a host, optionally with a port and a path, and no scheme`)
  }
  const path = slash < 0 ? undefined : patternPath(source.slice(slash), source, options.list)
  const lowered = authority.toLowerCase()
  if (lowered === '*') {
    if (options.list !== 'allow') {
      throw new PolicyError('"*" may only appear in the allow list; an empty allow list is how you deny everything')
    }
    if (path !== undefined) {
      throw new PolicyError(`"${source}" scopes every host to one path; "*" is the entry that means every host, so name the host you mean`)
    }
    return { source, kind: 'any', base: '' }
  }
  const { host, port } = splitPort(lowered, source)
  // The path is not lowered with the host: only the scheme and the authority of
  // a URL are case-insensitive, so `/Org/Repo` and `/org/repo` are two paths.
  const scoped = <T extends HostPattern>(pattern: T): T => ({
    ...pattern,
    ...port === undefined ? {} : { port },
    ...path === undefined ? {} : { path },
  })

  if (host.startsWith('**.')) {
    return scoped({ source, kind: 'apex-and-subdomains', base: wildcardBase(host.slice(3), source) })
  }
  if (host.startsWith('*.')) {
    return scoped({ source, kind: 'subdomains', base: wildcardBase(host.slice(2), source) })
  }
  if (host.includes('*')) throw interiorWildcard(source)
  const identity = identifyHost(host)
  if (identity === undefined) throw new PolicyError(`"${source}" does not name a host`)
  if (path !== undefined && identity.kind !== 'name') {
    throw new PolicyError(
      `"${source}" puts a path on an IP address, where it reads as a CIDR block; an address pattern matches that`
      + ' address only',
    )
  }
  return scoped({ source, kind: 'exact', base: identity.key })
}

/**
 * Whether one request path falls inside one pattern's path grant.
 *
 * The prefix has to land on a segment boundary: `example.com/api` covers
 * `/api` and `/api/v2`, and never `/apiv2`. The request path is
 * `URL.pathname`, so WHATWG `URL` has already resolved `.` and `..` away and a
 * traversal cannot climb out of the grant — but a percent-encoded slash it left
 * alone still can, on any origin that decodes before it routes, so a path
 * carrying one matches no path-scoped rule at all.
 * @param rule - the pattern's path prefix, or `undefined` when it grants every path.
 * @param path - the request path, or `undefined` when the caller has a host and no path.
 * @returns true when the pattern's path half permits this request.
 */
function pathMatches(rule: string | undefined, path: string | undefined): boolean {
  if (rule === undefined) return true
  // A host read out of a search query names no path, and the query filter is
  // deciding whether the *host* is one this policy tolerates. Refusing the
  // mention would refuse the work rather than the attack; the fetch path, which
  // always has a URL, is where the grant is enforced.
  if (path === undefined) return true
  if (ENCODED_SLASH.test(path)) return false
  return path === rule || path.startsWith(`${rule}/`)
}

/**
 * Whether one pattern selects one host, port and path.
 * @param pattern - the compiled pattern.
 * @param identity - the canonical host identity.
 * @param port - the request's effective port.
 * @param path - the request path, or `undefined` when the caller has none.
 * @returns true when the pattern matches.
 */
export function patternMatches(pattern: HostPattern, identity: HostIdentity, port: number, path?: string): boolean {
  if (pattern.port !== undefined && pattern.port !== port) return false
  if (!pathMatches(pattern.path, path)) return false
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
      allow.map(pattern => parseHostPattern(pattern, { list: 'allow' })),
      deny.map(pattern => parseHostPattern(pattern, { list: 'deny' })),
    )
  }

  /**
   * Decide one host, port and path.
   * @param identity - the canonical host identity.
   * @param port - the request's effective port.
   * @param path - the request path (`URL.pathname`), or `undefined` when the
   *   caller names a host with no path — only the search-query filter does,
   *   and a path-scoped rule then matches on its host alone.
   * @returns the verdict and the rule that produced it.
   */
  evaluate(identity: HostIdentity, port: number, path: string | undefined): HostVerdict {
    // No path is passed here: a deny entry is host-wide by grammar, so a deny
    // match cannot depend on which path was asked for.
    const denied = this.deny.find(pattern => patternMatches(pattern, identity, port))
    if (denied !== undefined) return { kind: 'deny', reason: 'blocked-by-denylist', rule: `deny:${denied.source}` }
    const allowed = this.allow.find(pattern => patternMatches(pattern, identity, port, path))
    if (allowed !== undefined) return { kind: 'allow', rule: `allow:${allowed.source}` }
    return { kind: 'deny', reason: 'blocked-by-allowlist' }
  }

  /** Every pattern, for the report command and for diagnostics. */
  describe(): { readonly allow: readonly string[]; readonly deny: readonly string[] } {
    return { allow: this.allow.map(pattern => pattern.source), deny: this.deny.map(pattern => pattern.source) }
  }
}
