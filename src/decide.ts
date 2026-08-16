/**
 * The decision itself: what a URL has to survive before a socket is opened, and
 * what a resolved address has to survive before it is dialled.
 *
 * The split matters. Everything here is a pure function of a URL, a resolver
 * answer and the resolved policy — no I/O, no clock — so the whole matrix is
 * unit-testable, and the transport in `fetch-provider.ts` is left with only the
 * job of making sure the socket goes to the address this module vetted.
 * @module dsh-netguard/decide
 */

import { identifyHost, refusedAddressClass, type HostIdentity } from './address.ts'
import type { ResolvedPolicy } from './policy.ts'
import type { DenialReason } from './reasons.ts'

/** Default port of each accepted scheme. */
const DEFAULT_PORTS: Readonly<Record<string, number>> = Object.freeze({ 'http:': 80, 'https:': 443 })

/** One request target, canonicalised. */
export interface Target {
  readonly url: URL
  /** The canonical host identity every rule is matched against. */
  readonly identity: HostIdentity
  /** The effective port: the explicit one, or the scheme's default. */
  readonly port: number
  /** `host` or `host:port`, for messages and for the record's `dst_endpoint`. */
  readonly display: string
}

/** What the policy decided about one target or address. */
export type Decision =
  | { readonly kind: 'allow'; readonly rule: string }
  | { readonly kind: 'deny'; readonly reason: DenialReason; readonly rule?: string; readonly detail?: string }

/** The result of checking one URL. */
export type TargetCheck =
  /** The text is not a URL this package can act on at all. */
  | { readonly kind: 'invalid'; readonly detail: string }
  | { readonly kind: 'checked'; readonly target: Target; readonly decision: Decision }

/**
 * The effective port of a URL.
 * @param url - the parsed URL, whose scheme is already known to be http(s).
 * @returns the explicit port, or the scheme default.
 */
export function effectivePort(url: URL): number {
  return url.port.length > 0 ? Number(url.port) : (DEFAULT_PORTS[url.protocol] ?? 0)
}

/**
 * Parse one URL and decide it against the host policy.
 *
 * The hostname is read from `url.hostname`, never from the raw string: WHATWG
 * `URL` has already turned `2130706433`, `0x7f000001`, `127.1` and
 * `017700000001` into `127.0.0.1`, and `identifyHost` unwraps the IPv4-mapped
 * IPv6 spellings it leaves compressed.
 * @param raw - the URL as the model wrote it.
 * @param policy - the resolved policy.
 * @returns the parse failure, or the target with its decision.
 */
export function checkUrl(raw: string, policy: ResolvedPolicy): TargetCheck {
  if (raw.length > policy.fetch.maxUrlLength) {
    return { kind: 'invalid', detail: `URL exceeds the maximum length of ${policy.fetch.maxUrlLength}` }
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    // URL parse failure only: there is no host to decide and nothing to record
    // beyond the failure itself.
    return { kind: 'invalid', detail: `invalid URL: ${raw}` }
  }
  const identity = identifyHost(url.hostname)
  if (identity === undefined) {
    // Only a non-special scheme reaches this: WHATWG `URL` refuses an empty host
    // for `http:` and `https:`, so a hostless URL here is `file:`, `data:` or
    // their kind. There is no target to decide and no endpoint to record, but
    // the message still names the scheme, because that is what the model has to
    // change.
    return {
      kind: 'invalid',
      detail: `unsupported URL scheme "${url.protocol}" (only http and https are allowed)`,
    }
  }
  const port = effectivePort(url)
  const display = url.port.length > 0 ? `${identity.key}:${String(port)}` : identity.key
  const target: Target = { url, identity, port, display }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { kind: 'checked', target, decision: { kind: 'deny', reason: 'blocked-by-scheme', detail: url.protocol } }
  }
  if (url.username.length > 0 || url.password.length > 0) {
    return { kind: 'checked', target, decision: { kind: 'deny', reason: 'blocked-by-credentials' } }
  }
  const verdict = policy.hosts.evaluate(identity, port)
  if (verdict.kind === 'allow') return { kind: 'checked', target, decision: { kind: 'allow', rule: verdict.rule } }
  return {
    kind: 'checked',
    target,
    decision: verdict.rule === undefined
      ? { kind: 'deny', reason: verdict.reason }
      : { kind: 'deny', reason: verdict.reason, rule: verdict.rule },
  }
}

/** One resolver answer, canonicalised. */
export interface ResolvedAddress {
  readonly identity: HostIdentity
  readonly family: 4 | 6
}

/**
 * Decide a resolver's answer.
 *
 * Every returned address is checked, and one refused address refuses the whole
 * answer: a name with a public `A` record and an internal `AAAA` record is a
 * name that reaches the internal host on any client that prefers IPv6, and
 * picking the "good" one would make the outcome depend on address selection
 * order rather than on policy.
 * @param addresses - every address the resolver returned.
 * @param policy - the resolved policy, for the ranges the deployment opened.
 * @returns the decision; the allow arm names the address rule that cleared it.
 */
export function checkAddresses(addresses: readonly ResolvedAddress[], policy: ResolvedPolicy): Decision {
  if (addresses.length === 0) {
    return { kind: 'deny', reason: 'blocked-by-private-address', detail: 'the host resolved to no addresses' }
  }
  for (const address of addresses) {
    const refused = refusedAddressClass(address.identity, policy.openedAddresses)
    if (refused !== undefined) {
      return {
        kind: 'deny',
        reason: 'blocked-by-private-address',
        rule: `address:${refused}`,
        detail: `${address.identity.key} is ${refused}`,
      }
    }
  }
  return { kind: 'allow', rule: 'address:public' }
}

/**
 * Whether a redirect target may be followed.
 *
 * Two URLs are same-origin when scheme, hostname and port match. The shipped
 * `web-fetch-http` provider refuses a cross-origin hop so each new origin needs
 * its own tool call and therefore its own policy decision; keeping that rule
 * here means an allowlisted host cannot be used as an open redirector into one
 * that is not.
 * @param from - the URL that answered with the redirect.
 * @param to - the redirect target, already parsed.
 * @returns true when the hop stays inside one origin.
 */
export function isSameOrigin(from: URL, to: URL): boolean {
  return from.protocol === to.protocol && from.hostname === to.hostname && from.port === to.port
}
