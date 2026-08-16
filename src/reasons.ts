/**
 * The closed vocabulary of refusal reasons, and the model-facing sentence each
 * one produces.
 *
 * The enumeration is closed on purpose: a model that receives
 * `blocked-by-allowlist` can ask the user to add a host, while a model that
 * receives a timeout retries the same request forever. The vocabulary is
 * borrowed from Codex's sandbox network policy so an operator reading two
 * products' logs sees one set of words.
 * @module dsh-netguard/reasons
 */

/** Why one request was refused. */
export type DenialReason =
  /** The host is not on the allowlist (an empty allowlist denies everything). */
  | 'blocked-by-allowlist'
  /** The host matched a deny pattern, which wins over every allow pattern. */
  | 'blocked-by-denylist'
  /** The host resolved to a loopback, private, link-local, or cloud-metadata address. */
  | 'blocked-by-private-address'
  /** The URL is not `http:` or `https:`. */
  | 'blocked-by-scheme'
  /** The URL carries a username or password. */
  | 'blocked-by-credentials'
  /** A redirect left the origin, exceeded the hop budget, or pointed at a refused target. */
  | 'blocked-by-redirect'

/** Every reason, in the order the README documents them. */
export const DENIAL_REASONS: readonly DenialReason[] = Object.freeze([
  'blocked-by-allowlist',
  'blocked-by-denylist',
  'blocked-by-private-address',
  'blocked-by-scheme',
  'blocked-by-credentials',
  'blocked-by-redirect',
])

/** The seam-compatible error code each reason is reported under. */
export const REASON_CODES: Readonly<Record<DenialReason, string>> = Object.freeze({
  'blocked-by-allowlist': 'WEB_BLOCKED_URL',
  'blocked-by-denylist': 'WEB_BLOCKED_URL',
  'blocked-by-private-address': 'WEB_BLOCKED_URL',
  'blocked-by-scheme': 'WEB_INVALID_URL',
  'blocked-by-credentials': 'WEB_BLOCKED_URL',
  'blocked-by-redirect': 'WEB_REDIRECT_BLOCKED',
})

/** What the model is told to do about each reason. */
const REASON_ADVICE: Readonly<Record<DenialReason, string>> = Object.freeze({
  'blocked-by-allowlist': 'Ask the user to add the host to netguard\'s allow list if this request is expected.',
  'blocked-by-denylist': 'This host is denied explicitly and cannot be reached from this agent.',
  'blocked-by-private-address': 'Internal and cloud-metadata addresses are never reachable from this agent.',
  'blocked-by-scheme': 'Only http and https URLs can be retrieved.',
  'blocked-by-credentials': 'Remove the credentials from the URL and pass them another way.',
  'blocked-by-redirect': 'Retry against the final URL directly, so it gets its own policy decision.',
})

/**
 * The sentence a refused request returns to the model.
 *
 * It names the host, the reason and the matched rule — never the path or the
 * query string, which is where a token rides and which this package digests
 * everywhere else.
 * @param reason - the refusal reason.
 * @param host - the hostname (and port, when not the scheme default) that was refused.
 * @param rule - the matched rule id, when a pattern decided it.
 * @returns the complete model-facing message.
 */
export function denialMessage(reason: DenialReason, host: string, rule?: string): string {
  const matched = rule === undefined ? '' : ` (rule ${rule})`
  return `dsh-netguard refused this request to ${host}: ${reason}${matched}. ${REASON_ADVICE[reason]}`
}
