/**
 * What the SOC lane is allowed to carry.
 *
 * Verbatim: hostname, port, resolved IP address, the verdict, the matched rule
 * id, the tool name. Digested: the full URL, its path, and a search query —
 * every one of which is a place a token, a customer name, or the content of the
 * task itself rides. The digest is `HMAC-SHA256(key, value)`, so the same URL
 * digests identically everywhere in a process (and across processes when the
 * key is configured) and a SIEM can still join on it, while nobody reading the
 * spool learns the value.
 *
 * This mirrors `dsh-ocsf-forwarder`'s lane rule exactly, so records from the
 * two packages can sit in one index without one of them being the leak.
 * @module dsh-netguard/privacy
 */

import { createHmac } from 'node:crypto'

/** Hex characters kept from each digest. 128 bits is far beyond collision reach here. */
const DIGEST_HEX_CHARS = 32

/**
 * Keyed digest of one value.
 * @param key - the process's HMAC key.
 * @param value - the value to digest.
 * @returns the truncated hex digest, prefixed with its algorithm.
 */
export function digest(key: Buffer, value: string): string {
  return `hmac-sha256:${createHmac('sha256', key).update(value).digest('hex').slice(0, DIGEST_HEX_CHARS)}`
}

/** A URL reduced to what the SOC lane may hold. */
export interface DigestedUrl {
  /** Keyed digest of the complete URL. */
  readonly digest: string
  /** Character length of the complete URL. */
  readonly length: number
  /** Whether the URL carried a query string, which is the field that matters for exfiltration. */
  readonly hasQuery: boolean
}

/**
 * Reduce one URL to the digest, the length and the query flag.
 * @param key - the process's HMAC key.
 * @param url - the parsed URL.
 * @returns the SOC-lane projection of the URL.
 */
export function digestUrl(key: Buffer, url: URL): DigestedUrl {
  return { digest: digest(key, url.href), length: url.href.length, hasQuery: url.search.length > 0 }
}

/**
 * What a record's `host` field says when there is no host to name.
 *
 * `dst_endpoint.hostname`, `observables[].value` and `message` are verbatim
 * fields, and a decision can arrive without a hostname at all: a `url` argument
 * that is not a string, text that is not a URL, a vendor source URL that does
 * not parse, a query rather than a target. Each of those gets one of these
 * fixed markers, and the value itself is carried as a digest.
 */
export const HOST_MARKERS = Object.freeze({
  /** The `url` or `query` argument was present but not a string. */
  nonString: '(non-string-argument)',
  /** The text is not a URL with a host this package can decide. */
  unparsedUrl: '(unparsed-url)',
  /** A vendor search result named a source URL that does not parse. */
  unparsedSource: '(unparsed-source)',
  /** The decision is about a search query rather than about one target. */
  query: '(query)',
  /** A hostname carrying characters a verbatim field may not hold. */
  unrecordableHost: '(unrecordable-host)',
})

/** Every marker, so a reader of the spool can tell one from a hostname. */
const MARKER_VALUES: ReadonlySet<string> = new Set(Object.values(HOST_MARKERS))

/**
 * Characters a hostname may carry into a verbatim record field.
 *
 * WHATWG `URL` keeps `'`, `"`, a backtick, `$`, `;`, `,` and `{` in a hostname,
 * and a vendor search result is not this package's text at all. A record field
 * is read by a SIEM, pasted into YAML by `--suggest`, and rendered in a report,
 * so anything outside a DNS name, a dotted quad or a compressed IPv6 literal is
 * replaced by a marker rather than written through.
 */
const RECORDABLE_HOST = /^[a-z0-9.:_-]+$/

/**
 * Whether a host may be written into a verbatim record field.
 * @param host - the canonical host key, or one of {@link HOST_MARKERS}.
 * @returns true when the value is a marker or a plain host spelling.
 */
export function isRecordableHost(host: string): boolean {
  return MARKER_VALUES.has(host) || RECORDABLE_HOST.test(host)
}

/** A search query reduced to what the SOC lane may hold. */
export interface DigestedQuery {
  readonly digest: string
  readonly length: number
}

/**
 * Reduce one search query to a digest and a length. The query string *is* the
 * payload of a search-based exfiltration, so it is never carried verbatim.
 * @param key - the process's HMAC key.
 * @param query - the outbound query.
 * @returns the SOC-lane projection of the query.
 */
export function digestQuery(key: Buffer, query: string): DigestedQuery {
  return { digest: digest(key, query), length: query.length }
}
