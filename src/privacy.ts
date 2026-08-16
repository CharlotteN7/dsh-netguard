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
